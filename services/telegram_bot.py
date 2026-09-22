"""Telegram bridge for the AgentWazuh conversational investigation pipeline."""

from __future__ import annotations

import asyncio
import html
import logging
import os
import re
from typing import Awaitable, Callable, Optional

from telegram import Update
from telegram.constants import ChatAction
from telegram.error import BadRequest, InvalidToken
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters


logger = logging.getLogger("AgentWazuhTelegram")
MessageProcessor = Callable[[int, str, str], Awaitable[str]]
MAX_TELEGRAM_MESSAGE = 4096


def _allowed_chat_ids() -> Optional[set[int]]:
    raw = os.getenv("TELEGRAM_ALLOWED_CHAT_IDS", "").strip()
    if not raw:
        return None
    allowed: set[int] = set()
    for value in raw.split(","):
        try:
            allowed.add(int(value.strip()))
        except ValueError:
            logger.warning("Bỏ qua TELEGRAM_ALLOWED_CHAT_IDS không hợp lệ: %s", value)
    return allowed or None


def _redact_http_logs(token: str) -> None:
    """Prevent httpx/PTB request logs from printing the bot token in URLs."""
    class TokenFilter(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            message = record.getMessage().replace(token, "<telegram-token-redacted>")
            record.msg = message
            record.args = ()
            return True

    for name in ("httpx", "httpcore"):
        logging.getLogger(name).addFilter(TokenFilter())


def _table_to_cards(lines: list[str]) -> list[str]:
    """Convert a Markdown table block into phone-friendly Telegram cards."""
    rows = []
    for line in lines:
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if cells and not all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells):
            rows.append(cells)
    if len(rows) < 2:
        return lines
    headers = rows[0]
    cards = []
    for index, row in enumerate(rows[1:], 1):
        cards.append(f"📋 **Bản ghi {index}**")
        for col, value in enumerate(row):
            label = headers[col] if col < len(headers) else f"Trường {col + 1}"
            cards.append(f"├ **{label}**: {value}")
        cards.append("└")
    return cards[:-1]


def _protect_code(text: str, protected: list[str]) -> str:
    def save_value(value: str) -> str:
        token = f"\x00{len(protected)}\x00"
        protected.append(value)
        return token

    # Preserve fenced and inline code before escaping/formatting HTML.
    text = re.sub(
        r"```(?:[\w+-]+)?\n?(.*?)```",
        lambda match: save_value(match.group(1)),
        text,
        flags=re.DOTALL,
    )
    text = re.sub(r"`([^`\n]+)`", lambda match: save_value(match.group(1)), text)

    patterns = [
        r"(?<![\w>])(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?(?!\w)",
        r"\b(?:port|cổng)\s*[:#]?\s*\d{1,5}\b",
        r"(?<![\w>])(?:/[\w.~-]+)+/?(?!\w)",
        r"(?<![\w>])\b[a-fA-F0-9]{32,64}\b(?!\w)",
        r"\b(?:rule|quy tắc)\s*#?\s*\d{4,6}\b",
    ]
    combined = re.compile("|".join(f"({pattern})" for pattern in patterns), re.IGNORECASE)
    return combined.sub(lambda match: save_value(match.group(0)), text)


def format_telegram_html(text: str) -> str:
    """Render assistant Markdown as Telegram-safe HTML cards."""
    raw = (text or "").strip() or "AgentWazuh không tạo được nội dung phản hồi."
    raw = re.sub(r"<\/?(?:button|div|span|i|strong|em|p)[^>]*>", "", raw, flags=re.I)
    lines = raw.splitlines()
    output: list[str] = []
    index = 0
    while index < len(lines):
        if "|" in lines[index] and index + 1 < len(lines) and "|" in lines[index + 1]:
            table = []
            while index < len(lines) and "|" in lines[index]:
                table.append(lines[index])
                index += 1
            output.extend(_table_to_cards(table))
            continue
        output.append(lines[index])
        index += 1
    raw = "\n".join(output)

    protected: list[str] = []
    raw = _protect_code(raw, protected)
    rendered = html.escape(raw, quote=False)
    rendered = re.sub(r"^#{1,6}\s+(.+)$", r"<b>\1</b>", rendered, flags=re.MULTILINE)
    rendered = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", rendered, flags=re.DOTALL)
    rendered = re.sub(r"__(.+?)__", r"<b>\1</b>", rendered, flags=re.DOTALL)
    rendered = re.sub(r"(?m)^\s*[-*]\s+", "🔹 ", rendered)
    rendered = re.sub(r"(?m)^\s*&gt;\s?(.*)$", r"<blockquote>\1</blockquote>", rendered)
    for index, value in enumerate(protected):
        token = f"\x00{index}\x00"
        if token in rendered:
            value = token
            rendered = rendered.replace(token, f"<code>{html.escape(protected[index], quote=False)}</code>")
    return rendered.strip()


def _split_message(text: str) -> list[str]:
    text = format_telegram_html(text)
    if len(text) <= MAX_TELEGRAM_MESSAGE:
        return [text]
    chunks = []
    current = ""
    for paragraph in text.split("\n\n"):
        candidate = f"{current}\n\n{paragraph}" if current else paragraph
        if len(candidate) <= MAX_TELEGRAM_MESSAGE:
            current = candidate
        else:
            if current:
                chunks.append(current)
            while len(paragraph) > MAX_TELEGRAM_MESSAGE:
                chunks.append(paragraph[:MAX_TELEGRAM_MESSAGE])
                paragraph = paragraph[MAX_TELEGRAM_MESSAGE:]
            current = paragraph
    if current:
        chunks.append(current)
    return chunks or ["AgentWazuh không tạo được nội dung phản hồi."]


def create_telegram_application(process_message: MessageProcessor) -> Optional[Application]:
    """Build the PTB application. Return None when no token is configured."""
    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    if not token:
        logger.warning("Telegram bridge disabled: thiếu TELEGRAM_BOT_TOKEN.")
        return None
    _redact_http_logs(token)

    allowed_ids = _allowed_chat_ids()
    if allowed_ids is None:
        logger.warning("Telegram bridge đang mở cho mọi chat; nên đặt TELEGRAM_ALLOWED_CHAT_IDS.")

    application = Application.builder().token(token).build()

    async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        message = update.effective_message
        chat = update.effective_chat
        user = update.effective_user
        if not message or not chat or not message.text:
            return
        if allowed_ids is not None and chat.id not in allowed_ids:
            await message.reply_text("Chat này chưa được cấp quyền sử dụng AgentWazuh.")
            return

        query = message.text.strip()
        if not query:
            return
        user_label = str(user.id if user else chat.id)
        await context.bot.send_chat_action(chat_id=chat.id, action=ChatAction.TYPING)
        try:
            response = await process_message(chat.id, query, user_label)
        except Exception:
            logger.exception("Xử lý Telegram thất bại cho chat %s", chat.id)
            response = "AgentWazuh gặp lỗi khi xử lý yêu cầu. Vui lòng thử lại sau."
        for part in _split_message(response):
            try:
                await message.reply_text(part, parse_mode="HTML")
            except BadRequest:
                # A malformed model fragment must not break the conversation.
                fallback = re.sub(r"<[^>]+>", "", html.unescape(part))
                await message.reply_text(fallback)

    async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        if update.effective_message:
            await update.effective_message.reply_text(
                "AgentWazuh đã sẵn sàng. Hãy gửi câu hỏi tự nhiên về Wazuh, alert hoặc agent."
            )

    application.add_handler(CommandHandler(["start", "help"], start_command))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    return application


async def run_telegram_bot(process_message: MessageProcessor, stop_event: asyncio.Event) -> None:
    """Run polling until the hosting application is stopped."""
    application = create_telegram_application(process_message)
    if application is None:
        return
    try:
        await application.initialize()
        await application.start()
        if application.updater is None:
            raise RuntimeError("Telegram updater không khả dụng")
        await application.updater.start_polling(allowed_updates=Update.ALL_TYPES)
        logger.info("Telegram bot đã kết nối polling.")
    except asyncio.CancelledError:
        raise
    except InvalidToken:
        logger.error("Telegram bridge không khởi động được: token không hợp lệ hoặc đã bị thu hồi.")
        return
    except Exception:
        logger.exception("Telegram bridge không khởi động được")
        return
    try:
        await stop_event.wait()
    finally:
        if application.updater and application.updater.running:
            await application.updater.stop()
        if application.running:
            await application.stop()
        await application.shutdown()
