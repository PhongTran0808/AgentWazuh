#!/usr/bin/env python3
"""
Knowledge base (RAG) cho AgentWazuh - Wazuh 4.14.x
Embedding LOCAL: BAAI/bge-m3 (sentence-transformers, đa ngôn ngữ, dense 1024 chiều), không cần API key.

Cài đặt:
    # --- Local Embedding Dependencies ---
    sentence-transformers>=2.2.0
    torch>=2.0.0
    # --- Còn lại ---
    chromadb
    rank-bm25

    pip install "sentence-transformers>=2.2.0" "torch>=2.0.0" chromadb rank-bm25

Dùng:
    git clone --depth 1 --branch 4.14 https://github.com/wazuh/wazuh-documentation.git
    python wazuh_kb_local.py build --docs ./wazuh-documentation --rebuild
    python wazuh_kb_local.py local --etc /var/ossec/etc      # index rule/decoder custom (chạy lại khi có rule mới)
    python wazuh_kb_local.py search "if_matched_sid frequency timeframe"
    python wazuh_kb_local.py search "rule phát hiện brute force ssh nhiều lần thất bại"
    python wazuh_kb_local.py next-id --etc /var/ossec/etc

Biến môi trường (tuỳ chọn):
    WAZUH_KB_PATH        thư mục lưu Chroma           (mặc định ./wazuh_kb_local)
    WAZUH_EMBED_MODEL    tên model HF hoặc đường dẫn local (mặc định BAAI/bge-m3)
    WAZUH_EMBED_DEVICE   cuda | mps | cpu             (mặc định cpu khi chạy trong agent)
    WAZUH_EMBED_FP16=1   chạy fp16 (chỉ có tác dụng khi device=cuda), giảm ~một nửa VRAM

GPU ít VRAM (vd 4 GB) dùng chung với LLM local:
    - Runtime (agent gọi search_*): mặc định chạy bge-m3 trên CPU -> nhường toàn bộ VRAM cho LLM.
      Embed 1 câu truy vấn trên CPU chỉ vài trăm ms.
    - Build index (chạy 1 lần, tắt LLM trước): `build` tự dùng GPU nếu có, xong thì giải phóng VRAM.
      Ép thiết bị bằng: python wazuh_kb_local.py build --docs ... --device cpu|cuda
    - Nếu GPU hết VRAM giữa chừng, tự chuyển model sang CPU thay vì crash.
    - Gọi warmup() lúc agent khởi động để lần truy vấn đầu không bị chậm.
    HF_HUB_OFFLINE=1     chạy offline sau khi đã tải model về cache

Gắn vào agent (function calling):
    from wazuh_kb_local import search_wazuh_docs, search_local_rules, next_free_rule_id
    tools=[search_wazuh_docs, search_local_rules, next_free_rule_id]

LƯU Ý: bge-m3 đa ngôn ngữ nên truy vấn tiếng Việt vẫn tìm được docs tiếng Anh (phần vector).
Phần BM25 chỉ khớp từ khoá/định danh (if_sid, sregex, frequency...) nên khi có thể hãy để
truy vấn chứa thuật ngữ Wazuh bằng tiếng Anh.
"""
import argparse
import hashlib
import os
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

os.environ.setdefault("HF_HUB_OFFLINE", "1")

import chromadb

# ---------------------------------------------------------------- cấu hình
WAZUH_VERSION = "4.14"                       # nhánh docs (docs chia theo minor, không có 4.14.7 riêng)
DOCS_BASE_URL = f"https://documentation.wazuh.com/{WAZUH_VERSION}/"

EMBED_MODEL = os.environ.get("WAZUH_EMBED_MODEL", "BAAI/bge-m3")
# Mặc định CPU: agent đang chạy LLM trên GPU nhỏ, không nên giành VRAM. `build` sẽ tự chọn GPU (xem use_device).
EMBED_DEVICE = os.environ.get("WAZUH_EMBED_DEVICE") or "cpu"
EMBED_FP16 = os.environ.get("WAZUH_EMBED_FP16") == "1"
MAX_SEQ_LEN = 1024      # bge-m3 hỗ trợ tới 8192 token; giới hạn 1024 để tiết kiệm RAM/VRAM và thời gian
# bge-m3 KHÔNG cần tiền tố instruction cho query (khác với bge-*-en-v1.5).

DB_PATH = os.environ.get("WAZUH_KB_PATH") or str(Path(__file__).resolve().parent / "wazuh_kb_local")
# Tên collection gắn theo model: đổi model thì tự tách collection mới, không lỗi lệch số chiều (1024 vs 3072...).
_SLUG = re.sub(r"[^a-z0-9]+", "_", EMBED_MODEL.lower()).strip("_")[-40:]
DOCS_COLLECTION = f"wazuh_{WAZUH_VERSION.replace('.', '_')}_{_SLUG}"
LOCAL_COLLECTION = f"wazuh_local_{_SLUG}"

# ~2000 ký tự ≈ 500-700 token (XML/code tốn token hơn văn xuôi), thoải mái dưới MAX_SEQ_LEN.
MAX_CHARS = 2000
MIN_CHARS = 60
EMBED_BATCH = 16        # giảm xuống 4-8 nếu hết RAM/VRAM
UPSERT_BATCH = 64

# Các mẫu file docs cần nạp (tính từ thư mục source/). Mẫu nào không khớp file nào sẽ được báo.
DOC_PATTERNS = [
    "user-manual/ruleset/**/*.rst",                    # rule/decoder syntax, regex, custom, testing...
    "user-manual/reference/ossec-conf/ruleset.rst",    # <ruleset> trong ossec.conf
    "user-manual/reference/**/*logtest*.rst",          # wazuh-logtest
]

# ---------------------------------------------------------------- embedding local + Chroma
_model = None
_chroma = None


def use_device(device):
    """Đổi thiết bị embed (chỉ có hiệu lực trước khi model được nạp, hoặc sẽ nạp lại)."""
    global EMBED_DEVICE
    if device != EMBED_DEVICE:
        release_embedder()
        EMBED_DEVICE = device


def embedder():
    """Nạp model một lần (lần đầu tải ~2.3 GB từ HuggingFace về cache)."""
    global _model
    if _model is None:
        from sentence_transformers import SentenceTransformer
        print(f"[embed] nạp {EMBED_MODEL} (device={EMBED_DEVICE}) ...", file=sys.stderr)
        _model = SentenceTransformer(EMBED_MODEL, device=EMBED_DEVICE)
        _model.max_seq_length = MAX_SEQ_LEN
        if EMBED_FP16 and str(EMBED_DEVICE).startswith("cuda"):
            _model.half()
    return _model


def _free_cuda():
    try:
        import gc
        import torch
        gc.collect()
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
    except ImportError:
        pass


def release_embedder():
    """Giải phóng model khỏi RAM/VRAM (dùng sau khi build index để trả VRAM cho LLM)."""
    global _model
    _model = None
    _free_cuda()


def warmup():
    """Gọi 1 lần lúc agent khởi động để nạp model trước, tránh chậm ở lần truy vấn đầu tiên."""
    embed_query("warmup")


def _encode(texts, batch_size):
    kwargs = dict(batch_size=batch_size, normalize_embeddings=True,
                  show_progress_bar=False, convert_to_numpy=True)
    m = embedder()
    try:
        return m.encode(texts, **kwargs)
    except RuntimeError as e:                       # torch.cuda.OutOfMemoryError là con của RuntimeError
        if "out of memory" not in str(e).lower():
            raise
        print("[embed] hết VRAM -> chuyển model sang CPU và thử lại", file=sys.stderr)
        m.to("cpu")
        m.float()                                   # fp16 trên CPU chậm/không ổn định
        _free_cuda()
        return m.encode(texts, **kwargs)


def embed_docs(texts):
    return _encode(texts, EMBED_BATCH).tolist()


def embed_query(text):
    return _encode([text], 1).tolist()


def count_tokens(texts):
    tk = embedder().tokenizer
    return [len(ids) for ids in tk(texts, add_special_tokens=True, truncation=False,
                                   verbose=False)["input_ids"]]


def chroma():
    global _chroma
    if _chroma is None:
        _chroma = chromadb.PersistentClient(path=DB_PATH)
    return _chroma


def get_collection(name):
    # Vector đã normalize -> cosine.
    # (Chroma bản mới nếu báo deprecated: dùng configuration={"hnsw": {"space": "cosine"}})
    return chroma().get_or_create_collection(name, metadata={"hnsw:space": "cosine"})


# ---------------------------------------------------------------- xử lý .rst
RULE_LINE = re.compile(r"^([=\-~^\"'`#*+])\1{2,}$")        # dòng gạch dưới/gạch trên của heading
DROP_DIRECTIVE = re.compile(r"^\.\. (meta|toctree|contents|include)::")
LABEL = re.compile(r"^\.\. _[^:]+:\s*$")


def clean_rst(text):
    """Bỏ phần nhiễu (meta, toctree, include, nhãn) nhưng giữ code-block/note/bảng."""
    out, skipping = [], False
    for line in text.splitlines():
        if DROP_DIRECTIVE.match(line) or LABEL.match(line):
            skipping = True
            continue
        if skipping:
            if not line.strip() or line[0] in " \t":
                continue
            skipping = False
        out.append(line)
    return "\n".join(out)


def split_sections(text):
    """Cắt theo heading rst. Trả về [(breadcrumb, nội_dung)], ví dụ 'Rules Syntax > Options'."""
    lines = text.splitlines()
    levels, path, buf, sections = [], [], [], []

    def flush():
        body = "\n".join(buf).strip()
        if body:
            sections.append((" > ".join(path), body))
        buf.clear()

    i = 0
    while i < len(lines):
        line = lines[i]
        s = line.strip()
        nxt = lines[i + 1].strip() if i + 1 < len(lines) else ""

        # dòng gạch trên của heading kiểu overline: bỏ qua
        if (RULE_LINE.match(s) and i + 2 < len(lines)
                and lines[i + 1].strip() and RULE_LINE.match(lines[i + 2].strip())):
            i += 1
            continue

        # heading kiểu underline
        if (s and not line[0].isspace() and not RULE_LINE.match(s)
                and RULE_LINE.match(nxt) and len(nxt) >= len(s)):
            flush()
            ch = nxt[0]
            if ch not in levels:
                levels.append(ch)
            del path[levels.index(ch):]
            path.append(s)
            i += 2
            continue

        buf.append(line)
        i += 1
    flush()
    return sections


def pack(body, max_chars=MAX_CHARS):
    """Gom đoạn văn thành chunk <= max_chars, cắt ở ranh giới đoạn/dòng, không cắt giữa chừng."""
    pieces = []
    for para in re.split(r"\n\s*\n", body):
        if len(para) <= max_chars:
            pieces.append(para)
            continue
        cur = ""                                    # đoạn quá dài (bảng/code) -> cắt theo dòng
        for ln in para.splitlines(keepends=True):
            if cur and len(cur) + len(ln) > max_chars:
                pieces.append(cur)
                cur = ""
            cur += ln
        if cur:
            pieces.append(cur)

    chunks, cur = [], ""
    for p in pieces:
        if cur and len(cur) + len(p) + 2 > max_chars:
            chunks.append(cur)
            cur = p
        else:
            cur = f"{cur}\n\n{p}" if cur else p
    if cur:
        chunks.append(cur)
    return chunks


def chunk_doc(path, src_root):
    rel = path.relative_to(src_root).as_posix()
    url = DOCS_BASE_URL + re.sub(r"\.rst$", ".html", rel)
    text = clean_rst(path.read_text(encoding="utf-8", errors="ignore"))
    idx = 0
    for section, body in split_sections(text):
        for ch in pack(body):
            if len(ch) < MIN_CHARS:
                continue
            header = f"[Wazuh {WAZUH_VERSION} docs] {rel}" + (f" | {section}" if section else "")
            yield {
                "id": f"{rel}#{idx}",
                "text": f"{header}\n\n{ch}",
                "meta": {"source": rel, "url": url, "section": section, "version": WAZUH_VERSION},
            }
            idx += 1


def _warn_truncation(chunks):
    """Model cắt cứng ở max_seq_length token: báo nếu có chunk bị mất đuôi."""
    limit = embedder().max_seq_length
    lens = count_tokens([c["text"] for c in chunks])
    over = [(c["id"], n) for c, n in zip(chunks, lens) if n > limit]
    print(f"  token/chunk: max={max(lens)}, trung bình={sum(lens) // len(lens)}, giới hạn model={limit}")
    if over:
        print(f"CẢNH BÁO: {len(over)}/{len(chunks)} chunk dài hơn {limit} token sẽ bị cắt đuôi khi embed. "
              f"Giảm MAX_CHARS (hiện {MAX_CHARS}). Ví dụ: {over[:3]}", file=sys.stderr)


def _upsert(col, chunks):
    for i in range(0, len(chunks), UPSERT_BATCH):
        b = chunks[i:i + UPSERT_BATCH]
        col.upsert(                                   # upsert: chạy lại không bị lỗi trùng ID
            ids=[c["id"] for c in b],
            documents=[c["text"] for c in b],
            metadatas=[c["meta"] for c in b],
            embeddings=embed_docs([c["text"] for c in b]),
        )
        print(f"  đã index {min(i + UPSERT_BATCH, len(chunks))}/{len(chunks)}")


# ---------------------------------------------------------------- build index docs
def _pick_build_device(arg):
    """auto: tôn trọng WAZUH_EMBED_DEVICE nếu có; nếu không thì dùng GPU khi có, ngược lại CPU."""
    if arg != "auto":
        return arg
    if os.environ.get("WAZUH_EMBED_DEVICE"):
        return os.environ["WAZUH_EMBED_DEVICE"]
    try:
        import torch
        return "cuda" if torch.cuda.is_available() else "cpu"
    except ImportError:
        return "cpu"


def build_docs(docs_root, rebuild=False, device="auto"):
    use_device(_pick_build_device(device))
    root = Path(docs_root)
    src = root / "source"
    if not src.is_dir():
        sys.exit(f"Không thấy {src}. Hãy clone wazuh-documentation trước.")

    head = root / ".git" / "HEAD"
    if head.exists() and WAZUH_VERSION not in head.read_text():
        print(f"CẢNH BÁO: repo docs không ở nhánh {WAZUH_VERSION}: {head.read_text().strip()}", file=sys.stderr)

    files = set()
    for pat in DOC_PATTERNS:
        found = sorted(src.glob(pat))
        print(f"  {pat}: {len(found)} file")
        files.update(found)
    if not files:
        sys.exit("Không có file nào khớp. Kiểm tra lại đường dẫn --docs.")

    chunks = [c for f in sorted(files) for c in chunk_doc(f, src)]
    print(f"Tổng {len(files)} file -> {len(chunks)} chunk (collection: {DOCS_COLLECTION})")
    _warn_truncation(chunks)

    if rebuild:
        try:
            chroma().delete_collection(DOCS_COLLECTION)
        except Exception:
            pass
    _upsert(get_collection(DOCS_COLLECTION), chunks)
    release_embedder()                              # trả VRAM/RAM ngay sau khi build
    print("Xong.")


# ---------------------------------------------------------------- rule/decoder custom
def _local_chunks(etc_dir):
    for sub, tag in (("rules", "rule"), ("decoders", "decoder")):
        for f in sorted(Path(etc_dir).glob(f"{sub}/*.xml")):
            raw = re.sub(r"<\?xml[^>]*\?>", "", f.read_text(encoding="utf-8", errors="ignore"))
            try:
                root = ET.fromstring(f"<root>{raw}</root>")    # file Wazuh có nhiều phần tử gốc
            except ET.ParseError as e:
                print(f"  bỏ qua {f} (XML lỗi: {e})", file=sys.stderr)
                continue
            for top in root:
                gname = top.get("name", "") if top.tag == "group" else ""
                elements = [top] if top.tag == tag else list(top.iter(tag))
                for el in elements:
                    key = el.get("id") or el.get("name") or hashlib.md5(
                        ET.tostring(el)).hexdigest()[:8]
                    yield {
                        "id": f"{f.name}:{tag}:{key}",
                        "text": f"[local {tag}] {f.name}\n\n" + ET.tostring(el, encoding="unicode").strip(),
                        "meta": {"kind": tag, "file": f.name, "key": str(key),
                                 "level": el.get("level", ""), "groups": gname},
                    }


def index_local(etc_dir="/var/ossec/etc"):
    """Index lại toàn bộ rule/decoder custom (nhỏ, nên xoá và build lại cho sạch)."""
    chunks = list(_local_chunks(etc_dir))
    try:
        chroma().delete_collection(LOCAL_COLLECTION)
    except Exception:
        pass
    col = get_collection(LOCAL_COLLECTION)
    if chunks:
        _upsert(col, chunks)
    print(f"Đã index {len(chunks)} rule/decoder custom từ {etc_dir}")


def next_free_rule_id(etc_dir: str = "/var/ossec/etc") -> int:
    """Return the next free custom Wazuh rule ID (range 100000-120000), scanning all rule files in etc_dir/rules."""
    used = set()
    try:
        for f in Path(etc_dir).glob("rules/*.xml"):
            try:
                text = f.read_text(encoding="utf-8", errors="ignore")
                used.update(int(x) for x in re.findall(r'<rule\s[^>]*?\bid=["\'](\d+)["\']', text))
            except Exception:
                pass
    except Exception:
        pass
    if not used:
        try:
            from integrations.wazuh_config_manager import _read_target
            _, text = _read_target("rules")
            used.update(int(x) for x in re.findall(r'<rule\s[^>]*?\bid=["\'](\d+)["\']', text))
        except Exception:
            pass
    custom = [i for i in used if 100000 <= i <= 120000]
    nxt = max(custom) + 1 if custom else 100001
    if nxt > 120000:
        raise ValueError("Hết dải rule ID custom 100000-120000")
    return nxt


# ---------------------------------------------------------------- tìm kiếm (tool cho agent)
_TOKEN = re.compile(r"\w+")          # unicode: từ tiếng Việt giữ nguyên, định danh như if_sid giữ nguyên
_bm25_cache = None


def _tok(s):
    return [t.lower() for t in _TOKEN.findall(s)]


def _load_bm25():
    """BM25 trên toàn bộ chunk docs để bắt từ khoá chính xác (if_matched_sid, sregex, pcre2...)."""
    global _bm25_cache
    if _bm25_cache is None:
        from rank_bm25 import BM25Okapi
        data = get_collection(DOCS_COLLECTION).get(include=["documents", "metadatas"])
        _bm25_cache = (BM25Okapi([_tok(d) for d in data["documents"]]),
                       data["ids"], data["documents"], data["metadatas"])
    return _bm25_cache


def search_wazuh_docs(query: str, k: int = 5) -> str:
    """Search the official Wazuh 4.14 documentation (rule/decoder XML syntax, regex types,
    if_sid, frequency/timeframe, wazuh-logtest, ...). Always call this before writing a rule
    to verify the options you plan to use. The query may be in English or Vietnamese; include exact
    Wazuh keywords (e.g. if_sid, frequency, sregex) when you know them.
    Returns the top-k passages with their source URL."""
    col = get_collection(DOCS_COLLECTION)
    if col.count() == 0:
        return "Knowledge base is empty. Run: python wazuh_kb_local.py build --docs <path>"
    n = max(k * 4, 20)
    vec = col.query(query_embeddings=embed_query(query),
                    n_results=min(n, col.count()), include=["documents", "metadatas"])

    store, score = {}, {}
    for r, cid in enumerate(vec["ids"][0]):                       # xếp hạng theo vector
        store[cid] = (vec["documents"][0][r], vec["metadatas"][0][r])
        score[cid] = score.get(cid, 0) + 1 / (60 + r)

    try:                                                           # xếp hạng theo từ khoá (RRF)
        bm, ids, docs, metas = _load_bm25()
        s = bm.get_scores(_tok(query))
        top = sorted(range(len(ids)), key=lambda i: s[i], reverse=True)[:n]
        for r, i in enumerate(top):
            if s[i] > 0:
                store[ids[i]] = (docs[i], metas[i])
                score[ids[i]] = score.get(ids[i], 0) + 1 / (60 + r)
    except ImportError:
        pass                                                       # chưa cài rank-bm25 -> chỉ dùng vector

    best = sorted(score, key=score.get, reverse=True)[:k]
    parts = []
    for n_, cid in enumerate(best, 1):
        doc, meta = store[cid]
        parts.append(f"### [{n_}] {meta.get('section') or meta.get('source')}\n"
                     f"Source: {meta.get('url')}\n\n{doc}")
    return "\n\n---\n\n".join(parts) or "No results."


def search_local_rules(query: str, k: int = 5) -> str:
    """Search the custom rules/decoders already deployed on this Wazuh manager
    (local_rules.xml, local_decoder.xml). Use it to avoid duplicates and to find a suitable if_sid.
    The query may be in English or Vietnamese."""
    col = get_collection(LOCAL_COLLECTION)
    if col.count() == 0:
        return "No local rules indexed."
    res = col.query(query_embeddings=embed_query(query),
                    n_results=min(k, col.count()), include=["documents"])
    return "\n\n---\n\n".join(res["documents"][0])


# ---------------------------------------------------------------- CLI
def main():
    ap = argparse.ArgumentParser(description="Wazuh knowledge base (local embedding) cho AgentWazuh")
    sub = ap.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="index docs Wazuh")
    b.add_argument("--docs", required=True, help="thư mục repo wazuh-documentation (nhánh 4.14)")
    b.add_argument("--rebuild", action="store_true", help="xoá collection cũ trước khi build")
    b.add_argument("--device", default="auto", choices=["auto", "cuda", "cpu"],
                   help="thiết bị embed khi build (auto = GPU nếu có). Nhớ tắt LLM trước nếu dùng GPU 4 GB")

    l = sub.add_parser("local", help="index rule/decoder custom")
    l.add_argument("--etc", default="/var/ossec/etc")

    s = sub.add_parser("search", help="thử truy vấn")
    s.add_argument("query")
    s.add_argument("-k", type=int, default=5)

    n = sub.add_parser("next-id", help="rule ID custom còn trống")
    n.add_argument("--etc", default="/var/ossec/etc")

    a = ap.parse_args()
    if a.cmd == "build":
        build_docs(a.docs, a.rebuild, a.device)
    elif a.cmd == "local":
        index_local(a.etc)
    elif a.cmd == "search":
        print(search_wazuh_docs(a.query, a.k))
    elif a.cmd == "next-id":
        print(next_free_rule_id(a.etc))


if __name__ == "__main__":
    main()
