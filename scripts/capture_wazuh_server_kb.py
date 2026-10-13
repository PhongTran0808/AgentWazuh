"""
Capture real screenshots from live Wazuh Server (https://100.69.72.103)
and draw crisp red bounding boxes (viền đỏ), red underlines (gạch chân đỏ),
and non-overlapping numbered Vietnamese callout badges directly on the Wazuh Server UI.
"""

from __future__ import annotations

import time
from pathlib import Path
from PIL import Image, ImageDraw
from playwright.sync_api import sync_playwright, Page

OUT_DIR = Path(__file__).resolve().parent.parent / "web" / "assets" / "kb"
OUT_DIR.mkdir(parents=True, exist_ok=True)

WAZUH_URL = "https://100.69.72.103"
USER = "admin"
PASS = "admin"

OVERLAY_HELPER_JS = """
window.__clearWzAnnotations = () => {
  document.querySelectorAll('.wz-kb-anno').forEach(e => e.remove());
  document.querySelectorAll('.euiGlobalToastList').forEach(e => e.style.display = 'none');
};

window.__addBoxByText = (text, label, mode = 'box', pad = 4, parentUp = 0, badgePos = 'top') => {
  const els = Array.from(document.querySelectorAll('button, a, span, div, h1, h2, h3, h4, p, td, th'));
  let candidates = [];
  for (const el of els) {
    const t = (el.innerText || '').trim();
    if (t === text) {
      const r = el.getBoundingClientRect();
      if (r.width > 12 && r.height > 10 && r.top >= 0 && r.top < window.innerHeight - 10) {
        candidates.push({el, area: r.width * r.height});
      }
    }
  }
  if (candidates.length === 0) {
    for (const el of els) {
      const t = (el.innerText || '').trim();
      if (t.startsWith(text) && t.length < text.length + 45) {
        const r = el.getBoundingClientRect();
        if (r.width > 12 && r.height > 10 && r.top >= 0 && r.top < window.innerHeight - 10) {
          candidates.push({el, area: r.width * r.height});
        }
      }
    }
  }
  if (candidates.length === 0) return false;
  candidates.sort((a, b) => a.area - b.area);
  let target = candidates[0].el;
  for (let i = 0; i < parentUp; i++) {
    if (target.parentElement) target = target.parentElement;
  }
  window.__drawRectAnno(target.getBoundingClientRect(), label, mode, pad, badgePos);
  return true;
};

window.__addBoxBySelector = (sel, label, mode = 'box', pad = 4, badgePos = 'top') => {
  const el = document.querySelector(sel);
  if (!el) return false;
  window.__drawRectAnno(el.getBoundingClientRect(), label, mode, pad, badgePos);
  return true;
};

window.__drawRectAnno = (r, label, mode = 'box', pad = 4, badgePos = 'top') => {
  if (!r || r.width < 5 || r.height < 5) return;
  const div = document.createElement('div');
  div.className = 'wz-kb-anno';
  const left = Math.max(2, r.left - pad);
  const top = Math.max(2, r.top - pad);
  const width = Math.min(window.innerWidth - left - 4, r.width + pad * 2);
  const height = r.height + pad * 2;

  div.style.position = 'fixed';
  div.style.left = left + 'px';
  div.style.top = top + 'px';
  div.style.width = width + 'px';
  div.style.height = height + 'px';
  div.style.zIndex = '999999';
  div.style.pointerEvents = 'none';
  div.style.boxSizing = 'border-box';

  if (mode === 'underline') {
    div.style.borderBottom = '4px solid #dc2626';
    div.style.background = 'rgba(220, 38, 38, 0.06)';
  } else {
    div.style.border = '3px solid #dc2626';
    div.style.borderRadius = '7px';
    div.style.background = 'rgba(220, 38, 38, 0.05)';
    div.style.boxShadow = '0 0 0 1.5px rgba(255,255,255,0.9), 0 4px 12px rgba(220,38,38,0.25)';
  }

  if (label) {
    const badge = document.createElement('div');
    badge.innerText = label;
    badge.style.position = 'fixed';
    let bLeft = Math.min(window.innerWidth - 320, Math.max(4, left));
    let bTop = top - 25;
    if (badgePos === 'right') {
      bLeft = left + width + 8;
      bTop = top + Math.max(0, (height - 22) / 2);
    } else if (badgePos === 'bottom') {
      bTop = top + height + 4;
    } else if (bTop < 4) {
      bTop = top + height + 4;
    }
    badge.style.left = bLeft + 'px';
    badge.style.top = bTop + 'px';
    badge.style.background = '#dc2626';
    badge.style.color = '#ffffff';
    badge.style.fontFamily = 'Inter, Arial, sans-serif';
    badge.style.fontSize = '12px';
    badge.style.fontWeight = '700';
    badge.style.padding = '3px 8px';
    badge.style.borderRadius = '5px';
    badge.style.whiteSpace = 'nowrap';
    badge.style.boxShadow = '0 2px 6px rgba(0,0,0,0.3)';
    badge.style.zIndex = '1000000';
    div.appendChild(badge);
  }
  document.body.appendChild(div);
};
"""


def inject_helpers(page: Page) -> None:
    page.evaluate(OVERLAY_HELPER_JS)
    page.evaluate("window.__clearWzAnnotations()")


def capture_all() -> None:
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        ctx = browser.new_context(
            ignore_https_errors=True,
            viewport={"width": 1600, "height": 960},
        )
        page = ctx.new_page()
        print("1. Logging into Wazuh Server...")
        page.goto(f"{WAZUH_URL}/app/login", wait_until="domcontentloaded", timeout=30000)
        page.wait_for_selector('input[data-test-subj="user-name"]', timeout=15000)
        page.fill('input[data-test-subj="user-name"]', USER)
        page.fill('input[data-test-subj="password"]', PASS)
        page.click('button[data-test-subj="submit"]')
        page.wait_for_url("**/app/wz-home**", timeout=30000)
        time.sleep(8)

        # ------------------------------------------------------------------
        # 1) WAZUH OVERVIEW (wz_overview_annotated.png)
        # ------------------------------------------------------------------
        print("2. Capturing wz_overview_annotated.png...")
        inject_helpers(page)
        page.evaluate("""() => {
            window.__addBoxBySelector('button[data-test-subj="toggleNavButton"]', '① Menu ☰ (Mở danh sách chức năng)', 'box', 4, 'right');
            window.__addBoxByText('AGENTS SUMMARY', '② AGENTS SUMMARY (Quản lý & Thêm thiết bị)', 'box', 6, 3, 'top');
            window.__addBoxByText('LAST 24 HOURS ALERTS', '③ Thống kê Cảnh báo 24h theo 4 mức độ', 'box', 6, 3, 'top');
            window.__addBoxByText('Configuration Assessment', '④ Kiểm tra cấu hình chuẩn CIS (SCA)', 'underline', 4, 2, 'top');
            window.__addBoxByText('File Integrity Monitoring', '⑤ Giám sát thay đổi File (FIM)', 'underline', 4, 2, 'top');
            window.__addBoxByText('Threat Hunting', '⑥ Threat Hunting (Đọc Log & Săn mối đe dọa)', 'box', 6, 3, 'top');
            window.__addBoxByText('Vulnerability Detection', '⑦ Quét lỗ hổng phần mềm (CVE)', 'underline', 4, 2, 'top');
            window.__addBoxByText('MITRE ATT&CK', '⑧ Bản đồ kỹ thuật tấn công MITRE', 'underline', 4, 2, 'top');
            window.__addBoxByText('IT Hygiene', '⑨ Giám sát vệ sinh an toàn hệ thống', 'underline', 4, 2, 'top');
            window.__addBoxByText('PCI DSS', '⑩ Báo cáo tuân thủ chuẩn quốc tế', 'underline', 4, 2, 'top');
        }""")
        page.screenshot(path=str(OUT_DIR / "wz_overview_annotated.png"))

        # ------------------------------------------------------------------
        # 2) WAZUH LEFT MENU (wz_left_menu_annotated.png) - Dual Composite
        # ------------------------------------------------------------------
        print("3. Capturing wz_left_menu_annotated.png...")
        inject_helpers(page)
        btn = page.query_selector('button[data-test-subj="toggleNavButton"]')
        if btn:
            btn.click()
            time.sleep(1.5)
        # DO NOT click already-open top groups! Just annotate the top half directly:
        inject_helpers(page)
        page.evaluate("""() => {
            window.__addBoxByText('Discover', '① Discover: Tìm kiếm Log thô OpenSearch', 'underline', 2, 0, 'right');
            window.__addBoxByText('Configuration Assessment', '② SCA: Chấm điểm cấu hình chuẩn CIS', 'underline', 2, 0, 'right');
            window.__addBoxByText('File Integrity Monitoring', '③ FIM: Theo dõi thêm/sửa/xóa file', 'underline', 2, 0, 'right');
            window.__addBoxByText('Threat Hunting', '④ Threat Hunting: Xem & lọc toàn bộ Alert', 'box', 3, 0, 'right');
            window.__addBoxByText('Vulnerability Detection', '⑤ Vulnerability: Danh sách lỗ hổng CVE', 'underline', 2, 0, 'right');
            window.__addBoxByText('MITRE ATT&CK', '⑥ MITRE ATT&CK: Kỹ thuật tấn công', 'underline', 2, 0, 'right');
            window.__addBoxByText('IT Hygiene', '⑦ IT Hygiene: Kiểm kê tiến trình & cổng mạng', 'underline', 2, 0, 'right');
        }""")
        top_menu_path = Path("/tmp/wz_menu_top.png")
        page.screenshot(path=str(top_menu_path))

        # Now scroll down in the left drawer and expand Agents management, Server management, Indexer management
        page.evaluate("""() => {
            window.__clearWzAnnotations();
            const scrollable = Array.from(document.querySelectorAll('*')).filter(el => el.scrollHeight > el.clientHeight + 40 && el.getBoundingClientRect().width < 450);
            scrollable.forEach(el => { el.scrollTop = 500; });
        }""")
        time.sleep(0.8)
        for grp_name in ("Agents management", "Server management", "Indexer management"):
            g = page.query_selector(f'.euiCollapsibleNavGroup__heading:has-text("{grp_name}")')
            if g:
                try:
                    g.click()
                    time.sleep(0.25)
                except Exception:
                    pass
        page.evaluate("""() => {
            const scrollable = Array.from(document.querySelectorAll('*')).filter(el => el.scrollHeight > el.clientHeight + 40 && el.getBoundingClientRect().width < 450);
            scrollable.forEach(el => { el.scrollTop = 760; });
        }""")
        time.sleep(0.8)
        inject_helpers(page)
        page.evaluate("""() => {
            window.__addBoxByText('Summary', '⑧ Agents -> Summary: Quản lý & Cài thêm Agent', 'box', 3, 0, 'right');
            window.__addBoxByText('Groups', '⑨ Groups: Cấu hình tập trung (agent.conf)', 'underline', 2, 0, 'right');
            window.__addBoxByText('Rules', '⑩ Rules: Quản lý & sửa Luật XML (local_rules.xml)', 'box', 3, 0, 'right');
            window.__addBoxByText('Decoders', '⑪ Decoders: Bộ tách trường dữ liệu Log', 'underline', 2, 0, 'right');
            window.__addBoxByText('Logs', '⑫ Server Logs: Đọc ossec.log trên Web', 'underline', 2, 0, 'right');
            window.__addBoxByText('Dev Tools', '⑬ Dev Tools: Bảng gọi thử Wazuh REST API', 'underline', 2, 0, 'right');
            window.__addBoxByText('Ruleset Test', '⑭ Ruleset Test: Công cụ test thử Log & Rule', 'box', 3, 0, 'right');
        }""")
        bot_menu_path = Path("/tmp/wz_menu_bot.png")
        page.screenshot(path=str(bot_menu_path))

        im1 = Image.open(top_menu_path).crop((0, 0, 800, 960))
        im2 = Image.open(bot_menu_path).crop((0, 0, 800, 960))
        combined = Image.new("RGB", (1600, 960), (245, 247, 250))
        combined.paste(im1, (0, 0))
        combined.paste(im2, (800, 0))
        draw = ImageDraw.Draw(combined)
        draw.line([(800, 0), (800, 960)], fill=(220, 38, 38), width=4)
        combined.save(str(OUT_DIR / "wz_left_menu_annotated.png"))

        # ------------------------------------------------------------------
        # 3) AGENTS SUMMARY & DEPLOY NEW AGENT (wz_agents_deploy_annotated.png)
        # ------------------------------------------------------------------
        print("4. Capturing wz_agents_deploy_annotated.png...")
        page.goto(f"{WAZUH_URL}/app/endpoints-summary#/agents-preview", wait_until="domcontentloaded", timeout=30000)
        time.sleep(7)
        inject_helpers(page)
        page.evaluate("""() => {
            window.__addBoxByText('Deploy new agent', '① Bấm "Deploy new agent" để thêm máy trạm mới', 'box', 5, 1, 'top');
            window.__addBoxByText('Active (2)', '② Số Agent đang kết nối (Active)', 'underline', 2, 0, 'right');
            window.__addBoxByText('Disconnected (1)', '③ Số Agent mất kết nối (Disconnected)', 'underline', 2, 0, 'right');
        }""")
        agents_list_path = Path("/tmp/wz_agents_list.png")
        page.screenshot(path=str(agents_list_path))

        page.evaluate("window.__clearWzAnnotations()")
        deploy_btn = page.query_selector('button:has-text("Deploy new agent"), span:has-text("Deploy new agent")')
        if deploy_btn:
            deploy_btn.click()
            time.sleep(3)
            deb_opt = page.query_selector('label:has-text("DEB amd64"), span:has-text("DEB amd64")')
            if deb_opt:
                try:
                    deb_opt.click()
                    time.sleep(1)
                except Exception:
                    pass
            addr_inp = page.query_selector('input[placeholder*="Server address"], input[type="text"]')
            if addr_inp:
                try:
                    addr_inp.fill("100.69.72.103")
                    time.sleep(1)
                except Exception:
                    pass
            page.evaluate("window.scrollTo(0, 260)")
            time.sleep(1)
            inject_helpers(page)
            page.evaluate("""() => {
                window.__addBoxByText('DEB amd64', '① Bước 1: Chọn gói Hệ điều hành (VD: DEB amd64 / MSI)', 'box', 5, 1, 'top');
                window.__addBoxByText('Server address:', '② Bước 2: Nhập IP của Wazuh Server (100.69.72.103)', 'underline', 3, 0, 'right');
                window.__addBoxByText('Copy command', '③ Bước 4 & 5: Bấm "Copy command" lấy lệnh cài lên máy trạm', 'box', 5, 1, 'top');
            }""")
            deploy_wiz_path = Path("/tmp/wz_deploy_wiz.png")
            page.screenshot(path=str(deploy_wiz_path))
            im_a = Image.open(agents_list_path).crop((0, 0, 1600, 440))
            im_b = Image.open(deploy_wiz_path).crop((0, 48, 1600, 568))
            comp_ag = Image.new("RGB", (1600, 960), (255, 255, 255))
            comp_ag.paste(im_a, (0, 0))
            comp_ag.paste(im_b, (0, 440))
            d_ag = ImageDraw.Draw(comp_ag)
            d_ag.line([(0, 440), (1600, 440)], fill=(220, 38, 38), width=4)
            comp_ag.save(str(OUT_DIR / "wz_agents_deploy_annotated.png"))

        # ------------------------------------------------------------------
        # 4) THREAT HUNTING -> EVENTS (wz_threat_hunting_logs_annotated.png)
        # ------------------------------------------------------------------
        print("5. Capturing wz_threat_hunting_logs_annotated.png...")
        th_url = f"{WAZUH_URL}/app/threat-hunting#/overview/?tab=general&tabView=events&_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:now-90d,to:now))"
        page.goto(th_url, wait_until="domcontentloaded", timeout=30000)
        time.sleep(9)
        inject_helpers(page)
        page.evaluate("""() => {
            window.__addBoxByText('Events', '① Chọn tab "Events" để đọc từng dòng Log chi tiết', 'box', 4, 0, 'right');
            window.__addBoxBySelector('[data-test-subj="queryInput"], textarea[placeholder*="Search"], input[placeholder*="Search"]', '② Thanh tìm kiếm DQL (VD: rule.id : 5710 hoặc data.srcip : ...)', 'box', 3, 'top');
            window.__addBoxBySelector('[data-test-subj="superDatePickerShowDatesButton"], button.euiSuperDatePicker__prettyFormat', '③ Bộ chọn lịch (Đổi từ Last 24 hours ➔ Last 90 days)', 'box', 4, 'top');
            window.__addBoxBySelector('table tbody tr:first-child td:first-child button', '④ Bấm biểu tượng đầu dòng để bung toàn bộ JSON & full_log', 'box', 4, 'right');
        }""")
        page.screenshot(path=str(OUT_DIR / "wz_threat_hunting_logs_annotated.png"))

        # ------------------------------------------------------------------
        # 5) SERVER MANAGEMENT -> RULES & RULESET TEST (wz_rules_decoders_annotated.png)
        # ------------------------------------------------------------------
        print("6. Capturing wz_rules_decoders_annotated.png...")
        page.goto(f"{WAZUH_URL}/app/rules", wait_until="domcontentloaded", timeout=30000)
        time.sleep(7)
        cust_btn = page.query_selector('button:has-text("Custom rules"), span:has-text("Custom rules")')
        if cust_btn:
            try:
                cust_btn.click()
                time.sleep(2.5)
            except Exception:
                pass
        inject_helpers(page)
        page.evaluate("""() => {
            window.__addBoxByText('Manage rules files', '① Mở danh sách file XML (local_rules.xml)', 'box', 4, 0, 'top');
            window.__addBoxByText('Add new rules file', '② Tạo file luật XML mới', 'underline', 3, 0, 'bottom');
            window.__addBoxByText('Custom rules', '③ Nút lọc nhanh các Luật tự tạo (Custom rules)', 'box', 4, 1, 'top');
            window.__addBoxByText('local_rules.xml', '④ Bấm vào local_rules.xml để sửa mã XML trực tiếp trên Web', 'underline', 2, 0, 'right');
        }""")
        rules_p = Path("/tmp/wz_rules_top.png")
        page.screenshot(path=str(rules_p))

        page.goto(f"{WAZUH_URL}/app/ruleset-test", wait_until="domcontentloaded", timeout=30000)
        time.sleep(6)
        inject_helpers(page)
        page.evaluate("""() => {
            window.__addBoxByText('Ruleset Test', '⑤ Server management -> Ruleset Test (wazuh-logtest trên Web)', 'underline', 3, 0, 'right');
            window.__addBoxByText('Test', '⑥ Dán dòng Log thô vào khung rồi bấm nút "Test"', 'box', 5, 1, 'top');
        }""")
        rtest_p = Path("/tmp/wz_rtest_bot.png")
        page.screenshot(path=str(rtest_p))

        im_r1 = Image.open(rules_p).crop((0, 0, 1600, 500))
        im_r2 = Image.open(rtest_p).crop((0, 0, 1600, 460))
        comp_r = Image.new("RGB", (1600, 960), (255, 255, 255))
        comp_r.paste(im_r1, (0, 0))
        comp_r.paste(im_r2, (0, 500))
        d_r = ImageDraw.Draw(comp_r)
        d_r.line([(0, 500), (1600, 500)], fill=(220, 38, 38), width=4)
        comp_r.save(str(OUT_DIR / "wz_rules_decoders_annotated.png"))

        browser.close()
        print("POLISHED SCREENSHOTS CAPTURED SUCCESSFULLY!")


if __name__ == "__main__":
    capture_all()
