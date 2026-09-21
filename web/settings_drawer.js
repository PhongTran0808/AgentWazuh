/* Hallmark · genre: modern-minimal · macrostructure: Workbench · design-system: design.md · designed-as-app */
/* AgentWazuh — Shared Settings drawer. Single source of truth for every app page.
 *
 * Contract (read by app.js / network_map.js / device_inventory.js / drilldown.js):
 *   #settings-modal, #btn-save-all-settings, .settings-sidebar .nav-item[data-tab],
 *   .settings-tab-content, #setting-timeout-min, #setting-wazuh-host, #setting-wazuh-port,
 *   #setting-ping-interval, #setting-ping-retry, #select-pi-model, #input-gemini-key,
 *   #select-gemini-model
 * The Activity-log console is injected only on pages that opt in with <body data-audit="on">,
 * because it is driven by app.js (dashboard only); elsewhere the tab shows a summary note.
 */
(() => {
  "use strict";

  if (document.getElementById("settings-modal")) return; // already present — stay idempotent

  const withAuditConsole = document.body.dataset.audit === "on";

  const auditTab = withAuditConsole
    ? `
                    <div id="tab-audit" class="settings-tab-content hidden">
                        <div class="setting-card-title">
                            <h2>Nhật ký hoạt động</h2>
                            <p>Toàn bộ luồng giao tiếp giữa AgentWazuh, Wazuh Manager, OpenSearch, LangGraph Engine và AI Advisor.</p>
                        </div>

                        <section class="audit-log-section">
                            <div class="audit-log-header">
                                <div class="audit-title-group">
                                    <i class="fa-solid fa-list-check audit-icon"></i>
                                    <div>
                                        <h3 class="audit-title">Agent Activity Log</h3>
                                        <p class="audit-subtitle">Cập nhật trực tiếp, 50 bản ghi gần nhất.</p>
                                    </div>
                                </div>
                                <div class="audit-controls">
                                    <label class="auto-refresh-toggle">
                                        <input type="checkbox" id="audit-auto-refresh" checked>
                                        <span>Auto-refresh (3s)</span>
                                    </label>
                                    <button type="button" id="btn-clear-audit-logs" class="btn btn--sm danger" title="Xoá nhật ký">
                                        <i class="fa-solid fa-trash-can"></i> Xoá
                                    </button>
                                    <button type="button" id="btn-toggle-audit-panel" class="btn btn--icon" title="Thu gọn / mở rộng" aria-label="Thu gọn nhật ký">
                                        <i class="fa-solid fa-chevron-down"></i>
                                    </button>
                                </div>
                            </div>

                            <div id="audit-log-body" class="audit-log-body">
                                <div class="table-wrap">
                                    <table class="audit-table">
                                        <thead>
                                            <tr>
                                                <th>Thời gian</th>
                                                <th>Phân loại</th>
                                                <th>Hành động</th>
                                                <th>Trạng thái</th>
                                                <th>Chi tiết</th>
                                            </tr>
                                        </thead>
                                        <tbody id="audit-logs-tbody">
                                            <tr><td colspan="5" class="loading-state">Đang tải nhật ký…</td></tr>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </section>
                    </div>`
    : `
                    <div id="tab-audit" class="settings-tab-content hidden">
                        <div class="setting-card-title">
                            <h2>Nhật ký hoạt động</h2>
                            <p>Bản ghi Read-Only Sync được lưu phía server. Mở trang Bảng điều khiển để xem luồng hoạt động trực tiếp.</p>
                        </div>
                        <p class="section-note">
                            Nhật ký đầy đủ nằm trong bảng <code>Nhật ký hoạt động</code> ở Bảng điều khiển.
                            Tại đây chỉ hiển thị trạng thái cấu hình Wazuh Manager và phiên làm việc hiện tại.
                        </p>
                    </div>`;

  const html = `
    <div id="settings-modal" class="modal-overlay hidden">
        <div class="modal-card drawer-card-large">
            <div class="modal-header">
                <h3><i class="fa-solid fa-sliders"></i> Cài đặt AgentWazuh</h3>
                <button type="button" class="btn-close" aria-label="Đóng" data-settings-close>
                    <i class="fa-solid fa-xmark"></i>
                </button>
            </div>

            <div class="drawer-split-body">
                <nav class="settings-sidebar" aria-label="Mục cài đặt">
                    <div class="sidebar-section-label">Chung</div>
                    <button type="button" class="nav-item active" data-tab="tab-general"><i class="fa-solid fa-gear"></i> Chung &amp; Phiên</button>
                    <button type="button" class="nav-item" data-tab="tab-wazuh"><i class="fa-solid fa-server"></i> Wazuh Manager</button>

                    <div class="sidebar-section-label">Giám sát</div>
                    <button type="button" class="nav-item" data-tab="tab-heartbeat"><i class="fa-solid fa-heart-pulse"></i> Heartbeat &amp; Ping</button>

                    <div class="sidebar-section-label">Trí tuệ</div>
                    <button type="button" class="nav-item" data-tab="tab-ai"><i class="fa-solid fa-robot"></i> AI Engine</button>

                    <div class="sidebar-section-label">Bảo mật</div>
                    <button type="button" class="nav-item" data-tab="tab-vault"><i class="fa-solid fa-shield-halved"></i> AES-256 Vault</button>
                    <button type="button" class="nav-item" data-tab="tab-audit"><i class="fa-solid fa-list-check"></i> Nhật ký hoạt động</button>
                </nav>

                <div class="settings-content-panel">

                    <div id="tab-general" class="settings-tab-content active">
                        <div class="setting-card-title">
                            <h2>Chung &amp; Phiên làm việc</h2>
                            <p>Thời gian duy trì phiên Admin và tuỳ chọn giao diện.</p>
                        </div>
                        <div class="setting-box-card">
                            <div class="setting-row-label">
                                <strong>Session Inactivity Timeout (phút)</strong>
                                <span>Tự động đăng xuất sau khoảng thời gian không thao tác.</span>
                            </div>
                            <input type="number" id="setting-timeout-min" value="30" min="5" max="480" class="input-setting-control">
                        </div>
                    </div>

                    <div id="tab-wazuh" class="settings-tab-content hidden">
                        <div class="setting-card-title">
                            <h2>Wazuh Manager REST API</h2>
                            <p>Thông số kết nối tới Wazuh Manager (HTTPS REST API, mặc định cổng 55000).</p>
                        </div>
                        <div class="setting-box-card">
                            <div class="setting-row-label">
                                <strong>Wazuh Server IP</strong>
                                <span>Địa chỉ IP máy chủ Wazuh Manager.</span>
                            </div>
                            <input type="text" id="setting-wazuh-host" value="" placeholder="192.168.1.10" class="input-setting-control">
                        </div>
                        <div class="setting-box-card">
                            <div class="setting-row-label">
                                <strong>Wazuh REST API Port</strong>
                                <span>Cổng SSL REST API (mặc định 55000).</span>
                            </div>
                            <input type="number" id="setting-wazuh-port" value="55000" class="input-setting-control">
                        </div>
                    </div>

                    <div id="tab-heartbeat" class="settings-tab-content hidden">
                        <div class="setting-card-title">
                            <h2>Heartbeat &amp; ICMP Ping</h2>
                            <p>Giảm độ nhạy ICMP ping và tích hợp Uptime Kuma Push API.</p>
                        </div>
                        <div class="setting-box-card">
                            <div class="setting-row-label">
                                <strong>Chu kỳ ICMP Ping (giây)</strong>
                                <span>Khoảng thời gian phát gói ping kiểm tra thiết bị.</span>
                            </div>
                            <input type="number" id="setting-ping-interval" value="15" min="5" max="120" class="input-setting-control">
                        </div>
                        <div class="setting-box-card">
                            <div class="setting-row-label">
                                <strong>Ngưỡng thử lại trước khi báo đứt (lần)</strong>
                                <span>Số chu kỳ ping thất bại liên tiếp mới chuyển ĐỎ.</span>
                            </div>
                            <input type="number" id="setting-ping-retry" value="3" min="1" max="10" class="input-setting-control">
                        </div>
                    </div>

                    <div id="tab-ai" class="settings-tab-content hidden">
                        <div class="setting-card-title">
                            <h2>AI Engine (PI.dev powered)</h2>
                            <p>Mặc định dùng <strong>PI.dev Agent CLI</strong> để diễn giải sự cố. Mọi truy vấn đều được ghi vào nhật ký hoạt động.</p>
                        </div>

                        <div class="setting-box-card setting-box-card--stack">
                            <span class="eyebrow">Chế độ engine</span>
                            <div class="mode-toggle">
                                <button type="button" id="engine-mode-pi" class="mode-btn active">
                                    <i class="fa-solid fa-terminal"></i> PI.dev Agent CLI (mặc định)
                                </button>
                            </div>
                        </div>

                        <div id="panel-pi-dev" class="engine-panel">
                            <div id="pi-status-badge" class="interactive-chip chip-low" role="status">
                                <i class="fa-solid fa-circle-check"></i> PI.dev Agent Framework sẵn sàng
                            </div>

                            <div class="field-note">
                                <i class="fa-solid fa-wand-magic-sparkles"></i>
                                <div>
                                    <strong>Kết nối AI khi đổi máy:</strong>
                                    <ol>
                                        <li>GitHub Copilot: chạy <code>pi auth github-copilot</code> trong terminal (hoặc chọn <code>openrouter/free</code>).</li>
                                        <li>Model mặc định: chọn <code>Auto</code> để tự nhận model tương thích.</li>
                                        <li>Hoặc điền Google Gemini API Key bên dưới.</li>
                                    </ol>
                                </div>
                            </div>

                            <div class="setting-box-card">
                                <div class="setting-row-label">
                                    <strong>Model mặc định (PI.dev)</strong>
                                    <span>Mô hình chạy qua PI.dev Framework.</span>
                                </div>
                                <select id="select-pi-model" class="input-setting-control">
                                    <option value="auto" selected>Auto (tự chọn model tương thích)</option>
                                    <option value="openrouter/free">openrouter/free</option>
                                    <option value="gemini/gemini-3.8-flash">gemini/gemini-3.8-flash (Mới nhất · Khuyên dùng)</option>
                                    <option value="gemini/gemini-3.7-flash">gemini/gemini-3.7-flash</option>
                                    <option value="gemini/gemini-2.5-flash">gemini/gemini-2.5-flash</option>
                                    <option value="gemini/gemini-2.5-pro">gemini/gemini-2.5-pro</option>
                                    <option value="gemini/gemini-2.0-flash">gemini/gemini-2.0-flash</option>
                                    <option value="github-copilot/gpt-4.1">github-copilot / gpt-4.1</option>
                                    <option value="github-copilot/claude-haiku-4.5">github-copilot / claude-haiku-4.5</option>
                                    <option value="github-copilot/gpt-5-mini">github-copilot / gpt-5-mini</option>
                                </select>
                            </div>

                            <div class="setting-box-card">
                                <div class="setting-row-label">
                                    <strong>Google Gemini API Key</strong>
                                    <span>API key dự phòng khi máy chưa đăng nhập GitHub Copilot.</span>
                                </div>
                                <input type="password" id="input-gemini-key" class="input-setting-control" placeholder="AIzaSy…">
                            </div>

                            <div class="setting-box-card">
                                <div class="setting-row-label">
                                    <strong>Gemini Model (Google AI Studio / API)</strong>
                                    <span>Chọn model Gemini chính thức trên ai.google.dev dùng cho phân tích cảnh báo và trợ lý SOC.</span>
                                </div>
                                <select id="select-gemini-model" class="input-setting-control">
                                    <optgroup label="Thế hệ Gemini 3 (Mới nhất · Khuyên dùng)">
                                        <option value="gemini-3.8-flash">gemini-3.8-flash (Flash thông minh nhất, Agentic &amp; SOC - Mới)</option>
                                        <option value="gemini-3.7-flash">gemini-3.7-flash (Lập trình phức tạp, suy luận đa bước)</option>
                                        <option value="gemini-3.6-flash">gemini-3.6-flash (Tốc độ cao &amp; Đa phương thức cân bằng)</option>
                                        <option value="gemini-3.5-flash">gemini-3.5-flash (Chuẩn ổn định, tác vụ thông thường)</option>
                                        <option value="gemini-3.5-flash-lite">gemini-3.5-flash-lite (Siêu nhanh, tối ưu chi phí)</option>
                                        <option value="gemini-3.1-flash-lite">gemini-3.1-flash-lite (Hiệu năng frontier-class giá rẻ)</option>
                                        <option value="gemini-3.1-pro-preview">gemini-3.1-pro-preview (Suy luận sâu &amp; Vibe Coding - Preview)</option>
                                        <option value="gemini-3-flash-preview">gemini-3-flash-preview (Bản xem trước Flash 3)</option>
                                    </optgroup>
                                    <optgroup label="Thế hệ Gemini 2.5 (Ổn định &amp; Suy luận sâu)">
                                        <option value="gemini-2.5-flash" selected>gemini-2.5-flash (Hiệu năng / Giá tối ưu có suy luận)</option>
                                        <option value="gemini-2.5-pro">gemini-2.5-pro (Mô hình mạnh nhất 2.5, Deep Reasoning)</option>
                                        <option value="gemini-2.5-flash-lite">gemini-2.5-flash-lite (Nhẹ &amp; Phù hợp tác vụ lặp lại)</option>
                                    </optgroup>
                                    <optgroup label="Thế hệ Gemini 2.0 &amp; 1.5 (Legacy)">
                                        <option value="gemini-2.0-flash">gemini-2.0-flash (Thế hệ 2.0 Flash)</option>
                                        <option value="gemini-2.0-flash-lite">gemini-2.0-flash-lite (Thế hệ 2.0 Flash-Lite)</option>
                                        <option value="gemini-1.5-flash">gemini-1.5-flash (Legacy)</option>
                                        <option value="gemini-1.5-pro">gemini-1.5-pro (Legacy)</option>
                                    </optgroup>
                                    <optgroup label="Chuyên dụng (Live / Voice / Research)">
                                        <option value="gemini-3.8-live">gemini-3.8-live (Live API Voice độ trễ cực thấp)</option>
                                        <option value="gemini-3.8-live-extended-thinking">gemini-3.8-live-extended-thinking (Voice + Suy luận ngầm)</option>
                                        <option value="gemini-2.5-flash-native-audio-preview-12-2025">gemini-2.5-flash-native-audio (Âm thanh 2 chiều)</option>
                                        <option value="deep-research-preview-04-2026">deep-research-preview-04-2026 (Nghiên cứu độc lập)</option>
                                    </optgroup>
                                </select>
                            </div>
                        </div>
                    </div>

                    <div id="tab-vault" class="settings-tab-content hidden">
                        <div class="setting-card-title">
                            <h2>AES-256 Fernet Vault</h2>
                            <p>Mã hoá thông tin đăng nhập thiết bị mạng nội bộ bằng AES-256-GCM.</p>
                        </div>
                        <p class="section-note">
                            Vault được lưu mã hoá tại <code>./config/device_vault.enc</code>. Khoá chủ nằm trong
                            <code>./config/vault_master.key</code> và đã được loại khỏi git.
                        </p>
                    </div>
${auditTab}
                    <div class="drawer-footer-bar">
                        <button type="button" id="btn-save-all-settings" class="btn btn--primary btn--lg">
                            <i class="fa-solid fa-floppy-disk"></i> Lưu tất cả cài đặt
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>`;

  const mount = document.createElement("div");
  mount.innerHTML = html.trim();
  const drawer = mount.firstElementChild;
  document.body.appendChild(drawer);

  const close = () => drawer.classList.add("hidden");
  if (typeof window.closeSettingsModal !== "function") window.closeSettingsModal = close;

  drawer.addEventListener("click", (e) => {
    if (e.target === drawer || e.target.closest("[data-settings-close]")) close();
  });

  // Tab switching, kept independent from page controllers (they re-bind harmlessly).
  drawer.querySelectorAll(".nav-item[data-tab]").forEach((btn) => {
    btn.addEventListener("click", () => {
      drawer.querySelectorAll(".nav-item").forEach((b) => b.classList.remove("active"));
      drawer.querySelectorAll(".settings-tab-content").forEach((t) => t.classList.add("hidden"));
      btn.classList.add("active");
      const target = drawer.querySelector("#" + btn.dataset.tab);
      if (target) target.classList.remove("hidden");
    });
  });
})();
