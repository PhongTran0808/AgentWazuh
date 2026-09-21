/* Hallmark · genre: modern-minimal · macrostructure: Workbench · design-system: design.md · designed-as-app */
/* AgentWazuh app shell controller. Presentation only — never owns page business logic. */
(() => {
  "use strict";

  const body = document.body;
  const MOBILE = window.matchMedia("(max-width: 980px)");
  const STORE_KEY = "awz.shell";

  const readStore = () => {
    try { return JSON.parse(localStorage.getItem(STORE_KEY) || "{}"); }
    catch (e) { return {}; }
  };
  const writeStore = (patch) => {
    try { localStorage.setItem(STORE_KEY, JSON.stringify({ ...readStore(), ...patch })); }
    catch (e) { /* storage unavailable — in-memory only */ }
  };

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  /* ------------------------------------------------------------ scrim */
  let scrim = $(".scrim");
  if (!scrim) {
    scrim = document.createElement("button");
    scrim.className = "scrim";
    scrim.type = "button";
    scrim.setAttribute("aria-label", "Đóng bảng phụ");
    body.appendChild(scrim);
  }

  const sidebar = document.getElementById("history-sidebar");

  function drawerOpen() {
    return !!sidebar && !sidebar.classList.contains("collapsed");
  }

  function syncScrim() {
    const active =
      body.classList.contains("rail-open") ||
      body.classList.contains("dock-open") ||
      drawerOpen();
    body.classList.toggle("scrim-open", active);
  }

  function closeAll() {
    body.classList.remove("rail-open", "dock-open");
    if (sidebar) sidebar.classList.add("collapsed");
    syncScrim();
  }

  function closeDrawer() {
    if (sidebar) sidebar.classList.add("collapsed");
    syncScrim();
  }

  scrim.addEventListener("click", closeAll);

  if (sidebar) {
    new MutationObserver(syncScrim).observe(sidebar, {
      attributes: true,
      attributeFilter: ["class"],
    });

    /* Shell owns backdrop/scroll for the drawer; page JS keeps toggling .collapsed. */
    const head = document.createElement("div");
    head.className = "sidebar-header";
    head.innerHTML =
      '<div class="sidebar-header__row">' +
      '<span class="eyebrow">Lịch sử hội thoại</span>' +
      '<button type="button" class="btn btn--icon" data-drawer-close aria-label="Đóng lịch sử">' +
      '<i class="fa-solid fa-xmark"></i></button></div>';
    sidebar.insertBefore(head, sidebar.firstChild);
    head.addEventListener("click", (e) => {
      if (e.target.closest("[data-drawer-close]")) closeDrawer();
    });
  }

  /* ------------------------------------------------------------- rail */
  function toggleRail() {
    if (MOBILE.matches) {
      body.classList.toggle("rail-open");
      syncScrim();
      return;
    }
    const collapsed = body.classList.toggle("rail-collapsed");
    writeStore({ railCollapsed: collapsed });
    const btn = $("[data-rail-toggle]");
    if (btn) btn.setAttribute("aria-expanded", String(!collapsed));
  }

  /* ------------------------------------------------------------- dock */
  function toggleDock() {
    if (MOBILE.matches) {
      body.classList.toggle("dock-open");
      syncScrim();
      return;
    }
    const collapsed = body.classList.toggle("dock-collapsed");
    writeStore({ dockCollapsed: collapsed });
    const btn = $("[data-dock-toggle]");
    if (btn) btn.setAttribute("aria-expanded", String(!collapsed));
  }

  function setDockTab(name) {
    const tabs = $$("[data-dock-tab]");
    const panes = $$("[data-dock-pane]");
    if (!tabs.length) return;
    tabs.forEach((t) => {
      const on = t.dataset.dockTab === name;
      t.classList.toggle("is-active", on);
      t.setAttribute("aria-selected", String(on));
    });
    panes.forEach((p) => p.classList.toggle("is-active", p.dataset.dockPane === name));
  }

  function bootShell() {
    const saved = readStore();
    if (!MOBILE.matches && saved.railCollapsed) body.classList.add("rail-collapsed");
    if (!MOBILE.matches && saved.dockCollapsed) body.classList.add("dock-collapsed");
    const requestedTab = new URLSearchParams(window.location.search).get("tab");
    setDockTab(requestedTab === "evidence" ? "evidence" : (readStore().dockTab || "advisor"));
    syncScrim();

    /* ------------------------------------------- draggable dock resizer */
    const dock = document.getElementById("agent-dock") || document.querySelector(".dock");
    if (dock && !document.querySelector(".dock-resizer-v")) {
      const resizer = document.createElement("div");
      resizer.className = "dock-resizer-v";
      resizer.title = "Kéo để điều chỉnh độ rộng bảng Trợ lý AI và Cảnh báo (Nhấp đúp để đặt lại)";
      resizer.setAttribute("role", "separator");
      resizer.setAttribute("aria-orientation", "vertical");

      const workspace = dock.parentNode ? dock.parentNode.querySelector(".workspace") : null;
      const isDockLeft = workspace && Boolean(dock.compareDocumentPosition(workspace) & Node.DOCUMENT_POSITION_FOLLOWING);

      // Place the handle between dock and workspace:
      // If dock is to the left of workspace (Dashboard), place resizer before workspace.
      // If dock is to the right of workspace (Topology, Devices, Scoped), place resizer before dock.
      if (isDockLeft && workspace) {
        workspace.parentNode.insertBefore(resizer, workspace);
      } else if (dock.parentNode) {
        dock.parentNode.insertBefore(resizer, dock);
      }

      let isDragging = false;
      let startX = 0;
      let startWidth = 0;

      const clampWidth = (w) => {
        const railEl = document.querySelector(".rail");
        const railWidth = (railEl && !document.body.classList.contains("rail-collapsed")) ? railEl.getBoundingClientRect().width : (document.body.classList.contains("rail-collapsed") ? 56 : 0);
        const minWorkspace = 340;
        const maxAllowed = Math.max(300, Math.floor(window.innerWidth - railWidth - minWorkspace));
        return Math.max(260, Math.min(maxAllowed, Math.round(w)));
      };

      const savedWidth = localStorage.getItem("agentwazuh_dock_width");
      if (savedWidth) {
        const parsed = parseInt(savedWidth, 10);
        if (!isNaN(parsed) && parsed >= 260) {
          document.documentElement.style.setProperty("--dock-w", `${clampWidth(parsed)}px`);
        }
      }

      resizer.addEventListener("mousedown", (e) => {
        isDragging = true;
        startX = e.clientX;
        startWidth = dock.getBoundingClientRect().width;
        resizer.classList.add("is-dragging");
        document.body.style.userSelect = "none";
        document.body.style.cursor = "col-resize";
      });

      document.addEventListener("mousemove", (e) => {
        if (!isDragging) return;
        const dx = e.clientX - startX;
        const delta = isDockLeft ? dx : -dx;
        const newWidth = clampWidth(startWidth + delta);
        document.documentElement.style.setProperty("--dock-w", `${newWidth}px`);
      });

      document.addEventListener("mouseup", () => {
        if (isDragging) {
          isDragging = false;
          resizer.classList.remove("is-dragging");
          document.body.style.userSelect = "";
          document.body.style.cursor = "";
          const currentWidth = parseInt(getComputedStyle(document.documentElement).getPropertyValue("--dock-w"), 10);
          if (currentWidth && !isNaN(currentWidth)) {
            localStorage.setItem("agentwazuh_dock_width", currentWidth);
          }
        }
      });

      resizer.addEventListener("dblclick", () => {
        document.documentElement.style.setProperty("--dock-w", "400px");
        localStorage.removeItem("agentwazuh_dock_width");
      });
    }
  }

  bootShell();

  /* -------------------------------------------------------- listeners */
  document.addEventListener("click", (e) => {
    const apiLink = e.target.closest('a[href="/api-inspector"]');
    if (apiLink) {
      e.preventDefault();
      window.openWazuhApiInspectorModal();
      return;
    }

    const railBtn = e.target.closest("[data-rail-toggle]");
    if (railBtn) { e.preventDefault(); toggleRail(); return; }

    const dockBtn = e.target.closest("[data-dock-toggle]");
    if (dockBtn) { e.preventDefault(); toggleDock(); return; }

    const tab = e.target.closest("[data-dock-tab]");
    if (tab) {
      setDockTab(tab.dataset.dockTab);
      writeStore({ dockTab: tab.dataset.dockTab });
      const dot = tab.querySelector(".dot");
      if (dot) dot.classList.add("hidden");
      if (MOBILE.matches) { body.classList.add("dock-open"); syncScrim(); }
      return;
    }

    const railLink = e.target.closest(".rail__link");
    if (railLink && MOBILE.matches) {
      body.classList.remove("rail-open");
      syncScrim();
    }

    if (e.target.closest("[data-palette-open]")) {
      e.preventDefault();
      openPalette();
    }

    if (e.target.classList && e.target.classList.contains("modal-overlay")) {
      if (!e.target.hasAttribute("data-static")) e.target.classList.add("hidden");
    }
  });

  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
      e.preventDefault();
      openPalette();
      return;
    }
    if (e.key === "Escape") {
      if (palette && !palette.classList.contains("hidden")) { closePalette(); return; }
      closeAll();
      $$(".modal-overlay:not(.hidden)").forEach((m) => m.classList.add("hidden"));
    }
  });

  /* ------------------------------------------- evidence tab badge update (no auto jump) */
  const evidence = document.getElementById("evidence-detail");
  if (evidence) {
    const dot = document.querySelector('[data-dock-tab="evidence"] .dot');
    new MutationObserver(() => {
      const active = document.querySelector('[data-dock-tab="evidence"]');
      if (active && !active.classList.contains("is-active")) {
        if (dot) dot.classList.remove("hidden");
      }
    }).observe(evidence, { childList: true });
  }

  /* --------------------------------------------------- modal helpers */
  window.openWazuhApiInspectorModal = () => {
    fetch("/api-inspector", { method: "HEAD" }).then(res => {
      if (res.ok) {
        window.location.href = "/api-inspector";
      } else {
        window.location.href = "/static/api_inspector.html";
      }
    }).catch(() => {
      window.location.href = "/static/api_inspector.html";
    });
  };
  if (!window.closeLogModal) {
    window.closeLogModal = () => {
      const m = document.getElementById("log-modal");
      if (m) m.classList.add("hidden");
    };
  }
  if (!window.closeExportModal) {
    window.closeExportModal = () => {
      const m = document.getElementById("export-modal");
      if (m) m.classList.add("hidden");
    };
  }

  /* ---------------------------------------------------------- palette */
  let palette = null;

  function paletteActions() {
    const actions = [
      { label: "Bảng điều khiển", hint: "Trang", icon: "fa-gauge-high", href: "/dashboard" },
      { label: "Sơ đồ mạng", hint: "Trang", icon: "fa-network-wired", href: "/network-map" },
      { label: "Thiết bị", hint: "Trang", icon: "fa-server", href: "/device-inventory" },
      { label: "Gói tin API", hint: "Trang", icon: "fa-satellite-dish", href: "/api-inspector" },
    ];
    if (document.getElementById("btn-open-settings")) {
      actions.push({ label: "Mở cài đặt", hint: "Hành động", icon: "fa-sliders", run: () => document.getElementById("btn-open-settings").click() });
    }
    if (document.getElementById("btn-toggle-sidebar")) {
      actions.push({ label: "Lịch sử hội thoại", hint: "Hành động", icon: "fa-clock-rotate-left", run: () => document.getElementById("btn-toggle-sidebar").click() });
    }
    if (document.getElementById("btn-new-chat")) {
      actions.push({ label: "Hội thoại mới", hint: "Hành động", icon: "fa-plus", run: () => document.getElementById("btn-new-chat").click() });
    }
    if (document.getElementById("btn-back-login")) {
      actions.push({ label: "Đăng xuất", hint: "Hành động", icon: "fa-right-from-bracket", run: () => document.getElementById("btn-back-login").click() });
    }
    $$(".chip-btn[data-query]").slice(0, 8).forEach((chip) => {
      actions.push({ label: chip.textContent.trim(), hint: "Truy vấn", icon: "fa-terminal", run: () => chip.click() });
    });
    return actions;
  }

  let paletteItems = [];
  let paletteIndex = 0;

  function renderPalette(query) {
    const list = palette.querySelector(".palette__list");
    const q = query.trim().toLowerCase();
    paletteItems = paletteActions().filter((a) => !q || a.label.toLowerCase().includes(q));
    paletteIndex = 0;
    list.innerHTML = "";
    if (!paletteItems.length) {
      list.innerHTML = '<li class="palette__empty">Không tìm thấy lệnh phù hợp.</li>';
      return;
    }
    paletteItems.forEach((action, i) => {
      const li = document.createElement("li");
      li.className = "palette__item" + (i === 0 ? " is-active" : "");
      li.innerHTML =
        `<i class="fa-solid ${action.icon}"></i><span>${action.label}</span>` +
        `<span class="hint">${action.hint}</span>`;
      li.addEventListener("click", () => runPalette(action, i));
      li.addEventListener("mousemove", () => setPaletteIndex(i));
      list.appendChild(li);
    });
  }

  function setPaletteIndex(i) {
    paletteIndex = i;
    $$(".palette__item", palette).forEach((el, idx) => el.classList.toggle("is-active", idx === i));
  }

  function runPalette(action, i) {
    if (typeof i === "number") setPaletteIndex(i);
    closePalette();
    if (action.href) window.location.href = action.href;
    else if (action.run) action.run();
  }

  function openPalette() {
    if (!palette) {
      palette = document.createElement("div");
      palette.className = "palette hidden";
      palette.innerHTML =
        '<div class="palette__box" role="dialog" aria-modal="true" aria-label="Bảng lệnh">' +
        '<div class="palette__field"><i class="fa-solid fa-magnifying-glass"></i>' +
        '<input type="text" placeholder="Tìm trang hoặc hành động…" aria-label="Tìm lệnh"></div>' +
        '<ul class="palette__list"></ul></div>';
      body.appendChild(palette);

      const input = palette.querySelector("input");
      input.addEventListener("input", () => renderPalette(input.value));
      input.addEventListener("keydown", (e) => {
        if (e.key === "ArrowDown") { e.preventDefault(); setPaletteIndex(Math.min(paletteIndex + 1, paletteItems.length - 1)); }
        else if (e.key === "ArrowUp") { e.preventDefault(); setPaletteIndex(Math.max(paletteIndex - 1, 0)); }
        else if (e.key === "Enter") { e.preventDefault(); if (paletteItems[paletteIndex]) runPalette(paletteItems[paletteIndex]); }
      });
      palette.addEventListener("click", (e) => { if (e.target === palette) closePalette(); });
    }
    renderPalette("");
    palette.classList.remove("hidden");
    palette.querySelector("input").value = "";
    palette.querySelector("input").focus();
  }

  function closePalette() {
    if (palette) palette.classList.add("hidden");
  }

  window.awzOpenPalette = openPalette;
})();

/* ==================================================== Global API Inspector */
window.openWazuhApiInspectorModal = function() {
  let modal = document.getElementById("wazuh-api-inspector-modal");
  if (!modal) {
    modal = document.createElement("div");
    modal.id = "wazuh-api-inspector-modal";
    modal.className = "modal-overlay hidden";
    modal.innerHTML = `
      <div class="inspector-card">
        <div class="inspector-head">
          <span><i class="fa-solid fa-satellite-dish"></i> Wazuh API & Packet Exchange Inspector</span>
          <button type="button" class="btn btn--icon" onclick="window.closeWazuhApiInspectorModal()" aria-label="Đóng">
            <i class="fa-solid fa-xmark"></i>
          </button>
        </div>
        <div class="inspector-subbar">
          <span>Nhật ký thời gian thực các gói REST API (cổng 55000/443) giữa AgentWazuh ↔ Wazuh Server. Sao chép API/Curl 1-Click.</span>
          <button type="button" class="btn btn--ghost btn--sm" onclick="window.refreshWazuhApiInspector()">
            <i class="fa-solid fa-rotate-right"></i> Làm mới
          </button>
        </div>
        <div id="wazuh-api-inspector-list">
          <div class="inspector-empty">Đang tải dữ liệu gói tin Wazuh API...</div>
        </div>
      </div>
    `;
    document.body.appendChild(modal);
  }
  modal.classList.remove("hidden");
  window.refreshWazuhApiInspector();
};

window.closeWazuhApiInspectorModal = function() {
  document.getElementById("wazuh-api-inspector-modal")?.classList.add("hidden");
};

window.refreshWazuhApiInspector = async function() {
  const listBox = document.getElementById("wazuh-api-inspector-list");
  if (!listBox) return;
  
  try {
    const res = await fetch("/api/wazuh/live-logs", { credentials: "same-origin" });
    const data = await res.json();
    const logs = data.logs || [];
    
    if (logs.length === 0) {
      listBox.innerHTML = `<div class="inspector-empty">Chưa có dữ liệu gói tin REST API nào được ghi nhận.</div>`;
      return;
    }

    const methodClass = { "GET": "is-get", "POST": "is-post", "PUT": "is-put" };
    const esc = (s) => String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

    let html = "";
    logs.forEach(log => {
      const mClass = methodClass[log.method] || "is-del";
      const sClass = log.status_code === 200 ? "is-ok" : "is-err";
      const rawUrl = log.url || "";
      const rawCurl = log.curl_command || "";

      html += `
      <article class="inspector-log">
        <div class="inspector-log__head">
          <div class="inspector-log__id">
            <span class="inspector-method ${mClass}">${esc(log.method)}</span>
            <span class="inspector-status ${sClass}">${esc(log.status_code)}</span>
            <span class="inspector-url">${esc(rawUrl)}</span>
          </div>
          <span class="inspector-ts">${esc(log.timestamp)}</span>
        </div>

        <p class="inspector-detail">${esc(log.detail || '')}</p>
        <div style="display:flex; justify-content:space-between; align-items:center; margin-top:4px; margin-bottom:4px;">
          <code style="font-size:11px; color:var(--ink-3);">${esc(log.direction || 'AgentWazuh ➔ Wazuh')}</code>
          <button type="button" class="btn btn--ghost btn--xs" onclick="window.copyTextToClipboard('${esc(rawCurl).replace(/'/g, "\\'")}', this)">
            <i class="fa-solid fa-copy"></i> Copy cURL
          </button>
        </div>
        <pre class="inspector-curl">${esc(rawCurl)}</pre>
      </article>`;
    });

    listBox.innerHTML = html;
  } catch (e) {
    listBox.innerHTML = `<div class="inspector-empty" style="color:var(--critical);">Lỗi khi nạp dữ liệu gói tin: ${e}</div>`;
  }
};

window.copyTextToClipboard = function(text, btnElement) {
  if (!text || !btnElement) return;
  navigator.clipboard.writeText(text).then(() => {
    const origText = btnElement.innerHTML;
    btnElement.innerHTML = `<i class="fa-solid fa-check"></i> Đã sao chép!`;
    setTimeout(() => { btnElement.innerHTML = origText; }, 1800);
  }).catch(err => {
    alert("Không thể sao chép: " + err);
  });
};
