/**
 * AgentWazuh — Security Topology SOC Map Controller (Version 2.0)
 *
 * Kiến trúc: 2 vòng polling tách biệt
 *   - pollConnState()   : mỗi 5s   → /api/security-map/conn  (nhẹ, chỉ ring buffer)
 *   - pollFullMap()     : mỗi 15s  → /api/security-map        (đầy đủ devices + health/risk)
 *
 * Fan-out dùng vis-network.js để giữ khả năng kéo-thả node tự do.
 * Đường nối AgentWazuh ↔ Wazuh Server dùng SVG CSS riêng.
 */

// ─────────────────────────────────────────────
//  ICON MAP: type → /static/assets/icons/*.svg
// ─────────────────────────────────────────────
const ICON_MAP = {
    "firewall":  "/static/assets/icons/firewall.svg",
    "router":    "/static/assets/icons/router.svg",
    "switch":    "/static/assets/icons/switch.svg",
    "server":    "/static/assets/icons/server.svg",
    "siem":      "/static/assets/icons/siem.svg",
    "endpoint":  "/static/assets/icons/pc.svg",
    "pc":        "/static/assets/icons/pc.svg",
    "unknown":   "/static/assets/icons/unknown.svg"
};

// Badge → vis-network node border colours (icon SVG colour NOT changed — overlay only)
const BADGE_BORDER = {
    "NORMAL":       "#22c55e",
    "WARNING":      "#f59e0b",
    "UNDER_ATTACK": "#ef4444",
    "OFFLINE":      "#475569"
};

const BADGE_GLOW = {
    "NORMAL":       "rgba(34,197,94,0.25)",
    "WARNING":      "rgba(245,158,11,0.25)",
    "UNDER_ATTACK": "rgba(239,68,68,0.4)",
    "OFFLINE":      "rgba(71,85,105,0.1)"
};

// Standard icon size for ALL device types (prevents the mismatched-size bug)
const NODE_ICON_SIZE = 48;

// ─────────────────────────────────────────────
//  STATE
// ─────────────────────────────────────────────
let network     = null;
let nodesDS     = null;
let edgesDS     = null;
let rawDevices  = [];       // last fetched devices array from /api/security-map
let savedPositions = JSON.parse(localStorage.getItem("secmap_positions") || "{}");

// ─────────────────────────────────────────────
//  INIT
// ─────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
    // Back button
    document.getElementById("btn-back-dash")?.addEventListener("click", () => {
        window.location.href = "/dashboard";
    });

    // Reset layout
    document.getElementById("btn-reset-layout")?.addEventListener("click", () => {
        localStorage.removeItem("secmap_positions");
        savedPositions = {};
        if (network) network.setOptions({ physics: { enabled: true } });
        setTimeout(() => { if (network) network.setOptions({ physics: { enabled: false } }); }, 3000);
    });

    // Zoom fit
    document.getElementById("btn-zoom-fit")?.addEventListener("click", () => {
        if (network) network.fit({ animation: { duration: 500, easingFunction: "easeInOutQuad" } });
    });

    // Settings modal
    document.getElementById("btn-open-settings")?.addEventListener("click", () => {
        document.getElementById("settings-modal")?.classList.remove("hidden");
    });
    window.closeSettingsModal = () => {
        document.getElementById("settings-modal")?.classList.add("hidden");
    };

    // Settings tabs (preserved from original)
    document.querySelectorAll(".nav-item[data-tab]").forEach(btn => {
        btn.addEventListener("click", () => {
            document.querySelectorAll(".nav-item").forEach(b => b.classList.remove("active"));
            document.querySelectorAll(".settings-tab-content").forEach(t => t.classList.add("hidden"));
            btn.classList.add("active");
            document.getElementById(btn.dataset.tab)?.classList.remove("hidden");
        });
    });

    // Initial data fetch + polling
    pollConnState();
    pollFullMap();
    setInterval(pollConnState, 5000);
    setInterval(pollFullMap,   15000);
});

// ─────────────────────────────────────────────
//  CONNECTION STATE POLLER (5s)
// ─────────────────────────────────────────────
async function pollConnState() {
    try {
        const res = await fetch("/api/security-map/conn", { credentials: "same-origin" });
        if (res.status === 401) { window.location.href = "/login"; return; }
        const json = await res.json();
        applyConnStateToBus(json.conn_state, json.wazuh_host || "—");
    } catch (e) {
        applyConnStateToBus("chua_ket_noi", "—");
    }
}

// ─────────────────────────────────────────────
//  FULL MAP POLLER (15s)
// ─────────────────────────────────────────────
async function pollFullMap() {
    try {
        const res = await fetch("/api/security-map", { credentials: "same-origin" });
        if (res.status === 401) { window.location.href = "/login"; return; }
        const json = await res.json();

        rawDevices = json.devices || [];
        updateSummaryStrip(json.summary || {});
        renderVisNetwork(rawDevices, json.wazuh_host);
        applyConnStateToBus(json.conn_state, json.wazuh_host || "—");

        const now = new Date();
        document.getElementById("secmap-last-refresh").textContent =
            `Cập nhật: ${now.toLocaleTimeString("vi-VN")}`;
    } catch (e) {
        console.error("[SecMap] pollFullMap error:", e);
    }
}

// ─────────────────────────────────────────────
//  CONNECTION BUS: SVG + BADGE
// ─────────────────────────────────────────────
function applyConnStateToBus(state, host) {
    const badge     = document.getElementById("bus-conn-badge");
    const activeLine = document.getElementById("bus-line-active");
    const packet    = document.getElementById("bus-packet");
    const connDot   = document.getElementById("hdr-conn-dot");
    const serverLabel = document.getElementById("bus-server-label");

    if (serverLabel) serverLabel.innerHTML = `${host}<br><span style="color:#38bdf8;font-size:0.6rem;">SIEM</span>`;

    const statusHost = document.getElementById("status-host");
    if (statusHost) statusHost.textContent = `Wazuh Server: ${host}`;

    const configs = {
        "chua_ket_noi": {
            badgeText: "⛔ Chưa kết nối",
            badgeBg: "#1e293b", badgeColor: "#64748b", badgeBorder: "#475569",
            lineColor: "#475569", lineDash: "6 8", lineAnim: "none",
            packetOpacity: "0", dotClass: "offline"
        },
        "da_ket_noi": {
            badgeText: "✅ Đã kết nối",
            badgeBg: "rgba(124,58,237,0.15)", badgeColor: "#a78bfa", badgeBorder: "#7c3aed",
            lineColor: "url(#line-grad)", lineDash: "180 0", lineAnim: "none",
            packetOpacity: "1", dotClass: "online"
        },
        "chap_chon": {
            badgeText: "⚠️ Chập chờn",
            badgeBg: "rgba(249,115,22,0.15)", badgeColor: "#fb923c", badgeBorder: "#f97316",
            lineColor: "#f97316", lineDash: "8 6", lineAnim: "dash-anim 0.6s linear infinite",
            packetOpacity: "0.5", dotClass: "warning"
        }
    };

    const cfg = configs[state] || configs["chua_ket_noi"];

    if (badge) {
        badge.textContent         = cfg.badgeText;
        badge.style.background    = cfg.badgeBg;
        badge.style.color         = cfg.badgeColor;
        badge.style.border        = `1px solid ${cfg.badgeBorder}`;
    }

    if (activeLine) {
        activeLine.style.stroke          = cfg.lineColor;
        activeLine.setAttribute("stroke-dasharray", cfg.lineDash);
        activeLine.style.animation       = cfg.lineAnim;
    }

    if (packet) {
        packet.style.opacity = cfg.packetOpacity;
        if (cfg.packetOpacity !== "0") {
            // Animate packet travelling left-to-right
            packet.style.animation = "travel-anim 1.8s linear infinite";
        } else {
            packet.style.animation = "none";
        }
    }

    if (connDot) {
        connDot.className = `status-indicator ${cfg.dotClass}`;
    }
}

// ─────────────────────────────────────────────
//  SUMMARY STRIP
// ─────────────────────────────────────────────
function updateSummaryStrip(summary) {
    const s = (id, val, suffix) => {
        const el = document.getElementById(id);
        if (el) el.textContent = `${val} ${suffix}`;
    };
    s("sum-total",   summary.total   ?? "—", "Tổng");
    s("sum-online",  summary.online  ?? "—", "Online");
    s("sum-warning", summary.warning ?? "—", "Warning");
    s("sum-offline", summary.offline ?? "—", "Offline");
    s("sum-attack",  summary.under_attack ?? "—", "🚨 Attack");
}

// ─────────────────────────────────────────────
//  VIS-NETWORK FAN-OUT RENDER
// ─────────────────────────────────────────────
function renderVisNetwork(devices, wazuhHost) {
    const container = document.getElementById("secmap-vis-container");
    if (!container) return;

    if (!devices || devices.length === 0) {
        container.innerHTML = `
            <div class="secmap-empty">
                <i class="fa-solid fa-shield-halved" style="font-size:3rem; color:#1e293b;"></i>
                <p style="color:#334155; font-size:0.88rem; max-width:380px;">
                    Không phát hiện thiết bị nào đang được giám sát.<br>
                    Sơ đồ sẽ xuất hiện ngay khi có Wazuh Agent kết nối hoặc thiết bị được xác minh trong known_devices.json.
                </p>
            </div>`;
        return;
    }

    // Build Wazuh Server centre node
    const serverNodeId = "__wazuh_server__";
    const nodes = [
        {
            id: serverNodeId,
            label: `Wazuh Server\n${wazuhHost || "SIEM"}`,
            shape: "image",
            image: ICON_MAP["siem"],
            size: NODE_ICON_SIZE + 8,
            borderWidth: 3,
            color: { border: "#818cf8", background: "transparent", highlight: { border: "#a78bfa" } },
            font: { color: "#f8fafc", face: "Inter", size: 11, strokeWidth: 3, strokeColor: "#020617" },
            shadow: { enabled: true, color: "rgba(129,140,248,0.4)", size: 16 },
            x: 0, y: 0,
            physics: false   // Centre node stays anchored
        }
    ];

    const edges = [];

    devices.forEach(dev => {
        const iconType = (dev.type || "unknown").toLowerCase();
        const iconSrc  = ICON_MAP[iconType] || ICON_MAP["unknown"];
        const border   = BADGE_BORDER[dev.badge] || BADGE_BORDER["OFFLINE"];
        const glow     = BADGE_GLOW[dev.badge]   || BADGE_GLOW["OFFLINE"];

        // Health-aware label
        const healthPct = dev.health?.score ?? 0;
        const riskVal   = dev.risk?.risk    ?? 0;
        const badgeEmoji = {
            "NORMAL":       "🟢",
            "WARNING":      "🟡",
            "UNDER_ATTACK": "🔴",
            "OFFLINE":      "⚫"
        }[dev.badge] || "⚫";

        const label = `${badgeEmoji} ${dev.name}\n${dev.ip}`;

        // Restore saved position if available
        const pos = savedPositions[dev.id];

        const nodeObj = {
            id: dev.id,
            label,
            shape: "image",
            image: iconSrc,
            size: NODE_ICON_SIZE,
            borderWidth: dev.badge === "UNDER_ATTACK" ? 4 : 2,
            borderWidthSelected: 3,
            color: {
                border: border,
                background: "transparent",
                highlight: { border: border }
            },
            font: { color: "#f8fafc", face: "Inter", size: 10, strokeWidth: 3, strokeColor: "#020617" },
            shadow: { enabled: true, color: glow, size: dev.badge === "UNDER_ATTACK" ? 20 : 10 },
            // Store raw device data for click handler
            _device: dev
        };

        if (pos) { nodeObj.x = pos.x; nodeObj.y = pos.y; }

        nodes.push(nodeObj);

        // Edge from Wazuh Server to this device
        const edgeColor = dev.health?.status === "offline" ? "#334155"
                        : dev.badge === "UNDER_ATTACK"     ? "#ef4444"
                        : dev.badge === "WARNING"           ? "#f59e0b"
                        : "#1e40af";

        edges.push({
            from: serverNodeId,
            to: dev.id,
            color: { color: edgeColor, highlight: edgeColor },
            width: dev.badge === "UNDER_ATTACK" ? 3 : 1.5,
            dashes: dev.health?.status === "offline" ? [4, 4] : false,
            smooth: { type: "curvedCW", roundness: 0.15 },
            font: { size: 0 },
            arrows: { to: { enabled: false } }
        });
    });

    const options = {
        nodes: { shadow: true, chosen: true },
        edges: { shadow: false },
        layout: {
            randomSeed: 42
        },
        physics: {
            enabled: Object.keys(savedPositions).length === 0,
            solver: "forceAtlas2Based",
            forceAtlas2Based: {
                gravitationalConstant: -80,
                centralGravity: 0.015,
                springLength: 160,
                springConstant: 0.06
            },
            stabilization: { iterations: 150 }
        },
        interaction: {
            hover: true,
            dragNodes: true,
            zoomView: true,
            tooltipDelay: 200
        }
    };

    if (!network) {
        nodesDS = new vis.DataSet(nodes);
        edgesDS = new vis.DataSet(edges);
        network  = new vis.Network(container, { nodes: nodesDS, edges: edgesDS }, options);

        // Save positions on drag
        network.on("dragEnd", params => {
            if (params.nodes.length > 0) {
                const positions = network.getPositions(params.nodes);
                Object.keys(positions).forEach(id => { savedPositions[id] = positions[id]; });
                localStorage.setItem("secmap_positions", JSON.stringify(savedPositions));
            }
            updateNodeCalloutBubbles(rawDevices);
        });

        // Update callout bubbles on drawing and zoom events
        network.on("afterDrawing", () => updateNodeCalloutBubbles(rawDevices));
        network.on("zoom", () => updateNodeCalloutBubbles(rawDevices));

        // Disable physics after stabilisation
        network.on("stabilizationIterationsDone", () => {
            network.setOptions({ physics: { enabled: false } });
            updateNodeCalloutBubbles(rawDevices);
        });

        // Single-click: show device detail panel
        network.on("click", params => {
            if (params.nodes.length > 0) {
                const nodeId = params.nodes[0];
                if (nodeId === "__wazuh_server__") {
                    renderServerDetail();
                    return;
                }
                const dev = rawDevices.find(d => d.id === nodeId);
                if (dev) renderDeviceDetail(dev);
            }
        });

        // Double-click: open AI Investigation (drilldown)
        network.on("doubleClick", params => {
            if (params.nodes.length > 0) {
                const nodeId = params.nodes[0];
                if (nodeId === "__wazuh_server__") return;
                const dev = rawDevices.find(d => d.id === nodeId);
                if (dev) {
                    const url = `/drilldown?device_id=${encodeURIComponent(dev.id)}`
                              + `&device_name=${encodeURIComponent(dev.name)}`
                              + `&ip=${encodeURIComponent(dev.ip)}`
                              + `&risk=${encodeURIComponent(dev.risk?.risk ?? 0)}`;
                    window.location.href = url;
                }
            }
        });

    } else {
        // Incremental update to avoid full re-render flicker
        nodesDS.update(nodes);
        edgesDS.update(edges);
        // Remove stale nodes
        const currentIds = new Set(nodes.map(n => n.id));
        nodesDS.forEach(n => { if (!currentIds.has(n.id)) nodesDS.remove(n.id); });
    }

    // Always update Callout Alert Bubbles after dataset updates
    setTimeout(() => updateNodeCalloutBubbles(rawDevices), 50);
}

// ─────────────────────────────────────────────
//  NODE CALLOUT ALERT BUBBLE OVERLAY
// ─────────────────────────────────────────────
function updateNodeCalloutBubbles(devices) {
    if (!network || !nodesDS) return;

    let overlayContainer = document.getElementById("secmap-bubbles-overlay");
    if (!overlayContainer) {
        const visContainer = document.getElementById("secmap-vis-container");
        if (!visContainer) return;
        overlayContainer = document.createElement("div");
        overlayContainer.id = "secmap-bubbles-overlay";
        overlayContainer.style.cssText = "position:absolute;top:0;left:0;width:100%;height:100%;pointer-events:none;z-index:90;overflow:hidden;";
        visContainer.appendChild(overlayContainer);
    }

    const activeBubbleIds = new Set();

    (devices || []).forEach(dev => {
        // Hide bubble for NORMAL status
        if (!dev.badge || dev.badge === "NORMAL") return;

        const nodeId = dev.id;
        const pos = network.getPositions([nodeId])[nodeId];
        if (!pos) return;

        const domPos = network.canvasToDOM(pos);
        activeBubbleIds.add(nodeId);

        let bubbleEl = document.getElementById(`bubble-${nodeId}`);
        if (!bubbleEl) {
            bubbleEl = document.createElement("div");
            bubbleEl.id = `bubble-${nodeId}`;
            overlayContainer.appendChild(bubbleEl);
        }

        const badgeClass = dev.badge === "UNDER_ATTACK" ? "callout-attack"
                         : dev.badge === "WARNING" ? "callout-warning"
                         : "callout-offline";
        bubbleEl.className = `node-callout-bubble ${badgeClass}`;

        let titleLine = "🚨 Đang bị tấn công";
        let detailLine = `${dev.ip} → ${dev.name}`;

        if (dev.top_alert) {
            titleLine = dev.top_alert.summary_line1 || `🚨 ${dev.top_alert.description}`;
            detailLine = dev.top_alert.summary_line2 || `${dev.top_alert.src_ip || dev.ip} → ${dev.name}`;
        } else if (dev.badge === "OFFLINE") {
            titleLine = "❌ Ngoại tuyến";
            detailLine = `Mất kết nối Agent (${dev.ip})`;
        } else if (dev.badge === "WARNING") {
            titleLine = "🟡 Cảnh báo nghi vấn";
            detailLine = `Cảnh báo mức trung bình (${dev.ip})`;
        }

        bubbleEl.innerHTML = `
            <div class="callout-title">${escHtml(titleLine)}</div>
            <div class="callout-detail">${escHtml(detailLine)}</div>
        `;

        bubbleEl.style.left = `${domPos.x}px`;
        bubbleEl.style.top = `${domPos.y - 28}px`;
        bubbleEl.style.display = "flex";
    });

    Array.from(overlayContainer.children).forEach(child => {
        const id = child.id.replace("bubble-", "");
        if (!activeBubbleIds.has(id)) {
            child.remove();
        }
    });
}

// ─────────────────────────────────────────────
//  DEVICE DETAIL PANEL
// ─────────────────────────────────────────────
function renderDeviceDetail(dev) {
    const panel = document.getElementById("device-detail-panel");
    if (!panel) return;

    const health     = dev.health   || {};
    const risk       = dev.risk     || {};
    const healthPct  = health.score  ?? 0;
    const riskVal    = risk.risk     ?? 0;
    const badge      = dev.badge || "OFFLINE";

    const iconSrc = ICON_MAP[(dev.type || "unknown").toLowerCase()] || ICON_MAP["unknown"];

    // Health bar colour
    const healthColor = healthPct >= 80 ? "#22c55e"
                      : healthPct >= 40 ? "#f59e0b"
                      : "#ef4444";

    // Last seen display
    const lastSeenSec = health.last_seen_seconds;
    const lastSeenStr = lastSeenSec == null  ? "N/A"
                      : lastSeenSec < 60      ? `${lastSeenSec}s trước`
                      : lastSeenSec < 3600    ? `${Math.round(lastSeenSec / 60)}m trước`
                      : `${Math.round(lastSeenSec / 3600)}h trước`;

    panel.innerHTML = `
        <div style="padding: 0.1rem 0.2rem;">
            <div class="device-detail-header">
                <img src="${iconSrc}" class="device-type-icon-lg" alt="${dev.type}" onerror="this.src='/static/assets/icons/unknown.svg'">
                <div style="flex:1; min-width:0;">
                    <div style="font-size:0.95rem; font-weight:700; color:#f8fafc; margin-bottom:2px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">
                        ${escHtml(dev.name)}
                    </div>
                    <code style="font-size:0.8rem; color:#38bdf8;">${escHtml(dev.ip)}</code>
                    <div style="margin-top:4px;">
                        <span class="badge-pill badge-${badge}">${badgeLabel(badge)}</span>
                    </div>
                </div>
            </div>

            <div class="evidence-section">
                <h3><i class="fa-solid fa-heart-pulse"></i> Health Score</h3>
                <div style="display:flex; align-items:center; gap:8px; margin-bottom:4px;">
                    <div class="health-bar-outer" style="flex:1;">
                        <div class="health-bar-inner" style="width:${healthPct}%; background:${healthColor};"></div>
                    </div>
                    <span style="font-size:0.8rem; font-weight:700; color:${healthColor}; width:36px; text-align:right;">${healthPct}%</span>
                </div>
                <p style="font-size:0.75rem; color:#64748b; margin:0;">
                    Trạng thái: <span style="color:${healthColor}; font-weight:600;">${healthStatusLabel(health.status)}</span>
                    &nbsp;·&nbsp; Lần cuối thấy: <span style="color:#94a3b8;">${lastSeenStr}</span>
                </p>
            </div>

            <div class="evidence-section" style="margin-top:0.8rem;">
                <h3><i class="fa-solid fa-skull-crossbones"></i> Risk Score</h3>
                <div style="display:flex; align-items:center; gap:8px; margin-bottom:4px;">
                    <div class="health-bar-outer" style="flex:1;">
                        <div class="health-bar-inner" style="width:${riskVal}%; background:${riskColor(riskVal)};"></div>
                    </div>
                    <span style="font-size:0.8rem; font-weight:700; color:${riskColor(riskVal)}; width:36px; text-align:right;">${riskVal}</span>
                </div>
                <p style="font-size:0.75rem; color:#64748b; margin:0;">
                    Alerts liên quan: <span style="color:#94a3b8;">${risk.alert_count ?? 0}</span>
                    &nbsp;·&nbsp; Nguồn: <span style="color:#7c3aed;">score_priority()</span>
                </p>
            </div>

            <div class="evidence-section" style="margin-top:0.8rem;">
                <h3><i class="fa-solid fa-info-circle"></i> Chi Tiết</h3>
                <table style="width:100%; font-size:0.78rem; border-collapse:collapse;">
                    <tr><td style="color:#64748b; padding:2px 0;">Loại thiết bị</td>
                        <td style="color:#94a3b8; text-align:right;">${escHtml(dev.type || "—")}</td></tr>
                    <tr><td style="color:#64748b; padding:2px 0;">Hệ điều hành</td>
                        <td style="color:#94a3b8; text-align:right;">${escHtml(dev.os || "—")}</td></tr>
                    <tr><td style="color:#64748b; padding:2px 0;">Wazuh Agent ID</td>
                        <td style="color:#94a3b8; text-align:right;">${escHtml(dev.agent_id || "Không có agent")}</td></tr>
                    <tr><td style="color:#64748b; padding:2px 0;">Agent Status</td>
                        <td style="color:#94a3b8; text-align:right;">${escHtml(dev.agent_status || "—")}</td></tr>
                    <tr><td style="color:#64748b; padding:2px 0;">Nguồn dữ liệu</td>
                        <td style="color:#7c3aed; text-align:right;">${escHtml(dev.source || "—")}</td></tr>
                </table>
            </div>

            <button class="btn-investigate" onclick="openInvestigation('${escHtml(dev.id)}','${escHtml(dev.name)}','${escHtml(dev.ip)}',${riskVal})">
                <i class="fa-solid fa-magnifying-glass-chart"></i>
                🔍 Mở AI Investigation (Double-click)
            </button>
        </div>`;
}

function renderServerDetail() {
    const panel = document.getElementById("device-detail-panel");
    if (!panel) return;
    panel.innerHTML = `
        <div style="padding:0.2rem;">
            <div class="device-detail-header">
                <img src="${ICON_MAP["siem"]}" class="device-type-icon-lg" alt="SIEM">
                <div>
                    <div style="font-size:0.95rem; font-weight:700; color:#f8fafc;">Wazuh Manager</div>
                    <code style="font-size:0.8rem; color:#818cf8;">SIEM — Nút trung tâm</code>
                </div>
            </div>
            <div class="evidence-section">
                <p style="font-size:0.82rem; color:#64748b; line-height:1.6;">
                    Đây là nút trung tâm Wazuh Manager — tất cả Agent gửi log về đây.<br>
                    Double-click vào thiết bị ngoài để mở AI Investigation scoped theo thiết bị đó.
                </p>
            </div>
        </div>`;
}

function openInvestigation(id, name, ip, risk) {
    const url = `/drilldown?device_id=${encodeURIComponent(id)}`
              + `&device_name=${encodeURIComponent(name)}`
              + `&ip=${encodeURIComponent(ip)}`
              + `&risk=${encodeURIComponent(risk)}`;
    window.location.href = url;
}

// ─────────────────────────────────────────────
//  HELPERS
// ─────────────────────────────────────────────
function escHtml(str) {
    if (str == null) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}

function badgeLabel(badge) {
    return {
        "NORMAL":       "🟢 BÌNH THƯỜNG",
        "WARNING":      "🟡 CẢNH BÁO",
        "UNDER_ATTACK": "🔴 ĐANG BỊ TẤN CÔNG",
        "OFFLINE":      "⚫ NGOẠI TUYẾN"
    }[badge] || badge;
}

function healthStatusLabel(status) {
    return {
        "online":  "Trực tuyến",
        "warning": "Chậm / Không ổn định",
        "offline": "Ngoại tuyến"
    }[status] || status || "Không rõ";
}

function riskColor(risk) {
    if (risk >= 70) return "#ef4444";
    if (risk >= 40) return "#f59e0b";
    return "#22c55e";
}
