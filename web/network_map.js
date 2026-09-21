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
    // Live API Log Bar Height Resizer
    const logBar = document.getElementById("live-api-log-bar");
    if (logBar && !document.querySelector(".live-log-resizer-h")) {
        const resizer = document.createElement("div");
        resizer.className = "live-log-resizer-h";
        resizer.title = "Kéo lên/xuống để điều chỉnh chiều cao bảng nhật ký log REST API";
        logBar.parentNode.insertBefore(resizer, logBar);

        let isDragging = false;
        let startY = 0;
        let startHeight = 0;

        const savedHeight = localStorage.getItem("agentwazuh_live_log_height");
        if (savedHeight) {
            logBar.style.height = `${savedHeight}px`;
        }

        resizer.addEventListener("mousedown", (e) => {
            isDragging = true;
            startY = e.clientY;
            startHeight = logBar.getBoundingClientRect().height;
            resizer.classList.add("is-dragging");
            document.body.style.userSelect = "none";
            document.body.style.cursor = "row-resize";
        });

        document.addEventListener("mousemove", (e) => {
            if (!isDragging) return;
            const dy = startY - e.clientY;
            const newHeight = Math.max(70, Math.min(600, startHeight + dy));
            logBar.style.height = `${newHeight}px`;
        });

        document.addEventListener("mouseup", () => {
            if (isDragging) {
                isDragging = false;
                resizer.classList.remove("is-dragging");
                document.body.style.userSelect = "";
                document.body.style.cursor = "";
                const currentHeight = logBar.getBoundingClientRect().height;
                if (currentHeight) {
                    localStorage.setItem("agentwazuh_live_log_height", currentHeight);
                }
            }
        });
    }

    // Back button
    document.getElementById("btn-back-dash")?.addEventListener("click", () => {
        window.location.href = "/dashboard";
    });
    document.getElementById("btn-open-evidence-dashboard")?.addEventListener("click", () => {
        window.location.href = "/dashboard?tab=evidence";
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

    // Settings modal open + save support on Network Map
    document.getElementById("btn-open-settings")?.addEventListener("click", async () => {
        document.getElementById("settings-modal")?.classList.remove("hidden");
        try {
            const res = await fetch("/api/settings", { credentials: "same-origin" });
            const json = await res.json();
            const s = json.settings || {};
            const hostEl = document.getElementById("setting-wazuh-host");
            const portEl = document.getElementById("setting-wazuh-port");
            const timeoutEl = document.getElementById("setting-timeout-min");
            const intervalEl = document.getElementById("setting-ping-interval");
            const retryEl = document.getElementById("setting-ping-retry");

            if (hostEl && s.wazuh_host) hostEl.value = s.wazuh_host;
            if (portEl && s.wazuh_port) portEl.value = s.wazuh_port;
            if (timeoutEl && s.session_timeout_minutes) timeoutEl.value = s.session_timeout_minutes;
            if (intervalEl && s.icmp_ping_interval_seconds) intervalEl.value = s.icmp_ping_interval_seconds;
            if (retryEl && s.ping_retry_threshold) retryEl.value = s.ping_retry_threshold;

            const resAi = await fetch("/api/settings/ai", { credentials: "same-origin" });
            const aiJson = await resAi.json();
            const geminiKeyEl = document.getElementById("input-gemini-key");
            const geminiModelEl = document.getElementById("select-gemini-model");
            if (geminiKeyEl && (aiJson.cloud_api_key || aiJson.gemini_api_key)) {
                geminiKeyEl.value = aiJson.cloud_api_key || aiJson.gemini_api_key;
            }
            if (geminiModelEl && aiJson.gemini_model) {
                geminiModelEl.value = aiJson.gemini_model;
            }
        } catch (e) {
            console.error("Error loading settings in network map:", e);
        }
    });

    document.getElementById("btn-save-all-settings")?.addEventListener("click", async () => {
        const hostEl = document.getElementById("setting-wazuh-host");
        const portEl = document.getElementById("setting-wazuh-port");
        const timeoutEl = document.getElementById("setting-timeout-min");
        const intervalEl = document.getElementById("setting-ping-interval");
        const retryEl = document.getElementById("setting-ping-retry");
        const geminiKeyEl = document.getElementById("input-gemini-key");
        const geminiModelEl = document.getElementById("select-gemini-model");

        const hostVal = hostEl ? hostEl.value.trim() : "127.0.0.1";
        const sysPayload = {
            session_timeout_minutes: parseInt(timeoutEl ? timeoutEl.value : 30) || 30,
            icmp_ping_interval_seconds: parseInt(intervalEl ? intervalEl.value : 15) || 15,
            ping_retry_threshold: parseInt(retryEl ? retryEl.value : 3) || 3,
            wazuh_host: hostVal,
            wazuh_port: parseInt(portEl ? portEl.value : 55000) || 55000,
            wazuh_user: "wazuh",
            uptime_kuma_push_token: "agentwazuh-push-secret-999",
            device_cache_ttl_days: 7,
            ui_theme: "cyber_dark"
        };

        const aiPayload = {
            mode: "pi_dev",
            pi_model: "openrouter/anthropic/claude-3-5-haiku",
            active_providers: ["gemini"],
            gemini_model: geminiModelEl ? geminiModelEl.value : "gemini-2.5-flash",
            cloud_api_key: geminiKeyEl ? geminiKeyEl.value.trim() : "",
            gemini_api_key: geminiKeyEl ? geminiKeyEl.value.trim() : ""
        };

        try {
            const resSys = await fetch("/api/settings", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(sysPayload),
                credentials: "same-origin"
            });

            if (!resSys.ok) {
                const errJson = await resSys.json();
                const errDetail = typeof errJson.detail === "string" ? errJson.detail : JSON.stringify(errJson.detail || errJson);
                alert(`❌ Lỗi lưu Cài đặt: ${errDetail}`);
                return;
            }

            await fetch("/api/ai/config", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(aiPayload),
                credentials: "same-origin"
            });

            alert(`🟢 ĐÃ LƯU TOÀN BỘ CÀI ĐẶT THÀNH CÔNG!\n- Wazuh Host: ${sysPayload.wazuh_host}\n- Port: ${sysPayload.wazuh_port}`);
            window.closeSettingsModal();
            pollFullMap();
        } catch (err) {
            alert(`❌ Lỗi khi lưu cài đặt: ${err.message}`);
        }
    });

    window.closeSettingsModal = () => {
        document.getElementById("settings-modal")?.classList.add("hidden");
    };

    // Settings drawer markup + tab switching are owned by the shared settings_drawer.js.

    // Initial data fetch + polling
    pollConnState();
    pollFullMap();
    connectRealtimeMapStream();
    setInterval(pollConnState, 5000);
    setInterval(pollFullMap,   15000);
});

function connectRealtimeMapStream() {
    if (!window.EventSource) return;
    const stream = new EventSource("/api/events/alerts");
    stream.addEventListener("alert", () => {
        // Alert changes can alter node risk/badges; refresh the monitoring map now.
        pollFullMap();
    });
}

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
    const bus         = document.getElementById("secmap-bus-wrapper");
    const badge       = document.getElementById("bus-conn-badge");
    const serverLabel = document.getElementById("bus-server-label");
    const connDot     = document.getElementById("hdr-conn-dot");

    if (serverLabel) {
        serverLabel.innerHTML = `${escHtml(host)}<br><span class="bus-node-role server">SIEM</span>`;
    }

    const statusHost = document.getElementById("status-host");
    if (statusHost) statusHost.textContent = `Wazuh Server: ${host}`;

    // Visual state (badge + SVG line + travelling packet) is driven by
    // #secmap-bus-wrapper[data-conn="…"] in topology.css.
    const connState = ["da_ket_noi", "chap_chon", "chua_ket_noi"].includes(state)
        ? state
        : "chua_ket_noi";
    if (bus) bus.dataset.conn = connState;

    const labels = {
        "chua_ket_noi": "⛔ Chưa kết nối",
        "da_ket_noi":   "✅ Đã kết nối",
        "chap_chon":    "⚠️ Chập chờn"
    };
    const dotClass = { "chua_ket_noi": "offline", "da_ket_noi": "online", "chap_chon": "warning" }[connState];

    if (badge) badge.textContent = labels[connState];
    if (connDot) connDot.className = `status-indicator ${dotClass}`;
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
                <i class="fa-solid fa-shield-halved"></i>
                <p>
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
        // Skip duplicate central Wazuh Server node if returned in devices list
        if (dev.id === "wazuh_manager_node" || dev.type === "wazuh" || dev.ip === wazuhHost) {
            nodes[0]._device = dev;
            return;
        }

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
            smooth: false,
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

        // Disable physics after stabilisation & freeze position coordinates
        network.on("stabilizationIterationsDone", () => {
            const currentPositions = network.getPositions();
            Object.keys(currentPositions).forEach(id => { savedPositions[id] = currentPositions[id]; });
            localStorage.setItem("secmap_positions", JSON.stringify(savedPositions));
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
        // Incremental update preserving current node coordinates
        const curPos = network.getPositions();
        nodes.forEach(n => {
            const p = curPos[n.id] || savedPositions[n.id];
            if (p) { n.x = p.x; n.y = p.y; }
        });
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
        overlayContainer.className = "secmap-bubbles-overlay";
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

        // Position is data-driven (canvas → DOM coords); visuals come from CSS classes.
        bubbleEl.style.left = `${domPos.x}px`;
        bubbleEl.style.top = `${domPos.y - 28}px`;
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

    // Tone classes mirror the severity tokens (see topology.css)
    const healthTone = healthPct >= 80 ? "tone-ok" : healthPct >= 40 ? "tone-warn" : "tone-bad";
    const riskTone   = riskVal   >= 70 ? "tone-bad" : riskVal   >= 40 ? "tone-warn" : "tone-ok";

    // Last seen display
    const lastSeenSec = health.last_seen_seconds;
    const lastSeenStr = lastSeenSec == null  ? "N/A"
                      : lastSeenSec < 60      ? `${lastSeenSec}s trước`
                      : lastSeenSec < 3600    ? `${Math.round(lastSeenSec / 60)}m trước`
                      : `${Math.round(lastSeenSec / 3600)}h trước`;

    panel.innerHTML = `
        <div class="device-detail-header">
            <img src="${iconSrc}" class="device-type-icon-lg" alt="${escHtml(dev.type)}" onerror="this.src='/static/assets/icons/unknown.svg'">
            <div class="device-detail-heading">
                <div class="device-detail-name">${escHtml(dev.name)}</div>
                <code class="device-detail-ip">${escHtml(dev.ip)}</code>
                <div>
                    <span class="badge-pill ${badge}">${badgeLabel(badge)}</span>
                </div>
            </div>
        </div>

        <section class="evidence-section">
            <h3><i class="fa-solid fa-heart-pulse"></i> Health Score</h3>
            <div class="metric-row">
                <div class="health-bar-outer">
                    <div class="health-bar-inner ${healthTone}" style="width:${healthPct}%"></div>
                </div>
                <span class="metric-value ${healthTone}">${healthPct}%</span>
            </div>
            <p class="metric-note">
                Trạng thái: <span class="kv ${healthTone}">${healthStatusLabel(health.status)}</span>
                &nbsp;·&nbsp; Lần cuối thấy: <span class="kv">${lastSeenStr}</span>
            </p>
        </section>

        <section class="evidence-section">
            <h3><i class="fa-solid fa-skull-crossbones"></i> Risk Score</h3>
            <div class="metric-row">
                <div class="health-bar-outer">
                    <div class="health-bar-inner ${riskTone}" style="width:${riskVal}%"></div>
                </div>
                <span class="metric-value ${riskTone}">${riskVal}</span>
            </div>
            <p class="metric-note">
                Alerts liên quan: <span class="kv">${risk.alert_count ?? 0}</span>
                &nbsp;·&nbsp; Nguồn: <span class="ref">score_priority()</span>
            </p>
        </section>

        <section class="evidence-section">
            <h3><i class="fa-solid fa-info-circle"></i> Chi tiết</h3>
            <table class="kv-table">
                <tr><td>Loại thiết bị</td><td>${escHtml(dev.type || "—")}</td></tr>
                <tr><td>Hệ điều hành</td><td>${escHtml(dev.os || "—")}</td></tr>
                <tr><td>Wazuh Agent ID</td><td>${escHtml(dev.agent_id || "Không có agent")}</td></tr>
                <tr><td>Agent Status</td><td>${escHtml(dev.agent_status || "—")}</td></tr>
                <tr><td>Nguồn dữ liệu</td><td class="ref">${escHtml(dev.source || "—")}</td></tr>
            </table>
        </section>

        <button type="button" class="btn btn--primary btn--block device-detail-cta"
                onclick="openInvestigation('${escHtml(dev.id)}','${escHtml(dev.name)}','${escHtml(dev.ip)}',${riskVal})">
            <i class="fa-solid fa-magnifying-glass-chart"></i> Mở AI Investigation
        </button>`;
}

function renderServerDetail() {
    const panel = document.getElementById("device-detail-panel");
    if (!panel) return;
    panel.innerHTML = `
        <div class="device-detail-header">
            <img src="${ICON_MAP["siem"]}" class="device-type-icon-lg" alt="SIEM">
            <div class="device-detail-heading">
                <div class="device-detail-name">Wazuh Manager</div>
                <code class="device-detail-ip">SIEM — Nút trung tâm</code>
            </div>
        </div>
        <section class="evidence-section">
            <p class="metric-note">
                Đây là nút trung tâm Wazuh Manager — tất cả Agent gửi log về đây.<br>
                Double-click vào thiết bị ngoài để mở AI Investigation scoped theo thiết bị đó.
            </p>
        </section>`;
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

    async function pollWazuhStatus() {
        try {
            const res = await fetch('/api/wazuh/status', { credentials: 'same-origin' });
            const data = await res.json();
            const statusIpEl = document.getElementById('status-host') || document.getElementById('status-wazuh-ip');
            const indicatorEl = document.querySelector('.header-status .status-indicator');
            if (statusIpEl && indicatorEl) {
                statusIpEl.textContent = 'Wazuh Server: ' + (data.wazuh_host || 'N/A');
                if (data.status === 'online') {
                    indicatorEl.className = 'status-indicator online';
                } else if (data.status === 'offline') {
                    indicatorEl.className = 'status-indicator offline';
                } else {
                    indicatorEl.className = 'status-indicator warning';
                }
            }
        } catch (err) {
            console.error('Failed to poll Wazuh status:', err);
            const indicatorEl = document.querySelector('.header-status .status-indicator');
            if (indicatorEl) indicatorEl.className = 'status-indicator offline';
        }
    }
    setInterval(pollWazuhStatus, 3000);
    pollWazuhStatus();

window.openWazuhApiInspectorModal = function() {
    const modal = document.getElementById("wazuh-api-inspector-modal");
    if (modal) {
        modal.classList.remove("hidden");
        window.refreshWazuhApiInspector();
    }
};

window.closeWazuhApiInspectorModal = function() {
    document.getElementById("wazuh-api-inspector-modal")?.classList.add("hidden");
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
                        <span class="inspector-method ${mClass}">${escHtml(log.method)}</span>
                        <span class="inspector-status ${sClass}">${escHtml(String(log.status_code))}</span>
                        <span class="inspector-url">${escHtml(rawUrl)}</span>
                    </div>
                    <span class="inspector-ts">${escHtml(log.timestamp)}</span>
                </div>

                <p class="inspector-detail">${escHtml(log.detail || '')}</p>
                <pre class="inspector-curl">${escHtml(rawCurl)}</pre>

                <div class="inspector-actions">
                    <button type="button" class="btn btn--ghost btn--sm"
                            onclick="window.copyTextToClipboard(this.dataset.copy, this)" data-copy="${escHtml(rawUrl)}">
                        <i class="fa-solid fa-copy"></i> Copy API Endpoint
                    </button>
                    <button type="button" class="btn btn--ghost btn--sm"
                            onclick="window.copyTextToClipboard(this.dataset.copy, this)" data-copy="${escHtml(rawCurl)}">
                        <i class="fa-solid fa-terminal"></i> Copy lệnh Curl
                    </button>
                </div>
            </article>`;
        });
        listBox.innerHTML = html;
    } catch(e) {
        listBox.innerHTML = `<div class="inspector-error">❌ Lỗi tải dữ liệu gói API Inspector: ${escHtml(e.message)}</div>`;
    }
};

// ─────────────────────────────────────────────
//  LIVE REST API EXCHANGE LOG (moved from inline <script>)
// ─────────────────────────────────────────────
async function pollLiveApiLogs() {
    try {
        const res = await fetch("/api/wazuh/live-logs", { credentials: "same-origin" });
        if (!res.ok) return;
        const data = await res.json();
        const container = document.getElementById("live-api-log-container");
        const statusText = document.getElementById("live-log-status-text");
        if (container && data.logs) {
            if (data.logs.length === 0) {
                container.innerHTML = `<span class="live-log-idle">[IDLE] Chưa có giao dịch REST API mới.</span>`;
            } else {
                container.innerHTML = data.logs.slice(0, 20).map(l => {
                    const outgoing = l.direction === "OUTGOING_REQUEST";
                    const dirClass = outgoing ? "is-out" : "is-in";
                    const httpClass = l.status_code === 200 ? "is-ok" : "is-fail";
                    const direction = outgoing ? "[AGENT -> WAZUH SERVER]" : "[WAZUH SERVER -> AGENT]";
                    return `<div class="live-log-line ${dirClass} ${httpClass}">`
                         + `<span class="live-log-ts">[${escHtml(l.timestamp)}]</span> `
                         + `<span class="live-log-dir">${direction}</span> `
                         + `<span class="live-log-http">${escHtml(l.method)} ${escHtml(l.url)} (HTTP ${escHtml(String(l.status_code))})</span>`
                         + ` — <span class="live-log-detail">${escHtml(l.detail || '')}</span>`
                         + `</div>`;
                }).join("");
            }
            if (statusText) statusText.textContent = `Đã cập nhật ${data.logs.length} giao dịch REST API thời gian thực`;
        }
    } catch (e) {
        console.error("Error polling live logs:", e);
    }
}

// Route both inspector entry points through a single action.
document.getElementById("btn-wazuh-api-inspector")?.addEventListener("click", () => window.openWazuhApiInspectorModal());
setInterval(pollLiveApiLogs, 2000);
document.addEventListener("DOMContentLoaded", pollLiveApiLogs);
