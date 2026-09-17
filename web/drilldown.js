// AgentWazuh Drill-down Dedicated Page Controller (Prompt 2)
document.addEventListener("DOMContentLoaded", () => {
    if (window.mermaid) {
        mermaid.initialize({ startOnLoad: false, theme: "dark", securityLevel: "loose" });
    }

    const urlParams = new URLSearchParams(window.location.search);

    // Hai kiểu URL được hỗ trợ:
    //  - /drilldown?type=severity&value=high   (phân vùng theo severity/rule)
    //  - /drilldown?device_id=..&device_name=..&ip=..&risk=..  (từ Sơ đồ mạng)
    const deviceId = urlParams.get("device_id") || "";
    const deviceName = urlParams.get("device_name") || "";
    const deviceIp = urlParams.get("ip") || "";
    const deviceRisk = urlParams.get("risk") || "";
    const isDeviceScope = Boolean(deviceId || deviceName || deviceIp) && !urlParams.get("type");

    const filterType = isDeviceScope ? "device" : (urlParams.get("type") || "severity");
    const filterVal = isDeviceScope ? (deviceId || deviceIp || deviceName) : (urlParams.get("value") || "low");
    const deviceLabel = deviceName || deviceIp || deviceId || "không rõ";

    const btnBackDash = document.getElementById("btn-back-dash");
    const drilldownTitle = document.getElementById("drilldown-title");
    const drilldownSubtitle = document.getElementById("drilldown-subtitle");
    const btnRefreshLogs = document.getElementById("btn-refresh-logs");
    const logsTbody = document.getElementById("logs-tbody");
    const chatStream = document.getElementById("chat-stream");
    const chatForm = document.getElementById("chat-form");
    const chatInput = document.getElementById("chat-input");
    const presetChips = document.querySelectorAll(".chip-btn");

    const logModal = document.getElementById("log-modal");
    const modalLogJson = document.getElementById("modal-log-json");

    let currentLogs = [];

    if (drilldownTitle) {
        drilldownTitle.innerHTML = isDeviceScope
            ? `<i class="fa-solid fa-crosshairs"></i> Thiết bị: ${escapeHtml(deviceLabel)}`
            : `<i class="fa-solid fa-filter"></i> Log Drill-down Inspector: [${escapeHtml(filterType.toUpperCase())} = ${escapeHtml(filterVal.toUpperCase())}]`;
    }

    if (drilldownSubtitle) {
        const parts = [];
        if (deviceIp) parts.push(`IP ${deviceIp}`);
        if (deviceRisk !== "") parts.push(`Điểm rủi ro ${deviceRisk}/100`);
        parts.push("Phân vùng log scoped theo thiết bị");
        drilldownSubtitle.textContent = parts.join(" · ");
    }

    window.openLogModalByIndex = function(idx) {
        const logObj = currentLogs[idx];
        if (logObj && modalLogJson) {
            modalLogJson.textContent = JSON.stringify(logObj, null, 2);
            logModal?.classList.remove("hidden");
        }
    };

    window.askAboutLogByIndex = function(idx) {
        const logObj = currentLogs[idx];
        if (logObj && chatInput) {
            const ruleId = logObj.rule?.id || "";
            const desc = logObj.rule?.description || "";
            chatInput.value = `Phân tích cụ thể nguy cơ từ log Rule ${ruleId}: "${desc}"`;
            chatForm?.dispatchEvent(new Event("submit"));
        }
    };

    btnBackDash?.addEventListener("click", () => {
        window.location.href = "/dashboard";
    });

    btnRefreshLogs?.addEventListener("click", () => {
        fetchFilteredLogs();
    });

    window.openLogModal = function(logObj) {
        if (modalLogJson) modalLogJson.textContent = JSON.stringify(logObj, null, 2);
        logModal?.classList.remove("hidden");
    };

    window.closeLogModal = function() {
        logModal?.classList.add("hidden");
    };

    // Fetch Filtered Logs
    async function fetchFilteredLogs() {
        if (logsTbody) logsTbody.innerHTML = '<tr><td colspan="6" class="loading-state">Đang tải dữ liệu log chi tiết...</td></tr>';
        try {
            const res = await fetch(`/api/wazuh/alerts/filter?type=${encodeURIComponent(filterType)}&value=${encodeURIComponent(filterVal)}&limit=200`, { credentials: "same-origin" });
            const data = await res.json();
            currentLogs = data.alerts || [];
            renderTable(currentLogs);
        } catch (err) {
            console.error("Failed to load filtered logs:", err);
            if (logsTbody) logsTbody.innerHTML = '<tr><td colspan="6" class="loading-state">Không thể tải dữ liệu log.</td></tr>';
        }
    }

    function renderTable(logs) {
        if (!logsTbody) return;
        if (!logs || logs.length === 0) {
            logsTbody.innerHTML = '<tr><td colspan="6" class="loading-state">Không tìm thấy log nào trong phân vùng này.</td></tr>';
            return;
        }

        logsTbody.innerHTML = "";
        logs.forEach((log, idx) => {
            const tr = document.createElement("tr");
            const level = log.rule?.level || 0;
            let levelClass = "level-low";
            if (level >= 15) levelClass = "level-critical";
            else if (level >= 12) levelClass = "level-high";
            else if (level >= 7) levelClass = "level-medium";

            let tsStr = log.timestamp || "";
            if (!tsStr.endsWith("Z") && !tsStr.includes("+") && !tsStr.includes("-", 10)) tsStr += "Z";
            let formattedTs = tsStr.substring(11, 19);
            try {
                const d = new Date(tsStr);
                if (!isNaN(d.getTime())) formattedTs = d.toLocaleTimeString("vi-VN", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
            } catch(e) {}

            tr.innerHTML = `
                <td class="mono">${escapeHtml(formattedTs)}</td>
                <td><strong>Rule ${escapeHtml(log.rule?.id || "")}</strong></td>
                <td><span class="badge-level ${levelClass}">LEVEL ${escapeHtml(level)}</span></td>
                <td>${escapeHtml(log.rule?.description || "")}</td>
                <td>${escapeHtml(log.agent?.name || "")} <span class="mono">(${escapeHtml(log.data?.srcip || log.agent?.ip || "")})</span></td>
                <td>
                    <button type="button" class="interactive-chip" onclick="window.openLogModalByIndex(${idx})">JSON</button>
                    <button type="button" class="interactive-chip chip-low" onclick="window.askAboutLogByIndex(${idx})">Hỏi AI</button>
                </td>
            `;
            logsTbody.appendChild(tr);
        });
    }

    // Scoped Chat Request
    async function sendScopedInvestigate(query) {
        appendChatUser(query);
        const loadingId = appendChatBot("Đang suy luận AI trong phạm vi phân vùng Scoped Context...");

        try {
            const res = await fetch("/api/wazuh/investigate/scoped", {
                method: "POST",
                credentials: "same-origin",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    query: query,
                    scope_filter: { type: filterType, value: filterVal }
                })
            });

            const data = await res.json();
            const inv = data.investigation || {};
            updateChatBot(loadingId, inv.layer_2_llm_reasoning || data.message || "Không nhận được nội dung phân tích.", inv.reasoning_steps);
        } catch (err) {
            console.error("Scoped investigate failed:", err);
            updateChatBot(loadingId, "Lỗi kết nối Scoped AI Engine.");
        }
    }

    function appendChatUser(msg) {
        if (!chatStream) return;
        const div = document.createElement("div");
        div.className = "chat-bubble user";
        div.innerHTML = `<i class="fa-solid fa-user avatar"></i><div class="bubble-content"><strong>Analyst:</strong><p>${escapeHtml(msg)}</p></div>`;
        chatStream.appendChild(div);
        chatStream.scrollTop = chatStream.scrollHeight;
    }

    function appendChatBot(msg) {
        const id = "bot_" + Date.now();
        if (!chatStream) return id;
        const div = document.createElement("div");
        div.className = "chat-bubble system";
        div.id = id;
        div.innerHTML = `<i class="fa-solid fa-robot avatar"></i><div class="bubble-content"><strong>AgentWazuh Scoped Inspector:</strong><div class="msg-text">${msg}</div></div>`;
        chatStream.appendChild(div);
        chatStream.scrollTop = chatStream.scrollHeight;
        return id;
    }

    function updateChatBot(id, markdownText, steps = []) {
        const div = document.getElementById(id);
        if (!div) return;
        const content = div.querySelector(".msg-text");
        if (!content) return;
        let stepperHtml = "";
        if (steps && steps.length > 0) {
            stepperHtml = '<div class="reasoning-stepper">';
            steps.forEach(s => {
                stepperHtml += `<div class="step-item completed"><i class="fa-solid fa-circle-check step-icon"></i> <strong>Step ${escapeHtml(s.step)}: ${escapeHtml(s.title)}</strong> — ${escapeHtml(s.detail)}</div>`;
            });
            stepperHtml += '</div>';
        }

        const text = String(markdownText ?? "");
        const parsedHtml = window.marked ? marked.parse(text) : escapeHtml(text).replace(/\n/g, "<br>");
        content.innerHTML = stepperHtml + parsedHtml;
        if (chatStream) chatStream.scrollTop = chatStream.scrollHeight;
    }

    function escapeHtml(text) {
        return String(text ?? "")
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;");
    }

    presetChips.forEach(chip => {
        chip.addEventListener("click", () => {
            const query = chip.getAttribute("data-query");
            if (query) {
                sendScopedInvestigate(query);
            }
        });
    });

    chatForm?.addEventListener("submit", (e) => {
        e.preventDefault();
        const query = chatInput.value.trim();
        if (!query) return;
        chatInput.value = "";
        sendScopedInvestigate(query);
    });

    fetchFilteredLogs();
});
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
