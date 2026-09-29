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
    const chatModelSelect = document.getElementById("chat-model-select");
    const presetChips = document.querySelectorAll(".chip-btn");
    const drilldownChatKey = "agentwazuh.drilldownChatSessionId";
    let currentChatSessionId = localStorage.getItem(drilldownChatKey) || null;
    let chatWriteQueue = Promise.resolve();

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

            let tsStr = (log["@timestamp"] || log.timestamp || "").trim().replace(/([+-]\d{2})(\d{2})$/, "$1:$2");
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
                    scope_filter: { type: filterType, value: filterVal },
                    model: chatModelSelect?.value || "auto"
                })
            });

            const data = await res.json();
            if (!res.ok) throw new Error(data.detail || data.message || `HTTP ${res.status}`);
            const inv = data.investigation || {};
            const answer = inv.layer_2_llm_reasoning || inv.summary || inv.answer || data.message;
            updateChatBot(loadingId, answer || "Chưa có nội dung phân tích. Hãy kiểm tra dữ liệu log và cấu hình model AI.");
        } catch (err) {
            console.error("Scoped investigate failed:", err);
            updateChatBot(loadingId, `Không thể phân tích: ${err.message || "Lỗi kết nối AI Engine."}`);
        }
    }

    function appendChatUser(msg) {
        if (!chatStream) return;
        const div = document.createElement("div");
        div.className = "chat-bubble user";
        div.innerHTML = `<i class="fa-solid fa-user avatar"></i><div class="bubble-content"><strong>Analyst:</strong><p>${escapeHtml(msg)}</p></div>`;
        chatStream.appendChild(div);
        chatStream.scrollTop = chatStream.scrollHeight;
        persistChatMessage("user", msg);
    }

    function appendChatBot(msg) {
        const id = "bot_" + Date.now();
        if (!chatStream) return id;
        const div = document.createElement("div");
        div.className = "chat-bubble system";
        div.id = id;
        div.innerHTML = `<i class="fa-solid fa-robot avatar"></i><div class="bubble-content"><strong>AgentWazuh AI:</strong><div class="msg-text">${msg}</div></div>`;
        chatStream.appendChild(div);
        chatStream.scrollTop = chatStream.scrollHeight;
        return id;
    }

    function updateChatBot(id, markdownText) {
        const div = document.getElementById(id);
        if (!div) return;
        const content = div.querySelector(".msg-text");
        if (!content) return;
        const text = String(markdownText ?? "");
        const parsedHtml = window.marked ? marked.parse(text) : escapeHtml(text).replace(/\n/g, "<br>");
        content.innerHTML = parsedHtml;
        if (chatStream) chatStream.scrollTop = chatStream.scrollHeight;
        persistChatMessage("ai", text);
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

    async function ensureChatSession(title = "Scoped Wazuh Investigation") {
        if (currentChatSessionId) return currentChatSessionId;
        const res = await fetch("/api/chat/history", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "same-origin",
            body: JSON.stringify({ title, project_name: "Scoped Investigation" })
        });
        const data = await res.json();
        if (!res.ok || !data.session?.id) throw new Error(data.detail || "Không tạo được phiên chat.");
        currentChatSessionId = data.session.id;
        localStorage.setItem(drilldownChatKey, currentChatSessionId);
        return currentChatSessionId;
    }

    function persistChatMessage(role, content) {
        if (!content || content === "Đang suy luận AI trong phạm vi phân vùng Scoped Context...") return;
        chatWriteQueue = chatWriteQueue.then(async () => {
            const id = await ensureChatSession(role === "user" ? content : "Scoped Wazuh Investigation");
            await fetch(`/api/chat/history/${encodeURIComponent(id)}/message`, {
                method: "PUT",
                headers: { "Content-Type": "application/json" },
                credentials: "same-origin",
                body: JSON.stringify({ role, content, timestamp: new Date().toISOString() })
            });
        }).catch(err => console.error("Không lưu được hội thoại scoped:", err));
    }

    async function loadDrilldownChatSession() {
        if (!currentChatSessionId) return;
        try {
            const res = await fetch(`/api/chat/history/${encodeURIComponent(currentChatSessionId)}`, { credentials: "same-origin" });
            const data = await res.json();
            if (!res.ok || !data.session) {
                currentChatSessionId = null;
                localStorage.removeItem(drilldownChatKey);
                return;
            }
            const messages = data.session.messages || [];
            if (!messages.length || !chatStream) return;
            chatStream.innerHTML = "";
            messages.forEach(msg => {
                const div = document.createElement("div");
                div.className = `chat-bubble ${msg.role === "user" ? "user" : "system"}`;
                const content = msg.role === "user" ? escapeHtml(msg.content) : (window.marked ? marked.parse(msg.content || "") : escapeHtml(msg.content || "").replace(/\n/g, "<br>"));
                div.innerHTML = `<i class="fa-solid ${msg.role === "user" ? "fa-user" : "fa-robot"} avatar"></i><div class="bubble-content"><strong>${msg.role === "user" ? "Analyst" : "AgentWazuh AI"}:</strong><div class="msg-text">${content}</div></div>`;
                chatStream.appendChild(div);
            });
            chatStream.scrollTop = chatStream.scrollHeight;
        } catch (err) {
            console.warn("Không khôi phục được hội thoại scoped:", err);
        }
    }

    async function openChatManager() {
        const modal = document.getElementById("chat-manager-modal");
        const list = document.getElementById("chat-manager-list");
        if (!modal || !list) return;
        modal.classList.remove("hidden");
        list.innerHTML = '<div class="loading-state">Đang tải lịch sử hội thoại…</div>';
        try {
            const res = await fetch("/api/chat/history", { credentials: "same-origin" });
            const data = await res.json();
            const sessions = data.sessions || [];
            list.innerHTML = sessions.length ? sessions.map(item => `
                <label class="chat-manager-item">
                    <input type="checkbox" class="chat-session-check" value="${escapeHtml(item.id)}">
                    <span class="chat-manager-item__body">
                        <span class="chat-manager-item__title">${escapeHtml(item.title || "Không tiêu đề")}</span><br>
                        <span class="chat-manager-item__meta">${escapeHtml(item.project_name || "Scoped Investigation")} · ${escapeHtml(item.updated_at || item.created_at || "")}</span>
                    </span>
                </label>`).join("") : '<div class="loading-state">Chưa có hội thoại được lưu.</div>';
            document.getElementById("chat-manager-select-all").checked = false;
        } catch (err) {
            list.innerHTML = `<div class="inline-alert danger">Không tải được lịch sử: ${escapeHtml(err.message)}</div>`;
        }
    }

    document.getElementById("btn-manage-drilldown-chats")?.addEventListener("click", openChatManager);
    document.getElementById("btn-close-chat-manager")?.addEventListener("click", () => document.getElementById("chat-manager-modal")?.classList.add("hidden"));
    document.getElementById("chat-manager-select-all")?.addEventListener("change", event => {
        document.querySelectorAll(".chat-session-check").forEach(box => { box.checked = event.target.checked; });
    });
    document.getElementById("btn-delete-selected-chats")?.addEventListener("click", async () => {
        const ids = [...document.querySelectorAll(".chat-session-check:checked")].map(box => box.value);
        if (!ids.length) return alert("Hãy chọn ít nhất một hội thoại.");
        if (!confirm(`Xóa vĩnh viễn ${ids.length} hội thoại đã chọn?`)) return;
        await fetch("/api/chat/history/bulk-delete", { method: "POST", headers: { "Content-Type": "application/json" }, credentials: "same-origin", body: JSON.stringify({ session_ids: ids }) });
        if (ids.includes(currentChatSessionId)) { currentChatSessionId = null; localStorage.removeItem(drilldownChatKey); }
        openChatManager();
    });
    document.getElementById("btn-delete-all-chats")?.addEventListener("click", async () => {
        if (!confirm("Xóa vĩnh viễn toàn bộ hội thoại đã lưu?")) return;
        await fetch("/api/chat/history/bulk-delete", { method: "POST", headers: { "Content-Type": "application/json" }, credentials: "same-origin", body: JSON.stringify({ delete_all: true }) });
        currentChatSessionId = null;
        localStorage.removeItem(drilldownChatKey);
        openChatManager();
    });

    loadDrilldownChatSession();

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
