// AgentWazuh Drill-down Dedicated Page Controller (Prompt 2)
document.addEventListener("DOMContentLoaded", () => {
    if (window.mermaid) {
        mermaid.initialize({ startOnLoad: false, theme: 'dark', securityLevel: 'loose' });
    }

    const urlParams = new URLSearchParams(window.location.search);
    const filterType = urlParams.get("type") || "severity";
    const filterVal = urlParams.get("value") || "low";

    const btnBackDash = document.getElementById("btn-back-dash");
    const drilldownTitle = document.getElementById("drilldown-title");
    const logsTbody = document.getElementById("logs-tbody");
    const chatStream = document.getElementById("chat-stream");
    const chatForm = document.getElementById("chat-form");
    const chatInput = document.getElementById("chat-input");
    const presetChips = document.querySelectorAll(".chip-btn");

    const logModal = document.getElementById("log-modal");
    const modalLogJson = document.getElementById("modal-log-json");

    let currentLogs = [];

    drilldownTitle.innerHTML = `<i class="fa-solid fa-filter"></i> Log Drill-down Inspector: [${filterType.toUpperCase()} = ${filterVal.toUpperCase()}]`;

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
            const res = await fetch(`/api/wazuh/alerts/filter?type=${filterType}&value=${filterVal}&limit=200`);
            const data = await res.json();
            currentLogs = data.alerts || [];
            renderTable(currentLogs);
        } catch (err) {
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
                <td>${formattedTs}</td>
                <td><strong>Rule ${log.rule?.id || ""}</strong></td>
                <td><span class="badge-level ${levelClass}">LEVEL ${level}</span></td>
                <td>${escapeHtml(log.rule?.description || "")}</td>
                <td>${escapeHtml(log.agent?.name || "")} (${escapeHtml(log.data?.srcip || log.agent?.ip || "")})</td>
                <td>
                    <button class="interactive-chip" onclick="window.openLogModalByIndex(${idx})">🔍 JSON</button>
                    <button class="interactive-chip chip-low" onclick="window.askAboutLogByIndex(${idx})">💬 Hỏi AI</button>
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
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    query: query,
                    scope_filter: { type: filterType, value: filterVal }
                })
            });

            const data = await res.json();
            const inv = data.investigation;
            updateChatBot(loadingId, inv.layer_2_llm_reasoning, inv.reasoning_steps);
        } catch (err) {
            updateChatBot(loadingId, "Lỗi kết nối Scoped AI Engine.");
        }
    }

    function appendChatUser(msg) {
        const div = document.createElement("div");
        div.className = "chat-bubble user";
        div.innerHTML = `<i class="fa-solid fa-user avatar"></i><div class="bubble-content"><strong>Analyst:</strong><p>${escapeHtml(msg)}</p></div>`;
        chatStream.appendChild(div);
        chatStream.scrollTop = chatStream.scrollHeight;
    }

    function appendChatBot(msg) {
        const id = "bot_" + Date.now();
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
        if (div) {
            const content = div.querySelector(".msg-text");
            let stepperHtml = "";
            if (steps && steps.length > 0) {
                stepperHtml = '<div class="reasoning-stepper">';
                steps.forEach(s => {
                    stepperHtml += `<div class="step-item completed"><i class="fa-solid fa-circle-check step-icon"></i> <strong>Step ${s.step}: ${s.title}</strong> — ${s.detail}</div>`;
                });
                stepperHtml += '</div>';
            }

            let parsedHtml = window.marked ? marked.parse(markdownText) : markdownText.replace(/\n/g, "<br>");
            content.innerHTML = stepperHtml + parsedHtml;
            chatStream.scrollTop = chatStream.scrollHeight;
        }
    }

    function escapeHtml(text) {
        return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    }

    presetChips.forEach(chip => {
        chip.addEventListener("click", () => {
            const query = chip.getAttribute("data-query");
            if (query) {
                sendScopedInvestigate(query);
            }
        });
    });

    chatForm.addEventListener("submit", (e) => {
        e.preventDefault();
        const query = chatInput.value.trim();
        if (!query) return;
        chatInput.value = "";
        sendScopedInvestigate(query);
    });

    fetchFilteredLogs();
});
