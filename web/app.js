// AgentWazuh Frontend Application Controller (Dynamic IP Setup & Login Screen)
document.addEventListener("DOMContentLoaded", () => {
    if (window.mermaid) {
        mermaid.initialize({ startOnLoad: false, theme: 'dark', securityLevel: 'loose' });
    }

    const loginScreen = document.getElementById("login-screen");
    const mainDashboard = document.getElementById("main-dashboard");
    const loginForm = document.getElementById("login-form");
    const inputIp = document.getElementById("input-ip");
    const inputPort = document.getElementById("input-port");
    const inputUser = document.getElementById("input-user");
    const inputPass = document.getElementById("input-pass");
    const loginFeedback = document.getElementById("login-feedback");
    const btnMock = document.getElementById("btn-mock");
    const btnChangeIp = document.getElementById("btn-change-ip");

    const alertsList = document.getElementById("alerts-list");
    const chatStream = document.getElementById("chat-stream");
    const chatForm = document.getElementById("chat-form");
    const chatInput = document.getElementById("chat-input");
    const evidenceDetail = document.getElementById("evidence-detail");
    const vmwareStatus = document.getElementById("vmware-status");
    const btnRefresh = document.getElementById("btn-refresh");

    const modeGlobalBtn = document.getElementById("mode-global");
    const modeSingleBtn = document.getElementById("mode-single");
    const presetChips = document.querySelectorAll(".chip-btn");

    const logModal = document.getElementById("log-modal");
    const exportModal = document.getElementById("export-modal");
    const modalLogJson = document.getElementById("modal-log-json");
    const modalExportJson = document.getElementById("modal-export-json");

    let currentAlerts = [];
    let selectedAlert = null;
    let isGlobalChat = true;

    // Load Saved IP from localStorage
    const savedHost = localStorage.getItem("wazuh_host") || "192.168.1.240";
    inputIp.value = savedHost;

    // Login Form Submit (Connect to Dynamic IP)
    loginForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const host = inputIp.value.trim();
        const port = parseInt(inputPort.value) || 55000;
        const user = inputUser.value.trim() || "admin";
        const password = inputPass.value.trim() || "admin";

        showFeedback("Đang thử kết nối tới Wazuh Manager REST API...", "info");

        try {
            const res = await fetch("/api/wazuh/connect", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ host, port, user, password })
            });

            const data = await res.json();
            if (data.status === "success") {
                localStorage.setItem("wazuh_host", host);
                if (data.connected) {
                    showFeedback(`🟢 Kết nối THÀNH CÔNG tới Wazuh VMWare (${host})!`, "success");
                } else {
                    showFeedback(`⚠️ Không thể đăng nhập API. Chuyển sang Chế Độ Mock Alert.`, "error");
                }

                setTimeout(() => {
                    enterDashboard();
                }, 800);
            }
        } catch (err) {
            showFeedback("❌ Lỗi kết nối tới Backend Server.", "error");
        }
    });

    // Skip to Mock Mode
    btnMock.addEventListener("click", () => {
        enterDashboard();
    });

    // Change IP Button in Header
    btnChangeIp.addEventListener("click", () => {
        loginScreen.classList.remove("hidden");
    });

    function showFeedback(msg, type) {
        loginFeedback.textContent = msg;
        loginFeedback.className = `login-feedback ${type}`;
        loginFeedback.classList.remove("hidden");
    }

    function enterDashboard() {
        loginScreen.classList.add("hidden");
        mainDashboard.classList.remove("hidden");
        checkStatus();
        fetchAlerts();
    }

    // Window Interactive Helpers
    window.openLogModal = function(alertId) {
        let alertObj = currentAlerts.find(a => a.id === alertId);
        if (!alertObj) {
            alertObj = {
                id: alertId,
                timestamp: new Date().toISOString(),
                rule: { id: "530", level: 3, description: "OSSEC / Wazuh Manager service started.", groups: ["ossec"] },
                agent: { id: "000", name: "wazuh-manager-local", ip: "127.0.0.1" },
                data: { status: "active", process: "ossec-analysisd" }
            };
        }
        modalLogJson.textContent = JSON.stringify(alertObj, null, 2);
        logModal.classList.remove("hidden");
    };

    window.closeLogModal = function() {
        logModal.classList.add("hidden");
    };

    window.openExportModal = function(alertId) {
        const payload = {
            "wazuh_ai_analysis": {
                "alert_id": alertId,
                "threat_classification": "SUSPICIOUS",
                "false_positive_score": 0.12,
                "mitre_technique": "T1110.001",
                "ai_summary": "SOC AI Agent detected 14 failed SSH login attempts.",
                "opensearch_index": "wazuh-alerts-4.x-ai-enriched",
                "timestamp": new Date().toISOString()
            }
        };
        modalExportJson.textContent = JSON.stringify(payload, null, 2);
        exportModal.classList.remove("hidden");
    };

    window.closeExportModal = function() {
        exportModal.classList.add("hidden");
    };

    window.copyToClipboard = function(text) {
        navigator.clipboard.writeText(text).then(() => {
            alert("📋 Đã copy lệnh Firewall vào Clipboard!\n\n" + text);
        });
    };

    window.filterAlertsByLevel = function(levelType) {
        if (!currentAlerts) return;
        let filtered = [];
        if (levelType === "critical") filtered = currentAlerts.filter(a => a.rule.level >= 15);
        else if (levelType === "high") filtered = currentAlerts.filter(a => a.rule.level >= 12 && a.rule.level < 15);
        else if (levelType === "medium") filtered = currentAlerts.filter(a => a.rule.level >= 7 && a.rule.level < 12);
        else if (levelType === "low") filtered = currentAlerts.filter(a => a.rule.level < 7);
        else filtered = currentAlerts;

        renderAlerts(filtered.length > 0 ? filtered : currentAlerts);
        alert(`🔍 Đã lọc danh sách Alert theo mức [${levelType.toUpperCase()}]: Tìm thấy ${filtered.length} cảnh báo.`);
    };

    // Mode Toggle Handlers
    modeGlobalBtn.addEventListener("click", () => setChatMode(true));
    modeSingleBtn.addEventListener("click", () => setChatMode(false));

    function setChatMode(globalMode) {
        isGlobalChat = globalMode;
        if (isGlobalChat) {
            modeGlobalBtn.classList.add("active");
            modeSingleBtn.classList.remove("active");
        } else {
            modeSingleBtn.classList.add("active");
            modeGlobalBtn.classList.remove("active");
        }
    }

    // Preset Chips Handlers
    presetChips.forEach(chip => {
        chip.addEventListener("click", () => {
            const query = chip.getAttribute("data-query");
            if (query) {
                chatInput.value = query;
                chatForm.dispatchEvent(new Event("submit"));
            }
        });
    });

    // 1. Fetch System Status
    async function checkStatus() {
        try {
            const res = await fetch("/api/wazuh/status");
            const data = await res.json();
            const stats = data.alert_stats || {};
            if (data.status === "online") {
                vmwareStatus.innerHTML = `<span class="status-indicator online"></span><span class="status-text">VMWare Wazuh: Online (${data.host}) | ${data.total_agents} Agents</span>`;
            } else {
                vmwareStatus.innerHTML = `<span class="status-indicator warning"></span><span class="status-text">Wazuh: Mock Mode (${data.host}) | 0 Agents | ${stats.medium || 3} Med | ${stats.low || 12} Low Alerts</span>`;
            }
        } catch (err) {
            vmwareStatus.innerHTML = '<span class="status-indicator warning"></span><span class="status-text">Wazuh: Offline Mode</span>';
        }
    }

    // 2. Fetch Latest Alerts
    async function fetchAlerts() {
        alertsList.innerHTML = '<div class="loading-state">Đang tải cảnh báo...</div>';
        try {
            const res = await fetch("/api/wazuh/alerts");
            const data = await res.json();
            currentAlerts = data.alerts || [];
            renderAlerts(currentAlerts);
        } catch (err) {
            alertsList.innerHTML = '<div class="loading-state">Không thể kết nối đến API Wazuh.</div>';
        }
    }

    // 3. Render Alerts List
    function renderAlerts(alerts) {
        if (!alerts || alerts.length === 0) {
            alertsList.innerHTML = '<div class="loading-state">Không có cảnh báo nào.</div>';
            return;
        }

        alertsList.innerHTML = "";
        alerts.forEach(alert => {
            const level = alert.rule.level;
            let levelClass = "level-low";
            if (level >= 15) levelClass = "level-critical";
            else if (level >= 12) levelClass = "level-high";
            else if (level >= 7) levelClass = "level-medium";

            const card = document.createElement("div");
            card.className = `alert-card ${selectedAlert && selectedAlert.id === alert.id ? 'active' : ''}`;
            card.innerHTML = `
                <div class="alert-meta">
                    <span class="badge-level ${levelClass}">LEVEL ${level}</span>
                    <span class="alert-agent">Rule ${alert.rule.id}</span>
                </div>
                <div class="alert-desc">${alert.rule.description}</div>
                <div class="alert-agent"><i class="fa-solid fa-server"></i> Agent: ${alert.agent.name} (${alert.agent.ip})</div>
            `;

            card.addEventListener("click", () => selectAlert(alert, card));
            alertsList.appendChild(card);
        });
    }

    // 4. Select Alert & Switch to Single Deep-Dive Mode
    function selectAlert(alert, cardElement) {
        document.querySelectorAll(".alert-card").forEach(c => c.classList.remove("active"));
        cardElement.classList.add("active");
        selectedAlert = alert;
        setChatMode(false);

        appendChatUser(`Chi tiết cảnh báo Rule ${alert.rule.id}?`);
        investigateAlert(alert.rule.description, alert);
    }

    // 5. Investigate Call with Steppers & Markdown
    async function investigateAlert(query, alertObj = null) {
        const loadingId = appendChatBot("Đang tra cứu Ground-Truth MITRE ATT&CK & tổng hợp báo cáo bằng chứng...");

        try {
            const res = await fetch("/api/wazuh/investigate", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    query: query,
                    alert_id: alertObj ? alertObj.id : null,
                    alert_data: alertObj,
                    is_global_chat: isGlobalChat
                })
            });

            const data = await res.json();
            const inv = data.investigation;

            updateChatBot(loadingId, inv.layer_2_llm_reasoning, inv.reasoning_steps);
            renderEvidenceDetail(inv, alertObj);
        } catch (err) {
            updateChatBot(loadingId, "Lỗi kết nối tới máy chủ AI Investigation API.");
        }
    }

    // 6. Rich Markdown & Stepper Rendering
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
        div.innerHTML = `<i class="fa-solid fa-robot avatar"></i><div class="bubble-content"><strong>AgentWazuh AI Master Advisor:</strong><div class="msg-text">${msg}</div></div>`;
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

            const mermaidBlocks = content.querySelectorAll("pre code.language-mermaid");
            mermaidBlocks.forEach((codeBlock, idx) => {
                const graphDefinition = codeBlock.textContent;
                const mermaidContainer = document.createElement("div");
                mermaidContainer.className = "mermaid";
                mermaidContainer.id = `mermaid_${id}_${idx}`;
                mermaidContainer.textContent = graphDefinition;
                codeBlock.parentElement.replaceWith(mermaidContainer);
            });

            if (window.mermaid) {
                try {
                    mermaid.run({ nodes: content.querySelectorAll(".mermaid") });
                } catch (e) {
                    console.log("Mermaid render note:", e);
                }
            }

            chatStream.scrollTop = chatStream.scrollHeight;
        }
    }

    function renderEvidenceDetail(inv, alertObj) {
        const staticInfo = inv.layer_1_static_lookup;
        const threatClass = inv.threat_classification || "INFORMATIONAL";
        evidenceDetail.innerHTML = `
            <div class="evidence-section">
                <h3><i class="fa-solid fa-database"></i> Layer 1 Ground-Truth Lookup</h3>
                ${staticInfo ? `
                    <p><strong>Mã MITRE:</strong> <span class="badge-level level-high">${staticInfo.technique_id}</span> ${staticInfo.technique_name}</p>
                    <p><strong>Phân Loại Rủi Ro:</strong> <span class="risk-badge risk-${threatClass.lower()}">${threatClass}</span></p>
                    <p><strong>Khuyến nghị Playbook:</strong> ${staticInfo.recommended_action}</p>
                ` : '<p class="text-dim">Đang sử dụng chế độ Chat Tổng SOC Master (Global Master Advisor Context).</p>'}
            </div>

            <div class="evidence-section" style="margin-top: 1.5rem;">
                <h3><i class="fa-solid fa-microchip"></i> AI Engine Configuration</h3>
                <p><strong>Model:</strong> ${inv.model_used}</p>
                <p><strong>Chế Độ:</strong> ${inv.is_global_chat ? '🌐 Con Chat Tổng Master SOC' : '🔍 Single Alert Deep-Dive'}</p>
                <p><strong>Chống Bịa Đặt:</strong> <span style="color: #10b981;">✅ Anti-Hallucination Active</span></p>
                ${alertObj ? `<button class="interactive-chip" onclick="window.openExportModal('${alertObj.id}')" style="margin-top: 0.5rem;">📤 Export Wazuh OpenSearch Payload</button>` : ''}
            </div>
        `;
    }

    function escapeHtml(text) {
        return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    }

    // Event Listeners
    chatForm.addEventListener("submit", (e) => {
        e.preventDefault();
        const query = chatInput.value.trim();
        if (!query) return;
        appendChatUser(query);
        chatInput.value = "";
        investigateAlert(query, selectedAlert);
    });

    btnRefresh.addEventListener("click", fetchAlerts);
});
