// AgentWazuh Dashboard Controller (Version 11.1 - Google Gemini API Integration)
document.addEventListener("DOMContentLoaded", () => {
    if (window.mermaid) {
        mermaid.initialize({ startOnLoad: false, theme: 'dark', securityLevel: 'loose' });
    }

    const btnBackLogin = document.getElementById("btn-back-login");
    const btnOpenNetmap = document.getElementById("btn-open-netmap");
    const btnOpenSettings = document.getElementById("btn-open-settings");
    const alertsList = document.getElementById("alerts-list");
    const chatStream = document.getElementById("chat-stream");

    // Drawer Settings elements
    const settingsModal = document.getElementById("settings-modal");
    const navItems = document.querySelectorAll(".settings-sidebar .nav-item");
    const tabContents = document.querySelectorAll(".settings-tab-content");

    const settingTimeoutMin = document.getElementById("setting-timeout-min");
    const settingUITheme = document.getElementById("setting-ui-theme");
    const settingWazuhHost = document.getElementById("setting-wazuh-host");
    const settingWazuhPort = document.getElementById("setting-wazuh-port");
    const settingWazuhUser = document.getElementById("setting-wazuh-user");
    const settingPingInterval = document.getElementById("setting-ping-interval");
    const settingPingRetry = document.getElementById("setting-ping-retry");
    const settingKumaToken = document.getElementById("setting-kuma-token");
    const btnSaveAllSettings = document.getElementById("btn-save-all-settings");
    const btnTestWazuhConn = document.getElementById("btn-test-wazuh-conn");
    const statusWazuhIp = document.getElementById("status-wazuh-ip");

    // AI Engine Presets
    const tabBtnGemini = document.getElementById("tab-btn-gemini");
    const tabBtnOllama = document.getElementById("tab-btn-ollama");
    const tabBtnCloud = document.getElementById("tab-btn-cloud");

    const boxGeminiApi = document.getElementById("box-gemini-api");
    const boxOllamaEngine = document.getElementById("box-ollama-engine");
    const boxCloudApi = document.getElementById("box-cloud-api");

    const inputGeminiKey = document.getElementById("input-gemini-key");
    const selectGeminiModel = document.getElementById("select-gemini-model");

    const btnStartOllamaDrawer = document.getElementById("btn-start-ollama-drawer");
    const selectOllamaModelDrawer = document.getElementById("select-ollama-model-drawer");
    const inputCloudUrlDrawer = document.getElementById("input-cloud-url-drawer");
    const inputCloudKeyDrawer = document.getElementById("input-cloud-key-drawer");

    let currentAIMode = "gemini";

    if (btnOpenNetmap) {
        btnOpenNetmap.addEventListener("click", () => {
            window.location.href = "/network-map";
        });
    }

    if (btnOpenSettings) {
        btnOpenSettings.addEventListener("click", () => {
            loadSystemSettings();
            loadAIConfig();
            settingsModal.classList.remove("hidden");
        });
    }

    window.closeSettingsModal = function() {
        if (settingsModal) settingsModal.classList.add("hidden");
    };

    // Sidebar Tab Switching
    navItems.forEach(item => {
        item.addEventListener("click", () => {
            navItems.forEach(i => i.classList.remove("active"));
            tabContents.forEach(c => c.classList.add("hidden"));
            item.classList.add("active");
            const targetId = item.getAttribute("data-tab");
            const targetContent = document.getElementById(targetId);
            if (targetContent) targetContent.classList.remove("hidden");
        });
    });

    // AI Engine 3 Presets Switcher
    if (tabBtnGemini && tabBtnOllama && tabBtnCloud) {
        tabBtnGemini.addEventListener("click", () => {
            currentAIMode = "gemini";
            tabBtnGemini.classList.add("active");
            tabBtnOllama.classList.remove("active");
            tabBtnCloud.classList.remove("active");
            boxGeminiApi.classList.remove("hidden");
            boxOllamaEngine.classList.add("hidden");
            boxCloudApi.classList.add("hidden");
        });

        tabBtnOllama.addEventListener("click", () => {
            currentAIMode = "ollama";
            tabBtnOllama.classList.add("active");
            tabBtnGemini.classList.remove("active");
            tabBtnCloud.classList.remove("active");
            boxOllamaEngine.classList.remove("hidden");
            boxGeminiApi.classList.add("hidden");
            boxCloudApi.classList.add("hidden");
        });

        tabBtnCloud.addEventListener("click", () => {
            currentAIMode = "cloud_api";
            tabBtnCloud.classList.add("active");
            tabBtnGemini.classList.remove("active");
            tabBtnOllama.classList.remove("active");
            boxCloudApi.classList.remove("hidden");
            boxGeminiApi.classList.add("hidden");
            boxOllamaEngine.classList.add("hidden");
        });
    }

    if (btnStartOllamaDrawer) {
        btnStartOllamaDrawer.addEventListener("click", async () => {
            try {
                const res = await fetch("/api/ai/ollama/start", { method: "POST", credentials: "same-origin" });
                const data = await res.json();
                alert(data.message || "Đã kiểm tra Ollama daemon.");
            } catch (err) {
                alert("Không thể bật Ollama tự động. Vui lòng gõ 'ollama serve' trong terminal.");
            }
        });
    }

    if (btnTestWazuhConn) {
        btnTestWazuhConn.addEventListener("click", async () => {
            const host = settingWazuhHost.value.trim();
            const port = parseInt(settingWazuhPort.value) || 55000;
            const user = settingWazuhUser ? settingWazuhUser.value.trim() : "admin";
            try {
                const res = await fetch("/api/wazuh/connect", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ host, port, user }),
                    credentials: "same-origin"
                });
                const data = await res.json();
                if (data.connected) {
                    alert(`🟢 Kết nối Wazuh Manager (${host}:${port}) THÀNH CÔNG! Server status: ONLINE`);
                } else {
                    alert(`⚠️ Không thể kết nối Wazuh Manager (${host}:${port}). Trạng thái: OFFLINE / Mock Data Mode.`);
                }
            } catch (err) {
                alert("❌ Lỗi kiểm tra kết nối API.");
            }
        });
    }

    async function loadSystemSettings() {
        try {
            const res = await fetch("/api/settings", { credentials: "same-origin" });
            const json = await res.json();
            const s = json.settings || {};
            if (s.session_timeout_minutes) settingTimeoutMin.value = s.session_timeout_minutes;
            if (s.icmp_ping_interval_seconds) settingPingInterval.value = s.icmp_ping_interval_seconds;
            if (s.ping_retry_threshold) settingPingRetry.value = s.ping_retry_threshold;
            if (s.wazuh_host) {
                settingWazuhHost.value = s.wazuh_host;
                if (statusWazuhIp) statusWazuhIp.textContent = `Wazuh Server: ${s.wazuh_host}`;
            }
            if (s.wazuh_port) settingWazuhPort.value = s.wazuh_port;
            if (s.wazuh_user && settingWazuhUser) settingWazuhUser.value = s.wazuh_user;
            if (s.uptime_kuma_push_token && settingKumaToken) settingKumaToken.value = s.uptime_kuma_push_token;
            if (s.ui_theme && settingUITheme) settingUITheme.value = s.ui_theme;
        } catch (err) {
            console.error("Failed to load system settings:", err);
        }
    }

    async function loadAIConfig() {
        try {
            const res = await fetch("/api/ai/config", { credentials: "same-origin" });
            const config = await res.json();
            currentAIMode = config.mode || "gemini";
            if (currentAIMode === "gemini") {
                if (tabBtnGemini) tabBtnGemini.click();
            } else if (currentAIMode === "cloud_api") {
                if (tabBtnCloud) tabBtnCloud.click();
            } else {
                if (tabBtnOllama) tabBtnOllama.click();
            }

            if (config.gemini_model && selectGeminiModel) selectGeminiModel.value = config.gemini_model;
            if (config.cloud_api_key && inputGeminiKey) inputGeminiKey.value = config.cloud_api_key;
            if (config.ollama_model && selectOllamaModelDrawer) selectOllamaModelDrawer.value = config.ollama_model;
            if (config.cloud_api_url && inputCloudUrlDrawer) inputCloudUrlDrawer.value = config.cloud_api_url;
            if (config.cloud_api_key && inputCloudKeyDrawer) inputCloudKeyDrawer.value = config.cloud_api_key;
        } catch (err) {
            console.error("Failed to load AI config:", err);
        }
    }

    btnSaveAllSettings.addEventListener("click", async () => {
        const sysPayload = {
            session_timeout_minutes: parseInt(settingTimeoutMin.value) || 30,
            icmp_ping_interval_seconds: parseInt(settingPingInterval.value) || 15,
            ping_retry_threshold: parseInt(settingPingRetry.value) || 3,
            wazuh_host: settingWazuhHost.value.trim(),
            wazuh_port: parseInt(settingWazuhPort.value) || 55000,
            wazuh_user: settingWazuhUser ? settingWazuhUser.value.trim() : "admin",
            uptime_kuma_push_token: settingKumaToken ? settingKumaToken.value.trim() : "agentwazuh-push-secret-999",
            ui_theme: settingUITheme ? settingUITheme.value : "cyber_dark"
        };

        let selectedKey = "";
        if (currentAIMode === "gemini") {
            selectedKey = inputGeminiKey ? inputGeminiKey.value.trim() : "";
        } else if (currentAIMode === "cloud_api") {
            selectedKey = inputCloudKeyDrawer ? inputCloudKeyDrawer.value.trim() : "";
        }

        const aiPayload = {
            mode: currentAIMode,
            ollama_url: "http://localhost:11434/api/generate",
            ollama_model: selectOllamaModelDrawer ? selectOllamaModelDrawer.value : "qwen2.5:3b",
            gemini_model: selectGeminiModel ? selectGeminiModel.value : "gemini-1.5-flash",
            cloud_api_enabled: currentAIMode !== "ollama",
            cloud_api_url: inputCloudUrlDrawer ? inputCloudUrlDrawer.value.trim() : "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
            cloud_api_key: selectedKey,
            cloud_model: "gpt-4o-mini"
        };

        try {
            await fetch("/api/settings", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(sysPayload),
                credentials: "same-origin"
            });

            await fetch("/api/ai/config", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(aiPayload),
                credentials: "same-origin"
            });

            alert(`🟢 ĐÃ LƯU TOÀN BỘ CÀI ĐẶT HỆ THỐNG THÀNH CÔNG!\n- Wazuh Host: ${sysPayload.wazuh_host}\n- Chế độ AI Active: ${currentAIMode.toUpperCase()}`);
            if (statusWazuhIp) statusWazuhIp.textContent = `Wazuh Server: ${sysPayload.wazuh_host}`;
            window.closeSettingsModal();
        } catch (err) {
            alert("❌ Lỗi khi lưu cài đặt.");
        }
    });

    window.openDrilldown = function(type, value) {
        window.location.href = `/drilldown?type=${encodeURIComponent(type)}&value=${encodeURIComponent(value)}`;
    };

    const chatForm = document.getElementById("chat-form");
    const chatInput = document.getElementById("chat-input");
    const evidenceDetail = document.getElementById("evidence-detail");
    const presetChips = document.querySelectorAll(".chip-btn");

    if (btnBackLogin) {
        btnBackLogin.addEventListener("click", async () => {
            try {
                await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin" });
            } catch (e) {}
            window.location.href = "/login";
        });
    }

    async function fetchLiveAlerts() {
        try {
            const res = await fetch("/api/wazuh/alerts", { credentials: "same-origin" });
            if (res.status === 401) {
                window.location.href = "/login";
                return;
            }
            const data = await res.json();
            renderAlertsList(data.alerts || []);
        } catch (err) {
            alertsList.innerHTML = '<div class="loading-state">Không thể kết nối đến Wazuh API.</div>';
        }
    }

    function renderAlertsList(alerts) {
        alertsList.innerHTML = "";
        alerts.forEach(alert => {
            const card = document.createElement("div");
            const level = alert.rule.level;
            let levelClass = "level-low";
            if (level >= 15) levelClass = "level-critical";
            else if (level >= 12) levelClass = "level-high";
            else if (level >= 7) levelClass = "level-medium";

            card.className = `alert-card ${levelClass}`;
            card.innerHTML = `
                <div class="alert-header-row">
                    <span class="badge-level ${levelClass}">LEVEL ${level}</span>
                    <span class="alert-time">${alert.timestamp.substring(11, 19)}</span>
                </div>
                <div class="alert-title">Rule ${alert.rule.id}: ${alert.rule.description}</div>
                <div class="alert-meta">
                    <span><i class="fa-solid fa-server"></i> ${alert.agent.name}</span>
                    <span><i class="fa-solid fa-network-wired"></i> ${alert.data.srcip || alert.agent.ip}</span>
                </div>
            `;

            card.addEventListener("click", () => {
                document.querySelectorAll(".alert-card").forEach(c => c.classList.remove("selected"));
                card.classList.add("selected");
                investigateAlert(`Phân tích sự cố Alert ${alert.id} (${alert.rule.description})`, alert);
            });

            alertsList.appendChild(card);
        });
    }

    async function investigateAlert(query, alertObj = null) {
        const progressBarHtml = `
            <div class="ai-loading-container" style="margin-bottom: 15px; padding: 15px; background: rgba(0,0,0,0.2); border-radius: 8px; border: 1px solid rgba(16, 185, 129, 0.2);">
                <div style="display: flex; justify-content: space-between; margin-bottom: 8px; font-size: 0.9em; color: #10b981; font-weight: 600;">
                    <span id="loading-text-phase"><i class="fa-solid fa-microchip"></i> Đang khởi tạo AI Model Engine...</span>
                    <span id="loading-percent">0%</span>
                </div>
                <div class="progress-bar-bg" style="width: 100%; height: 8px; background: #27272a; border-radius: 4px; overflow: hidden; box-shadow: inset 0 1px 3px rgba(0,0,0,0.5);">
                    <div id="progress-bar-fill" style="width: 0%; height: 100%; background: linear-gradient(90deg, #3b82f6, #10b981); transition: width 0.3s ease; box-shadow: 0 0 10px rgba(16, 185, 129, 0.5);"></div>
                </div>
            </div>
        `;
        const loadingId = appendChatBot(progressBarHtml);
        
        const progressBarFill = document.getElementById("progress-bar-fill");
        const loadingPercent = document.getElementById("loading-percent");
        const loadingTextPhase = document.getElementById("loading-text-phase");
        
        let progress = 0;
        const phases = [
            "<i class='fa-solid fa-database'></i> Đang trích xuất log từ Wazuh...",
            "<i class='fa-solid fa-sitemap'></i> Đang tra cứu Ground-Truth MITRE...",
            "<i class='fa-solid fa-shield-halved'></i> Đang phân loại Threat Classification...",
            "<i class='fa-solid fa-brain'></i> Đang nạp ngữ cảnh cho AI Engine...",
            "<i class='fa-solid fa-laptop-code'></i> LLM đang suy luận giải pháp..."
        ];
        
        const progressInterval = setInterval(() => {
            if (progress < 95) {
                progress += Math.random() * 8 + 2; 
                if (progress > 95) progress = 95;
                if (progressBarFill && loadingPercent && loadingTextPhase) {
                    progressBarFill.style.width = progress + "%";
                    loadingPercent.textContent = Math.floor(progress) + "%";
                    
                    let phaseIndex = Math.floor((progress / 100) * phases.length);
                    if (phaseIndex >= phases.length) phaseIndex = phases.length - 1;
                    loadingTextPhase.innerHTML = phases[phaseIndex];
                }
            }
        }, 500);

        try {
            const res = await fetch("/api/wazuh/investigate", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    query: query,
                    alert_id: alertObj ? alertObj.id : null,
                    alert_data: alertObj,
                    is_global_chat: true
                }),
                credentials: "same-origin"
            });

            const data = await res.json();
            const inv = data.investigation;

            clearInterval(progressInterval);
            if (progressBarFill && loadingPercent && loadingTextPhase) {
                progressBarFill.style.width = "100%";
                loadingPercent.textContent = "100%";
                loadingTextPhase.innerHTML = "<i class='fa-solid fa-check-circle'></i> Hoàn tất phân tích!";
            }

            setTimeout(() => {
                updateChatBot(loadingId, inv.layer_2_llm_reasoning, inv.reasoning_steps);
                renderEvidenceDetail(inv, alertObj);
            }, 600);
            
        } catch (err) {
            clearInterval(progressInterval);
            updateChatBot(loadingId, "Lỗi kết nối tới máy chủ AI Investigation API.");
        }
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
            let parsedHtml = window.marked ? marked.parse(markdownText) : markdownText.replace(/\n/g, "<br>");
            content.innerHTML = parsedHtml;

            const mermaidBlocks = content.querySelectorAll("pre code.language-mermaid");
            mermaidBlocks.forEach((codeBlock, idx) => {
                const mermaidContent = codeBlock.textContent;
                const containerId = `mermaid_diag_${Date.now()}_${idx}`;
                const mermaidDiv = document.createElement("div");
                mermaidDiv.className = "mermaid-container";
                mermaidDiv.id = containerId;
                codeBlock.parentNode.replaceWith(mermaidDiv);

                try {
                    mermaid.render(containerId + "_svg", mermaidContent).then(renderResult => {
                        mermaidDiv.innerHTML = renderResult.svg;
                    });
                } catch (e) {
                    mermaidDiv.innerHTML = `<pre class="mermaid">${mermaidContent}</pre>`;
                }
            });

            chatStream.scrollTop = chatStream.scrollHeight;
        }
    }

    function renderEvidenceDetail(inv, alertObj) {
        const steps = inv.reasoning_steps || [];
        let stepperHtml = '<div class="reasoning-stepper" style="margin-bottom: 1.2rem;">';
        steps.forEach(s => {
            stepperHtml += `<div class="step-item completed"><i class="fa-solid fa-circle-check step-icon"></i> <strong>Step ${s.step}: ${s.title}</strong><br><span style="font-size:0.8rem; color:#94a3b8;">${s.detail}</span></div>`;
        });
        stepperHtml += '</div>';

        const tClass = inv.threat_classification || "INFORMATIONAL";
        let riskBadge = `<span class="risk-badge risk-low">${tClass}</span>`;
        if (tClass === "TRUE_THREAT") riskBadge = `<span class="risk-badge risk-critical">${tClass}</span>`;
        else if (tClass === "SUSPICIOUS") riskBadge = `<span class="risk-badge risk-high">${tClass}</span>`;

        evidenceDetail.innerHTML = `
            ${stepperHtml}
            <div class="evidence-section">
                <h3><i class="fa-solid fa-shield-cat"></i> Threat Assessment</h3>
                <p><strong>Classification:</strong> ${riskBadge}</p>
                <p><strong>AI Engine Used:</strong> <code>${inv.model_used || "Qwen2.5-3B Local"}</code></p>
                <p><strong>MITRE Technique:</strong> <code>${inv.layer_1_static_lookup?.technique_id || "T1110"}</code></p>
            </div>
        `;
    }

    presetChips.forEach(chip => {
        chip.addEventListener("click", () => {
            const query = chip.getAttribute("data-query");
            if (query) investigateAlert(query);
        });
    });

    chatForm.addEventListener("submit", (e) => {
        e.preventDefault();
        const query = chatInput.value.trim();
        if (!query) return;
        chatInput.value = "";
        investigateAlert(query);
    });

    fetchLiveAlerts();
    loadSystemSettings();
});
