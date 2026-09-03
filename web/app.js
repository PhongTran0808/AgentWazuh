// AgentWazuh Dashboard Controller (Version 16.0 Strict API-Driven & User Chat Render Release)
document.addEventListener("DOMContentLoaded", () => {
    if (window.mermaid) {
        mermaid.initialize({ startOnLoad: false, theme: 'dark', securityLevel: 'loose' });
    }

    let globalState = {
        network_topology: [],
        device_nodes: [],
        ip_addresses: [],
        cached_rules: [],
        active_forms: []
    };

    let current_session_id = null;

    async function pollWazuhStatus() {
        try {
            const res = await fetch("/api/wazuh/status", { credentials: "same-origin" });
            const data = await res.json();
            
            // support both dashboard (status-wazuh-ip) and other pages (status-host)
            const statusIpEl = document.getElementById("status-wazuh-ip") || document.getElementById("status-host");
            const indicatorEl = document.querySelector(".header-status .status-indicator");
            
            if (statusIpEl && indicatorEl) {
                statusIpEl.textContent = `Wazuh Server: ${data.wazuh_host || "N/A"}`;
                if (data.status === "online") {
                    indicatorEl.className = "status-indicator online";
                } else if (data.status === "offline") {
                    indicatorEl.className = "status-indicator offline";
                } else {
                    indicatorEl.className = "status-indicator warning";
                }
            }
        } catch (err) {
            console.error("Failed to poll Wazuh status:", err);
            const indicatorEl = document.querySelector(".header-status .status-indicator");
            if (indicatorEl) indicatorEl.className = "status-indicator offline";
        }
    }
    
    // Poll every 3 seconds
    setInterval(pollWazuhStatus, 3000);
    pollWazuhStatus();

    async function loadChatHistoryList() {
        try {
            const res = await fetch("/api/chat/history", { credentials: "same-origin" });
            const data = await res.json();
            const tree = document.getElementById("history-list");
            if (!tree) return;
            tree.innerHTML = "";
            
            if (!data.sessions || data.sessions.length === 0) {
                tree.innerHTML = '<div style="padding: 1rem; font-size: 0.8rem; color: #64748b;">Chưa có lịch sử.</div>';
                return;
            }

            const groups = {};
            data.sessions.forEach(s => {
                const proj = s.project_name || "Default Project";
                if (!groups[proj]) groups[proj] = [];
                groups[proj].push(s);
            });

            for (const proj in groups) {
                const groupDiv = document.createElement("div");
                groupDiv.className = "history-group";
                
                const groupHeader = document.createElement("div");
                groupHeader.className = "history-group-header";
                groupHeader.style.cssText = "display:flex; justify-content:space-between; align-items:center; padding:0.4rem 0.6rem; font-weight:700; color:#38bdf8; font-size:0.8rem; border-bottom:1px solid rgba(255,255,255,0.05);";
                groupHeader.innerHTML = `
                    <span style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap;"><i class="fa-regular fa-folder-open"></i> ${escapeHtml(proj)}</span>
                    <button class="btn-history-action" style="background:transparent; border:none; color:#94a3b8; cursor:pointer; font-size:0.75rem; padding:2px 4px;" title="Đổi Tên Dự Án này" onclick="event.stopPropagation(); window.promptRenameProject('${escapeHtml(proj)}')">
                        <i class="fa-solid fa-pen-to-square"></i>
                    </button>
                `;
                groupDiv.appendChild(groupHeader);

                const listDiv = document.createElement("div");
                groups[proj].forEach(s => {
                    const item = document.createElement("div");
                    item.className = "history-item";
                    if (s.id === current_session_id) item.classList.add("active");
                    item.style.cssText = "display:flex; justify-content:space-between; align-items:center; padding:0.4rem 0.6rem; cursor:pointer; border-radius:4px; font-size:0.8rem;";
                    
                    const titleSpan = document.createElement("span");
                    titleSpan.style.cssText = "flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;";
                    titleSpan.innerHTML = `<i class="fa-solid fa-message"></i> ${escapeHtml(s.title)}`;
                    titleSpan.onclick = () => loadChatSession(s.id);
                    item.appendChild(titleSpan);

                    const actionsDiv = document.createElement("div");
                    actionsDiv.style.cssText = "display:flex; gap:4px; opacity:0.7;";
                    actionsDiv.innerHTML = `
                        <button class="btn-history-action" style="background:transparent; border:none; color:#cbd5e1; cursor:pointer; font-size:0.72rem; padding:2px;" title="Đổi Tên Hội Thoại" onclick="event.stopPropagation(); window.promptRenameSession('${s.id}', '${escapeHtml(s.title)}', '${escapeHtml(proj)}')">
                            <i class="fa-solid fa-pen"></i>
                        </button>
                        <button class="btn-history-action" style="background:transparent; border:none; color:#f87171; cursor:pointer; font-size:0.72rem; padding:2px;" title="Xóa Hội Thoại" onclick="event.stopPropagation(); window.promptDeleteSession('${s.id}')">
                            <i class="fa-solid fa-trash-can"></i>
                        </button>
                    `;
                    item.appendChild(actionsDiv);

                    listDiv.appendChild(item);
                });
                groupDiv.appendChild(listDiv);
                tree.appendChild(groupDiv);
            }
        } catch (e) {
            console.error("Error loading chat history:", e);
        }
    }

    window.promptRenameProject = async function(oldProjectName) {
        const newProjectName = prompt(`✏️ Nhập TÊN DỰ ÁN MỚI cho nhóm "${oldProjectName}":`, oldProjectName);
        if (!newProjectName || newProjectName.trim() === "" || newProjectName.trim() === oldProjectName) return;

        try {
            const res = await fetch("/api/chat/project/rename", {
                method: "PUT",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ old_project_name: oldProjectName, new_project_name: newProjectName.trim() }),
                credentials: "same-origin"
            });
            const data = await res.json();
            if (res.ok) {
                await loadChatHistoryList();
            } else {
                alert(data.detail || "Lỗi đổi tên dự án.");
            }
        } catch (e) {
            alert(`Lỗi đổi tên dự án: ${e}`);
        }
    };

    window.promptRenameSession = async function(sessionId, currentTitle, currentProject) {
        const newTitle = prompt(`✏️ ĐỔI TÊN HỘI THOẠI:`, currentTitle);
        if (newTitle === null) return;
        
        const newProject = prompt(`📁 THUỘC DỰ ÁN (Project):`, currentProject);
        if (newProject === null) return;

        try {
            const res = await fetch(`/api/chat/history/${sessionId}/rename`, {
                method: "PUT",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ title: newTitle.trim() || currentTitle, project_name: newProject.trim() || currentProject }),
                credentials: "same-origin"
            });
            if (res.ok) {
                await loadChatHistoryList();
            }
        } catch (e) {
            alert(`Lỗi đổi tên hội thoại: ${e}`);
        }
    };

    window.promptDeleteSession = async function(sessionId) {
        if (!confirm("🗑️ Bạn có chắc chắn muốn xóa cuộc hội thoại này?")) return;
        try {
            const res = await fetch(`/api/chat/history/${sessionId}`, {
                method: "DELETE",
                credentials: "same-origin"
            });
            if (res.ok) {
                if (current_session_id === sessionId) {
                    current_session_id = null;
                    const chatStream = document.getElementById("chat-stream");
                    if (chatStream) chatStream.innerHTML = "";
                }
                await loadChatHistoryList();
            }
        } catch (e) {
            alert(`Lỗi xóa hội thoại: ${e}`);
        }
    };

    async function createNewChat() {
        try {
            const res = await fetch("/api/chat/history", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ title: "New Conversation", project_name: "Default Project" }),
                credentials: "same-origin"
            });
            const data = await res.json();
            const chatStream = document.getElementById("chat-stream");
            if (chatStream) chatStream.innerHTML = "";
            if (data.session && data.session.id) {
                current_session_id = data.session.id;
            }
            await loadChatHistoryList();
        } catch (e) {
            console.error("Error creating chat:", e);
        }
    }

    async function loadChatSession(id) {
        try {
            const res = await fetch(`/api/chat/history/${id}`, { credentials: "same-origin" });
            const data = await res.json();
            if (data.session && data.session.id) {
                current_session_id = data.session.id;
                const chatStream = document.getElementById("chat-stream");
                if (chatStream) {
                    chatStream.innerHTML = "";
                    (data.session.messages || []).forEach(msg => {
                        if (msg.role === "user") {
                            const div = document.createElement("div");
                            div.className = "chat-bubble user";
                            div.innerHTML = `<i class="fa-solid fa-user avatar"></i><div class="bubble-content"><strong>Analyst:</strong><div class="msg-text">${escapeHtml(msg.content)}</div></div>`;
                            chatStream.appendChild(div);
                        } else {
                            const div = document.createElement("div");
                            div.className = "chat-bubble system";
                            let cleanContent = (msg.content || "")
                                .replace(/```(?:json:form|json)?\s*\{\s*"type"\s*:\s*"CONFIG_FORM"[\s\S]*?\}\s*```/g, "")
                                .replace(/\{\s*"type"\s*:\s*"CONFIG_FORM"[\s\S]*?\}/g, "")
                                .trim();
                            let parsedHtml = window.marked ? marked.parse(cleanContent || msg.content) : (cleanContent || msg.content).replace(/\n/g, "<br>");
                            div.innerHTML = `<i class="fa-solid fa-robot avatar"></i><div class="bubble-content"><strong>AgentWazuh AI Master Advisor:</strong><div class="msg-text">${parsedHtml}</div></div>`;
                            chatStream.appendChild(div);
                        }
                    });
                    chatStream.scrollTop = chatStream.scrollHeight;
                }
            }
            await loadChatHistoryList(); // to update active item
        } catch (e) {
            console.error("Error loading chat session:", e);
        }
    }

    async function appendMessageToSession(role, content) {
        if (!current_session_id) {
            await createNewChat();
        }
        try {
            await fetch(`/api/chat/history/${current_session_id}/message`, {
                method: "PUT",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ role, content, timestamp: new Date().toISOString() }),
                credentials: "same-origin"
            });
            await loadChatHistoryList();
        } catch (e) {
            console.error("Error appending message:", e);
        }
    }

    function resetGlobalState() {
        globalState = {
            network_topology: [],
            device_nodes: [],
            ip_addresses: [],
            cached_rules: [],
            active_forms: []
        };
    }

    let currentViewMode = "single"; // "single" or "group"

    function escapeHtml(str) {
        return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
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
    const statusWazuhIp = document.getElementById("status-wazuh-ip");

    // AI Engine 2-Step Selector Elements
    const engineModeCloud = document.getElementById("engine-mode-cloud");
    const engineModeOllama = document.getElementById("engine-mode-ollama");

    const panelCloudApi = document.getElementById("panel-cloud-api");
    const panelOllamaApi = document.getElementById("panel-ollama-api");

    const chkGemini = document.getElementById("provider-chk-gemini");
    const chkOpenAI = document.getElementById("provider-chk-openai");
    const chkAnthropic = document.getElementById("provider-chk-anthropic");

    const subBoxGemini = document.getElementById("sub-box-gemini");
    const subBoxOpenAI = document.getElementById("sub-box-openai");
    const subBoxAnthropic = document.getElementById("sub-box-anthropic");

    const inputGeminiKey = document.getElementById("input-gemini-key");
    const selectGeminiModel = document.getElementById("select-gemini-model");

    const inputOpenAIKey = document.getElementById("input-openai-key");
    const selectOpenAIModel = document.getElementById("select-openai-model");

    const inputAnthropicKey = document.getElementById("input-anthropic-key");
    const selectAnthropicModel = document.getElementById("select-anthropic-model");

    const ollamaStatusBadge = document.getElementById("ollama-status-badge");
    const btnRequestStartOllama = document.getElementById("btn-request-start-ollama");
    const ollamaConfirmModal = document.getElementById("ollama-confirm-modal");
    const btnConfirmStartOllama = document.getElementById("btn-confirm-start-ollama");
    const selectPiModel = document.getElementById("select-pi-model");
    const selectOllamaModelDrawer = document.getElementById("select-ollama-model-drawer");

    let currentAIMode = "pi_dev";

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

    const btnViewModeSingle = document.getElementById("view-mode-single");
    const btnViewModeGroup = document.getElementById("view-mode-group");
    
    if (btnViewModeSingle && btnViewModeGroup) {
        btnViewModeSingle.addEventListener("click", () => {
            currentViewMode = "single";
            btnViewModeSingle.classList.add("active");
            btnViewModeGroup.classList.remove("active");
            fetchLiveAlerts();
        });
        
        btnViewModeGroup.addEventListener("click", () => {
            currentViewMode = "group";
            btnViewModeGroup.classList.add("active");
            btnViewModeSingle.classList.remove("active");
            fetchLiveAlerts();
        });
    }

    const btnOpenImport = document.getElementById("btn-open-import");
    const importModal = document.getElementById("import-modal");
    const btnSubmitImport = document.getElementById("btn-submit-import");
    const importJsonText = document.getElementById("import-json-text");
    const importStatusMsg = document.getElementById("import-status-msg");

    if (btnOpenImport && importModal) {
        btnOpenImport.addEventListener("click", () => {
            if (importStatusMsg) importStatusMsg.style.display = "none";
            if (importJsonText) importJsonText.value = "";
            importModal.classList.remove("hidden");
        });
    }

    if (btnSubmitImport && importJsonText) {
        btnSubmitImport.addEventListener("click", async () => {
            const rawJson = importJsonText.value.trim();
            if (!rawJson) {
                if (importStatusMsg) {
                    importStatusMsg.style.display = "block";
                    importStatusMsg.style.color = "#ef4444";
                    importStatusMsg.innerText = "Vui lòng nhập chuỗi JSON Alert!";
                }
                return;
            }

            btnSubmitImport.disabled = true;
            btnSubmitImport.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Đang nạp dữ liệu...';

            try {
                const res = await fetch("/api/wazuh/alerts/import", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ raw_json: rawJson }),
                    credentials: "same-origin"
                });

                const data = await res.json();
                if (res.status === 200 && data.status === "success") {
                    if (importStatusMsg) {
                        importStatusMsg.style.display = "block";
                        importStatusMsg.style.color = "#10b981";
                        importStatusMsg.innerText = data.message;
                    }
                    setTimeout(() => {
                        importModal.classList.add("hidden");
                        fetchLiveAlerts();
                        fetchWazuhStatus();
                    }, 1200);
                } else {
                    if (importStatusMsg) {
                        importStatusMsg.style.display = "block";
                        importStatusMsg.style.color = "#ef4444";
                        importStatusMsg.innerText = data.detail || "Lỗi khi nhập dữ liệu JSON!";
                    }
                }
            } catch (err) {
                if (importStatusMsg) {
                    importStatusMsg.style.display = "block";
                    importStatusMsg.style.color = "#ef4444";
                    importStatusMsg.innerText = "Lỗi kết nối server: " + err.message;
                }
            } finally {
                btnSubmitImport.disabled = false;
                btnSubmitImport.innerHTML = '<i class="fa-solid fa-file-arrow-up"></i> Nạp Dữ Liệu Vào System';
            }
        });
    }

    // Sidebar Tab Switching Handler
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

    // PI.dev Agent Framework Initialization
    const engineModePi = document.getElementById("engine-mode-pi");
    const panelPiDev = document.getElementById("panel-pi-dev");
    const piStatusBadge = document.getElementById("pi-status-badge");

    if (engineModePi) {
        engineModePi.addEventListener("click", () => {
            currentAIMode = "pi_dev";
            engineModePi.classList.add("active");
            if (panelPiDev) panelPiDev.classList.remove("hidden");
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
            const ttlEl = document.getElementById("setting-device-ttl");
            if (ttlEl && s.device_cache_ttl_days) ttlEl.value = s.device_cache_ttl_days;
        } catch (err) {
            console.error("Failed to load system settings:", err);
        }
    }

    async function loadAIConfig() {
        try {
            const res = await fetch("/api/ai/config", { credentials: "same-origin" });
            const config = await res.json();
            currentAIMode = config.mode || "cloud_api";
            
            if (currentAIMode === "ollama") {
                if (engineModeOllama) engineModeOllama.click();
            } else {
                if (engineModeCloud) engineModeCloud.click();
            }

            const activeProvs = config.active_providers || ["gemini"];
            if (chkGemini) chkGemini.checked = activeProvs.includes("gemini");
            if (chkOpenAI) chkOpenAI.checked = activeProvs.includes("openai");
            if (chkAnthropic) chkAnthropic.checked = activeProvs.includes("anthropic");

            if (subBoxGemini) subBoxGemini.classList.toggle("hidden", !chkGemini.checked);
            if (subBoxOpenAI) subBoxOpenAI.classList.toggle("hidden", !chkOpenAI.checked);
            if (subBoxAnthropic) subBoxAnthropic.classList.toggle("hidden", !chkAnthropic.checked);

            if (config.gemini_model && selectGeminiModel) selectGeminiModel.value = config.gemini_model;
            if (config.openai_model && selectOpenAIModel) selectOpenAIModel.value = config.openai_model;
            if (config.anthropic_model && selectAnthropicModel) selectAnthropicModel.value = config.anthropic_model;
            if (config.pi_model && selectPiModel) selectPiModel.value = config.pi_model;

            const gKey = config.cloud_api_key || config.gemini_api_key || "";
            if (gKey && inputGeminiKey) inputGeminiKey.value = gKey;
            if (config.openai_api_key && inputOpenAIKey) inputOpenAIKey.value = config.openai_api_key;
            if (config.anthropic_api_key && inputAnthropicKey) inputAnthropicKey.value = config.anthropic_api_key;

            if (config.ollama_model && selectOllamaModelDrawer) selectOllamaModelDrawer.value = config.ollama_model;
        } catch (err) {
            console.error("Failed to load AI config:", err);
        }
    }

    btnSaveAllSettings?.addEventListener("click", async () => {
        const hostVal = (settingWazuhHost && settingWazuhHost.value.trim()) ? settingWazuhHost.value.trim() : "172.16.175.145";
        const sysPayload = {
            session_timeout_minutes: parseInt(settingTimeoutMin ? settingTimeoutMin.value : 30) || 30,
            icmp_ping_interval_seconds: parseInt(settingPingInterval ? settingPingInterval.value : 15) || 15,
            ping_retry_threshold: parseInt(settingPingRetry ? settingPingRetry.value : 3) || 3,
            wazuh_host: hostVal,
            wazuh_port: parseInt(settingWazuhPort ? settingWazuhPort.value : 55000) || 55000,
            wazuh_user: (settingWazuhUser && settingWazuhUser.value.trim()) ? settingWazuhUser.value.trim() : "agentwazuh",
            uptime_kuma_push_token: (settingKumaToken && settingKumaToken.value.trim()) ? settingKumaToken.value.trim() : "agentwazuh-push-secret-999",
            device_cache_ttl_days: parseInt((document.getElementById("setting-device-ttl") || {}).value) || 7,
            ui_theme: settingUITheme ? settingUITheme.value : "cyber_dark"
        };

        const activeProvs = [];
        if (chkGemini && chkGemini.checked) activeProvs.push("gemini");
        if (chkOpenAI && chkOpenAI.checked) activeProvs.push("openai");
        if (chkAnthropic && chkAnthropic.checked) activeProvs.push("anthropic");

        if (currentAIMode === "cloud_api" && activeProvs.length === 0) {
            activeProvs.push("gemini");
        }

        const geminiKeyVal = inputGeminiKey ? inputGeminiKey.value.trim() : "";
        const openaiKeyVal = inputOpenAIKey ? inputOpenAIKey.value.trim() : "";
        const anthropicKeyVal = inputAnthropicKey ? inputAnthropicKey.value.trim() : "";
        const piModelVal = selectPiModel ? selectPiModel.value : "openrouter/anthropic/claude-3-5-haiku";

        const aiPayload = {
            mode: currentAIMode || "pi_dev",
            pi_model: piModelVal,
            active_providers: activeProvs,
            gemini_model: selectGeminiModel ? selectGeminiModel.value : "gemini-2.5-flash",
            openai_model: selectOpenAIModel ? selectOpenAIModel.value : "gpt-4o-mini",
            anthropic_model: selectAnthropicModel ? selectAnthropicModel.value : "claude-3-5-sonnet",
            cloud_api_key: geminiKeyVal,
            gemini_api_key: geminiKeyVal,
            openai_api_key: openaiKeyVal,
            anthropic_api_key: anthropicKeyVal,
            ollama_url: "http://localhost:11434/api/generate",
            ollama_model: selectOllamaModelDrawer ? selectOllamaModelDrawer.value : "qwen2.5:3b",
            multi_api_enabled: activeProvs.length > 1
        };

        try {
            const resSys = await fetch("/api/settings", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(sysPayload),
                credentials: "same-origin"
            });

            if (!resSys.ok) {
                const sysErr = await resSys.json();
                const errDetail = typeof sysErr.detail === "string" ? sysErr.detail : JSON.stringify(sysErr.detail || sysErr);
                alert(`❌ Lỗi lưu Cài đặt Hệ thống: ${errDetail}`);
                return;
            }

            const resAi = await fetch("/api/ai/config", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(aiPayload),
                credentials: "same-origin"
            });

            if (!resAi.ok) {
                const aiErr = await resAi.json();
                const errDetail = typeof aiErr.detail === "string" ? aiErr.detail : JSON.stringify(aiErr.detail || aiErr);
                alert(`❌ Lỗi lưu Cài đặt AI: ${errDetail}`);
                return;
            }

            alert(`🟢 ĐÃ LƯU TOÀN BỘ CÀI ĐẶT HỆ THỐNG THÀNH CÔNG!\n- Session Timeout: ${sysPayload.session_timeout_minutes} phút\n- Wazuh Host: ${sysPayload.wazuh_host}\n- Mode AI: ${currentAIMode.toUpperCase()}`);
            if (statusWazuhIp) statusWazuhIp.textContent = `Wazuh Server: ${sysPayload.wazuh_host}`;
            if (typeof window.closeSettingsModal === "function") window.closeSettingsModal();
        } catch (err) {
            alert(`❌ Lỗi khi lưu cài đặt: ${err.message}`);
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
            resetGlobalState();
            if (window.purgeAllClientState) window.purgeAllClientState();
            window.location.href = "/login";
        });
    }

    async function fetchLiveAlerts() {
        try {
            const endpoint = currentViewMode === "group" ? "/api/wazuh/alerts/correlated" : "/api/wazuh/alerts";
            const res = await fetch(endpoint, { credentials: "same-origin" });
            if (res.status === 401) {
                resetGlobalState();
                if (window.purgeAllClientState) window.purgeAllClientState();
                window.location.href = "/login";
                return;
            }
            const data = await res.json();
            if (currentViewMode === "group") {
                renderIncidentGroupsList(data.groups || []);
            } else {
                renderAlertsList(data.alerts || []);
            }
        } catch (err) {
            const errorHtml = `
                <div class="login-error-alert" style="margin: 1rem; border-color: #ef4444; background: rgba(239, 68, 68, 0.1); color: #f87171;">
                    <i class="fa-solid fa-plug-circle-xmark"></i> Mất kết nối tới Wazuh Server/Backend. Đang thử kết nối lại...
                </div>
            `;
            // Only update if it's not already showing the error to avoid flicker
            if (!alertsList.innerHTML.includes("Mất kết nối tới")) {
                alertsList.innerHTML = errorHtml;
            }
        }
    }

    function renderAlertsList(alerts) {
        alertsList.innerHTML = "";
        if (!alerts || alerts.length === 0) {
            alertsList.innerHTML = `
                <div class="empty-state" style="padding: 2rem 1rem; text-align: center; color: #94a3b8;">
                    <i class="fa-solid fa-shield-check" style="font-size: 2.5rem; color: #10b981; margin-bottom: 0.8rem; display: block;"></i>
                    <strong style="color: #f8fafc; display: block; margin-bottom: 0.4rem;">Chưa có Cảnh báo mới (0 Real Alerts)</strong>
                    <span style="font-size: 0.8rem; color: #64748b;">Hệ thống đang ở chế độ Real-Time Fetch từ Wazuh API. Toàn bộ log giả lập cũ đã được gỡ bỏ 100%.</span>
                </div>
            `;
            return;
        }

function formatLocalTime(tsStr) {
    if (!tsStr) return "--:--:--";
    try {
        let str = String(tsStr).trim();
        if (!str.endsWith("Z") && !str.includes("+") && !str.includes("-", 10)) {
            str += "Z";
        }
        const d = new Date(str);
        if (isNaN(d.getTime())) {
            return tsStr.substring(11, 19) || "--:--:--";
        }
        return d.toLocaleTimeString("vi-VN", {
            hour12: false,
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit"
        });
    } catch (e) {
        return (tsStr || "").substring(11, 19) || "--:--:--";
    }
}

        alerts.forEach(alert => {
            const card = document.createElement("div");
            const rule = alert.rule || {};
            const agent = alert.agent || {};
            const data = alert.data || {};
            const level = rule.level || 0;
            const ts = formatLocalTime(alert.timestamp);
            const agentIp = data.srcip || agent.ip || agent.name || "N/A";
            let levelClass = "level-low";
            let levelLabel = "LOW";
            if (level >= 15) { levelClass = "level-critical"; levelLabel = "CRITICAL"; }
            else if (level >= 12) { levelClass = "level-high"; levelLabel = "HIGH"; }
            else if (level >= 7) { levelClass = "level-medium"; levelLabel = "MEDIUM"; }

            card.className = `alert-card ${levelClass}`;
            card.innerHTML = `
                <div class="alert-header-row">
                    <span class="badge-level ${levelClass}">${levelLabel} ${level}</span>
                    <span class="alert-time">${ts}</span>
                </div>
                <div class="alert-title">Rule ${rule.id || "?"}: ${rule.description || "Cảnh báo Wazuh"}</div>
                <div class="alert-meta">
                    <span><i class="fa-solid fa-server"></i> ${agent.name || "wazuh-server"}</span>
                    <span><i class="fa-solid fa-network-wired"></i> ${agentIp}</span>
                </div>
            `;

            card.addEventListener("click", () => {
                document.querySelectorAll(".alert-card").forEach(c => c.classList.remove("selected"));
                card.classList.add("selected");
                appendUserBubble(`Phân tích sự cố Alert ${alert.id} (${rule.description || "Wazuh Alert"})`);
                investigateAlert(`Phân tích sự cố Alert ${alert.id} (${rule.description || "Wazuh Alert"})`, alert);
            });

            alertsList.appendChild(card);
        });
    }

    function renderIncidentGroupsList(groups) {
        alertsList.innerHTML = "";
        if (!groups || groups.length === 0) {
            alertsList.innerHTML = `
                <div class="empty-state" style="padding: 2rem 1rem; text-align: center; color: #94a3b8;">
                    <i class="fa-solid fa-layer-group" style="font-size: 2.5rem; color: #10b981; margin-bottom: 0.8rem; display: block;"></i>
                    <strong style="color: #f8fafc; display: block; margin-bottom: 0.4rem;">Chưa có Incident Group</strong>
                    <span style="font-size: 0.8rem; color: #64748b;">Chưa có cảnh báo nào được tương quan thành nhóm.</span>
                </div>
            `;
            return;
        }

        groups.forEach(group => {
            const card = document.createElement("div");
            const score = group.priority_score;
            let levelClass = "level-low";
            if (score >= 80) levelClass = "level-critical";
            else if (score >= 50) levelClass = "level-high";
            else if (score >= 30) levelClass = "level-medium";

            card.className = `alert-card ${levelClass}`;
            card.innerHTML = `
                <div class="alert-header-row">
                    <span class="badge-level ${levelClass}">PRIORITY SCORE: ${score}/100</span>
                    <span class="alert-time">${new Date(group.time_span.start * 1000).toISOString().substring(11, 19)}</span>
                </div>
                <div class="alert-title"><i class="fa-solid fa-layer-group"></i> ${group.group_id} (Gồm ${group.alert_count} cảnh báo)</div>
                <div class="alert-meta">
                    <span><i class="fa-solid fa-network-wired"></i> Entity: ${group.entity}</span>
                    <span><i class="fa-solid fa-spider"></i> MITRE: ${group.breakdown.mitre_techniques_found.join(", ") || "Chưa có dữ liệu"}</span>
                </div>
            `;

            card.addEventListener("click", () => {
                document.querySelectorAll(".alert-card").forEach(c => c.classList.remove("selected"));
                card.classList.add("selected");
                
                // Trích xuất alert đầu tiên đại diện
                const repAlert = group.alerts && group.alerts.length > 0 ? group.alerts[0] : null;
                const queryMsg = `Phân tích nhóm sự cố ${group.group_id} (Điểm: ${score}/100)`;
                appendUserBubble(queryMsg);
                investigateAlert(queryMsg, repAlert);
            });

            alertsList.appendChild(card);
        });
    }

    function appendUserBubble(msg) {
        const div = document.createElement("div");
        div.className = "chat-bubble user";
        div.innerHTML = `<i class="fa-solid fa-user avatar"></i><div class="bubble-content"><strong>Analyst:</strong><div class="msg-text">${escapeHtml(msg)}</div></div>`;
        chatStream.appendChild(div);
        chatStream.scrollTop = chatStream.scrollHeight;
        appendMessageToSession("user", msg);
    }

    async function investigateAlert(query, alertObj = null) {
        const progressBarHtml = `
            <div class="ai-loading-container" style="margin-bottom: 12px; padding: 10px 14px; background: rgba(15, 23, 42, 0.7); border-radius: 8px; border: 1px solid rgba(56, 189, 248, 0.25);">
                <div style="display: flex; justify-content: flex-end; align-items: center; margin-bottom: 6px;">
                    <span id="loading-percent" style="font-size: 0.95rem; color: #10b981; font-weight: 700;">0%</span>
                </div>
                <div class="progress-bar-bg" style="width: 100%; height: 6px; background: #1e293b; border-radius: 3px; overflow: hidden;">
                    <div id="progress-bar-fill" style="width: 0%; height: 100%; background: linear-gradient(90deg, #0284c7, #10b981); transition: width 0.3s ease; box-shadow: 0 0 8px rgba(16, 185, 129, 0.5);"></div>
                </div>
            </div>
        `;
        const loadingId = appendChatBot(progressBarHtml);

        const progressBarFill = document.getElementById("progress-bar-fill");
        const loadingPercent = document.getElementById("loading-percent");

        let progress = 0;
        const progressInterval = setInterval(() => {
            if (progress < 95) {
                progress += Math.random() * 12 + 4;
                if (progress > 95) progress = 95;
                if (progressBarFill && loadingPercent) {
                    progressBarFill.style.width = progress + "%";
                    loadingPercent.textContent = Math.floor(progress) + "%";
                }
            }
        }, 300);

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
            if (progressBarFill && loadingPercent) {
                progressBarFill.style.width = "100%";
                loadingPercent.textContent = "100%";
            }

            setTimeout(() => {
                const textToRender = inv.layer_2_llm_reasoning || inv.answer || inv.summary || "";
                const formToRender = inv.config_form || inv.active_form_session || null;
                updateChatBot(loadingId, textToRender, inv.reasoning_steps || [], formToRender);
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

    function updateChatBot(id, markdownText, steps = [], configForm = null) {
        if (!markdownText) markdownText = "";

        // 1. Auto-extract CONFIG_FORM JSON from markdownText if configForm is null
        if (!configForm) {
            const formMatch = markdownText.match(/```(?:json:form|json)?\s*(\{\s*"type"\s*:\s*"CONFIG_FORM"[\s\S]*?\})\s*```/) ||
                              markdownText.match(/(\{\s*"type"\s*:\s*"CONFIG_FORM"[\s\S]*?\})/);
            if (formMatch) {
                try {
                    configForm = JSON.parse(formMatch[1]);
                } catch (e) {
                    console.error("Failed to parse extracted CONFIG_FORM JSON:", e);
                }
            }
        }

        // Ensure form_data and form_id exist
        if (configForm && configForm.form_data) {
            if (!configForm.form_data.form_id) {
                configForm.form_data.form_id = "form_" + Date.now();
            }
        }

        // 2. Strip raw CONFIG_FORM JSON text from markdownText so it doesn't print raw text to the user
        let cleanMarkdown = markdownText
            .replace(/```(?:json:form|json)?\s*\{\s*"type"\s*:\s*"CONFIG_FORM"[\s\S]*?\}\s*```/g, "")
            .replace(/\{\s*"type"\s*:\s*"CONFIG_FORM"[\s\S]*?\}/g, "")
            .trim();

        appendMessageToSession("ai", cleanMarkdown || markdownText);
        const div = document.getElementById(id);
        if (!div) return;

        const content = div.querySelector(".msg-text");
        let parsedHtml = window.marked ? marked.parse(cleanMarkdown || markdownText) : (cleanMarkdown || markdownText).replace(/\n/g, "<br>");

        if (configForm && configForm.form_data) {
            const f = configForm.form_data;
            const formCardHtml = `
                <div class="hitl-card-container" id="hitl_card_${f.form_id}" style="margin-top: 1.2rem; background: #0f172a; border: 1px solid #38bdf8; border-radius: 14px; padding: 1.2rem; box-shadow: 0 10px 30px rgba(0,0,0,0.5);">
                    <div style="display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 0.8rem; margin-bottom: 1rem;">
                        <h4 style="margin: 0; color: #38bdf8; font-size: 0.95rem; display: flex; align-items: center; gap: 0.5rem;">
                            <i class="fa-solid fa-sliders"></i> ${configForm.title || "Human-In-The-Loop Interactive Form"}
                        </h4>
                        <span class="status-pill pill-secure" style="font-size: 0.7rem;"><i class="fa-solid fa-shield"></i> HITL Guarded</span>
                    </div>
                    
                    <p style="font-size: 0.82rem; color: #94a3b8; margin: 0 0 1rem 0;">${configForm.description || "Vui lòng kiểm tra và duyệt thông số cấu hình bên dưới trước khi áp dụng lên Wazuh Manager."}</p>
                    
                    <div style="display: flex; flex-direction: column; gap: 0.8rem;">
                        <div>
                            <label style="font-size: 0.78rem; color: #cbd5e1; display: block; margin-bottom: 0.3rem;">Tên quy tắc cảnh báo:</label>
                            <input type="text" id="hitl_input_name_${f.form_id}" value="${f.rule_name || ''}" class="input-setting-control" style="width: 100%;">
                        </div>

                        <div>
                            <label style="font-size: 0.78rem; color: #cbd5e1; display: block; margin-bottom: 0.3rem;">Chuỗi nhận diện Log Match:</label>
                            <input type="text" id="hitl_input_match_${f.form_id}" value="${f.match_pattern || ''}" class="input-setting-control" style="width: 100%;">
                        </div>

                        <div style="display: flex; gap: 0.8rem;">
                            <div style="flex: 1;">
                                <label style="font-size: 0.78rem; color: #cbd5e1; display: block; margin-bottom: 0.3rem;">Ngưỡng số lần:</label>
                                <input type="number" id="hitl_input_freq_${f.form_id}" value="${f.frequency || 5}" class="input-setting-control" style="width: 100%;">
                            </div>
                            <div style="flex: 1;">
                                <label style="font-size: 0.78rem; color: #cbd5e1; display: block; margin-bottom: 0.3rem;">Thời gian (giây):</label>
                                <input type="number" id="hitl_input_time_${f.form_id}" value="${f.timeframe || 60}" class="input-setting-control" style="width: 100%;">
                            </div>
                            <div style="flex: 1;">
                                <label style="font-size: 0.78rem; color: #cbd5e1; display: block; margin-bottom: 0.3rem;">Mức độ Rule Level:</label>
                                <select id="hitl_input_level_${f.form_id}" class="input-setting-control" style="width: 100%;">
                                    <option value="5" ${f.level === 5 ? 'selected' : ''}>Level 5 - Low</option>
                                    <option value="7" ${f.level === 7 ? 'selected' : ''}>Level 7 - Medium</option>
                                    <option value="10" ${f.level === 10 ? 'selected' : ''}>Level 10 - High</option>
                                    <option value="12" ${f.level === 12 ? 'selected' : ''}>Level 12 - Critical</option>
                                </select>
                            </div>
                        </div>

                        <button id="hitl_btn_apply_${f.form_id}" class="btn-primary" style="margin-top: 0.6rem; padding: 0.7rem 1.2rem; font-size: 0.88rem; width: 100%;">
                            <i class="fa-solid fa-bolt"></i> Áp Dụng Vào Wazuh Manager
                        </button>
                    </div>
                </div>
            `;
            parsedHtml += formCardHtml;
        }

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

        // Render Chart.js dynamic blocks if present
        const chartBlocks = div.querySelectorAll("code.language-chart, code.language-chartjs, code.language-json");
        chartBlocks.forEach((codeBlock, idx) => {
            const chartContent = codeBlock.textContent.trim();
            if (!chartContent.includes('"type"') || !chartContent.includes('"data"')) return;
            
            try {
                const chartConfig = JSON.parse(chartContent);
                const chartContainerId = "chart_canvas_" + Date.now() + "_" + idx;
                
                const wrapper = document.createElement("div");
                wrapper.className = "chart-wrapper-card";
                wrapper.style.cssText = "margin: 1rem 0; background: #0f172a; padding: 1.2rem; border-radius: 12px; border: 1px solid #38bdf8; position: relative; max-width: 100%; min-height: 260px;";
                
                const canvas = document.createElement("canvas");
                canvas.id = chartContainerId;
                wrapper.appendChild(canvas);
                
                codeBlock.parentNode.replaceWith(wrapper);
                
                if (window.Chart) {
                    new Chart(canvas.getContext("2d"), chartConfig);
                }
            } catch (e) {
                // Ignore non-chart json blocks
            }
        });

        if (configForm && configForm.form_data) {
            const f = configForm.form_data;
            setTimeout(() => {
                const btnApply = document.getElementById(`hitl_btn_apply_${f.form_id}`);
                if (btnApply) {
                    btnApply.addEventListener("click", async () => {
                        const rule_name = document.getElementById(`hitl_input_name_${f.form_id}`).value.trim();
                        const match_pattern = document.getElementById(`hitl_input_match_${f.form_id}`).value.trim();
                        const frequency = parseInt(document.getElementById(`hitl_input_freq_${f.form_id}`).value) || 5;
                        const timeframe = parseInt(document.getElementById(`hitl_input_time_${f.form_id}`).value) || 60;
                        const level = parseInt(document.getElementById(`hitl_input_level_${f.form_id}`).value) || 10;

                        btnApply.disabled = true;
                        btnApply.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Đang nạp rule & khởi động lại Wazuh Manager...';

                        try {
                            const res = await fetch("/api/wazuh/apply-rule", {
                                method: "POST",
                                headers: { "Content-Type": "application/json" },
                                body: JSON.stringify({ rule_name, match_pattern, frequency, timeframe, level }),
                                credentials: "same-origin"
                            });

                            const data = await res.json();
                            if (data.status === "success") {
                                btnApply.className = "interactive-chip chip-low";
                                btnApply.style.background = "rgba(16, 185, 129, 0.2)";
                                btnApply.style.borderColor = "#10b981";
                                btnApply.style.color = "#34d399";
                                btnApply.style.width = "100%";
                                btnApply.style.padding = "0.7rem";
                                btnApply.innerHTML = `<i class="fa-solid fa-circle-check"></i> ✔ Đã áp dụng thành công Rule [${data.rule_id}] vào Wazuh Manager (Level ${level})`;
                            } else {
                                alert("Lỗi khi áp dụng rule.");
                                btnApply.disabled = false;
                                btnApply.innerHTML = '<i class="fa-solid fa-bolt"></i> Thử lại Áp Dụng Vào Wazuh';
                            }
                        } catch (err) {
                            alert("Không thể kết nối đến API Wazuh Manager.");
                            btnApply.disabled = false;
                            btnApply.innerHTML = '<i class="fa-solid fa-bolt"></i> Thử lại Áp Dụng Vào Wazuh';
                        }
                    });
                }
            }, 100);
        }

        chatStream.scrollTop = chatStream.scrollHeight;
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
                <p><strong>AI Engine Used:</strong> <code>${inv.model_used || "Cloud API Engine"}</code></p>
                <p><strong>MITRE Technique:</strong> <code>${inv.layer_1_static_lookup?.technique_id || "T1110"}</code></p>
            </div>
        `;
    }

    presetChips.forEach(chip => {
        chip.addEventListener("click", () => {
            const query = chip.getAttribute("data-query");
            if (query) {
                appendUserBubble(query);
                investigateAlert(query);
            }
        });
    });

    chatForm.addEventListener("submit", (e) => {
        e.preventDefault();
        const query = chatInput.value.trim();
        if (!query) return;
        chatInput.value = "";
        appendUserBubble(query);
        investigateAlert(query);
    });

    fetchLiveAlerts();
    loadSystemSettings();

    // AUTO-SYNC THỜI GIAN THỰC TỪ BACKEND CACHE MỖI 5 GIÂY (POLLING PUSH-FALLBACK)
    setInterval(fetchLiveAlerts, 5000);

    // Sidebar listeners
    const btnToggleSidebar = document.getElementById("btn-toggle-sidebar");
    if (btnToggleSidebar) {
        btnToggleSidebar.addEventListener("click", () => {
            const sidebar = document.getElementById("history-sidebar");
            if (sidebar) sidebar.classList.toggle("collapsed");
        });
    }

    const btnNewChat = document.getElementById("btn-new-chat");
    if (btnNewChat) {
        btnNewChat.addEventListener("click", () => {
            createNewChat();
        });
    }

    // Load initial history
    loadChatHistoryList();

    // --- AUDIT LOGS CONSOLE CONTROLLER ---
    async function fetchAndRenderAuditLogs() {
        try {
            const res = await fetch("/api/system/audit-logs?limit=50", { credentials: "same-origin" });
            if (!res.ok) return;
            const data = await res.json();
            if (!data.logs) return;

            const tbody = document.getElementById("audit-logs-tbody");
            if (!tbody) return;

            if (data.logs.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: #64748b; padding: 1rem;">Chưa có nhật ký hoạt động nào.</td></tr>';
                return;
            }

            tbody.innerHTML = data.logs.map(log => {
                let statusBadgeClass = "badge-info";
                let statusIcon = "fa-circle-info";

                if (log.status === "SUCCESS") {
                    statusBadgeClass = "badge-success";
                    statusIcon = "fa-circle-check";
                } else if (log.status === "WARNING") {
                    statusBadgeClass = "badge-warning";
                    statusIcon = "fa-triangle-exclamation";
                } else if (log.status === "ERROR") {
                    statusBadgeClass = "badge-error";
                    statusIcon = "fa-circle-xmark";
                }

                let sourceBadgeClass = "source-badge-wazuh";
                if (log.source.includes("Indexer") || log.source.includes("OpenSearch")) sourceBadgeClass = "source-badge-indexer";
                else if (log.source.includes("AI")) sourceBadgeClass = "source-badge-ai";
                else if (log.source.includes("LangGraph")) sourceBadgeClass = "source-badge-langgraph";
                else if (log.source.includes("User")) sourceBadgeClass = "source-badge-user";

                const safePayload = encodeURIComponent(log.payload_preview || "");

                return `
                    <tr class="audit-row row-${log.status.toLowerCase()}" onclick="window.viewAuditLogDetail('${log.id}', '${safePayload}')">
                        <td class="cell-time"><code>${escapeHtml(log.timestamp)}</code></td>
                        <td class="cell-source"><span class="source-tag ${sourceBadgeClass}">${escapeHtml(log.source)}</span></td>
                        <td class="cell-action"><code>${escapeHtml(log.action)}</code></td>
                        <td class="cell-status">
                            <span class="status-pill ${statusBadgeClass}">
                                <i class="fa-solid ${statusIcon}"></i> ${escapeHtml(log.status)}
                            </span>
                        </td>
                        <td class="cell-summary" title="Nhấp chuột để xem chi tiết JSON">
                            <span class="summary-text">${escapeHtml(log.message)}</span>
                            ${log.payload_preview ? `<span class="payload-chip"><i class="fa-solid fa-code"></i> JSON</span>` : ''}
                        </td>
                    </tr>
                `;
            }).join('');
        } catch (err) {
            console.error("Audit Log Fetch Error:", err);
        }
    }

    window.viewAuditLogDetail = function(id, encodedPayload) {
        try {
            const payload = decodeURIComponent(encodedPayload);
            let formatted = payload;
            try {
                formatted = JSON.stringify(JSON.parse(payload), null, 2);
            } catch (e) {
                // plain text
            }
            const modalJson = document.getElementById("modal-log-json");
            if (modalJson) modalJson.textContent = formatted || "Không có payload thô.";
            const modal = document.getElementById("log-modal");
            if (modal) modal.classList.remove("hidden");
        } catch (e) {
            console.error("View detail error:", e);
        }
    };

    window.clearAuditLogs = async function() {
        if (!confirm("Bạn có chắc chắn muốn xóa sạch bộ đệm Nhật ký Hoạt động?")) return;
        try {
            await fetch("/api/system/audit-logs", { method: "DELETE", credentials: "same-origin" });
            await fetchAndRenderAuditLogs();
        } catch (e) {
            console.error("Clear log error:", e);
        }
    };

    function setupAuditLogsController() {
        const autoRefreshCheckbox = document.getElementById("audit-auto-refresh");
        const btnClear = document.getElementById("btn-clear-audit-logs");
        const btnToggle = document.getElementById("btn-toggle-audit-panel");
        const logBody = document.getElementById("audit-log-body");

        if (btnClear) btnClear.addEventListener("click", window.clearAuditLogs);
        if (btnToggle && logBody) {
            btnToggle.addEventListener("click", () => {
                logBody.classList.toggle("collapsed");
                const icon = btnToggle.querySelector("i");
                if (icon) {
                    if (logBody.classList.contains("collapsed")) {
                        icon.className = "fa-solid fa-chevron-up";
                    } else {
                        icon.className = "fa-solid fa-chevron-down";
                    }
                }
            });
        }

        fetchAndRenderAuditLogs();

        // Live update every 3 seconds
        setInterval(() => {
            if (autoRefreshCheckbox && autoRefreshCheckbox.checked) {
                fetchAndRenderAuditLogs();
            }
        }, 3000);
    }

    setupAuditLogsController();
});
