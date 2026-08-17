// AgentWazuh Dynamic Network Topology Map Controller (Version 10.3 - Clean UI & Settings Support)
document.addEventListener("DOMContentLoaded", async () => {
    const container = document.getElementById("vis-netmap-container");
    const nodeDetailPanel = document.getElementById("node-detail-panel");
    const btnBackDash = document.getElementById("btn-back-dash");
    const btnResetLayout = document.getElementById("btn-reset-layout");
    const btnZoomFit = document.getElementById("btn-zoom-fit");
    const statusHost = document.getElementById("status-host");
    const presetSelector = document.getElementById("preset-selector");

    const btnOpenSettings = document.getElementById("btn-open-settings");
    const btnOpenAIConfig = document.getElementById("btn-open-ai-config");

    // Modal AI elements
    const aiModal = document.getElementById("ai-modal");
    const tabOllama = document.getElementById("tab-ollama");
    const tabCloud = document.getElementById("tab-cloud");
    const contentOllama = document.getElementById("content-ollama");
    const contentCloud = document.getElementById("content-cloud");
    const btnStartOllama = document.getElementById("btn-start-ollama");
    const btnSaveAIConfig = document.getElementById("btn-save-ai-config");
    const selectOllamaModel = document.getElementById("select-ollama-model");
    const inputOllamaUrl = document.getElementById("input-ollama-url");
    const inputCloudUrl = document.getElementById("input-cloud-url");
    const inputCloudKey = document.getElementById("input-cloud-key");
    const inputCloudModel = document.getElementById("input-cloud-model");

    // Modal Settings elements
    const settingsModal = document.getElementById("settings-modal");
    const settingTimeoutMin = document.getElementById("setting-timeout-min");
    const settingPingInterval = document.getElementById("setting-ping-interval");
    const settingPingRetry = document.getElementById("setting-ping-retry");
    const settingWazuhHost = document.getElementById("setting-wazuh-host");
    const settingWazuhPort = document.getElementById("setting-wazuh-port");
    const btnSaveSettings = document.getElementById("btn-save-settings");

    let currentAIMode = "ollama";

    btnBackDash.addEventListener("click", () => {
        window.location.href = "/dashboard";
    });

    if (btnOpenSettings) {
        btnOpenSettings.addEventListener("click", () => {
            loadSystemSettings();
            settingsModal.classList.remove("hidden");
        });
    }

    if (btnOpenAIConfig) {
        btnOpenAIConfig.addEventListener("click", () => {
            loadAIConfig();
            aiModal.classList.remove("hidden");
        });
    }

    window.closeAIModal = function() {
        if (aiModal) aiModal.classList.add("hidden");
    };

    window.closeSettingsModal = function() {
        if (settingsModal) settingsModal.classList.add("hidden");
    };

    if (tabOllama && tabCloud) {
        tabOllama.addEventListener("click", () => {
            currentAIMode = "ollama";
            tabOllama.classList.add("active");
            tabCloud.classList.remove("active");
            contentOllama.classList.remove("hidden");
            contentCloud.classList.add("hidden");
        });

        tabCloud.addEventListener("click", () => {
            currentAIMode = "cloud_api";
            tabCloud.classList.add("active");
            tabOllama.classList.remove("active");
            contentCloud.classList.remove("hidden");
            contentOllama.classList.add("hidden");
        });
    }

    if (btnStartOllama) {
        btnStartOllama.addEventListener("click", async () => {
            try {
                const res = await fetch("/api/ai/ollama/start", { method: "POST", credentials: "same-origin" });
                const data = await res.json();
                alert(data.message || "Đã kiểm tra Ollama daemon.");
            } catch (err) {
                alert("Không thể bật Ollama tự động. Vui lòng gõ 'ollama serve' trong terminal.");
            }
        });
    }

    async function loadAIConfig() {
        try {
            const res = await fetch("/api/ai/config", { credentials: "same-origin" });
            const config = await res.json();
            currentAIMode = config.mode || "ollama";
            if (currentAIMode === "cloud_api") {
                if (tabCloud) tabCloud.click();
            } else {
                if (tabOllama) tabOllama.click();
            }
            if (config.ollama_model) selectOllamaModel.value = config.ollama_model;
            if (config.ollama_url) inputOllamaUrl.value = config.ollama_url;
            if (config.cloud_api_url) inputCloudUrl.value = config.cloud_api_url;
            if (config.cloud_api_key) inputCloudKey.value = config.cloud_api_key;
            if (config.cloud_model) inputCloudModel.value = config.cloud_model;
        } catch (err) {
            console.error("Failed to load AI config:", err);
        }
    }

    if (btnSaveAIConfig) {
        btnSaveAIConfig.addEventListener("click", async () => {
            const payload = {
                mode: currentAIMode,
                ollama_url: inputOllamaUrl.value.trim(),
                ollama_model: selectOllamaModel.value,
                cloud_api_enabled: currentAIMode === "cloud_api",
                cloud_api_url: inputCloudUrl.value.trim(),
                cloud_api_key: inputCloudKey.value.trim(),
                cloud_model: inputCloudModel.value.trim()
            };

            try {
                const res = await fetch("/api/ai/config", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(payload),
                    credentials: "same-origin"
                });
                const data = await res.json();
                if (data.status === "success") {
                    alert(`🟢 Đã lưu cấu hình AI Mode [${currentAIMode.toUpperCase()}] thành công!`);
                    window.closeAIModal();
                }
            } catch (err) {
                alert("❌ Lỗi khi lưu cấu hình AI.");
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
                if (statusHost) statusHost.textContent = `Wazuh Server: ${s.wazuh_host}`;
            }
            if (s.wazuh_port) settingWazuhPort.value = s.wazuh_port;
        } catch (err) {
            console.error("Failed to load system settings:", err);
        }
    }

    if (btnSaveSettings) {
        btnSaveSettings.addEventListener("click", async () => {
            const payload = {
                session_timeout_minutes: parseInt(settingTimeoutMin.value) || 30,
                icmp_ping_interval_seconds: parseInt(settingPingInterval.value) || 15,
                ping_retry_threshold: parseInt(settingPingRetry.value) || 3,
                wazuh_host: settingWazuhHost.value.trim(),
                wazuh_port: parseInt(settingWazuhPort.value) || 55000
            };

            try {
                const res = await fetch("/api/settings", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(payload),
                    credentials: "same-origin"
                });
                const data = await res.json();
                if (data.status === "success") {
                    alert(data.message || "🟢 Đã lưu thông số hệ thống!");
                    if (statusHost) statusHost.textContent = `Wazuh Server: ${payload.wazuh_host}`;
                    window.closeSettingsModal();
                }
            } catch (err) {
                alert("❌ Lỗi khi lưu thông số hệ thống.");
            }
        });
    }

    let network = null;
    let nodesDataSet = null;
    let edgesDataSet = null;
    let rawNodesData = [];

    const savedPositions = JSON.parse(localStorage.getItem("wazuh_netmap_positions") || "{}");

    async function loadTopology(preset = "default") {
        try {
            const res = await fetch(`/api/wazuh/topology?preset=${preset}`, {
                credentials: "same-origin"
            });
            if (res.status === 401) {
                window.location.href = "/login";
                return;
            }
            const data = await res.json();
            if (data.host && statusHost) {
                statusHost.textContent = `Wazuh Server: ${data.host}`;
            }

            rawNodesData = data.nodes || [];
            renderVisNetwork(data.nodes, data.edges);
        } catch (err) {
            console.error("Failed to load topology:", err);
        }
    }

    function renderVisNetwork(nodesList, edgesList) {
        const formattedNodes = nodesList.map(n => {
            let iconCode = "\uf233";
            let iconColor = "#0284c7";
            let borderColor = "#38bdf8";

            if (n.group === "server") {
                iconCode = "\uf233"; iconColor = "#0284c7"; borderColor = "#38bdf8";
            } else if (n.group === "router") {
                iconCode = "\uf6ff"; iconColor = "#f59e0b"; borderColor = "#fde047";
            } else if (n.group === "firewall") {
                iconCode = "\uf3ed"; iconColor = "#f97316"; borderColor = "#fb923c";
            } else if (n.group === "switch") {
                iconCode = "\uf6ff"; iconColor = "#10b981"; borderColor = "#34d399";
            } else if (n.group === "pc" || n.group === "endpoint") {
                iconCode = "\uf108"; iconColor = "#10b981"; borderColor = "#34d399";
            }

            const nodeObj = {
                id: n.id,
                label: n.label,
                originalLabel: n.label,
                shape: "icon",
                icon: {
                    face: "'Font Awesome 6 Free'",
                    code: iconCode,
                    size: 45,
                    color: iconColor,
                    weight: "900"
                },
                font: { color: "#f8fafc", face: "Inter", size: 12, strokeWidth: 4, strokeColor: "#020617" },
                borderWidth: 2,
                color: { border: borderColor }
            };

            if (n.level) {
                nodeObj.level = n.level;
            }

            if (savedPositions[n.id]) {
                nodeObj.x = savedPositions[n.id].x;
                nodeObj.y = savedPositions[n.id].y;
            }

            return nodeObj;
        });

        const formattedEdges = edgesList.map(e => ({
            from: e.from,
            to: e.to,
            label: e.label,
            font: { color: "#38bdf8", face: "Inter", size: 11, align: "middle", background: "#0f172a", strokeWidth: 4, strokeColor: "#020617" },
            arrows: { to: { enabled: true, scaleFactor: 0.85 } },
            color: e.color || { color: "#38bdf8", highlight: "#0284c7" },
            width: 2,
            smooth: false
        }));

        nodesDataSet = new vis.DataSet(formattedNodes);
        edgesDataSet = new vis.DataSet(formattedEdges);

        const options = {
            nodes: { shadow: true },
            edges: { shadow: true, smooth: false },
            physics: {
                enabled: Object.keys(savedPositions).length === 0,
                solver: "forceAtlas2Based",
                forceAtlas2Based: { gravitationalConstant: -60, centralGravity: 0.01, springLength: 140, springConstant: 0.08 }
            },
            interaction: { hover: true, dragNodes: true, zoomView: true }
        };

        network = new vis.Network(container, { nodes: nodesDataSet, edges: edgesDataSet }, options);

        network.on("dragEnd", (params) => {
            if (params.nodes.length > 0) {
                const positions = network.getPositions(params.nodes);
                Object.keys(positions).forEach(id => { savedPositions[id] = positions[id]; });
                localStorage.setItem("wazuh_netmap_positions", JSON.stringify(savedPositions));
            }
        });

        network.on("click", (params) => {
            if (params.nodes.length > 0) {
                const nodeId = params.nodes[0];
                const nodeInfo = rawNodesData.find(n => n.id === nodeId);
                if (nodeInfo) {
                    renderReadOnlyNodePanel(nodeInfo);
                }
            }
        });
    }

    function renderReadOnlyNodePanel(n) {
        const portsList = (n.open_ports || []).map(p => `<li><code>${p}</code></li>`).join("");
        nodeDetailPanel.innerHTML = `
            <div class="evidence-section">
                <h3><i class="fa-solid fa-server"></i> ${n.label.replace(/\n/g, " ")}</h3>
                <p><strong>Loại Thiết Bị:</strong> <span class="badge-level level-low">${n.device_type}</span></p>
                <p><strong>Địa Chỉ IP Phân Giải:</strong> <code>${n.ip}</code> ${n.secondary_ip ? `| <code>${n.secondary_ip}</code>` : ""}</p>
                <p><strong>Hệ Điều Hành / Firmware:</strong> ${n.os || "FortiOS v7.2"}</p>
                <p><strong>Trạng Thái Giám Sát:</strong> <span style="color: #10b981;">🟢 ${n.agent_status || "Active Device"}</span></p>
            </div>

            <div class="evidence-section" style="margin-top: 1.2rem;">
                <h3><i class="fa-solid fa-plug"></i> Interface & Open Ports</h3>
                <ul style="padding-left: 1.2rem; margin: 0.5rem 0; font-size: 0.85rem; color: var(--accent-cyan);">
                    ${portsList || "<li>LAN Port3: 172.16.10.99/24</li><li>WAN: 172.16.30.3/24</li>"}
                </ul>
            </div>
        `;
    }

    function startHeartbeatPolling() {
        setInterval(async () => {
            try {
                const res = await fetch("/api/network/status", { credentials: "same-origin" });
                if (res.status === 401) return;
                const json = await res.json();
                const nodeStatuses = json.data?.nodes || {};

                if (nodesDataSet) {
                    nodesDataSet.forEach(node => {
                        const rawNode = rawNodesData.find(n => n.id === node.id);
                        if (!rawNode) return;

                        const statusObj = nodeStatuses[rawNode.ip];
                        if (statusObj) {
                            if (statusObj.status === "down") {
                                const timestampMsg = statusObj.down_since ? `\n🚨 Mất kết nối lúc: ${statusObj.down_since}` : "\n🚨 Mất kết nối";
                                nodesDataSet.update({
                                    id: node.id,
                                    label: node.originalLabel + timestampMsg,
                                    icon: { ...node.icon, color: "#ef4444" },
                                    color: { border: "#ef4444" }
                                });
                            } else if (statusObj.status === "degraded") {
                                nodesDataSet.update({
                                    id: node.id,
                                    label: node.originalLabel + "\n🟠 Nghẽn mạng nhẹ",
                                    icon: { ...node.icon, color: "#f59e0b" },
                                    color: { border: "#f59e0b" }
                                });
                            } else {
                                nodesDataSet.update({
                                    id: node.id,
                                    label: node.originalLabel,
                                    icon: { ...node.icon, color: node.icon.color },
                                    color: { border: node.color.border }
                                });
                            }
                        }
                    });
                }
            } catch (err) {
                console.error("Heartbeat poll error:", err);
            }
        }, 10000);
    }

    if (presetSelector) {
        presetSelector.addEventListener("change", (e) => {
            loadTopology(e.target.value);
        });
    }

    if (btnResetLayout) {
        btnResetLayout.addEventListener("click", () => {
            localStorage.removeItem("wazuh_netmap_positions");
            loadTopology(presetSelector ? presetSelector.value : "default");
        });
    }

    if (btnZoomFit) {
        btnZoomFit.addEventListener("click", () => {
            if (network) {
                network.fit({ animation: { duration: 500, easingFunction: "easeInOutQuad" } });
            }
        });
    }

    loadTopology("default");
    startHeartbeatPolling();
});
