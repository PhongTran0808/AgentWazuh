// AgentWazuh Dynamic Real-Time Topology Controller (Version 14.0 Enterprise)
document.addEventListener("DOMContentLoaded", async () => {
    const container = document.getElementById("vis-netmap-container");
    const nodeDetailPanel = document.getElementById("node-detail-panel");
    const btnBackDash = document.getElementById("btn-back-dash");
    const btnResetLayout = document.getElementById("btn-reset-layout");
    const btnZoomFit = document.getElementById("btn-zoom-fit");
    const statusHost = document.getElementById("status-host");
    const presetSelector = document.getElementById("preset-selector");

    const btnOpenSettings = document.getElementById("btn-open-settings");
    const settingsModal = document.getElementById("settings-modal");

    btnBackDash.addEventListener("click", () => {
        window.location.href = "/dashboard";
    });

    if (btnOpenSettings) {
        btnOpenSettings.addEventListener("click", () => {
            if (settingsModal) settingsModal.classList.remove("hidden");
        });
    }

    window.closeSettingsModal = function() {
        if (settingsModal) settingsModal.classList.add("hidden");
    };

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
            renderVisNetwork(data.nodes, data.edges, data.empty_state);
        } catch (err) {
            console.error("Failed to load topology:", err);
        }
    }

    function renderVisNetwork(nodesList, edgesList, isEmptyState = false) {
        if (isEmptyState || !nodesList || nodesList.length === 0) {
            container.innerHTML = `
                <div class="empty-topology-overlay" style="display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100%; color: #94a3b8; text-align: center; padding: 2rem;">
                    <div class="radar-pulse-ring" style="font-size: 3.5rem; color: #38bdf8; margin-bottom: 1.2rem; animation: pulse 2s infinite;">
                        <i class="fa-solid fa-radar fa-spin"></i>
                    </div>
                    <h3 style="color: #f8fafc; font-size: 1.2rem; margin-bottom: 0.5rem;">Chưa phát hiện thiết bị kết nối (Real-time Discovery)</h3>
                    <p style="font-size: 0.88rem; max-width: 480px; color: #64748b; line-height: 1.5;">Toàn bộ sơ đồ giả lập cũ đã được gỡ bỏ 100%. Sơ đồ mạng sẽ tự động khởi tạo ngay khi hệ thống ghi nhận có Wazuh Agent active hoặc thiết bị thực tế cắm vào hạ tầng.</p>
                </div>
            `;
            if (nodeDetailPanel) {
                nodeDetailPanel.innerHTML = `
                    <div class="empty-state">
                        <i class="fa-solid fa-network-wired empty-icon"></i>
                        <p>Hệ thống mạng hiện chưa có thiết bị kết nối. Trạng thái hiển thị rỗng theo đúng thực tế Wazuh API.</p>
                    </div>
                `;
            }
            return;
        }

        container.innerHTML = ""; // Clear canvas container for vis.js

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

        const formattedEdges = (edgesList || []).map(e => ({
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
                <p><strong>Hệ Điều Hành / Firmware:</strong> ${n.os || "Linux / Wazuh OS"}</p>
                <p><strong>Trạng Thái Giám Sát:</strong> <span style="color: #10b981;">🟢 ${n.agent_status || "Active Device"}</span></p>
            </div>

            <div class="evidence-section" style="margin-top: 1.2rem;">
                <h3><i class="fa-solid fa-plug"></i> Interface & Real Ports</h3>
                <ul style="padding-left: 1.2rem; margin: 0.5rem 0; font-size: 0.85rem; color: var(--accent-cyan);">
                    ${portsList}
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
