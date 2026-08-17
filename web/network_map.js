// AgentWazuh Dynamic Network Topology Map Controller (Vis.js Implementation)
document.addEventListener("DOMContentLoaded", async () => {
    const container = document.getElementById("vis-netmap-container");
    const nodeDetailPanel = document.getElementById("node-detail-panel");
    const btnBackDash = document.getElementById("btn-back-dash");
    const btnResetLayout = document.getElementById("btn-reset-layout");
    const btnZoomFit = document.getElementById("btn-zoom-fit");
    const statusHost = document.getElementById("status-host");

    btnBackDash.addEventListener("click", () => {
        window.location.href = "/dashboard";
    });

    let network = null;
    let nodesDataSet = null;
    let edgesDataSet = null;
    let rawNodesData = [];

    // Load saved positions from localStorage
    const savedPositions = JSON.parse(localStorage.getItem("wazuh_netmap_positions") || "{}");

    // Fetch Topology Data from API
    try {
        const res = await fetch("/api/wazuh/topology");
        const data = await res.json();
        if (data.host) {
            statusHost.textContent = `Wazuh Server: ${data.host}`;
        }

        rawNodesData = data.nodes || [];
        renderVisNetwork(data.nodes, data.edges);
    } catch (err) {
        console.error("Failed to load topology:", err);
    }

    function renderVisNetwork(nodesList, edgesList) {
        const formattedNodes = nodesList.map(n => {
            let shape = "icon";
            let iconCode = "\uf233"; // fa-server default
            let iconColor = "#38bdf8"; // cyan default
            let borderColor = "#38bdf8";

            if (n.group === "server") {
                iconCode = "\uf233"; // fa-server
                iconColor = "#0284c7";
                borderColor = "#38bdf8";
            } else if (n.group === "router") {
                iconCode = "\uf6ff"; // fa-router
                iconColor = "#f59e0b";
                borderColor = "#fde047";
            } else if (n.group === "firewall") {
                iconCode = "\uf3ed"; // fa-shield-halved
                iconColor = "#f97316";
                borderColor = "#fb923c";
            } else if (n.group === "switch") {
                iconCode = "\uf6ff"; // fa-network-wired
                iconColor = "#10b981";
                borderColor = "#34d399";
            } else if (n.group === "pc") {
                iconCode = "\uf108"; // fa-desktop
                iconColor = "#10b981";
                borderColor = "#34d399";
            } else if (n.group === "attacker") {
                iconCode = "\uf071"; // fa-triangle-exclamation
                iconColor = "#ef4444";
                borderColor = "#fca5a5";
            }

            const nodeObj = {
                id: n.id,
                label: n.label,
                shape: "icon",
                icon: {
                    face: "'Font Awesome 6 Free'",
                    code: iconCode,
                    size: 45,
                    color: iconColor,
                    weight: "900"
                },
                font: { color: "#f8fafc", face: "Inter", size: 12, strokeWidth: 3, strokeColor: "#020617" },
                borderWidth: 2,
                color: { border: borderColor }
            };

            // Restore saved position if available
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
            font: { color: "#94a3b8", face: "JetBrains Mono", size: 11, align: "middle", background: "#0f172a" },
            arrows: e.arrows || "to",
            color: e.color || { color: "#38bdf8", highlight: "#0284c7" },
            width: 2,
            smooth: { type: "continuous" }
        }));

        nodesDataSet = new vis.DataSet(formattedNodes);
        edgesDataSet = new vis.DataSet(formattedEdges);

        const options = {
            nodes: {
                shadow: true
            },
            edges: {
                shadow: true
            },
            physics: {
                enabled: Object.keys(savedPositions).length === 0,
                solver: "forceAtlas2Based",
                forceAtlas2Based: {
                    gravitationalConstant: -50,
                    centralGravity: 0.01,
                    springLength: 100,
                    springConstant: 0.08
                }
            },
            interaction: {
                hover: true,
                dragNodes: true,
                zoomView: true
            }
        };

        network = new vis.Network(container, { nodes: nodesDataSet, edges: edgesDataSet }, options);

        // Save position on node drag end
        network.on("dragEnd", (params) => {
            if (params.nodes.length > 0) {
                const positions = network.getPositions(params.nodes);
                Object.keys(positions).forEach(id => {
                    savedPositions[id] = positions[id];
                });
                localStorage.setItem("wazuh_netmap_positions", JSON.stringify(savedPositions));
            }
        });

        // Click node event -> populate detail panel
        network.on("click", (params) => {
            if (params.nodes.length > 0) {
                const nodeId = params.nodes[0];
                const nodeInfo = rawNodesData.find(n => n.id === nodeId);
                if (nodeInfo) {
                    renderNodeDetail(nodeInfo);
                }
            }
        });
    }

    function renderNodeDetail(n) {
        const portsList = (n.open_ports || []).map(p => `<li><code>${p}</code></li>`).join("");
        nodeDetailPanel.innerHTML = `
            <div class="evidence-section">
                <h3><i class="fa-solid fa-microchip"></i> ${n.label.replace(/\n/g, " ")}</h3>
                <p><strong>Loại Thiết Bị:</strong> <span class="badge-level level-low">${n.device_type}</span></p>
                <p><strong>Địa Chỉ IP:</strong> <code>${n.ip}</code></p>
                <p><strong>Hệ Điều Hành (OS):</strong> ${n.os}</p>
                <p><strong>Trạng Thái Agent Wazuh:</strong> <span style="color: ${n.agent_status.includes('Active') ? '#10b981' : '#f59e0b'};">🟢 ${n.agent_status}</span></p>
            </div>

            <div class="evidence-section" style="margin-top: 1.2rem;">
                <h3><i class="fa-solid fa-plug"></i> Danh Sách Port Đang Mở</h3>
                <ul style="padding-left: 1.2rem; margin: 0.5rem 0; font-size: 0.85rem; color: var(--accent-cyan);">
                    ${portsList || "<li>Không có thông tin port</li>"}
                </ul>
            </div>

            <button class="btn-primary" style="width: 100%; margin-top: 1.5rem;" onclick="window.askAboutDevice('${n.ip}')">
                <i class="fa-solid fa-comment"></i> Hỏi AI Về Thiết Bị ${n.ip}
            </button>
        `;
    }

    window.askAboutDevice = function(ip) {
        window.location.href = `/dashboard?query=${encodeURIComponent("Kiểm tra chi tiết lưu lượng và cảnh báo của thiết bị " + ip)}`;
    };

    btnResetLayout.addEventListener("click", () => {
        localStorage.removeItem("wazuh_netmap_positions");
        location.reload();
    });

    btnZoomFit.addEventListener("click", () => {
        if (network) {
            network.fit({ animation: { duration: 500, easingFunction: "easeInOutQuad" } });
        }
    });
});
