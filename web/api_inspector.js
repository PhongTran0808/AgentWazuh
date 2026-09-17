/**
 * AgentWazuh — Dedicated REST API Exchange Auditor Controller
 */
document.addEventListener("DOMContentLoaded", () => {
    const tbody = document.getElementById("api-inspector-tbody");
    const searchInput = document.getElementById("input-search-api");
    const filterMethod = document.getElementById("select-filter-method");
    const filterStatus = document.getElementById("select-filter-status");
    const btnRefresh = document.getElementById("btn-refresh-api-log");
    const btnClear = document.getElementById("btn-clear-api-log");
    const btnToggleAuto = document.getElementById("btn-toggle-autorefresh");
    const spinIcon = document.getElementById("spin-icon");
    const summaryEl = document.getElementById("api-log-summary");
    const lastUpdateEl = document.getElementById("api-log-last-update");

    const modal = document.getElementById("packet-detail-modal");
    const modalCurlInput = document.getElementById("modal-curl-input");
    const modalRequestJson = document.getElementById("modal-request-json");
    const modalResponseJson = document.getElementById("modal-response-json");
    const btnCopyModalCurl = document.getElementById("btn-modal-copy-curl");

    let allLogs = [];
    let autoRefreshInterval = null;
    let isAutoRefreshActive = true;

    // Load logs from backend
    async function loadApiLogs() {
        try {
            const res = await fetch("/api/wazuh/live-logs", { credentials: "same-origin" });
            if (res.status === 401) { window.location.href = "/login"; return; }
            const json = await res.json();
            allLogs = json.logs || [];
            
            // Also fetch system audit logs if live logs are fewer than 10
            if (allLogs.length < 5) {
                const auditRes = await fetch("/api/system/audit-logs?limit=100", { credentials: "same-origin" });
                if (auditRes.ok) {
                    const auditJson = await auditRes.json();
                    const auditLogs = (auditJson.logs || []).map(a => ({
                        id: `audit-${a.id || Date.now()}`,
                        timestamp: a.timestamp || "",
                        direction: "System Engine",
                        method: a.level || "INFO",
                        endpoint: a.module || a.action || "/audit",
                        url: a.action || "",
                        status_code: a.level === "ERROR" ? 500 : 200,
                        detail: a.message,
                        curl_command: `curl -k "https://127.0.0.1:55000${a.action || ''}"`
                    }));
                    allLogs = [...allLogs, ...auditLogs];
                }
            }

            renderLogs();
            const now = new Date();
            if (lastUpdateEl) lastUpdateEl.textContent = `Cập nhật: ${now.toLocaleTimeString("vi-VN")}`;
        } catch (err) {
            console.error("Failed to fetch API logs:", err);
            if (tbody) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="5" class="loading-state" style="padding: 20px; text-align: center; color: var(--critical);">
                            ❌ Không thể kết nối tới AgentWazuh Server API.
                        </td>
                    </tr>`;
            }
        }
    }

    function renderLogs() {
        if (!tbody) return;

        const query = searchInput ? searchInput.value.trim().toLowerCase() : "";
        const mFilter = filterMethod ? filterMethod.value : "all";
        const sFilter = filterStatus ? filterStatus.value : "all";

        let filtered = allLogs.filter(item => {
            if (mFilter !== "all" && item.method !== mFilter) return false;
            if (sFilter === "200" && (item.status_code < 200 || item.status_code >= 300)) return false;
            if (sFilter === "error" && item.status_code >= 200 && item.status_code < 400) return false;
            
            if (query) {
                const searchStr = `${item.timestamp} ${item.method} ${item.endpoint} ${item.url} ${item.status_code} ${item.detail || ''} ${item.curl_command || ''}`.toLowerCase();
                if (!searchStr.includes(query)) return false;
            }
            return true;
        });

        if (summaryEl) {
            const okCount = allLogs.filter(l => l.status_code >= 200 && l.status_code < 300).length;
            const errCount = allLogs.length - okCount;
            summaryEl.innerHTML = `Hiển thị <strong>${filtered.length}</strong> / <strong>${allLogs.length}</strong> gói tin API ` +
                `<span style="color:var(--ok); font-weight:600; margin-left:8px;">✅ ${okCount} Thành công</span> ` +
                `<span style="color:var(--critical); font-weight:600; margin-left:8px;">🚨 ${errCount} Lỗi</span>`;
        }

        if (filtered.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="5" class="loading-state" style="padding: 24px; text-align: center; color: var(--ink-3);">
                        Không tìm thấy gói tin API nào phù hợp với bộ lọc.
                    </td>
                </tr>`;
            return;
        }

        tbody.innerHTML = "";
        filtered.forEach((pkt, idx) => {
            const tr = document.createElement("tr");
            tr.style.borderBottom = "1px solid var(--rule-soft)";

            const isOk = pkt.status_code >= 200 && pkt.status_code < 300;
            const statusClass = isOk ? "chip-low" : "chip-high";
            const methodColor = pkt.method === "GET" ? "var(--accent)" : pkt.method === "POST" ? "var(--ok)" : pkt.method === "DELETE" ? "var(--critical)" : "var(--medium)";

            tr.innerHTML = `
                <td style="padding: 8px 12px; font-family: var(--font-mono); color: var(--ink-3);">${escapeHtml(pkt.timestamp || "—")}</td>
                <td style="padding: 8px 12px;">
                    <span style="display:inline-block; padding: 2px 6px; border-radius: 4px; background: var(--paper-sunk); color: ${methodColor}; font-weight: 700; font-family: var(--font-mono); font-size: 11px;">
                        ${escapeHtml(pkt.method || "API")}
                    </span>
                </td>
                <td style="padding: 8px 12px;">
                    <span class="interactive-chip ${statusClass}" style="font-weight: 600;">
                        ${pkt.status_code ? pkt.status_code : "—"}
                    </span>
                </td>
                <td style="padding: 8px 12px; word-break: break-all;">
                    <strong style="color: var(--ink);">${escapeHtml(pkt.endpoint || pkt.url || "Wazuh Endpoint")}</strong>
                    <br><span style="color: var(--ink-3); font-size: 11px; font-family: var(--font-mono);">${escapeHtml(pkt.url || pkt.detail || "")}</span>
                </td>
                <td style="padding: 8px 12px; text-align: right; white-space: nowrap;">
                    <button type="button" class="btn btn--ghost btn--sm" onclick="window.copyPacketCurl('${pkt.id}')" title="Sao chép cURL 1-Click">
                        <i class="fa-solid fa-copy"></i> Copy cURL
                    </button>
                    <button type="button" class="btn btn--ghost btn--sm" onclick="window.viewPacketDetail('${pkt.id}')" title="Xem chi tiết Request/Response JSON">
                        <i class="fa-solid fa-code"></i> JSON
                    </button>
                    <button type="button" class="btn btn--primary btn--sm" onclick="window.askAiAboutPacket('${pkt.id}')" title="Hỏi AI về gói tin này">
                        <i class="fa-solid fa-robot"></i> Hỏi AI
                    </button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    }

    function escapeHtml(text) {
        return String(text ?? "")
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;");
    }

    // Interactive Packet Action Helpers
    window.copyPacketCurl = function(pktId) {
        const pkt = allLogs.find(l => l.id === pktId);
        if (!pkt || !pkt.curl_command) {
            alert("❌ Không có lệnh cURL khả thi cho gói tin này.");
            return;
        }
        navigator.clipboard.writeText(pkt.curl_command).then(() => {
            alert(`🟢 ĐÃ SAO CHÉP LỆNH cURL MỚI!\n\n${pkt.curl_command}`);
        }).catch(err => {
            prompt("Sao chép cURL bên dưới:", pkt.curl_command);
        });
    };

    window.viewPacketDetail = function(pktId) {
        const pkt = allLogs.find(l => l.id === pktId);
        if (!pkt) return;

        if (modalCurlInput) modalCurlInput.value = pkt.curl_command || `curl -k -X ${pkt.method} "${pkt.url}"`;
        if (modalRequestJson) {
            const reqData = pkt.request_payload || pkt.headers || { url: pkt.url, method: pkt.method };
            modalRequestJson.textContent = JSON.stringify(reqData, null, 2);
        }
        if (modalResponseJson) {
            const resData = pkt.response_preview || pkt.detail || { status_code: pkt.status_code };
            modalResponseJson.textContent = JSON.stringify(resData, null, 2);
        }

        btnCopyModalCurl.onclick = () => {
            navigator.clipboard.writeText(modalCurlInput.value).then(() => {
                alert("🟢 Đã copy lệnh cURL vào bộ nhớ tạm!");
            });
        };

        modal?.classList.remove("hidden");
    };

    window.closePacketDetailModal = function() {
        modal?.classList.add("hidden");
    };

    window.askAiAboutPacket = function(pktId) {
        const pkt = allLogs.find(l => l.id === pktId);
        if (!pkt) return;
        const promptText = `Phân tích gói tin REST API Wazuh [${pkt.method} ${pkt.endpoint}] - Status ${pkt.status_code}:\n${pkt.curl_command || pkt.url}`;
        window.location.href = `/dashboard?query=${encodeURIComponent(promptText)}`;
    };

    // Event Listeners
    searchInput?.addEventListener("input", renderLogs);
    filterMethod?.addEventListener("change", renderLogs);
    filterStatus?.addEventListener("change", renderLogs);

    btnRefresh?.addEventListener("click", () => {
        loadApiLogs();
    });

    btnClear?.addEventListener("click", async () => {
        if (confirm("Bạn có chắc chắn muốn xóa toàn bộ nhật ký gói tin REST API khỏi bộ đệm?")) {
            try {
                await fetch("/api/system/audit-logs", { method: "DELETE", credentials: "same-origin" });
                allLogs = [];
                renderLogs();
            } catch(e) {
                console.error("Clear logs failed:", e);
            }
        }
    });

    btnToggleAuto?.addEventListener("click", () => {
        isAutoRefreshActive = !isAutoRefreshActive;
        if (isAutoRefreshActive) {
            spinIcon?.classList.add("fa-spin");
            btnToggleAuto.style.opacity = "1";
            startAutoRefresh();
        } else {
            spinIcon?.classList.remove("fa-spin");
            btnToggleAuto.style.opacity = "0.5";
            stopAutoRefresh();
        }
    });

    function startAutoRefresh() {
        stopAutoRefresh();
        autoRefreshInterval = setInterval(loadApiLogs, 3000);
    }

    function stopAutoRefresh() {
        if (autoRefreshInterval) clearInterval(autoRefreshInterval);
    }

    // Boot
    loadApiLogs();
    startAutoRefresh();
});
