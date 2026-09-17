// AgentWazuh Device Inventory Controller (TẦNG 0 Ground Truth)
document.addEventListener("DOMContentLoaded", () => {
    const inventoryTbody = document.getElementById("inventory-tbody");
    const unverifiedChipsContainer = document.getElementById("unverified-chips-container");
    const confirmForm = document.getElementById("confirm-device-form");
    const confirmStatus = document.getElementById("confirm-status");
    const btnBackDash = document.getElementById("btn-back-dash");
    const btnRefresh = document.getElementById("btn-refresh-inv");

    const inputIp = document.getElementById("form-ip");
    const inputName = document.getElementById("form-name");
    const selectType = document.getElementById("form-type");
    const inputRole = document.getElementById("form-role");

    function escapeHtml(value) {
        return String(value ?? "")
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;");
    }

    function setStatus(message, kind) {
        if (!confirmStatus) return;
        confirmStatus.textContent = message || "";
        confirmStatus.classList.toggle("is-ok", kind === "ok");
        confirmStatus.classList.toggle("is-error", kind === "error");
        confirmStatus.hidden = !message;
    }

    btnBackDash?.addEventListener("click", () => {
        window.location.href = "/dashboard";
    });

    btnRefresh?.addEventListener("click", () => {
        loadInventoryData();
    });

    async function loadInventoryData() {
        if (inventoryTbody) inventoryTbody.innerHTML = '<tr><td colspan="5" class="loading-state">Đang tải dữ liệu kiểm kê...</td></tr>';
        if (unverifiedChipsContainer) unverifiedChipsContainer.innerHTML = '<span class="loading-state">Đang tìm IP chưa xác minh...</span>';

        try {
            const res = await fetch("/api/wazuh/inventory", { credentials: "same-origin" });
            const data = await res.json();
            renderTable(data.known_devices || []);
            renderUnverifiedChips(data.unverified_candidates || []);
        } catch (err) {
            console.error("Failed to load inventory:", err);
            if (inventoryTbody) inventoryTbody.innerHTML = '<tr><td colspan="5" class="loading-state">Không thể tải dữ liệu kiểm kê.</td></tr>';
            if (unverifiedChipsContainer) unverifiedChipsContainer.innerHTML = '<span class="loading-state">Không thể tải danh sách IP chưa xác minh.</span>';
        }
    }

    function renderTable(devices) {
        if (!inventoryTbody) return;
        if (!devices || devices.length === 0) {
            inventoryTbody.innerHTML = '<tr><td colspan="5" class="loading-state">Chưa có thiết bị nào trong known_devices.json.</td></tr>';
            return;
        }

        inventoryTbody.innerHTML = "";
        devices.forEach(d => {
            const type = String(d.type || "unknown");
            const toneClass = (type === "firewall" || type === "router") ? "level-high" : "level-low";

            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td><code class="mono">${escapeHtml(d.ip)}</code></td>
                <td><strong>${escapeHtml(d.name)}</strong></td>
                <td><span class="badge-level ${toneClass}">${escapeHtml(type.toUpperCase())}</span></td>
                <td><code class="mono">${escapeHtml(d.role || "-")}</code></td>
                <td><span class="tone-ok"><i class="fa-solid fa-user-check"></i> ${escapeHtml(d.verified_by || "manual")}</span></td>
            `;
            inventoryTbody.appendChild(tr);
        });
    }

    function renderUnverifiedChips(candidates) {
        if (!unverifiedChipsContainer) return;
        if (!candidates || candidates.length === 0) {
            unverifiedChipsContainer.innerHTML = '<span class="section-note tone-ok"><i class="fa-solid fa-circle-check"></i> Không có IP nghi vấn chưa xác minh nào!</span>';
            return;
        }

        unverifiedChipsContainer.innerHTML = "";
        candidates.forEach(c => {
            const btn = document.createElement("button");
            btn.type = "button";
            btn.className = "interactive-chip chip-medium";
            btn.innerHTML = `<i class="fa-solid fa-circle-question"></i> ${escapeHtml(c.ip)} (${escapeHtml(c.count)} alerts)`;
            btn.addEventListener("click", () => {
                inputIp.value = c.ip;
                inputName.value = `Thiết bị ${c.ip}`;
                inputRole.value = "infrastructure_device";
                setStatus("");
                inputName.focus();
            });
            unverifiedChipsContainer.appendChild(btn);
        });
    }

    confirmForm?.addEventListener("submit", async (e) => {
        e.preventDefault();
        const payload = {
            ip: inputIp.value.trim(),
            name: inputName.value.trim(),
            type: selectType.value,
            role: inputRole.value.trim(),
            verified_by: "manual"
        };

        if (!payload.ip || !payload.name) {
            setStatus("Vui lòng nhập đầy đủ IP và tên thiết bị.", "error");
            return;
        }

        try {
            const res = await fetch("/api/wazuh/inventory/confirm", {
                method: "POST",
                credentials: "same-origin",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });

            const data = await res.json();
            if (data.status === "success") {
                setStatus(`Đã xác nhận thiết bị ${payload.name} (${payload.ip}).`, "ok");
                inputIp.value = "";
                inputName.value = "";
                inputRole.value = "";
                loadInventoryData();
            } else {
                setStatus(data.message || "Không thể lưu thiết bị.", "error");
            }
        } catch (err) {
            console.error("Failed to confirm device:", err);
            setStatus("Không thể lưu thiết bị (lỗi kết nối).", "error");
        }
    });

    loadInventoryData();
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
