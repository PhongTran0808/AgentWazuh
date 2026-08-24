// AgentWazuh Device Inventory Controller (TẦNG 0 Ground Truth)
document.addEventListener("DOMContentLoaded", () => {
    const inventoryTbody = document.getElementById("inventory-tbody");
    const unverifiedChipsContainer = document.getElementById("unverified-chips-container");
    const confirmForm = document.getElementById("confirm-device-form");
    const btnBackDash = document.getElementById("btn-back-dash");
    const btnOpenNetmap = document.getElementById("btn-open-netmap");
    const btnRefresh = document.getElementById("btn-refresh-inv");

    const inputIp = document.getElementById("form-ip");
    const inputName = document.getElementById("form-name");
    const selectType = document.getElementById("form-type");
    const inputRole = document.getElementById("form-role");

    btnBackDash?.addEventListener("click", () => {
        window.location.href = "/dashboard";
    });

    btnOpenNetmap?.addEventListener("click", () => {
        window.location.href = "/network-map";
    });

    btnRefresh?.addEventListener("click", () => {
        loadInventoryData();
    });

    async function loadInventoryData() {
        if (inventoryTbody) inventoryTbody.innerHTML = '<tr><td colspan="5" class="loading-state">Đang tải dữ liệu kiểm kê...</td></tr>';
        if (unverifiedChipsContainer) unverifiedChipsContainer.innerHTML = '<span class="loading-state">Đang tìm IP chưa xác minh...</span>';

        try {
            const res = await fetch("/api/wazuh/inventory");
            const data = await res.json();
            renderTable(data.known_devices || []);
            renderUnverifiedChips(data.unverified_candidates || []);
        } catch (err) {
            inventoryTbody.innerHTML = '<tr><td colspan="5" class="loading-state">Không thể tải dữ liệu kiểm kê.</td></tr>';
        }
    }

    function renderTable(devices) {
        if (!devices || devices.length === 0) {
            inventoryTbody.innerHTML = '<tr><td colspan="5" class="loading-state">Chưa có thiết bị nào trong known_devices.json.</td></tr>';
            return;
        }

        inventoryTbody.innerHTML = "";
        devices.forEach(d => {
            const tr = document.createElement("tr");
            let typeBadge = `<span class="badge-level level-low">${d.type.toUpperCase()}</span>`;
            if (d.type === "firewall" || d.type === "router") {
                typeBadge = `<span class="badge-level level-high">${d.type.toUpperCase()}</span>`;
            }

            tr.innerHTML = `
                <td><code>${d.ip}</code></td>
                <td><strong>${d.name}</strong></td>
                <td>${typeBadge}</td>
                <td><code>${d.role || "-"}</code></td>
                <td><span style="color: #10b981;"><i class="fa-solid fa-user-check"></i> ${d.verified_by || "manual"}</span></td>
            `;
            inventoryTbody.appendChild(tr);
        });
    }

    function renderUnverifiedChips(candidates) {
        if (!candidates || candidates.length === 0) {
            unverifiedChipsContainer.innerHTML = '<span style="font-size: 0.8rem; color: #10b981;"><i class="fa-solid fa-circle-check"></i> Không có IP nghi vấn chưa xác minh nào!</span>';
            return;
        }

        unverifiedChipsContainer.innerHTML = "";
        candidates.forEach(c => {
            const btn = document.createElement("button");
            btn.className = "interactive-chip chip-medium";
            btn.style.margin = "0.2rem";
            btn.innerHTML = `<i class="fa-solid fa-circle-question"></i> ${c.ip} (${c.count} alerts)`;
            btn.addEventListener("click", () => {
                inputIp.value = c.ip;
                inputName.value = `Thiết bị ${c.ip}`;
                inputRole.value = "infrastructure_device";
            });
            unverifiedChipsContainer.appendChild(btn);
        });
    }

    confirmForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const payload = {
            ip: inputIp.value.trim(),
            name: inputName.value.trim(),
            type: selectType.value,
            role: inputRole.value.trim(),
            verified_by: "manual"
        };

        if (!payload.ip || !payload.name) return;

        try {
            const res = await fetch("/api/wazuh/inventory/confirm", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });

            const data = await res.json();
            if (data.status === "success") {
                alert(`🟢 Đã xác nhận thiết bị ${payload.name} (${payload.ip}) thành công!`);
                inputIp.value = "";
                inputName.value = "";
                inputRole.value = "";
                loadInventoryData();
            }
        } catch (err) {
            alert("❌ Không thể lưu thiết bị.");
        }
    });

    loadInventoryData();
});
