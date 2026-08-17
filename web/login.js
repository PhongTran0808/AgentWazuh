// AgentWazuh Dedicated Login Page Controller (Trang 1)
document.addEventListener("DOMContentLoaded", () => {
    const loginForm = document.getElementById("login-form");
    const inputIp = document.getElementById("input-ip");
    const inputPort = document.getElementById("input-port");
    const inputUser = document.getElementById("input-user");
    const inputPass = document.getElementById("input-pass");
    const loginFeedback = document.getElementById("login-feedback");
    const btnMock = document.getElementById("btn-mock");

    // Load saved IP from localStorage
    const savedHost = localStorage.getItem("wazuh_host") || "192.168.1.240";
    inputIp.value = savedHost;

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
                    showFeedback(`🟢 Kết nối THÀNH CÔNG (${host})! Đang chuyển sang màn hình Chat...`, "success");
                } else {
                    showFeedback(`⚠️ Không thể xác thực API. Chuyển sang màn hình Chat ở Chế Độ Mock.`, "error");
                }

                setTimeout(() => {
                    window.location.href = "/dashboard";
                }, 800);
            }
        } catch (err) {
            showFeedback("❌ Lỗi kết nối tới Backend Server.", "error");
        }
    });

    btnMock.addEventListener("click", () => {
        window.location.href = "/dashboard";
    });

    function showFeedback(msg, type) {
        loginFeedback.textContent = msg;
        loginFeedback.className = `login-feedback ${type}`;
        loginFeedback.classList.remove("hidden");
    }
});
