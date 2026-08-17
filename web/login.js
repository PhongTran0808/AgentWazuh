// AgentWazuh Single Account Auth Controller (Version 10.3 Enterprise)
document.addEventListener("DOMContentLoaded", () => {
    const loginForm = document.getElementById("login-form-v2") || document.getElementById("auth-login-form");
    const wazuhHostInput = document.getElementById("wazuh_host");
    const wazuhPortInput = document.getElementById("wazuh_port");
    const usernameInput = document.getElementById("username");
    const passwordInput = document.getElementById("password");
    const loginError = document.getElementById("login-error-msg") || document.getElementById("login-error");
    const errorText = document.getElementById("error-text");
    const btnSubmit = document.getElementById("btn-submit-login") || document.getElementById("btn-login");

    if (!loginForm) return;

    loginForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        if (loginError) loginError.classList.add("hidden");
        if (btnSubmit) {
            btnSubmit.disabled = true;
            btnSubmit.innerHTML = '<span><i class="fa-solid fa-spinner fa-spin"></i> Đang kết nối Wazuh & xác thực...</span>';
        }

        const wazuh_host = wazuhHostInput ? wazuhHostInput.value.trim() : "172.16.10.254";
        const wazuh_port = wazuhPortInput ? parseInt(wazuhPortInput.value.trim()) || 55000 : 55000;
        const username = usernameInput.value.trim();
        const password = passwordInput.value.trim();

        try {
            const res = await fetch("/api/auth/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username, password, wazuh_host, wazuh_port }),
                credentials: "same-origin"
            });

            const data = await res.json();
            if (res.ok && data.authenticated) {
                window.location.href = data.redirect || "/dashboard";
            } else {
                if (errorText) errorText.textContent = data.detail || "Tên đăng nhập hoặc mật khẩu không chính xác.";
                if (loginError) loginError.classList.remove("hidden");
            }
        } catch (err) {
            if (errorText) errorText.textContent = "Không thể kết nối đến máy chủ xác thực API.";
            if (loginError) loginError.classList.remove("hidden");
        } finally {
            if (btnSubmit) {
                btnSubmit.disabled = false;
                btnSubmit.innerHTML = '<span><i class="fa-solid fa-right-to-bracket"></i> Đăng Nhập Hệ Thống SOC</span><i class="fa-solid fa-arrow-right arrow-icon"></i>';
            }
        }
    });
});
