document.addEventListener("DOMContentLoaded", function () {
    const form = document.querySelector(".analyze-form");
    const input = document.querySelector(".url-input");
    const button = document.querySelector(".analyze-btn");
    const overlay = document.getElementById("loading-overlay");

    if (form && input && button && overlay) {
        form.addEventListener("submit", function () {
            if (input.value.trim() !== "") {
                button.disabled = true;
                overlay.classList.remove("hidden");
            }
        });
    }
});