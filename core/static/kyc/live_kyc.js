let currentStep = 1;
const maxStep = 5;
showStep(currentStep);

function showStep(step) {
    if (step < 1) step = 1;
    if (step > maxStep) step = maxStep;
    document.querySelectorAll(".step-section").forEach(s => s.classList.remove("active-section"));
    const el = document.querySelector(`#step-${step}`);
    if (el) el.classList.add("active-section");
    updateSidebar(step);
}

function updateSidebar(step) {
    let all = document.querySelectorAll(".kyc-step");
    all.forEach((it, idx) => {
        let num = idx + 1;
        let circle = it.querySelector(".circle");
        if (num < step) {
            circle.classList.add("completed-circle");
            circle.innerHTML = "✔";
            it.classList.remove("active");
        } else {
            circle.classList.remove("completed-circle");
            circle.innerHTML = num;
        }

        if (num === step) {
            circle.classList.add("active-circle");
            it.classList.add("active");
        } else {
            circle.classList.remove("active-circle");
            it.classList.remove("active");
        }
    });
    currentStep = step;
}

// next / back buttons
document.querySelectorAll(".next-btn").forEach(btn => {
    btn.addEventListener("click", () => {
        if (currentStep < maxStep) showStep(currentStep + 1);
    });
});
document.querySelectorAll(".back-btn").forEach(btn => {
    btn.addEventListener("click", () => {
        if (currentStep > 1) showStep(currentStep - 1);
    });
});

// clickable sidebar
document.querySelectorAll(".kyc-step").forEach(item => {
    item.addEventListener("click", () => {
        let step = parseInt(item.getAttribute("data-step"));
        showStep(step);
    });
});
