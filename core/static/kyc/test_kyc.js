// Show first step by default
let currentStep = 1;
showStep(currentStep);

// Show a specific step
function showStep(step) {
    document.querySelectorAll(".step-section").forEach(sec => sec.classList.remove("active-section"));
    document.querySelector(`#step-${step}`).classList.add("active-section");

    updateSidebar(step);
}

// Sidebar & progress highlight
function updateSidebar(step) {
    let allSteps = document.querySelectorAll(".kyc-step");

    allSteps.forEach((item, index) => {
        let stepNum = index + 1;
        let circle = item.querySelector(".circle");

        if (stepNum < step) {
            circle.classList.add("completed-circle");
            circle.innerHTML = "✔";
        } else {
            circle.classList.remove("completed-circle");
            circle.innerHTML = stepNum;
        }

        if (stepNum === step) {
            circle.classList.add("active-circle");
            item.classList.add("active");
        } else {
            circle.classList.remove("active-circle");
            item.classList.remove("active");
        }
    });
}

// Step navigation
document.querySelectorAll(".next-btn").forEach(btn => {
    btn.addEventListener("click", () => {
        currentStep++;
        showStep(currentStep);
    });
});

document.querySelectorAll(".back-btn").forEach(btn => {
    btn.addEventListener("click", () => {
        currentStep--;
        showStep(currentStep);
    });
});

// Clickable sidebar
document.querySelectorAll(".kyc-step").forEach(button => {
    button.addEventListener("click", () => {
        let step = button.getAttribute("data-step");
        currentStep = parseInt(step);
        showStep(currentStep);
    });
});
