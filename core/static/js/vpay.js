/* vpay.js — Full drop-in (CSS included).  */
(function () {
  /* ---------------- Styles (single injection) ---------------- */
  const CSS_ID = "vpay-styles-v4";
  const styles = `
/* === OVERLAY & MODAL === */
.vpay-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,0.55);
  display:flex;
  align-items:center;
  justify-content:center;
  backdrop-filter: blur(8px) saturate(1.2);
  z-index: 999999;
}

.vpay-modal {
  width: 860px;
  max-width: 96%;
  border-radius: 24px;
  overflow:hidden;
  background: #ffffff;
  display: flex;
  animation: vpayModalPop .3s cubic-bezier(.2,.9,.2,1);
  box-shadow: 0 28px 80px rgba(0,0,0,0.28);
  position: relative;
}

@keyframes vpayModalPop {
  from { opacity: 0; transform: scale(.92) translateY(10px); }
  to   { opacity: 1; transform: scale(1) translateY(0); }
}

/* GRID WRAP */
.vpay-modal-wrap {
  display: grid;
  grid-template-columns: 300px 1fr;
  width: 100%;
  min-height: 520px;
}

/* CLOSE BUTTON */
.vpay-close-new {
  position:absolute;
  top:14px;
  right:14px;
  width:40px;height:40px;
  border-radius:12px;
  background:#f2f4f7;
  display:flex;align-items:center;justify-content:center;
  font-size:18px;
  cursor:pointer;
  transition:.2s ease;
}
.vpay-close-new:hover {
  background:#e5e7eb;
  transform:scale(1.12);
}

/* === LEFT PANEL === */
.vpay-left {
  padding: 26px 24px;
  display:flex;
  flex-direction:column;
  gap:22px;
  background: linear-gradient(180deg,#fff9f3,#ffe7d2);
  position:relative;
}

.vpay-left::after {
  content:"";
  position:absolute;
  bottom:0;
  left:0;
  width:100%;
  height:180px;
  background-image:url("/static/images/phonepe.png"); /* replace if you like */
  background-repeat:no-repeat;
  background-size:150px;
  background-position:center bottom;
  opacity:0.15;
  pointer-events:none;
}

/* Merchant info */
.vpay-left-merchant {
  display: flex;
  align-items: center;
  gap: 14px;
}

.vpay-logo {
  width:52px;
  height:52px;
  border-radius:16px;
  background:white;
  padding:6px;
  box-shadow:0 4px 12px rgba(0,0,0,0.18);
  object-fit:contain;
}

.vpay-merchant {
  font-weight:700;
  font-size:16px;
  color:#0f172a;
}

.vpay-sub {
  font-size:12px;
  color:#6b7280;
}

/* Amount card */
.vpay-left-amount {
  padding:14px;
  background:white;
  border-radius:16px;
  box-shadow:0 6px 18px rgba(0,0,0,0.08);
  text-align:left;
  font-size:14px;
}
.vpay-order {
  color:#64748b;
  font-size:13px;
}
.vpay-amount {
  margin-top:4px;
  font-weight:800;
  font-size:18px;
  color:#ff6a00;
}

/* Left tabs */
.vpay-tabs-left {
  display:flex;
  flex-direction:column;
  gap:12px;
  margin-top:20px;
}

.vpay-tab {
  padding:12px 16px;
  border-radius:14px;
  background:white;
  border:1px solid #e5e7eb;
  font-weight:600;
  display:flex;
  align-items:center;
  gap:10px;
  cursor:pointer;
  transition:.22s ease;
  font-size:14px;
  color:#111827;
}

.vpay-tab:hover {
  background:#fff4ea;
  border-color:#ff8a3d;
  transform:translateX(6px);
}

.vpay-tab.active {
  background:#ff6a00;
  color:white;
  border:none;
  transform:translateX(8px);
  box-shadow:0 6px 18px rgba(255,106,0,0.38);
}

/* === RIGHT PANEL === */
.vpay-right {
  padding:34px;
  animation:vpaySlideIn .35s ease;
}
@keyframes vpaySlideIn {
  from { opacity:0; transform: translateX(30px); }
  to   { opacity:1; transform: translateX(0); }
}

.vpay-section {
  max-width: 420px;
  margin: 0 auto;
  padding-top: 10px;
}

.vpay-title {
  font-size: 20px;
  font-weight: 700;
  margin-bottom: 14px;
  color: #0f172a;
}

/* Inputs & buttons */
.vpay-input {
  background:white;
  border-radius:14px;
  padding:14px;
  border:1px solid #d0d5dd;
  transition:.25s ease;
  width:100%;
  font-size:14px;
  outline:none;
}
.vpay-input:focus {
  border-color:#ff6a00;
  box-shadow:0 0 0 4px rgba(255,106,0,0.25);
}

.vpay-btn {
  background:#ff6a00;
  color:white;
  font-weight:700;
  padding:14px;
  border-radius:14px;
  box-shadow:0 6px 18px rgba(255,106,0,0.25);
  transition:.2s ease;
  border:none;
  cursor:pointer;
  width:100%;
}
.vpay-btn:hover {
  transform:translateY(-3px);
  box-shadow:0 10px 28px rgba(255,106,0,0.32);
}
.vpay-btn:active {
  transform:translateY(1px);
}
.vpay-ghost {
  background:#fff;
  color:#111827;
  box-shadow:none;
  border:1px solid #e5e7eb;
}

/* Card logos */
.vpay-card-logos img {
  width: 46px;
  height: 30px;
  object-fit: contain;
  margin-right: 8px;
}

/* Card box */
.vpay-card-box {
  background: white;
  padding: 16px;
  border-radius: 18px;
  box-shadow: 0 6px 16px rgba(0,0,0,0.06);
  display:flex;
  flex-direction:column;
  gap:12px;
}

/* Checkbox row */
.vpay-check-row {
  display:flex;
  align-items:center;
  gap:10px;
  color:#475569;
  margin:8px 0;
  font-size:13px;
}

/* UPI apps */
.vpay-upi-apps {
  display:flex;
  gap:12px;
  margin-bottom:14px;
}
.vpay-upi-apps img {
  width:48px;
  height:48px;
  object-fit:contain;
  border-radius:12px;
  background:#fff;
  padding:6px;
  box-shadow:0 4px 10px rgba(0,0,0,.06);
}

/* NETBANKING */
.vpay-netbanking {
  display:flex;
  flex-direction:column;
  gap:22px;
}
.vpay-nb-title {
  font-size: 20px;
  font-weight: 700;
  color: #0f172a;
  margin-bottom: 5px;
}
.vpay-nb-grid {
  display:grid;
  grid-template-columns: repeat(auto-fill, minmax(120px, 1fr));
  gap: 14px;
}
.vpay-bank-card {
  background: #ffffff;
  border-radius: 14px;
  padding: 14px 10px;
  text-align: center;
  box-shadow: 0 4px 14px rgba(0,0,0,0.05);
  cursor: pointer;
  transition: .25s ease;
  border: 2px solid transparent;
}
.vpay-bank-card img {
  width: 42px;
  height: 42px;
  object-fit: contain;
  margin-bottom: 6px;
}
.vpay-bank-card span {
  display: block;
  font-size: 14px;
  font-weight: 600;
}
.vpay-bank-card:hover {
  transform: translateY(-3px);
  box-shadow: 0 6px 20px rgba(255,106,0,0.22);
}
.vpay-bank-card.active {
  border-color: #ff6a00;
  box-shadow: 0 8px 28px rgba(255,106,0,0.30);
  transform: translateY(-4px);
}
.vpay-nb-other-title {
  font-size: 15px;
  font-weight: 600;
  color: #334155;
}
.vpay-nb-row {
  display:flex;
  align-items:center;
  gap:12px;
}

/* Wallets */
.vpay-wallet {
  display:flex;
  align-items:center;
  gap:12px;
  margin-bottom:14px;
}
.vpay-wallet img {
  width:46px;
  height:46px;
  object-fit:contain;
  border-radius:12px;
  background:white;
  padding:6px;
  box-shadow:0 4px 12px rgba(0,0,0,.06);
}

/* QR + OTP + loader + result */
.vpay-qr-wrap { display:flex; flex-direction:column; align-items:center; gap:12px; }
.vpay-qr-img { width:200px; height:200px; border-radius:12px; background:#fff; box-shadow:0 8px 26px rgba(9,13,20,0.06); object-fit:contain; }

.vpay-otp { display:flex; gap:10px; justify-content:center; margin-top:8px; }
.vpay-otp input { width:52px; height:52px; font-size:20px; text-align:center; border-radius:10px; border:1px solid #e6eef3; }

.vpay-loader { display:flex; gap:14px; align-items:center; justify-content:center; flex-direction:column; padding:26px 12px; }
.vpay-spinner { width:46px; height:46px; border-radius:50%; border:5px solid rgba(15,23,42,0.08); border-top-color:#FF6A00; animation:vpaySpin 0.95s linear infinite; }
@keyframes vpaySpin { to { transform: rotate(360deg); } }

.vpay-check { width:120px; height:120px; border-radius:60px; background: linear-gradient(180deg,#fff,#fff); display:flex; align-items:center; justify-content:center; margin:8px auto; box-shadow: 0 14px 40px rgba(8,12,20,0.07); }
.vpay-success-title { font-weight:900; font-size:18px; text-align:center; margin-top:6px; }
.vpay-success-sub { text-align:center; color:#475569; margin-top:6px; font-size:13px; }
.vpay-muted { color:#64748b; font-size:13px; text-align:center; margin-top:8px; }

.vpay-fail { text-align:center; padding:18px; }
.vpay-fail .icon { font-size:52px; color:#ef4444; margin-top:6px; }
.vpay-fail-title { font-weight:800; font-size:18px; margin-top:6px; }
.vpay-fail-sub { color:#475569; margin-top:4px; font-size:13px; }

/* Close-confirm sheet (Option B) */
.vpay-close-confirm-backdrop {
  position:absolute;
  inset:0;
  background:rgba(15,23,42,0.45);
  display:flex;
  align-items:center;
  justify-content:center;
  z-index:50;
}
.vpay-close-confirm {
  background:#fff;
  border-radius:18px;
  padding:18px 20px 14px;
  max-width:340px;
  width:90%;
  box-shadow:0 18px 45px rgba(15,23,42,0.35);
}
.vpay-close-confirm-title {
  font-weight:800;
  font-size:16px;
  margin-bottom:4px;
  color:#0f172a;
}
.vpay-close-confirm-text {
  font-size:13px;
  color:#64748b;
  margin-bottom:14px;
}
.vpay-close-confirm-actions {
  display:flex;
  gap:10px;
  justify-content:flex-end;
}
.vpay-close-confirm-actions .vpay-btn {
  width:auto;
  padding-inline:14px;
  font-size:13px;
}

/* Responsive */
@media (max-width:720px){
  .vpay-modal { width:100%; height:100%; border-radius:0; }
  .vpay-modal-wrap { grid-template-columns: 1fr; }
  .vpay-left { min-height:220px; }
}
`;

  if (!document.getElementById(CSS_ID)) {
    const s = document.createElement("style");
    s.id = CSS_ID;
    s.innerHTML = styles;
    document.head.appendChild(s);
  }

  /* ---------------- Utilities ---------------- */
  function qs(sel, root = document) {
    return root.querySelector(sel);
  }
  function qsa(sel, root = document) {
    return Array.from((root || document).querySelectorAll(sel));
  }
  function formatAmountCents(a, cur) {
    const amt = Number(a || 0) / 100;
    if ((cur || "INR").toUpperCase() === "INR") return "₹" + amt.toFixed(2);
    return amt.toFixed(2) + " " + (cur || "");
  }

  function getCookie(name) {
    const match = document.cookie.match("(^|;)\\s*" + name + "\\s*=\\s*([^;]+)");
    return match ? match.pop() : "";
  }

  async function postJsonWithCsrf(url, payload) {
    const csrftoken = getCookie("csrftoken");
    const res = await fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        "X-CSRFToken": csrftoken || "",
      },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const text = (await res.text().catch(() => "")) || "";
      console.error(
        "postJsonWithCsrf non-OK",
        url,
        res.status,
        text.slice(0, 500)
      );
      throw new Error(
        `Request to ${url} failed: ${res.status} ${res.statusText}\n${text.slice(
          0,
          500
        )}`
      );
    }
    return await res.json();
  }

  function overlayFor(modal) {
    return modal && modal.parentNode;
  }

  /* --- track whether user has typed/selected anything --- */
  let hasUserInput = false;

  function markDirtyOnInput(root) {
    if (!root) return;
    qsa("input, select, textarea", root).forEach((el) => {
      if (el._vpayDirtyHooked) return;
      el._vpayDirtyHooked = true;
      const mark = () => {
        if (el.value && String(el.value).trim() !== "") {
          hasUserInput = true;
        }
      };
      el.addEventListener("input", mark);
      el.addEventListener("change", mark);
    });
  }

  /* ---------------- Confetti ---------------- */
  function simpleConfetti(modal) {
    const canvas = document.createElement("canvas");
    canvas.style.position = "absolute";
    canvas.style.inset = "0";
    canvas.style.pointerEvents = "none";
    modal.appendChild(canvas);
    const ctx = canvas.getContext("2d");
    function resize() {
      canvas.width = modal.clientWidth;
      canvas.height = modal.clientHeight;
    }
    resize();
    window.addEventListener("resize", resize);
    const pieces = [];
    const colors = [
      "#FF6A00",
      "#FFB07A",
      "#FFD8B5",
      "#FF3B30",
      "#22c55e",
      "#9b5cff",
    ];
    for (let i = 0; i < 40; i++)
      pieces.push({
        x: Math.random() * canvas.width,
        y: -Math.random() * canvas.height,
        w: 6 + Math.random() * 10,
        h: 8 + Math.random() * 10,
        vx: -1 + Math.random() * 2,
        vy: 2 + Math.random() * 5,
        color: colors[Math.floor(Math.random() * colors.length)],
        rot: Math.random() * 360,
        rotV: -6 + Math.random() * 12,
      });
    let raf = 0;
    function draw() {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      for (const p of pieces) {
        p.x += p.vx;
        p.y += p.vy;
        p.rot += p.rotV;
        ctx.save();
        ctx.translate(p.x, p.y);
        ctx.rotate((p.rot * Math.PI) / 180);
        ctx.fillStyle = p.color;
        ctx.fillRect(-p.w / 2, -p.h / 2, p.w, p.h);
        ctx.restore();
        if (p.y > canvas.height + 20) {
          p.y = -20;
          p.x = Math.random() * canvas.width;
        }
      }
      raf = requestAnimationFrame(draw);
    }
    draw();
    setTimeout(() => {
      cancelAnimationFrame(raf);
      canvas.remove();
      window.removeEventListener("resize", resize);
    }, 3000);
  }

  /* -------- Close confirmation (Option B) -------- */
  function showCloseConfirm(modal, onConfirm) {
    if (qs(".vpay-close-confirm-backdrop", modal)) return;
    const wrap = document.createElement("div");
    wrap.className = "vpay-close-confirm-backdrop";
    wrap.innerHTML = `
      <div class="vpay-close-confirm">
        <div class="vpay-close-confirm-title">Cancel this payment?</div>
        <div class="vpay-close-confirm-text">
          Your current payment details will be discarded. You can reopen checkout and try again anytime.
        </div>
        <div class="vpay-close-confirm-actions">
          <button class="vpay-btn vpay-ghost" id="vpayCloseStay">Continue payment</button>
          <button class="vpay-btn" id="vpayCloseDiscard">Discard &amp; close</button>
        </div>
      </div>
    `;
    modal.appendChild(wrap);
    qs("#vpayCloseStay", wrap).onclick = () => {
      wrap.remove();
    };
    qs("#vpayCloseDiscard", wrap).onclick = () => {
      wrap.remove();
      if (typeof onConfirm === "function") onConfirm();
    };
  }

  function handleCloseClick(modal) {
    if (!hasUserInput) {
      overlayRemove(modal);
      return;
    }
    showCloseConfirm(modal, () => {
      overlayRemove(modal);
    });
  }

  /* ---------------- Core: Open Checkout ---------------- */
  window.VPayCheckout = function (options = {}) {
    const endpoints = {
      createPayment:
        options.createPaymentEndpoint || "/api/v1/create-payment/",
      capture: options.captureEndpoint || "/api/v1/capture-payment/",
      upi: options.upiEndpoint || "/api/v1/create-upi-collect/",
      netbanking:
        options.netbankingEndpoint || "/api/v1/create-netbanking/",
      getQr: options.getQREndpoint || "/api/v1/get-qr/",
      status: options.paymentStatusEndpoint || "/api/v1/payment-status/",
      verifyOtp: options.verifyOtpEndpoint || "/api/v1/verify-otp/",
    };

    const overlay = document.createElement("div");
    overlay.className = "vpay-overlay";
    const modal = document.createElement("div");
    modal.className = "vpay-modal";

    modal.innerHTML = `
      <div class="vpay-modal-wrap">

        <!-- LEFT PANEL -->
        <div class="vpay-left">
          <div class="vpay-left-merchant">
            <img class="vpay-logo" id="vpayLogo" src="" alt="logo" />
            <div>
              <div class="vpay-merchant" id="vpayMerchant">VPay</div>
              <div class="vpay-sub" id="vpaySub">Secure payment</div>
            </div>
          </div>

          <div class="vpay-left-amount">
            <div class="vpay-order" id="vpayOrder">Order</div>
            <div class="vpay-amount" id="vpayAmount">Loading…</div>
          </div>

          <div class="vpay-tabs vpay-tabs-left" role="tablist">
            <div class="vpay-tab active" data-tab="card">💳 Card</div>
            <div class="vpay-tab" data-tab="upi">🔗 UPI</div>
            <div class="vpay-tab" data-tab="netbanking">🏦 Netbanking</div>
            <div class="vpay-tab" data-tab="wallets">👛 Wallets</div>
            <div class="vpay-tab" data-tab="qr">🔲 QR</div>
          </div>
        </div>

        <!-- RIGHT PANEL -->
        <div class="vpay-right">
          <div id="vpayInnerBody" class="vpay-right-body">
            ${getTabHTML("card")}
          </div>
        </div>

        <div class="vpay-close-new" id="vpayClose">✕</div>
      </div>
    `;

    overlay.appendChild(modal);
    document.body.appendChild(overlay);

    /* close = option-B confirm */
    const closeBtn = qs("#vpayClose", modal);
    if (closeBtn) {
      closeBtn.onclick = () => handleCloseClick(modal);
    }

    // track inputs on initial tab
    markDirtyOnInput(modal);

    // Create payment session
    postJsonWithCsrf(endpoints.createPayment, {
      key: options.key,
      amount: options.amount,
      currency: options.currency || "INR",
      customer: options.customer || {},
    })
      .then((data) => {
        if (!data || data.success !== true) {
          showFailure(modal, {
            message:
              (data && data.message) || "Unable to create payment session",
            callback_url: options.callback_url,
          });
          return;
        }

        const mName = data.merchant_name || "VPay Merchant";
        const mLogo = data.merchant_logo || "";
        qs("#vpayMerchant", modal).innerText = mName;
        qs("#vpaySub", modal).innerText =
          data.merchant_tagline || "Secure payment";
        qs("#vpayLogo", modal).src = mLogo || fallbackDataUri(mName);
        qs("#vpayAmount", modal).innerText = formatAmountCents(
          data.amount,
          data.currency || options.currency
        );
        qs("#vpayOrder", modal).innerText =
          (data.order_id && `Order • ${data.order_id}`) || "Order";

        options._session = {
          id: data.payment_session_id,
          amount: data.amount,
          currency: data.currency,
        };

        loadTabs(modal, overlay, options, endpoints);
      })
      .catch((err) => {
        console.error("create-payment error", err);
        showFailure(modal, {
          message: "Network error creating payment",
          retryCallback: () => {
            overlayRemove(modal);
            setTimeout(() => window.VPayCheckout(options), 200);
          },
        });
      });
  };

  /* ---------------- Tabs wiring ---------------- */
  function loadTabs(modal, overlay, options, endpoints) {
    const tabs = qsa(".vpay-tab", modal);
    tabs.forEach((tab) => {
      tab.onclick = () => {
        tabs.forEach((t) => t.classList.remove("active"));
        tab.classList.add("active");

        const inner = qs("#vpayInnerBody", modal);
        inner.innerHTML = getTabHTML(tab.dataset.tab || "card");

        // whenever we render a new tab, hook input listeners
        markDirtyOnInput(inner);

        if (tab.dataset.tab === "qr" && typeof attachQrHandlers === "function") {
          attachQrHandlers(modal, options, endpoints);
        }

        wireTabActions(modal, overlay, options, endpoints);
      };
    });

    wireTabActions(modal, overlay, options, endpoints);
  }

  /* ---------------- Tab HTML ---------------- */
  function getTabHTML(tab) {
    const visa = "/static/images/visa.png";
    const mc = "/static/images/master.png";
    const rupay = "/static/images/rupay.png";

    const gpay = "/static/images/gpay.png";
    const phonepe = "/static/images/phonepe.png";
    const paytm = "/static/images/phonepe.png";
    const bhim = "/static/images/phonepe.png";

    const wallet_paytm = "/static/images/phonepe.png";
    const wallet_mobikwik = "/static/images/phonepe.png";
    const wallet_amazon = "/static/images/phonepe.png";

    if (tab === "card") {
      return `
        <div class="vpay-section">
          <div class="vpay-title">Add New Card</div>
          <div class="vpay-card-logos">
            <img src="${visa}" alt="Visa" />
            <img src="${mc}" alt="Mastercard" />
            <img src="${rupay}" alt="RuPay" />
          </div>

          <div class="vpay-card-box">
            <input class="vpay-input" id="vpay_card_pan" placeholder="Card Number (XXXX XXXX XXXX 4242)" inputmode="numeric" />
            <div style="display:flex;gap:12px;">
              <input class="vpay-input" id="vpay_card_exp" placeholder="MM/YY" style="flex:1" />
              <input class="vpay-input" id="vpay_card_cvv" placeholder="CVV" style="flex:1" inputmode="numeric" />
            </div>
            <label class="vpay-check-row">
              <input type="checkbox" />
              <span>Save this card securely</span>
            </label>
            <button class="vpay-btn" id="vpay_card_pay">Pay Securely</button>
            <div class="vpay-muted" style="margin-top:6px;">Sandbox: card is simulated — OTP may be required.</div>
          </div>
        </div>
      `;
    }

    if (tab === "upi") {
      return `
        <div class="vpay-section">
          <div class="vpay-title">Pay Using UPI App</div>
          <div class="vpay-upi-apps">
            <img src="${gpay}" alt="GPay" />
            <img src="${phonepe}" alt="PhonePe" />
            <img src="${paytm}" alt="Paytm" />
            <img src="${bhim}" alt="BHIM" />
          </div>
          <div style="margin:12px 0;color:#475569;font-weight:600;">or Enter UPI ID</div>
          <input class="vpay-input" id="vpay_upi_id" placeholder="example@upi" />
          <button class="vpay-btn" id="vpay_upi_pay">Pay via UPI</button>
        </div>
      `;
    }

    if (tab === "netbanking") {
      return `
        <div class="vpay-netbanking">
          <h3 class="vpay-nb-title">Choose Your Bank</h3>

          <div class="vpay-nb-grid">
            <div class="vpay-bank-card" data-bank="sbi">
              <img src="${phonepe}" alt="SBI" />
              <span>SBI</span>
            </div>
            <div class="vpay-bank-card" data-bank="hdfc">
              <img src="${phonepe}" alt="HDFC" />
              <span>HDFC</span>
            </div>
            <div class="vpay-bank-card" data-bank="icici">
              <img src="${phonepe}" alt="ICICI" />
              <span>ICICI</span>
            </div>
            <div class="vpay-bank-card" data-bank="axis">
              <img src="${phonepe}" alt="Axis" />
              <span>Axis</span>
            </div>
          </div>

          <div class="vpay-nb-other-title">Other Banks</div>
          <div class="vpay-nb-row">
            <select class="vpay-input" id="vpay_bank_select">
              <option value="">Select Bank</option>
              <option value="sbi">State Bank of India</option>
              <option value="hdfc">HDFC Bank</option>
              <option value="icici">ICICI Bank</option>
              <option value="axis">Axis Bank</option>
              <option value="kotak">Kotak Mahindra Bank</option>
            </select>
            <button class="vpay-btn" id="vpay_netbank_pay">Proceed</button>
          </div>
        </div>
      `;
    }

    if (tab === "wallets") {
      return `
        <div class="vpay-section">
          <div class="vpay-title">Select Wallet</div>

          <div class="vpay-wallet">
            <img src="${wallet_paytm}" alt="Paytm Wallet"/>
            <button class="vpay-btn" id="vpay_wallet_paytm">Pay with Paytm Wallet</button>
          </div>

          <div class="vpay-wallet">
            <img src="${wallet_mobikwik}" alt="Mobikwik"/>
            <button class="vpay-btn vpay-ghost" id="vpay_wallet_mobikwik">Mobikwik Wallet</button>
          </div>

          <div class="vpay-wallet">
            <img src="${wallet_amazon}" alt="Amazon Pay"/>
            <button class="vpay-btn vpay-ghost" id="vpay_wallet_amazon">Amazon Pay</button>
          </div>
        </div>
      `;
    }

    if (tab === "qr") {
      return `
        <div class="vpay-section" style="text-align:center;">
          <div class="vpay-title">Scan & Pay</div>
          <form id="quickPayForm" style="display:flex;flex-direction:column;gap:12px;">
            <input name="to_upi" class="vpay-input" placeholder="UPI ID or Phone" />
            <input name="amount" class="vpay-input" placeholder="Amount" inputmode="decimal" />
            <button class="vpay-btn" type="submit">Generate QR</button>
          </form>
          <div id="qrContainer" style="display:none;margin-top:20px;">
            <canvas id="upiQr" width="240" height="240" style="border-radius:12px;background:white;box-shadow:0 6px 16px rgba(0,0,0,.08)"></canvas>
            <button id="downloadQrBtn" class="vpay-btn vpay-ghost" style="margin-top:12px;">Download QR</button>
          </div>
        </div>
      `;
    }

    return `<div>Unsupported Method</div>`;
  }

  /* ---------------- QR handlers ---------------- */
  function attachQrHandlers(modal, options, endpoints) {
    const quickForm = qs("#quickPayForm", modal);
    const qrContainer = qs("#qrContainer", modal);
    const downloadBtn = qs("#downloadQrBtn", modal);
    const qrCanvas = qs("#upiQr", modal);

    function genTxnNum() {
      return (
        "TXN" +
        Date.now().toString().slice(-8) +
        Math.random().toString(16).slice(2, 9).toUpperCase()
      );
    }

    function buildUpiUri({ pa, pn = "", amount = "", tn = "" } = {}) {
      const q = new URLSearchParams();
      if (pa) q.set("pa", pa);
      if (pn) q.set("pn", pn);
      if (amount) q.set("am", amount);
      if (tn) q.set("tn", tn);
      return `upi://pay?${q.toString()}`;
    }

    function generateQrCode(text) {
      if (!qrCanvas || !qrContainer) return;

      qrContainer.style.display = "block";

      try {
        if (typeof QRious !== "undefined") {
          new QRious({
            element: qrCanvas,
            value: text,
            size: 220,
          });
          return;
        }
      } catch (e) {
        console.warn("QRious failed", e);
      }

      const ctx = qrCanvas.getContext("2d");
      ctx.clearRect(0, 0, 220, 220);
      ctx.fillStyle = "#333";
      ctx.font = "14px Arial";
      ctx.fillText("QR library missing", 40, 110);
    }

    if (quickForm) {
      quickForm.addEventListener("submit", async function (e) {
        e.preventDefault();
        const to_upi = (quickForm.elements["to_upi"]?.value || "").trim();
        const amount = (quickForm.elements["amount"]?.value || "").trim();
        if (!to_upi || !amount) {
          alert("Please enter UPI and amount");
          return;
        }

        const txnNum = genTxnNum();
        try {
          localStorage.setItem("pending_txn", txnNum);
        } catch (err) {}

        const upiLink = buildUpiUri({
          pa: to_upi,
          pn: "Customer",
          amount: amount,
          tn: txnNum,
        });
        generateQrCode(upiLink);
        if (qrContainer) qrContainer.style.display = "block";

        try {
          await postJsonWithCsrf(endpoints.capture, {
            payment_session_id: options._session.id,
            method: "upi",
            upi_id: to_upi,
            amount: Math.round(Number(amount) * 100),
            txn_ref: txnNum,
          });
        } catch (err) {
          console.warn(
            "Backend order/create failed (optional). QR generated locally.",
            err
          );
        }
      });
    }

    if (downloadBtn && qrCanvas) {
      downloadBtn.addEventListener("click", () => {
        const url = qrCanvas.toDataURL("image/png");
        const a = document.createElement("a");
        a.download = "upi_qr.png";
        a.href = url;
        a.click();
      });
    }
  }

  /* ---------------- Wire actions per tab ---------------- */
  function wireTabActions(modal, overlay, options, endpoints) {
    /* ensure inputs are watched */
    markDirtyOnInput(modal);

    /* CARD */
    const cardBtn = qs("#vpay_card_pay", modal);
    if (cardBtn) {
      cardBtn.onclick = () => {
        const pan = (qs("#vpay_card_pan", modal)?.value || "").replace(
          /\s+/g,
          ""
        );
        const exp = qs("#vpay_card_exp", modal)?.value || "";
        const cvv = qs("#vpay_card_cvv", modal)?.value || "";
        if (!pan || pan.length < 12) {
          alert("Enter valid card number");
          return;
        }
        if (!exp) {
          alert("Enter expiry");
          return;
        }
        if (!cvv || cvv.length < 3) {
          alert("Enter CVV");
          return;
        }

        showInterim(modal, "Authorizing card…");

        postJsonWithCsrf(endpoints.capture, {
          payment_session_id: options._session.id,
          method: "card",
          card_last4: pan.slice(-4),
        })
          .then((resp) => {
            handleCaptureResponse(modal, options, endpoints, resp);
          })
          .catch((err) => {
            console.error("card capture err", err);
            showFailure(modal, {
              message: "Network error",
              retryCallback: () =>
                wireTabActions(modal, overlay, options, endpoints),
            });
          });
      };
    }

    /* UPI */
    const upiBtn = qs("#vpay_upi_pay", modal);
    if (upiBtn) {
      upiBtn.onclick = () => {
        const upi = (qs("#vpay_upi_id", modal)?.value || "").trim();
        if (!upi) {
          alert("Enter UPI ID");
          return;
        }
        showInterim(modal, "Creating UPI request…");
        postJsonWithCsrf(endpoints.capture, {
          payment_session_id: options._session.id,
          method: "upi",
          upi_id: upi,
        })
          .then((resp) => {
            handleCaptureResponse(modal, options, endpoints, resp);
          })
          .catch((err) => {
            console.error(err);
            showFailure(modal, {
              message: "Network error",
              retryCallback: () =>
                wireTabActions(modal, overlay, options, endpoints),
            });
          });
      };
    }

    /* NETBANKING */
    const netBtn = qs("#vpay_netbank_pay", modal);
    if (netBtn) {
      const bankSelect = qs("#vpay_bank_select", modal);
      const bankCards = qsa(".vpay-bank-card", modal);

      // clicking image cards sets active + syncs dropdown
      if (bankCards.length) {
        bankCards.forEach((card) => {
          card.onclick = () => {
            bankCards.forEach((c) => c.classList.remove("active"));
            card.classList.add("active");
            const v = card.dataset.bank || "";
            if (bankSelect) bankSelect.value = v;
          };
        });
      }

      netBtn.onclick = () => {
        const activeCard = qs(".vpay-bank-card.active", modal);
        const bankFromCard = activeCard ? activeCard.dataset.bank : "";
        const bankFromSelect = bankSelect ? bankSelect.value : "";
        const bank = bankFromCard || bankFromSelect;

        if (!bank) {
          alert("Select a bank");
          return;
        }
        showInterim(modal, "Redirecting to bank…");
        postJsonWithCsrf(endpoints.capture, {
          payment_session_id: options._session.id,
          method: "netbanking",
          bank,
        })
          .then((resp) => {
            handleCaptureResponse(modal, options, endpoints, resp);
            if (resp && resp.redirect_url) {
              try {
                window.open(resp.redirect_url, "_blank");
              } catch (e) {}
            }
          })
          .catch((err) => {
            console.error(err);
            showFailure(modal, {
              message: "Network error",
              retryCallback: () =>
                wireTabActions(modal, overlay, options, endpoints),
            });
          });
      };
    }

    /* WALLETS – all three clickable */
    ["paytm", "mobikwik", "amazon"].forEach((name) => {
      const btn = qs("#vpay_wallet_" + name, modal);
      if (!btn) return;
      btn.onclick = () => {
        showInterim(modal, "Processing wallet…");
        postJsonWithCsrf(endpoints.capture, {
          payment_session_id: options._session.id,
          method: "wallet",
          wallet: name,
        })
          .then((resp) => {
            handleCaptureResponse(modal, options, endpoints, resp);
          })
          .catch((err) => {
            console.error(err);
            showFailure(modal, {
              message: "Network error",
              retryCallback: () =>
                wireTabActions(modal, overlay, options, endpoints),
            });
          });
      };
    });

    /* QR dynamic handler if needed */
    if (qs("#quickPayForm", modal)) {
      attachQrHandlers(modal, options, endpoints);
    }
  }

  /* ---------------- Capture response handler ---------------- */
  function handleCaptureResponse(modal, options, endpoints, resp) {
    if (!resp) {
      showFailure(modal, { message: "Empty response" });
      return;
    }
    if (resp.success) {
      showSuccess(modal, {
        payment_id:
          resp.payment_id || resp.payment_session_id || options._session.id,
        amount: options._session.amount,
        currency: options._session.currency,
        callback_url: options.callback_url,
      });
      return;
    }
    if (resp.requires_otp) {
      if (resp.redirect_url) {
        try {
          window.open(resp.redirect_url, "_blank");
        } catch (e) {}
      }
      showOtpScreen(modal, options, endpoints, resp);
      return;
    }
    showFailure(modal, { message: resp.message || "Payment failed" });
  }

  /* ---------------- OTP screen ---------------- */
  function showOtpScreen(modal, options, endpoints, respFromCapture) {
    const body = qs("#vpayInnerBody", modal);
    body.innerHTML = `
      <div style="text-align:center;">
        <div style="font-weight:800;font-size:16px;">Enter OTP</div>
        <div class="vpay-small vpay-muted" style="margin-top:6px;">An OTP has been sent to your device (sandbox).</div>
        <div class="vpay-otp" style="margin-top:14px;">
          <input maxlength="1" class="vpay-input" id="otp1" />
          <input maxlength="1" class="vpay-input" id="otp2" />
          <input maxlength="1" class="vpay-input" id="otp3" />
          <input maxlength="1" class="vpay-input" id="otp4" />
        </div>
        <div style="margin-top:16px;display:flex;gap:10px;">
          <button class="vpay-ghost vpay-btn" id="vpayOtpCancel">Cancel</button>
          <button class="vpay-btn" id="vpayOtpVerify">Verify</button>
        </div>
      </div>
    `;

    // watch these inputs as well
    markDirtyOnInput(body);

    const inputs = [
      qs("#otp1", modal),
      qs("#otp2", modal),
      qs("#otp3", modal),
      qs("#otp4", modal),
    ];
    inputs.forEach((inp, i) => {
      if (!inp) return;
      inp.addEventListener("input", () => {
        if (inp.value.length === 1 && i < inputs.length - 1)
          inputs[i + 1].focus();
      });
    });

    qs("#vpayOtpCancel", modal).onclick = () => {
      qs("#vpayInnerBody", modal).innerHTML = getTabHTML("card");
      markDirtyOnInput(qs("#vpayInnerBody", modal));
      wireTabActions(modal, overlayFor(modal), options, endpoints);
    };

    qs("#vpayOtpVerify", modal).onclick = () => {
      const otp = inputs.map((i) => i.value || "").join("");
      if (otp.length < 4) {
        alert("Enter complete OTP");
        return;
      }
      showInterim(modal, "Verifying OTP…");
      postJsonWithCsrf(endpoints.verifyOtp, {
        payment_session_id: options._session.id,
        otp,
      })
        .then((resp) => {
          if (resp && resp.success) {
            showSuccess(modal, {
              payment_id: resp.payment_id || resp.payment_session_id,
              amount: options._session.amount,
              currency: options._session.currency,
              callback_url: options.callback_url,
            });
          } else {
            showFailure(modal, {
              message:
                (resp && resp.message) || "OTP verification failed",
              retryCallback: () =>
                showOtpScreen(modal, options, endpoints, respFromCapture),
            });
          }
        })
        .catch((err) => {
          console.error("verify-otp err", err);
          showFailure(modal, {
            message: "Network error",
            retryCallback: () =>
              showOtpScreen(modal, options, endpoints, respFromCapture),
          });
        });
    };
  }

  /* ---------------- Success / Failure / Interim ---------------- */
  function showSuccess(modal, opts) {
    const body = qs("#vpayInnerBody", modal);
    body.innerHTML = `
      <div>
        <div class="vpay-check" aria-hidden>
          <svg width="84" height="84" viewBox="0 0 52 52">
            <path d="M14 27 L22 34 L38 16" stroke="#22c55e" stroke-width="5" stroke-linecap="round" stroke-linejoin="round" fill="none" stroke-dasharray="120" stroke-dashoffset="120" />
          </svg>
        </div>
        <div class="vpay-success-title">Payment Successful</div>
        <div class="vpay-success-sub">Payment ID: <strong>${opts.payment_id ||
          "—"}</strong></div>
        <div class="vpay-muted" style="margin-top:8px">${formatAmountCents(
          opts.amount,
          opts.currency
        )}</div>
      </div>
    `;
    hasUserInput = false;
    simpleConfetti(modal);
    if (opts.callback_url) {
      try {
        const u = new URL(opts.callback_url, window.location.href);
        u.searchParams.set("status", "success");
        if (opts.payment_id) u.searchParams.set("payment_id", opts.payment_id);
        setTimeout(() => {
          window.location.href = u.toString();
        }, 3200);
      } catch (e) {
        setTimeout(() => {
          overlayRemove(modal);
        }, 3200);
      }
    } else {
      setTimeout(() => {
        overlayRemove(modal);
      }, 3200);
    }
  }

  function showFailure(modal, data = {}) {
    const body = qs("#vpayInnerBody", modal);
    body.innerHTML = `
      <div class="vpay-fail">
        <div class="icon">✖</div>
        <div class="vpay-fail-title">Payment Failed</div>
        <div class="vpay-fail-sub">${data.message ||
          "Unable to process payment"}</div>
        <div style="display:flex;gap:10px;margin-top:14px;">
          <button class="vpay-ghost vpay-btn" id="vpayFailClose">Close</button>
          <button class="vpay-btn" id="vpayFailRetry">Retry</button>
        </div>
        <div class="vpay-muted">Contact merchant if the issue persists.</div>
      </div>
    `;
    hasUserInput = false;
    qs("#vpayFailClose", modal).onclick = () => {
      if (data.callback_url) {
        try {
          const u = new URL(data.callback_url, window.location.href);
          u.searchParams.set("status", "failed");
          if (data.payment_id)
            u.searchParams.set("payment_id", data.payment_id);
          window.location.href = u.toString();
        } catch (e) {
          overlayRemove(modal);
        }
      } else overlayRemove(modal);
    };
    qs("#vpayFailRetry", modal).onclick = () => {
      if (typeof data.retryCallback === "function") data.retryCallback();
      else overlayRemove(modal);
    };
  }

  function showInterim(modal, message) {
    const body = qs("#vpayInnerBody", modal);
    body.innerHTML = `
      <div class="vpay-loader">
        <div class="vpay-spinner"></div>
        <div style="font-weight:700;color:#0f172a;">${message ||
          "Processing…"} </div>
        <div class="vpay-muted">This may take a few seconds.</div>
      </div>
    `;
  }

  /* ---------------- small helpers ---------------- */
  function overlayRemove(modal) {
    hasUserInput = false;
    const root = modal && modal.parentNode;
    if (root) root.remove();
  }
  function fallbackDataUri(name) {
    const svg = `<svg xmlns='http://www.w3.org/2000/svg' width='120' height='120'><rect rx='16' width='100%' height='100%' fill='#fff'/><text x='50%' y='50%' dominant-baseline='middle' text-anchor='middle' fill='#FF6A00' font-family='Arial' font-size='20'>${escapeHtml(
      name.charAt(0) || "V"
    )}</text></svg>`;
    return "data:image/svg+xml;utf8," + encodeURIComponent(svg);
  }
  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      }[c])
    );
  }
})();
