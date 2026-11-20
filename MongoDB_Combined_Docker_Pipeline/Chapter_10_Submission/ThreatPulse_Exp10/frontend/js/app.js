/**
 * ThreatPulse SOC Platform - Main Application Controller
 * Experiment 10: Multi-Document Transactions & Subscription SOC Platform
 */

import { API } from "./api.js";
import { initTxnLab } from "./txn_lab.js";

// Application State
let currentUser = null;
let currentPlans = [];
let selectedPlanForCheckout = null;

document.addEventListener("DOMContentLoaded", async () => {
  setupNavigation();
  setupModals();
  setupDemoSwitcher();
  setupFeatureTriggers();
  setupTransferForm();
  initTxnLab(refreshUserData);

  // Initialize Data
  await checkHealth();
  await loadDemoAccounts();
  await refreshUserData();
  await loadPlans();
  await loadFeed();
  await loadStock();
});

// 1. Navigation Tabs
function setupNavigation() {
  const tabs = document.querySelectorAll(".tab-btn");
  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      const targetId = tab.dataset.tab;
      tabs.forEach(t => t.classList.remove("active"));
      tab.classList.add("active");

      document.querySelectorAll(".tab-pane").forEach(pane => {
        pane.classList.remove("active");
        if (pane.id === targetId) {
          pane.classList.add("active");
        }
      });

      // Tab specific triggers
      if (targetId === "tab-invoices") loadInvoices();
      if (targetId === "tab-admin") loadAdminMetrics();
      if (targetId === "tab-features") loadStock();
    });
  });
}

// 2. Health & Replica Set Status
async function checkHealth() {
  try {
    const health = await API.getHealth();
    const rsLabel = document.getElementById("replica-status-label");
    if (rsLabel && health.database) {
      rsLabel.innerHTML = `Replica Set: <strong>${health.database.replica_set}</strong> (${health.database.primary_node})`;
    }
  } catch (err) {
    console.warn("Health check error:", err);
  }
}

// 3. Demo Accounts Switcher
async function loadDemoAccounts() {
  try {
    const res = await API.getDemoAccounts();
    const select = document.getElementById("demo-user-select");
    if (!select) return;

    select.innerHTML = "";
    res.demo_accounts.forEach(acc => {
      const opt = document.createElement("option");
      opt.value = acc.email;
      opt.textContent = `${acc.name} (${acc.plan.toUpperCase()} • $${acc.wallet_balance.toFixed(2)})`;
      select.appendChild(opt);
    });
  } catch (err) {
    console.error("Failed to load demo accounts:", err);
  }
}

function setupDemoSwitcher() {
  const select = document.getElementById("demo-user-select");
  if (!select) return;

  select.addEventListener("change", async () => {
    const email = select.value;
    try {
      await API.switchDemoAccount(email);
      await refreshUserData();
      await loadFeed();
      showToast(`Switched active account to ${email}`);
    } catch (err) {
      alert("Failed to switch demo account: " + err.message);
    }
  });
}

// 4. Refresh User HUD
async function refreshUserData() {
  try {
    currentUser = await API.getMe();
    updateHud(currentUser);
    const select = document.getElementById("demo-user-select");
    if (select && currentUser.email) {
      select.value = currentUser.email;
    }
  } catch (err) {
    currentUser = null;
    updateHud(null);
  }
}

function updateHud(user) {
  const authContainer = document.getElementById("hud-auth-container");
  const guestContainer = document.getElementById("hud-guest-container");

  if (!user) {
    if (authContainer) authContainer.style.display = "none";
    if (guestContainer) guestContainer.style.display = "flex";
    return;
  }

  if (authContainer) authContainer.style.display = "flex";
  if (guestContainer) guestContainer.style.display = "none";

  const nameEl = document.getElementById("hud-user-name");
  const avatarEl = document.getElementById("hud-user-avatar");
  const walletEl = document.getElementById("hud-wallet-balance");
  const creditsEl = document.getElementById("hud-credit-balance");
  const planEl = document.getElementById("hud-plan-badge");

  if (nameEl) nameEl.textContent = user.name || user.email;
  if (avatarEl) {
    const initials = (user.name || user.email || "AV")
      .split(" ")
      .map(w => w[0])
      .join("")
      .substring(0, 2)
      .toUpperCase();
    avatarEl.textContent = initials;
  }
  if (walletEl) walletEl.textContent = `$${(user.wallet_balance || 0).toFixed(2)}`;
  if (creditsEl) creditsEl.textContent = `${user.current_credits || 0} Credits`;
  if (planEl) {
    planEl.textContent = `${user.plan || 'Free'} Tier`;
    planEl.className = `hud-pill tier tier-${user.plan || 'free'}`;
  }
}

// 5. Load Subscription Plans
async function loadPlans() {
  try {
    const res = await API.getPlans();
    currentPlans = res.plans || [];
    renderPlanCards(currentPlans);
  } catch (err) {
    console.error("Failed to load plans:", err);
  }
}

function renderPlanCards(plans) {
  const container = document.getElementById("plans-cards-grid");
  if (!container) return;

  container.innerHTML = "";
  plans.forEach(plan => {
    const isCurrent = currentUser && currentUser.plan === plan.id;
    const isPro = plan.id === "pro";

    const card = document.createElement("div");
    card.className = `card plan-card ${isPro ? 'highlight' : ''}`;
    card.innerHTML = `
      <div>
        <div class="card-header">
          <div>
            <h3 class="card-title">${plan.name}</h3>
            <div class="card-subtitle">${plan.badge}</div>
          </div>
          ${isCurrent ? `<span class="badge-tag hot" style="background: rgba(16,185,129,0.2); color: var(--accent-emerald); border-color: rgba(16,185,129,0.4)">CURRENT PLAN</span>` : ''}
        </div>
        <p style="font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 0.75rem;">${plan.description}</p>
        <div class="plan-price-box">
          <span class="plan-price">$${plan.price.toFixed(0)}</span>
          <span class="plan-period">/ month</span>
        </div>
        <div class="plan-credits-pill">
          ⚡ ${plan.monthly_credits} Credits / mo
        </div>
        <ul class="feature-list">
          ${plan.features.map(f => `<li><span class="check-icon">&#10003;</span> ${f}</li>`).join("")}
        </ul>
      </div>
      <div>
        ${isCurrent 
          ? `<button class="btn btn-secondary" disabled style="opacity: 0.6">Active Tier</button>`
          : `<button class="btn btn-primary btn-checkout-plan" data-plan-id="${plan.id}">
               Upgrade with Transaction &rarr;
             </button>`
        }
      </div>
    `;
    container.appendChild(card);
  });

  // Attach checkout button listeners
  document.querySelectorAll(".btn-checkout-plan").forEach(btn => {
    btn.addEventListener("click", () => {
      const planId = btn.dataset.planId;
      openCheckoutModal(planId);
    });
  });
}

// 6. Checkout Modal & Coupon Validation
function openCheckoutModal(planId) {
  if (!currentUser) {
    document.getElementById("auth-modal").classList.add("active");
    showToast("Please sign in or choose a demo profile to upgrade.");
    return;
  }

  selectedPlanForCheckout = currentPlans.find(p => p.id === planId);
  if (!selectedPlanForCheckout) return;

  const modal = document.getElementById("checkout-modal");
  document.getElementById("modal-plan-name").textContent = selectedPlanForCheckout.name;
  document.getElementById("modal-plan-price").textContent = `$${selectedPlanForCheckout.price.toFixed(2)}`;
  document.getElementById("modal-plan-credits").textContent = `+${selectedPlanForCheckout.monthly_credits} Feature Credits`;
  document.getElementById("checkout-coupon-input").value = "";
  document.getElementById("checkout-discount-row").style.display = "none";
  document.getElementById("modal-final-price").textContent = `$${selectedPlanForCheckout.price.toFixed(2)}`;
  document.getElementById("checkout-error-msg").textContent = "";

  modal.classList.add("active");
}

function setupModals() {
  // Close buttons
  document.querySelectorAll(".modal-close, .btn-modal-cancel").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".modal-overlay").forEach(m => m.classList.remove("active"));
    });
  });

  // Header Sign Out Handler
  const btnLogout = document.getElementById("btn-header-logout");
  if (btnLogout) {
    btnLogout.addEventListener("click", async () => {
      try {
        await API.logout();
        currentUser = null;
        updateHud(null);
        await loadFeed();
        await loadPlans();
        showToast("Signed out. Switched to public guest mode.");
      } catch (err) {
        console.warn("Logout error:", err);
      }
    });
  }

  // Header Sign In Open Handler
  const btnOpenLogin = document.getElementById("btn-header-login");
  if (btnOpenLogin) {
    btnOpenLogin.addEventListener("click", () => {
      document.getElementById("auth-modal").classList.add("active");
    });
  }

  // Auth Modal Tab Switcher (Sign In vs Register)
  const btnTabLogin = document.getElementById("auth-tab-btn-login");
  const btnTabReg = document.getElementById("auth-tab-btn-register");
  const formLogin = document.getElementById("form-login");
  const formReg = document.getElementById("form-register");

  if (btnTabLogin && btnTabReg) {
    btnTabLogin.addEventListener("click", () => {
      btnTabLogin.classList.add("active");
      btnTabReg.classList.remove("active");
      if (formLogin) formLogin.style.display = "block";
      if (formReg) formReg.style.display = "none";
    });
    btnTabReg.addEventListener("click", () => {
      btnTabReg.classList.add("active");
      btnTabLogin.classList.remove("active");
      if (formReg) formReg.style.display = "block";
      if (formLogin) formLogin.style.display = "none";
    });
  }

  // Sign In Form Submission
  if (formLogin) {
    formLogin.addEventListener("submit", async (e) => {
      e.preventDefault();
      const email = document.getElementById("login-email-input").value.trim();
      const password = document.getElementById("login-password-input").value;
      const errEl = document.getElementById("login-error-msg");
      errEl.textContent = "";
      try {
        const res = await API.login(email, password);
        currentUser = res.user;
        updateHud(currentUser);
        document.getElementById("auth-modal").classList.remove("active");
        await refreshUserData();
        await loadPlans();
        await loadFeed();
        showToast(`Signed in successfully as ${res.user.name || res.user.email}!`);
      } catch (err) {
        errEl.textContent = err.message;
      }
    });
  }

  // Register Form Submission
  if (formReg) {
    formReg.addEventListener("submit", async (e) => {
      e.preventDefault();
      const name = document.getElementById("reg-name-input").value.trim();
      const email = document.getElementById("reg-email-input").value.trim();
      const password = document.getElementById("reg-password-input").value;
      const errEl = document.getElementById("reg-error-msg");
      errEl.textContent = "";
      try {
        const res = await API.register(name, email, password);
        currentUser = res.user;
        updateHud(currentUser);
        document.getElementById("auth-modal").classList.remove("active");
        await refreshUserData();
        await loadPlans();
        await loadFeed();
        showToast(`Account created! Welcome, ${res.user.name} (+50 Free Credits).`);
      } catch (err) {
        errEl.textContent = err.message;
      }
    });
  }

  // 1-Click Demo Profiles in Auth Modal
  document.querySelectorAll(".btn-quick-login").forEach(btn => {
    btn.addEventListener("click", async () => {
      const email = btn.dataset.email;
      try {
        await API.switchDemoAccount(email);
        document.getElementById("auth-modal").classList.remove("active");
        await refreshUserData();
        await loadPlans();
        await loadFeed();
        showToast(`Switched active profile to ${email}`);
      } catch (err) {
        alert("Login failed: " + err.message);
      }
    });
  });

  // Top-Up Modal Open
  const btnTopUpHud = document.getElementById("btn-hud-topup");
  if (btnTopUpHud) {
    btnTopUpHud.addEventListener("click", () => {
      document.getElementById("topup-modal").classList.add("active");
    });
  }

  // Top-Up Preset Amounts
  document.querySelectorAll(".btn-topup-preset").forEach(btn => {
    btn.addEventListener("click", async () => {
      const amount = parseFloat(btn.dataset.amount);
      try {
        btn.disabled = true;
        await API.topUpWallet(amount);
        await refreshUserData();
        document.getElementById("topup-modal").classList.remove("active");
        showToast(`Successfully added $${amount.toFixed(2)} to wallet!`);
      } catch (err) {
        alert("Top-up error: " + err.message);
      } finally {
        btn.disabled = false;
      }
    });
  });

  // Coupon Validate in Checkout
  const btnApplyCoupon = document.getElementById("btn-apply-coupon");
  if (btnApplyCoupon) {
    btnApplyCoupon.addEventListener("click", async () => {
      const code = document.getElementById("checkout-coupon-input").value.trim();
      const errorMsg = document.getElementById("checkout-error-msg");
      errorMsg.textContent = "";

      if (!code) return;
      try {
        btnApplyCoupon.disabled = true;
        const res = await API.validateCoupon(code, selectedPlanForCheckout.id);
        document.getElementById("checkout-discount-row").style.display = "flex";
        document.getElementById("modal-discount-val").textContent = `-$${res.discount_amount.toFixed(2)} (${res.code})`;
        document.getElementById("modal-final-price").textContent = `$${res.final_price.toFixed(2)}`;
        showToast(`Coupon '${res.code}' applied! Saved $${res.discount_amount.toFixed(2)}`);
      } catch (err) {
        errorMsg.textContent = err.message;
      } finally {
        btnApplyCoupon.disabled = false;
      }
    });
  }

  // Confirm Subscription Upgrade
  const btnConfirmSub = document.getElementById("btn-confirm-subscription");
  if (btnConfirmSub) {
    btnConfirmSub.addEventListener("click", async () => {
      const coupon = document.getElementById("checkout-coupon-input").value.trim() || null;
      const errorMsg = document.getElementById("checkout-error-msg");
      errorMsg.textContent = "";

      try {
        btnConfirmSub.disabled = true;
        btnConfirmSub.textContent = "Executing Multi-Doc Transaction...";
        const res = await API.subscribePlan(selectedPlanForCheckout.id, coupon);
        document.getElementById("checkout-modal").classList.remove("active");
        await refreshUserData();
        await loadPlans();
        await loadFeed();
        showReceiptModal(res.receipt);
      } catch (err) {
        errorMsg.textContent = err.message;
      } finally {
        btnConfirmSub.disabled = false;
        btnConfirmSub.textContent = "Confirm & Execute Transaction";
      }
    });
  }
}

// 7. Receipts Modal
function showReceiptModal(receipt) {
  const modal = document.getElementById("receipt-modal");
  document.getElementById("rcpt-id").textContent = receipt.receipt_id;
  document.getElementById("rcpt-status").textContent = receipt.status;
  document.getElementById("rcpt-status").className = `badge-tag ${receipt.status === 'COMMITTED' ? 'txn' : 'hot'}`;
  document.getElementById("rcpt-type").textContent = receipt.type;
  document.getElementById("rcpt-duration").textContent = `${receipt.duration_ms || 0} ms`;

  const timeline = document.getElementById("rcpt-timeline-list");
  timeline.innerHTML = "";
  if (receipt.steps) {
    receipt.steps.forEach(s => {
      const item = document.createElement("div");
      item.className = "timeline-item";
      item.innerHTML = `
        <span class="badge-step">${s.step}</span>
        <span class="detail">${s.reason || s.detail || s.status || JSON.stringify(s)}</span>
      `;
      timeline.appendChild(item);
    });
  }

  modal.classList.add("active");
}

// 8. Paid Features Triggers
function setupFeatureTriggers() {
  // VirusTotal Scan
  const btnVT = document.getElementById("btn-run-vt-scan");
  if (btnVT) {
    btnVT.addEventListener("click", async () => {
      if (!currentUser) {
        document.getElementById("auth-modal").classList.add("active");
        showToast("Authentication required! Please sign in or pick a demo profile.");
        return;
      }

      const target = document.getElementById("vt-target-input").value.trim();
      const simCrash = document.getElementById("vt-sim-crash-check").checked;
      const output = document.getElementById("vt-output");

      if (!target) {
        alert("Please enter a target IP, Domain or Hash");
        return;
      }

      btnVT.disabled = true;
      output.innerHTML = `<div class="timeline-item"><span class="badge-step">SCANNING</span><span class="detail">Executing VirusTotal Transaction (Deducting 5 cr + reserving 1 quota slot)...</span></div>`;
      try {
        const res = await API.runVTScan(target, simCrash);
        await refreshUserData();
        await loadStock();

        output.innerHTML = `
          <div style="background: rgba(0,240,255,0.05); border: 1px solid rgba(0,240,255,0.3); border-radius: 8px; padding: 1rem; margin-top: 0.5rem;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
              <strong style="color: var(--accent-cyan);">${res.data.detection_score}</strong>
              <span class="badge-tag hot">${res.data.threat_label}</span>
            </div>
            <div style="font-size: 0.8rem; font-family: var(--font-mono); color: var(--text-muted); margin-bottom: 0.5rem;">Target: ${res.data.target} (SHA256: ${res.data.sha256.substring(0, 16)}...)</div>
            <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 0.5rem; font-size: 0.75rem; font-family: var(--font-mono);">
              ${res.data.engines_analyzed.map(e => `
                <div style="background: #1e293b; padding: 0.35rem 0.5rem; border-radius: 4px; display: flex; justify-content: space-between;">
                  <span>${e.engine}</span>
                  <span style="color: ${e.category === 'malicious' ? 'var(--accent-rose)' : 'var(--accent-emerald)'}">${e.result}</span>
                </div>
              `).join("")}
            </div>
          </div>
        `;
      } catch (err) {
        output.innerHTML = `<div style="color: var(--accent-rose); padding: 0.5rem 0;">Transaction Failed: ${err.message}</div>`;
      } finally {
        btnVT.disabled = false;
      }
    });
  }

  // Threat Verifier
  const btnVerifier = document.getElementById("btn-run-verifier");
  if (btnVerifier) {
    btnVerifier.addEventListener("click", async () => {
      if (!currentUser) {
        document.getElementById("auth-modal").classList.add("active");
        showToast("Authentication required! Please sign in or pick a demo profile.");
        return;
      }

      const ioc = document.getElementById("verifier-ioc-input").value.trim();
      const output = document.getElementById("verifier-output");
      if (!ioc) return alert("Enter an IOC to verify");

      btnVerifier.disabled = true;
      output.innerHTML = `<div class="timeline-item"><span class="badge-step">QUERYING</span><span class="detail">Deducting 3 credits inside transaction & querying CTI knowledge graph...</span></div>`;
      try {
        const res = await API.runVerifier(ioc);
        await refreshUserData();
        output.innerHTML = `
          <div style="background: rgba(16,185,129,0.08); border: 1px solid rgba(16,185,129,0.3); border-radius: 8px; padding: 1rem; margin-top: 0.5rem;">
            <div style="font-weight: 700; color: var(--accent-emerald);">Verified Matches: ${res.matches_found} Found</div>
            <pre style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-secondary); margin-top: 0.5rem; max-height: 150px; overflow-y: auto;">${JSON.stringify(res.threat_intel_context, null, 2)}</pre>
          </div>
        `;
      } catch (err) {
        output.innerHTML = `<div style="color: var(--accent-rose)">${err.message}</div>`;
      } finally {
        btnVerifier.disabled = false;
      }
    });
  }

  // IOC Batch Export
  const btnExport = document.getElementById("btn-run-ioc-export");
  if (btnExport) {
    btnExport.addEventListener("click", async () => {
      const output = document.getElementById("export-output");
      btnExport.disabled = true;
      try {
        const res = await API.runIOCExport("json");
        await refreshUserData();
        output.innerHTML = `
          <div style="background: rgba(139,92,246,0.08); border: 1px solid rgba(139,92,246,0.3); border-radius: 8px; padding: 1rem; margin-top: 0.5rem;">
            <div style="font-weight: 700; color: var(--accent-purple);">${res.message}</div>
            <pre style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-secondary); margin-top: 0.5rem; max-height: 140px; overflow-y: auto;">${JSON.stringify(res.iocs, null, 2)}</pre>
          </div>
        `;
      } catch (err) {
        output.innerHTML = `<div style="color: var(--accent-rose)">${err.message}</div>`;
      } finally {
        btnExport.disabled = false;
      }
    });
  }

  // Reserve Briefing Seat
  const btnBriefing = document.getElementById("btn-reserve-briefing");
  if (btnBriefing) {
    btnBriefing.addEventListener("click", async () => {
      btnBriefing.disabled = true;
      try {
        const res = await API.reserveBriefing("Zero-Day Emergency Briefing");
        await refreshUserData();
        await loadStock();
        showToast(res.message);
      } catch (err) {
        alert("Reservation failed: " + err.message);
      } finally {
        btnBriefing.disabled = false;
      }
    });
  }
}

// 9. Peer-to-Peer Transfer Form
function setupTransferForm() {
  const btnSend = document.getElementById("btn-send-transfer");
  const btnRollbackPreset = document.getElementById("btn-transfer-ghost-preset");

  if (btnRollbackPreset) {
    btnRollbackPreset.addEventListener("click", () => {
      document.getElementById("p2p-recipient-input").value = "fake_ghost@unknown.org";
      document.getElementById("p2p-amount-input").value = "50";
      document.getElementById("p2p-memo-input").value = "Simulated rollback test";
    });
  }

  if (btnSend) {
    btnSend.addEventListener("click", async () => {
      if (!currentUser) {
        document.getElementById("auth-modal").classList.add("active");
        showToast("Authentication required! Please sign in or pick a demo profile.");
        return;
      }

      const recipient = document.getElementById("p2p-recipient-input").value.trim();
      const amount = parseInt(document.getElementById("p2p-amount-input").value, 10);
      const memo = document.getElementById("p2p-memo-input").value.trim();
      const output = document.getElementById("p2p-output");

      if (!recipient || isNaN(amount) || amount <= 0) {
        alert("Enter a valid recipient and credit amount");
        return;
      }

      btnSend.disabled = true;
      output.innerHTML = `<div class="timeline-item"><span class="badge-step">TRANSFERRING</span><span class="detail">Starting atomic P2P transfer of ${amount} credits to ${recipient}...</span></div>`;
      try {
        const res = await API.sendP2PTransfer(recipient, amount, memo);
        await refreshUserData();
        output.innerHTML = `
          <div style="background: rgba(16,185,129,0.1); border: 1px solid rgba(16,185,129,0.3); border-radius: 8px; padding: 1rem; color: var(--accent-emerald);">
            <strong>Transfer Complete!</strong> ${res.message}
          </div>
        `;
        showReceiptModal(res.receipt);
      } catch (err) {
        output.innerHTML = `
          <div style="background: rgba(244,63,94,0.1); border: 1px solid rgba(244,63,94,0.3); border-radius: 8px; padding: 1rem; color: var(--accent-rose);">
            <strong>Transfer Aborted & Rolled Back:</strong> ${err.message}
            <div style="font-size: 0.8rem; color: var(--text-secondary); margin-top: 0.35rem;">Zero credits were lost from your balance.</div>
          </div>
        `;
      } finally {
        btnSend.disabled = false;
      }
    });
  }
}

// 10. Load Feed
async function loadFeed() {
  try {
    const res = await API.getThreatFeed(20);
    const container = document.getElementById("threat-feed-container");
    if (!container) return;

    container.innerHTML = "";
    res.reports.forEach(r => {
      const card = document.createElement("div");
      card.className = "card";
      card.style.marginBottom = "1rem";
      card.innerHTML = `
        <div class="card-header">
          <div>
            <span class="badge-tag ${r.severity === 'CRITICAL' ? 'hot' : 'txn'}">${r.severity}</span>
            <span style="font-size: 0.75rem; color: var(--text-muted); margin-left: 0.5rem; font-family: var(--font-mono);">${r.report_id} • ${r.threat_actor}</span>
            <h4 style="font-size: 1.05rem; font-weight: 700; margin-top: 0.35rem;">${r.title}</h4>
          </div>
          <span style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--accent-amber);">CVSS ${r.cvss}</span>
        </div>
        <p style="font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 0.75rem;">${r.summary}</p>
        <div style="display: flex; gap: 0.5rem; flex-wrap: wrap; margin-bottom: 0.75rem;">
          ${(r.tags || []).map(t => `<span style="font-size: 0.7rem; background: #1e293b; padding: 0.15rem 0.5rem; border-radius: 4px; color: var(--text-muted);">${t}</span>`).join("")}
        </div>
        <div style="font-size: 0.8rem; font-family: var(--font-mono); color: var(--accent-cyan); border-top: 1px solid rgba(255,255,255,0.05); padding-top: 0.5rem;">
          ${r.upgrade_required_for_full_iocs ? `
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <span>1 Preview IOC: <code>${r.iocs[0].value}</code></span>
              <span style="color: var(--accent-amber); font-size: 0.75rem;">+${r.iocs_redacted_count} More IOCs Locked (Upgrade to Analyst to view)</span>
            </div>
          ` : `
            <div>Active IOCs: ${(r.iocs || []).map(i => `<code>${i.value}</code>`).join(", ")}</div>
          `}
        </div>
      `;
      container.appendChild(card);
    });
  } catch (err) {
    console.error("Failed to load feed:", err);
  }
}

// 11. Load Stock Quota Meters
async function loadStock() {
  try {
    const res = await API.getInventoryStock();
    res.stock.forEach(item => {
      if (item.item_key === "vt_quota") {
        const label = document.getElementById("vt-quota-label");
        const bar = document.getElementById("vt-quota-fill");
        if (label && bar) {
          label.textContent = `${item.available_units} / ${item.total_units} Slots Remaining`;
          const pct = Math.max(0, Math.min(100, (item.available_units / item.total_units) * 100));
          bar.style.width = `${pct}%`;
        }
      }
      if (item.item_key === "briefing_seats") {
        const bLabel = document.getElementById("briefing-seats-label");
        if (bLabel) bLabel.textContent = `${item.available_units} / ${item.total_units} Seats Left`;
      }
    });
  } catch (err) {
    console.warn("Failed to load stock:", err);
  }
}

// 12. Load Invoices
async function loadInvoices() {
  try {
    const res = await API.getInvoices();
    const container = document.getElementById("invoices-container");
    if (!container) return;

    if (!res.invoices || res.invoices.length === 0) {
      container.innerHTML = `<div style="color: var(--text-muted); font-size: 0.9rem; padding: 1.5rem; text-align: center;">No payment records found. Upgrade a plan to generate invoices.</div>`;
      return;
    }

    container.innerHTML = "";
    res.invoices.forEach(inv => {
      const card = document.createElement("div");
      card.className = "card";
      card.style.marginBottom = "1rem";
      card.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <div>
            <div style="font-family: var(--font-mono); font-size: 0.95rem; font-weight: 700; color: var(--accent-cyan);">${inv.payment_id}</div>
            <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.2rem;">Plan: <strong>${inv.plan_name}</strong> • Credits: +${inv.credits_granted}</div>
          </div>
          <div style="text-align: right;">
            <div style="font-size: 1.25rem; font-weight: 800; font-family: var(--font-mono);">$${inv.amount_paid.toFixed(2)}</div>
            <span class="badge-tag txn">${inv.status}</span>
          </div>
        </div>
      `;
      container.appendChild(card);
    });
  } catch (err) {
    console.error("Failed to load invoices:", err);
  }
}

// 13. Load Admin Metrics & Mathematical Audit
async function loadAdminMetrics() {
  try {
    const rev = await API.getAdminRevenue();
    const audit = await API.getAdminAudit();

    document.getElementById("admin-platform-revenue").textContent = `$${rev.realized_platform_revenue_usd.toFixed(2)}`;
    document.getElementById("admin-mrr").textContent = `$${rev.calculated_mrr_usd.toFixed(2)}`;
    document.getElementById("admin-subscribers").textContent = `${rev.total_active_users} Users`;

    const auditContainer = document.getElementById("admin-audit-results");
    if (auditContainer) {
      auditContainer.innerHTML = `
        <div style="padding: 1.5rem; background: rgba(16,185,129,0.06); border: 1px solid rgba(16,185,129,0.3); border-radius: var(--radius-lg); margin-top: 1rem;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
            <div class="audit-badge">&#10003; MATHEMATICAL CONSERVATION CERTIFICATE: ${audit.integrity_certificate}</div>
            <span style="font-size: 0.75rem; font-family: var(--font-mono); color: var(--text-muted);">${audit.audit_timestamp}</span>
          </div>
          <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; font-family: var(--font-mono); font-size: 0.8rem;">
            <div style="background: rgba(0,0,0,0.3); padding: 0.75rem; border-radius: 6px;">
              <div style="color: var(--text-muted); font-size: 0.7rem;">User Wallets Total</div>
              <strong style="color: var(--text-primary);">$${audit.money_conservation.total_user_wallets_usd.toFixed(2)}</strong>
            </div>
            <div style="background: rgba(0,0,0,0.3); padding: 0.75rem; border-radius: 6px;">
              <div style="color: var(--text-muted); font-size: 0.7rem;">Platform Revenue Account</div>
              <strong style="color: var(--accent-emerald);">$${audit.money_conservation.platform_revenue_account_usd.toFixed(2)}</strong>
            </div>
            <div style="background: rgba(0,0,0,0.3); padding: 0.75rem; border-radius: 6px;">
              <div style="color: var(--text-muted); font-size: 0.7rem;">Active System Credits</div>
              <strong style="color: var(--accent-amber);">${audit.credit_conservation.sum_active_user_credits} Credits</strong>
            </div>
          </div>
          <div style="margin-top: 1rem; font-size: 0.85rem; color: var(--text-secondary);">
            ${audit.verdict}
          </div>
        </div>
      `;
    }
  } catch (err) {
    console.error("Failed to load admin metrics:", err);
  }
}

// Toast helper
function showToast(message) {
  const toast = document.createElement("div");
  toast.style.position = "fixed";
  toast.style.bottom = "20px";
  toast.style.right = "20px";
  toast.style.background = "#1e293b";
  toast.style.color = "var(--accent-cyan)";
  toast.style.border = "1px solid var(--border-glow)";
  toast.style.padding = "0.75rem 1.25rem";
  toast.style.borderRadius = "8px";
  toast.style.zIndex = "9999";
  toast.style.boxShadow = "var(--shadow-card)";
  toast.style.fontFamily = "var(--font-sans)";
  toast.style.fontSize = "0.85rem";
  toast.textContent = message;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 3500);
}
