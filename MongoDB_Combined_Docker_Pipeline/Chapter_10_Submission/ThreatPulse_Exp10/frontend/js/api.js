/**
 * ThreatPulse SOC Platform - API Client
 * Facilitates all authenticated communication with FastAPI backend.
 */

const API_BASE = "";

async function request(endpoint, options = {}) {
  const config = {
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {})
    },
    credentials: "include", // Send & receive HttpOnly session cookies
    ...options
  };

  const response = await fetch(`${API_BASE}${endpoint}`, config);
  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    const errorMsg = data.detail || data.error || response.statusText || "Request failed";
    throw new Error(typeof errorMsg === "object" ? JSON.stringify(errorMsg) : errorMsg);
  }

  return data;
}

export const API = {
  // Auth & Profile
  getMe: () => request("/api/auth/me"),
  login: (email, password) => request("/api/auth/login", { method: "POST", body: JSON.stringify({ email, password }) }),
  register: (name, email, password) => request("/api/auth/register", { method: "POST", body: JSON.stringify({ name, email, password }) }),
  logout: () => request("/api/auth/logout", { method: "POST" }),
  getDemoAccounts: () => request("/api/auth/demo-accounts"),
  switchDemoAccount: (email) => request("/api/auth/demo-switch", { method: "POST", body: JSON.stringify({ email }) }),

  // Health
  getHealth: () => request("/api/health"),

  // Billing & Plans
  getPlans: () => request("/api/billing/plans"),
  getWallet: () => request("/api/billing/wallet"),
  topUpWallet: (amount) => request("/api/billing/top-up", { method: "POST", body: JSON.stringify({ amount }) }),
  validateCoupon: (code, plan_id) => request("/api/billing/coupon/validate", { method: "POST", body: JSON.stringify({ code, plan_id }) }),
  subscribePlan: (plan_id, coupon_code) => request("/api/billing/subscribe", { method: "POST", body: JSON.stringify({ plan_id, coupon_code }) }),
  getInvoices: () => request("/api/billing/invoices"),
  getReceipt: (receipt_id) => request(`/api/billing/receipts/${receipt_id}`),

  // Paid Features & Stock
  getInventoryStock: () => request("/api/features/stock"),
  runVTScan: (target, simulate_failure = false) => request("/api/features/vt-scan", { method: "POST", body: JSON.stringify({ target, simulate_failure }) }),
  runVerifier: (ioc_value) => request("/api/features/verifier", { method: "POST", body: JSON.stringify({ ioc_value }) }),
  runIOCExport: (format = "json", severity = null) => request("/api/features/ioc-export", { method: "POST", body: JSON.stringify({ format, severity }) }),
  reserveBriefing: (session_title) => request("/api/features/reserve-briefing", { method: "POST", body: JSON.stringify({ session_title }) }),

  // P2P Transfers
  sendP2PTransfer: (recipient_email, amount, memo = "", simulate_receiver_failure = false) =>
    request("/api/transfers/send", { method: "POST", body: JSON.stringify({ recipient_email, amount, memo, simulate_receiver_failure }) }),
  getTransferHistory: () => request("/api/transfers/history"),

  // Threat Intel Feed
  getThreatFeed: (limit = 20, severity = null) => {
    let q = `?limit=${limit}`;
    if (severity) q += `&severity=${severity}`;
    return request(`/api/reports/feed${q}`);
  },
  getFeedStats: () => request("/api/reports/stats"),

  // Transaction Lab Sandbox
  simulateTransferFail: (mode, amount = 10) => request("/api/txn-lab/simulate-transfer", { method: "POST", body: JSON.stringify({ mode, amount }) }),
  simulateOversell: (mode, initial_stock = 5, concurrent_requests = 15) => request("/api/txn-lab/simulate-oversell", { method: "POST", body: JSON.stringify({ mode, initial_stock, concurrent_requests }) }),
  demoRetryConflict: () => request("/api/txn-lab/retry-demo", { method: "POST" }),

  // Benchmark
  runBenchmark: (ops_per_worker = 20, worker_counts = [1, 2, 4]) => request("/api/benchmark/run", { method: "POST", body: JSON.stringify({ ops_per_worker, worker_counts }) }),

  // Admin & Financial Auditing
  getAdminRevenue: () => request("/api/admin/revenue"),
  getAdminAudit: () => request("/api/admin/audit"),
  getAllReceipts: (limit = 20) => request(`/api/admin/receipts?limit=${limit}`)
};
