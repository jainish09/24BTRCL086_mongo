/**
 * Threat Intelligence Dashboard - API Service Layer
 * Cleanly separates all data-fetching functions from the UI logic.
 * Automatically discovers active backend port (8080 or 8000) on 127.0.0.1 / localhost.
 */

class ApiService {
  constructor() {
    const isFastApiDirect = (window.location.protocol.startsWith('http') && (window.location.port === '8080' || window.location.port === '8000'));
    
    this.candidateUrls = isFastApiDirect 
      ? ['', window.location.origin, 'http://127.0.0.1:8080', 'http://localhost:8080']
      : ['', 'http://127.0.0.1:8080', 'http://localhost:8080', 'http://127.0.0.1:8000', 'http://localhost:8000'];
    
    // Default to same-origin relative root ('') for seamless cookie & session security
    this.activeBaseUrl = '';
  }

  /**
   * Helper method for standard JSON HTTP requests with port failover and error handling
   */
  async request(endpoint, options = {}) {
    const { headers: optHeaders, ...restOptions } = options;
    const mergedHeaders = {
      'Content-Type': 'application/json',
      ...(optHeaders || {})
    };

    if (this.activeBaseUrl !== null) {
      try {
        const url = `${this.activeBaseUrl}/api${endpoint}`;
        const response = await fetch(url, {
          credentials: 'include',
          ...restOptions,
          headers: mergedHeaders
        });

        if (response.ok) {
          return await response.json();
        }

        // Server responded with an HTTP status code (400, 401, 404, 409, 500, etc.)
        let errMsg = `Request failed (HTTP ${response.status})`;
        try {
          const errData = await response.json();
          errMsg = errData.detail?.error || errData.detail?.message || errData.detail || errData.message || errMsg;
          if (typeof errMsg === 'object') errMsg = errMsg.error || errMsg.message || JSON.stringify(errMsg);
        } catch (_) {}
        throw new Error(errMsg);
      } catch (err) {
        // If it was a network failure (backend not responding at this port), reset activeBaseUrl
        if (err.name === 'TypeError' || err.message.toLowerCase().includes('failed to fetch')) {
          this.activeBaseUrl = null;
        } else {
          // Genuine backend error response - do not retry on other ports
          throw err;
        }
      }
    }

    let lastError = null;
    for (const base of this.candidateUrls) {
      try {
        const url = `${base}/api${endpoint}`;
        const response = await fetch(url, {
          credentials: 'include',
          ...restOptions,
          headers: mergedHeaders
        });

        if (response.ok) {
          this.activeBaseUrl = base;
          return await response.json();
        }

        let errMsg = `Request failed (HTTP ${response.status})`;
        try {
          const errData = await response.json();
          errMsg = errData.detail?.error || errData.detail?.message || errData.detail || errData.message || errMsg;
          if (typeof errMsg === 'object') errMsg = errMsg.error || errMsg.message || JSON.stringify(errMsg);
        } catch (_) {}
        this.activeBaseUrl = base;
        throw new Error(errMsg);
      } catch (err) {
        lastError = err;
        if (err.name !== 'TypeError' && !err.message.toLowerCase().includes('failed to fetch')) {
          throw err;
        }
      }
    }

    console.warn(`[API Warning] Could not reach backend at /api${endpoint}`);
    throw (lastError || new Error(`Failed request to /api${endpoint}`));
  }

  /**
   * GET /api/reports
   */
  async getReports({ search = '', year = '', threatType = '', severity = '', page = 1, limit = 12, sortBy = 'createdAt', order = 'desc' } = {}) {
    const params = new URLSearchParams();
    if (search) params.append('search', search);
    if (year) params.append('year', year);
    if (threatType && threatType !== 'All') params.append('threatType', threatType);
    if (severity && severity !== 'All') params.append('severity', severity);
    params.append('page', page);
    params.append('limit', limit);
    params.append('sort_by', sortBy);
    params.append('order', order);

    return this.request(`/reports?${params.toString()}`);
  }

  /**
   * GET /api/reports/:id
   */
  async getReportById(reportId) {
    return this.request(`/reports/${encodeURIComponent(reportId)}`);
  }

  /**
   * GET /api/reports/count
   */
  async getReportsCount() {
    return this.request('/reports/count');
  }

  /**
   * GET /api/cache
   */
  async getCacheStats() {
    return this.request('/cache');
  }

  /**
   * GET /api/working-set
   */
  async getWorkingSetAnalysis() {
    return this.request('/working-set');
  }
  async getWorkingSet() {
    return this.getWorkingSetAnalysis();
  }

  /**
   * GET /api/random-read/status
   */
  async getRandomReadStatus() {
    return this.request('/random-read/status');
  }

  /**
   * POST /api/random-read/start
   */
  async startRandomReadExperiment(reads = 500) {
    return this.request(`/random-read/start?reads=${reads}`, {
      method: 'POST'
    });
  }
  async startRandomRead(reads = 500) {
    return this.startRandomReadExperiment(reads);
  }

  /**
   * POST /api/random-read/stop
   */
  async stopRandomReadExperiment() {
    return this.request('/random-read/stop', {
      method: 'POST'
    });
  }

  /**
   * GET /api/lab71/schema-analysis
   */
  async getLab71SchemaAnalysis() {
    return this.request('/lab71/schema-analysis');
  }
  async getLab71Analysis() {
    return this.getLab71SchemaAnalysis();
  }

  /**
   * POST /api/lab71/benchmark-redesign
   */
  async benchmarkLab71Redesign(iterations = 100) {
    return this.request(`/lab71/benchmark-redesign?iterations=${iterations}`, {
      method: 'POST'
    });
  }
  async runRedesignBenchmark(iterations = 100) {
    return this.benchmarkLab71Redesign(iterations);
  }

  /**
   * --- Lab Runner Endpoints (Labs 7, 8, 9) ---
   */
  async getLabStatus() {
    return this.request('/labs/status');
  }

  async runLab7() {
    return this.request('/labs/7/run', { method: 'POST' });
  }

  async runLab8() {
    return this.request('/labs/8/run', { method: 'POST' });
  }

  async runLab9() {
    return this.request('/labs/9/run', { method: 'POST' });
  }

  async runLab10() {
    return this.request('/labs/10/run', { method: 'POST' });
  }

  async runLab11() {
    return this.request('/labs/11/run', { method: 'POST' });
  }

  async runLab12() {
    return this.request('/labs/12/run', { method: 'POST' });
  }

  async runLab13() {
    return this.request('/labs/13/run', { method: 'POST' });
  }

  async runLab14() {
    return this.request('/labs/14/run', { method: 'POST' });
  }

  async runLab15() {
    return this.request('/labs/15/run', { method: 'POST' });
  }

  async runLab16() {
    return this.request('/labs/16/run', { method: 'POST' });
  }

  async runLab17() {
    return this.request('/labs/17/run', { method: 'POST' });
  }

  async runLab18() {
    return this.request('/labs/18/run', { method: 'POST' });
  }

  async runAllLabs() {
    return this.request('/labs/run-all', { method: 'POST' });
  }

  async getLabLogs(since = 0) {
    return this.request(`/labs/logs?since=${since}`);
  }

  async getLabResults(labId) {
    return this.request(`/labs/results/${encodeURIComponent(labId)}`);
  }

  /**
   * --- Chapter 13 & Cloud Deployment Service APIs ---
   */
  async getLab13Services() {
    return this.request('/services/lab13');
  }

  async testFailover({ confirmed = true, stepDownSeconds = 30 } = {}) {
    return this.request('/services/lab13/failover/test', {
      method: 'POST',
      headers: {
        'X-Admin-Confirm': 'true',
        'X-Admin-Key': 'threatpulse-soc-admin-secret-2026'
      },
      body: JSON.stringify({ confirmed, stepDownSeconds })
    });
  }

  async startKubernetes({ confirmed = true } = {}) {
    return this.request('/services/lab13/k8s/start', {
      method: 'POST',
      headers: {
        'X-Admin-Confirm': 'true',
        'X-Admin-Key': 'threatpulse-soc-admin-secret-2026'
      },
      body: JSON.stringify({ confirmed })
    });
  }

  async deployAtlas({ confirmed = true } = {}) {
    return this.request('/services/lab13/atlas/deploy', {
      method: 'POST',
      headers: {
        'X-Admin-Confirm': 'true',
        'X-Admin-Key': 'threatpulse-soc-admin-secret-2026'
      },
      body: JSON.stringify({ confirmed })
    });
  }

  /**
   * --- Admin Operations Telemetry ---
   */
  async getDeploymentMetrics(minutes = 15) {
    return this.request(`/ops/metrics/deployment?minutes=${encodeURIComponent(minutes)}`);
  }

  /**
   * --- Authentication & Session APIs ---
   */
  async getAuthMe() {
    return this.request('/auth/me');
  }

  async login(username, password) {
    return this.request('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, email: username, password })
    });
  }

  async loginAdmin(email, password) {
    return this.login(email, password);
  }

  async logout() {
    return this.request('/auth/logout', { method: 'POST' });
  }

  async logoutAdmin() {
    return this.logout();
  }

  /**
   * --- Chapter 14: Monitoring, Alerts & Backup Services ---
   */
  async getLab14Services() {
    return this.request('/services/lab14');
  }

  async getMonitoringMetrics(minutes = 30) {
    return this.request(`/ops/metrics/monitoring?minutes=${encodeURIComponent(minutes)}`);
  }

  async triggerManualBackup(adminKey = 'threatpulse-soc-admin-secret-2026', confirmed = true) {
    return this.request('/ops/lab14/backup', {
      method: 'POST',
      headers: {
        'X-Admin-Confirm': 'true',
        'X-Admin-Key': adminKey
      },
      body: JSON.stringify({ confirmed })
    });
  }

  async triggerRestoreVerification(adminKey = 'threatpulse-soc-admin-secret-2026', confirmed = true, backupId = null) {
    return this.request('/ops/lab14/verify', {
      method: 'POST',
      headers: {
        'X-Admin-Confirm': 'true',
        'X-Admin-Key': adminKey
      },
      body: JSON.stringify({ confirmed, backupId })
    });
  }

  async getModerationAlerts(adminKey = 'threatpulse-soc-admin-secret-2026') {
    return this.request('/moderation/alerts', {
      headers: { 'X-Admin-Key': adminKey }
    });
  }

  async acknowledgeAlert(alertId, adminKey = 'threatpulse-soc-admin-secret-2026') {
    return this.request('/moderation/alerts/ack', {
      method: 'POST',
      headers: {
        'X-Admin-Key': adminKey
      },
      body: JSON.stringify({ alertId })
    });
  }

  async runLab14() {
    return this.request('/labs/14/run', { method: 'POST' });
  }

  /**
   * --- Chapter 15: Multi-Tenant Case Management Services ---
   */
  async getCasesMe(headers = {}) {
    return this.request('/cases/me', { headers });
  }

  async getCases({ status = '', priority = '', search = '' } = {}, headers = {}) {
    const params = new URLSearchParams();
    if (status) params.append('status', status);
    if (priority) params.append('priority', priority);
    if (search) params.append('search', search);
    const qs = params.toString() ? `?${params.toString()}` : '';
    return this.request(`/cases${qs}`, { headers });
  }

  async createCase(caseData, headers = {}) {
    return this.request('/cases', {
      method: 'POST',
      headers,
      body: JSON.stringify(caseData)
    });
  }

  async getCaseById(caseId, headers = {}) {
    return this.request(`/cases/${encodeURIComponent(caseId)}`, { headers });
  }

  async updateCase(caseId, updateData, headers = {}) {
    return this.request(`/cases/${encodeURIComponent(caseId)}`, {
      method: 'PATCH',
      headers,
      body: JSON.stringify(updateData)
    });
  }

  async deleteCase(caseId, headers = {}) {
    return this.request(`/cases/${encodeURIComponent(caseId)}`, {
      method: 'DELETE',
      headers
    });
  }

  async getOrgMembers(headers = {}) {
    return this.request('/cases/org/members', { headers });
  }

  async getModerationOrganisations(adminKey = 'threatpulse-soc-admin-secret-2026') {
    return this.request('/moderation/organisations', {
      headers: { 'X-Admin-Key': adminKey }
    });
  }

  async getLab15Services() {
    return this.request('/services/lab15');
  }

  async runLab15() {
    return this.request('/labs/15/run', { method: 'POST' });
  }

  /* -------------------------------------------------------------
     CHAPTER 16: CASSANDRA & NEO4J MULTI-DATABASE INTEGRATION
  ------------------------------------------------------------- */
  async getLab16Services() {
    return this.request('/services/lab16');
  }

  async startLab16Services(adminKey = 'threatpulse-soc-admin-secret-2026') {
    return this.request('/services/lab16/start', {
      method: 'POST',
      headers: { 'X-Admin-Key': adminKey }
    });
  }

  async stopLab16Services(adminKey = 'threatpulse-soc-admin-secret-2026') {
    return this.request('/services/lab16/stop', {
      method: 'POST',
      headers: { 'X-Admin-Key': adminKey }
    });
  }

  async getAuditLogs(params = {}) {
    const q = new URLSearchParams();
    if (params.day) q.append('day', params.day);
    if (params.actor) q.append('actor', params.actor);
    if (params.role) q.append('role', params.role);
    if (params.action) q.append('action', params.action);
    if (params.outcome) q.append('outcome', params.outcome);
    if (params.limit) q.append('limit', params.limit);
    const qs = q.toString() ? `?${q.toString()}` : '';
    return this.request(`/ops/audit${qs}`);
  }

  async getAuditSummary(days = 7) {
    return this.request(`/ops/audit/summary?days=${days}`);
  }

  async getFraudAccounts(adminKey = 'threatpulse-soc-admin-secret-2026') {
    return this.request('/moderation/fraud', {
      headers: { 'X-Admin-Key': adminKey }
    });
  }

  async getFraudAccountDossier(accountId, adminKey = 'threatpulse-soc-admin-secret-2026') {
    return this.request(`/moderation/fraud/${encodeURIComponent(accountId)}`, {
      headers: { 'X-Admin-Key': adminKey }
    });
  }

  async runLab16() {
    return this.request('/labs/16/run', { method: 'POST' });
  }

  /* -------------------------------------------------------------
     CHAPTER 17: VECTOR SEARCH & RAG THREAT INTELLIGENCE
  ------------------------------------------------------------- */
  async askQuestion(question, headers = {}) {
    return this.request('/ask', {
      method: 'POST',
      headers,
      body: JSON.stringify({ question })
    });
  }

  async getAskHistory(headers = {}) {
    return this.request('/ask/history', { headers });
  }

  async clearAskHistory(headers = {}) {
    return this.request('/ask/history', {
      method: 'DELETE',
      headers
    });
  }

  async getAskIndexOverview(adminKey = 'threatpulse-soc-admin-secret-2026') {
    return this.request('/ops/ask-index', {
      headers: { 'X-Admin-Key': adminKey }
    });
  }

  async triggerAskIndexing(adminKey = 'threatpulse-soc-admin-secret-2026') {
    return this.request('/ops/ask-index', {
      method: 'POST',
      headers: {
        'X-Admin-Key': adminKey,
        'X-Admin-Confirm': 'true'
      }
    });
  }

  async getLab17Services() {
    return this.request('/services/lab17');
  }

  async runLab17() {
    return this.request('/labs/17/run', { method: 'POST' });
  }

  /* -------------------------------------------------------------
     CHAPTER 18: COMPARATIVE DATABASE CAPSTONE (FALSE-POSITIVE DETECTION)
  ------------------------------------------------------------- */
  async getLab18Services() {
    return this.request('/services/lab18');
  }

  async getModerationFpCandidates(params = {}, headers = {}) {
    const qs = new URLSearchParams();
    if (params.state) qs.set('state', params.state);
    if (params.source) qs.set('source', params.source);
    if (params.threat_type) qs.set('threat_type', params.threat_type);
    if (params.consensus) qs.set('consensus', params.consensus);
    if (params.limit) qs.set('limit', params.limit);
    if (params.skip) qs.set('skip', params.skip);
    const queryString = qs.toString() ? `?${qs.toString()}` : '';
    return this.request(`/moderation/fp${queryString}`, { headers });
  }

  async getModerationFpValueDetail(value, headers = {}) {
    return this.request(`/moderation/fp/value?value=${encodeURIComponent(value)}`, { headers });
  }

  async postModerationFpDecision(decisionData, headers = {}) {
    return this.request('/moderation/fp/decision', {
      method: 'POST',
      headers,
      body: JSON.stringify(decisionData)
    });
  }

  async getOpsSourcesAnalytics(adminKey = 'threatpulse-soc-admin-secret-2026') {
    return this.request('/ops/sources', {
      headers: { 'X-Admin-Key': adminKey }
    });
  }

  async getExportThreats(params = {}, headers = {}) {
    const qs = new URLSearchParams();
    if (params.exclude_fp !== undefined) qs.set('exclude_fp', params.exclude_fp);
    if (params.format) qs.set('format', params.format);
    if (params.limit) qs.set('limit', params.limit);
    const queryString = qs.toString() ? `?${qs.toString()}` : '';
    return this.request(`/ops/export/threats${queryString}`, { headers });
  }

  async runLab18() {
    return this.request('/labs/18/run', { method: 'POST' });
  }
}

window.apiService = new ApiService();

