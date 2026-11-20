/**
 * Threat Advisor Frontend Controller
 * Handles streaming NDJSON chat with requestAnimationFrame,
 * 3 Side Panels (Evidence, My System, Monitor), Threat Catalog search,
 * and Grounding Comparison Test.
 */

(function () {
  let currentPlatform = null;
  let currentStatus = null;
  let activeSessionId = null;
  let streamAbortController = null;
  let streamPendingText = "";
  let currentAssistantDiv = null;
  let rafId = null;

  // Initialize once DOM is ready
  document.addEventListener("DOMContentLoaded", () => {
    setupChips();
    setupChatInputs();
    setupSidePanelTabs();
    loadMySystemPanel();
    loadMonitorPanel();
    loadSessionHistory();

    // Re-check periodically
    setInterval(loadMySystemPanel, 15000);
  });

  function setupChips() {
    // Platform chips
    document.querySelectorAll(".ta-chip-platform").forEach(chip => {
      chip.addEventListener("click", () => {
        document.querySelectorAll(".ta-chip-platform").forEach(c => c.classList.remove("active"));
        const plat = chip.getAttribute("data-platform");
        if (currentPlatform === plat) {
          currentPlatform = null;
        } else {
          currentPlatform = plat;
          chip.classList.add("active");
        }
      });
    });

    // Status chips
    document.querySelectorAll(".ta-chip-status").forEach(chip => {
      chip.addEventListener("click", () => {
        const status = chip.getAttribute("data-status");
        openThreatCatalogModal(status, currentPlatform);
      });
    });
  }

  function setupSidePanelTabs() {
    const tabs = document.querySelectorAll(".ta-side-tab-btn");
    tabs.forEach(btn => {
      btn.addEventListener("click", () => {
        tabs.forEach(b => b.classList.remove("active"));
        document.querySelectorAll(".ta-side-tab-content").forEach(c => c.classList.remove("active"));

        btn.classList.add("active");
        const targetId = btn.getAttribute("data-target");
        const pane = document.getElementById(targetId);
        if (pane) pane.classList.add("active");
      });
    });
  }

  function setupChatInputs() {
    const btnSend = document.getElementById("btnTaSend");
    const btnStop = document.getElementById("btnTaStop");
    const inputArea = document.getElementById("taChatInput");
    const btnNewChat = document.getElementById("btnTaNewChat");
    const btnScanNow = document.getElementById("btnTaScanNow");
    const btnRunCompare = document.getElementById("btnTaRunCompare");

    if (btnSend && inputArea) {
      btnSend.addEventListener("click", () => submitMessage());
      inputArea.addEventListener("keydown", (e) => {
        if (e.key === "Enter" && !e.shiftKey) {
          e.preventDefault();
          submitMessage();
        }
      });
    }

    if (btnStop) {
      btnStop.addEventListener("click", () => {
        if (streamAbortController) {
          streamAbortController.abort();
          streamAbortController = null;
          updateStatusIndicator("Generation stopped.");
          btnStop.style.display = "none";
        }
      });
    }

    if (btnNewChat) {
      btnNewChat.addEventListener("click", () => {
        activeSessionId = "sess_" + Date.now();
        const container = document.getElementById("taMessagesContainer");
        if (container) {
          container.innerHTML = `
            <div class="ta-msg ta-msg-assistant">
              <strong>Threat Advisor:</strong> Ready. Ask about threats (Active, Evolving, Anticipated, Resolved) across Windows, Linux, macOS, Android, iOS, or ask about your PC inventory (e.g., <em>"is Chrome installed?"</em> or <em>"Am I affected by CVE-2024-38063?"</em>).
            </div>
          `;
        }
        clearEvidencePanel();
      });
    }

    if (btnScanNow) {
      btnScanNow.addEventListener("click", async () => {
        btnScanNow.disabled = true;
        const originalText = btnScanNow.innerHTML;
        btnScanNow.innerHTML = `<span style="display:inline-block; width:12px; height:12px; border:2px solid #fff; border-top-color:transparent; border-radius:50%; animation:ta-spin 0.8s linear infinite; margin-right:6px; vertical-align:middle;"></span> Scanning System...`;
        try {
          const res = await fetch("/api/agent/scan-now", { method: "POST" });
          const data = await res.json();
          await loadMySystemPanel();
          showToast(data.message || "Host system scan completed! Telemetry refreshed.", "success");
        } catch (e) {
          showToast("Error executing scan: " + e.message, "error");
        } finally {
          btnScanNow.disabled = false;
          btnScanNow.innerHTML = originalText || "⚡ Scan Now";
        }
      });
    }

    if (btnRunCompare) {
      btnRunCompare.addEventListener("click", () => runGroundingCompareDemo());
    }
  }

  async function submitMessage() {
    const inputArea = document.getElementById("taChatInput");
    const text = inputArea.value.trim();
    if (!text) return;

    inputArea.value = "";
    appendUserMessage(text);

    if (!activeSessionId) {
      activeSessionId = "sess_" + Date.now();
    }

    updateStatusIndicator("Searching MongoDB & Grounding Context...");

    const btnStop = document.getElementById("btnTaStop");
    if (btnStop) btnStop.style.display = "inline-flex";

    streamAbortController = new AbortController();

    currentAssistantDiv = appendAssistantPlaceholder();
    streamPendingText = "";

    try {
      const response = await fetch("/chat/stream", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          question: text,
          sessionId: activeSessionId,
          platformFilter: currentPlatform,
          statusFilter: currentStatus
        }),
        signal: streamAbortController.signal
      });

      if (!response.ok) {
        throw new Error("HTTP " + response.status);
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder("utf-8");
      let buffer = "";

      startAnimationLoop();

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop(); // keep trailing incomplete chunk

        for (const line of lines) {
          if (!line.trim()) continue;
          try {
            const ev = jsonParse(line);
            handleStreamEvent(ev);
          } catch (err) {
            console.error("Stream parse error:", err);
          }
        }
      }

      updateStatusIndicator("Completed (Verified against MongoDB).");
    } catch (e) {
      if (e.name === "AbortError") {
        updateStatusIndicator("Stopped by user.");
      } else {
        updateStatusIndicator("Error: " + e.message);
        if (currentAssistantDiv) {
          currentAssistantDiv.innerHTML += `<div style="color:#f87171; margin-top:8px;">[Connection error: ${e.message}]</div>`;
        }
      }
    } finally {
      stopAnimationLoop();
      if (btnStop) btnStop.style.display = "none";
      streamAbortController = null;
      loadSessionHistory();
    }
  }

  function handleStreamEvent(ev) {
    if (ev.event === "meta") {
      updateEvidencePanel(ev.data);
      updateStatusIndicator(ev.data.skipLlm ? "Backend writing deterministic answer..." : "Writing answer (Grounded in MongoDB)...");
    } else if (ev.event === "delta") {
      streamPendingText += ev.data.text;
    } else if (ev.event === "done") {
      updateGroundingPanel(ev.data.grounding);
    }
  }

  function startAnimationLoop() {
    function tick() {
      if (currentAssistantDiv && streamPendingText) {
        currentAssistantDiv.innerHTML = formatMarkdown(streamPendingText);
        autoScrollBottom();
      }
      rafId = requestAnimationFrame(tick);
    }
    rafId = requestAnimationFrame(tick);
  }

  function stopAnimationLoop() {
    if (rafId) {
      cancelAnimationFrame(rafId);
      rafId = null;
    }
    if (currentAssistantDiv && streamPendingText) {
      currentAssistantDiv.innerHTML = formatMarkdown(streamPendingText);
      autoScrollBottom();
    }
  }

  function autoScrollBottom() {
    const c = document.getElementById("taMessagesContainer");
    if (!c) return;
    const isAtBottom = (c.scrollHeight - c.scrollTop - c.clientHeight) < 80;
    if (isAtBottom) {
      c.scrollTop = c.scrollHeight;
    }
  }

  function appendUserMessage(text) {
    const c = document.getElementById("taMessagesContainer");
    if (!c) return;
    const d = document.createElement("div");
    d.className = "ta-msg ta-msg-user";
    d.textContent = text;
    c.appendChild(d);
    c.scrollTop = c.scrollHeight;
  }

  function appendAssistantPlaceholder() {
    const c = document.getElementById("taMessagesContainer");
    if (!c) return null;
    const d = document.createElement("div");
    d.className = "ta-msg ta-msg-assistant";
    d.innerHTML = "<em>Analyzing catalog and verifying against MongoDB...</em>";
    c.appendChild(d);
    c.scrollTop = c.scrollHeight;
    return d;
  }

  function updateStatusIndicator(text) {
    const el = document.getElementById("taStatusIndicator");
    if (el) el.textContent = text;
  }

  function updateEvidencePanel(meta) {
    const container = document.getElementById("taEvidenceContent");
    if (!container) return;

    let html = "";

    // 1. Timings
    const t = meta.timings || {};
    html += `
      <div class="ta-card">
        <div class="ta-card-title">Execution Timings</div>
        <div class="ta-stat-row"><span>Retrieval Time</span><span style="color:#38bdf8;">${t.retrievalMs || t.totalMs || 0} ms</span></div>
        <div class="ta-stat-row"><span>Host Enrolled</span><span>${meta.hostEnrolled ? "✓ Yes" : "No (Install Scanner)"}</span></div>
      </div>
    `;

    // 2. Deterministic Verdicts
    if (meta.verdicts && meta.verdicts.length > 0) {
      html += `
        <div class="ta-card" style="border-color:#10b981;">
          <div class="ta-card-title" style="color:#10b981;">Deterministic Checks (${meta.verdicts.length})</div>
      `;
      meta.verdicts.forEach(v => {
        const badgeClass = v.verdict === "AFFECTED" ? "ta-badge-affected" : (v.verdict === "PATCHED" ? "ta-badge-patched" : "ta-badge-safe");
        html += `
          <div style="font-size:0.78rem; margin-bottom:8px; border-bottom:1px solid #334155; padding-bottom:6px;">
            <div style="display:flex; justify-content:space-between; margin-bottom:2px;">
              <strong>${v.cveId}</strong>
              <span class="ta-badge ${badgeClass}">${v.verdict}</span>
            </div>
            <div style="color:#94a3b8;">${v.details}</div>
          </div>
        `;
      });
      html += `</div>`;
    }

    // 3. Retrieved Records
    if (meta.retrievedRecords && meta.retrievedRecords.length > 0) {
      html += `
        <div class="ta-card">
          <div class="ta-card-title">Retrieved MongoDB Threats (${meta.retrievedRecords.length})</div>
      `;
      meta.retrievedRecords.forEach(r => {
        html += `
          <div style="font-size:0.78rem; border-bottom:1px solid #334155; padding:4px 0;">
            <a href="javascript:void(0)" onclick="window.askAboutCVE('${r.cveId}')" class="ta-cve-link">${r.cveId}</a>
            <span style="color:#94a3b8; margin-left:6px;">CVSS: ${r.cvss} | Status: ${r.status}</span>
          </div>
        `;
      });
      html += `</div>`;
    }

    // 4. Chunks
    if (meta.chunks && meta.chunks.length > 0) {
      html += `
        <div class="ta-card">
          <div class="ta-card-title">Top Vector Knowledge Chunks (${meta.chunks.length})</div>
      `;
      meta.chunks.forEach(c => {
        html += `
          <div style="font-size:0.75rem; margin-bottom:6px; background:#0f172a; padding:6px; border-radius:4px;">
            <div style="display:flex; justify-content:space-between; color:#38bdf8;">
              <span>${c.chunkId}</span>
              <span>Score: ${c.score}</span>
            </div>
            <div style="color:#cbd5e1; margin-top:4px;">${c.text.substring(0, 110)}...</div>
          </div>
        `;
      });
      html += `</div>`;
    }

    container.innerHTML = html;
  }

  function updateGroundingPanel(grounding) {
    if (!grounding) return;
    const container = document.getElementById("taEvidenceContent");
    if (!container) return;

    let html = `
      <div class="ta-card" style="border-color:${grounding.fullyGrounded ? '#10b981' : '#f59e0b'};">
        <div class="ta-card-title">
          <span>Grounding Audit</span>
          <span class="ta-badge ${grounding.fullyGrounded ? 'ta-badge-patched' : 'ta-badge-affected'}">
            ${grounding.fullyGrounded ? '100% Grounded' : 'Warning'}
          </span>
        </div>
        <div style="font-size:0.78rem; color:#94a3b8; margin-bottom:8px;">
          Audited cited CVEs against MongoDB knowledge base:
        </div>
    `;

    if (grounding.cveAudits && grounding.cveAudits.length > 0) {
      grounding.cveAudits.forEach(a => {
        const color = a.status === "from the context" ? "#10b981" : (a.status === "in MongoDB but not in the context" ? "#38bdf8" : "#ef4444");
        html += `
          <div class="ta-stat-row">
            <strong>${a.cveId}</strong>
            <span style="color:${color}; font-weight:600;">${a.status}</span>
          </div>
        `;
      });
    } else {
      html += `<div style="font-size:0.78rem; color:#64748b;">No individual CVE IDs cited in this response.</div>`;
    }

    html += `</div>`;
    container.innerHTML += html;
  }

  function clearEvidencePanel() {
    const c = document.getElementById("taEvidenceContent");
    if (c) c.innerHTML = `<div style="color:#64748b; font-size:0.8rem; text-align:center; padding:20px 0;">Ask a question to see retrieved MongoDB records, CPE verdicts, and grounding breakdown.</div>`;
  }

  async function loadMySystemPanel() {
    try {
      const res = await fetch("/api/agent/my-system");
      if (!res.ok) return;
      const data = await res.json();

      const hostEl = document.getElementById("taHostHostname");
      const buildEl = document.getElementById("taHostBuild");
      const lastScanEl = document.getElementById("taHostLastScan");
      const affEl = document.getElementById("taCountAffected");
      const patEl = document.getElementById("taCountPatched");
      const safeEl = document.getElementById("taCountSafe");

      if (hostEl) hostEl.textContent = data.hostname || "Windows Host";
      if (buildEl) buildEl.textContent = data.osBuild || "N/A";
      if (lastScanEl) lastScanEl.textContent = data.lastScanTime ? new Date(data.lastScanTime).toLocaleTimeString() : "Never";
      if (affEl) affEl.textContent = data.affectedCount || 0;
      if (patEl) patEl.textContent = data.patchedCount || 0;
      if (safeEl) safeEl.textContent = data.notAffectedCount || 0;
    } catch (e) {
      console.warn("My system poll failed:", e);
    }
  }

  async function loadMonitorPanel() {
    try {
      const res = await fetch("/api/monitor/metrics");
      if (!res.ok) return;
      const data = await res.json();

      const p50El = document.getElementById("taMetricP50");
      const p95El = document.getElementById("taMetricP95");
      const errEl = document.getElementById("taMetricError");
      const reqEl = document.getElementById("taMetricRequests");

      if (p50El) p50El.textContent = data.p50LatencyMs + " ms";
      if (p95El) p95El.textContent = data.p95LatencyMs + " ms";
      if (errEl) errEl.textContent = data.errorRatePct + " %";
      if (reqEl) reqEl.textContent = data.totalRequests;
    } catch (e) {
      console.warn("Monitor metrics fetch failed:", e);
    }
  }

  async function runGroundingCompareDemo(customQ) {
    const q = customQ || "What active threats affect Windows and how are they mitigated?";

    const modal = document.getElementById("taCompareModal");
    const body = document.getElementById("taCompareModalBody");
    if (!modal || !body) return;

    modal.style.display = "flex";
    body.innerHTML = `<div style="text-align:center; padding:30px; color:#38bdf8;">Running Model Alone (No RAG) vs Hybrid MongoDB RAG...</div>`;

    try {
      const res = await fetch("/api/compare", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question: q })
      });
      const data = await res.json();

      body.innerHTML = `
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:16px;">
          <div style="background:#1e293b; padding:14px; border-radius:8px; border:1px solid #ef4444;">
            <div style="display:flex; justify-content:space-between; margin-bottom:10px;">
              <strong style="color:#f87171;">Model Alone (Raw LLM - No RAG)</strong>
              <span class="ta-badge ta-badge-affected">Ungrounded</span>
            </div>
            <div style="font-size:0.8rem; color:#94a3b8; margin-bottom:10px;">${data.modelAlone.explanation}</div>
            <div style="font-size:0.82rem; line-height:1.4; max-height:340px; overflow-y:auto; color:#cbd5e1; white-space:pre-wrap;">${data.modelAlone.answer}</div>
          </div>
          <div style="background:#1e293b; padding:14px; border-radius:8px; border:1px solid #10b981;">
            <div style="display:flex; justify-content:space-between; margin-bottom:10px;">
              <strong style="color:#34d399;">MongoDB Hybrid RAG (Ground Truth)</strong>
              <span class="ta-badge ta-badge-patched">100% Grounded</span>
            </div>
            <div style="font-size:0.8rem; color:#94a3b8; margin-bottom:10px;">${data.mongoRAG.explanation}</div>
            <div style="font-size:0.82rem; line-height:1.4; max-height:340px; overflow-y:auto; color:#f1f5f9; white-space:pre-wrap;">${data.mongoRAG.answer}</div>
          </div>
        </div>
      `;
    } catch (e) {
      body.innerHTML = `<div style="color:#f87171;">Comparison error: ${e.message}</div>`;
    }
  }

  async function openThreatCatalogModal(status, platform) {
    const modal = document.getElementById("taCatalogModal");
    const body = document.getElementById("taCatalogModalBody");
    const title = document.getElementById("taCatalogModalTitle");
    if (!modal || !body) return;

    modal.style.display = "flex";
    if (title) title.textContent = `${status} Threats Catalog (${platform || 'All Platforms'})`;
    body.innerHTML = `<div style="text-align:center; padding:20px; color:#38bdf8;">Loading ${status} records from MongoDB...</div>`;

    try {
      const url = `/api/threats?status=${status || ''}&platform=${platform || ''}&limit=50`;
      const res = await fetch(url);
      const data = await res.json();

      let html = `
        <table style="width:100%; border-collapse:collapse; font-size:0.82rem;">
          <thead>
            <tr style="background:#0f172a; text-align:left;">
              <th style="padding:8px 10px; border:1px solid #334155;">CVE ID</th>
              <th style="padding:8px 10px; border:1px solid #334155;">Title / Product</th>
              <th style="padding:8px 10px; border:1px solid #334155;">CVSS</th>
              <th style="padding:8px 10px; border:1px solid #334155;">EPSS</th>
              <th style="padding:8px 10px; border:1px solid #334155;">Platforms</th>
              <th style="padding:8px 10px; border:1px solid #334155;">Action</th>
            </tr>
          </thead>
          <tbody>
      `;

      data.threats.forEach(t => {
        html += `
          <tr style="border-bottom:1px solid #1e293b;">
            <td style="padding:8px 10px; font-weight:700; color:#38bdf8;">${t.cveId}</td>
            <td style="padding:8px 10px;">
              <strong>${t.product}</strong>
              <div style="font-size:0.75rem; color:#94a3b8;">${t.title}</div>
            </td>
            <td style="padding:8px 10px; color:#f87171; font-weight:700;">${t.cvss}</td>
            <td style="padding:8px 10px; color:#fbbf24;">${t.epss}</td>
            <td style="padding:8px 10px; text-transform:uppercase; font-size:0.72rem;">${t.platforms.join(', ')}</td>
            <td style="padding:8px 10px;">
              <button class="btn-runner-primary" style="padding:4px 8px; font-size:0.74rem;" onclick="window.askAboutCVE('${t.cveId}')">Ask CTI</button>
            </td>
          </tr>
        `;
      });

      html += `</tbody></table>`;
      body.innerHTML = html;
    } catch (e) {
      body.innerHTML = `<div style="color:#f87171;">Failed to load catalog: ${e.message}</div>`;
    }
  }

  async function loadSessionHistory() {
    const list = document.getElementById("taSessionList");
    if (!list) return;

    try {
      const res = await fetch("/api/sessions");
      if (!res.ok) return;
      const data = await res.json();

      if (!data.sessions || data.sessions.length === 0) {
        list.innerHTML = `<div style="color:#64748b; font-size:0.75rem; padding:6px 0;">No past sessions</div>`;
        return;
      }

      let html = "";
      data.sessions.forEach(s => {
        html += `
          <div style="display:flex; justify-content:space-between; align-items:center; padding:6px 8px; border-bottom:1px solid #1e293b; font-size:0.78rem;">
            <span style="color:#cbd5e1; cursor:pointer; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; max-width:180px;" onclick="window.openSession('${s.sessionId}')">
              ${s.title}
            </span>
            <button style="background:transparent; border:none; color:#ef4444; cursor:pointer;" onclick="window.deleteSession('${s.sessionId}')" title="Delete">✕</button>
          </div>
        `;
      });
      list.innerHTML = html;
    } catch (e) {
      console.warn("Session history error:", e);
    }
  }

  window.askAboutCVE = function (cveId) {
    const modal = document.getElementById("taCatalogModal");
    if (modal) modal.style.display = "none";

    const input = document.getElementById("taChatInput");
    if (input) {
      input.value = `Tell me about ${cveId}, its lifecycle status, and exact mitigation steps.`;
      submitMessage();
    }
  };

  window.openSession = async function (sessionId) {
    activeSessionId = sessionId;
    try {
      const res = await fetch(`/api/sessions/${sessionId}`);
      const data = await res.json();
      const c = document.getElementById("taMessagesContainer");
      if (!c) return;
      c.innerHTML = "";
      data.messages.forEach(m => {
        const d = document.createElement("div");
        d.className = m.role === "user" ? "ta-msg ta-msg-user" : "ta-msg ta-msg-assistant";
        d.innerHTML = m.role === "user" ? m.content : formatMarkdown(m.content);
        c.appendChild(d);
      });
      c.scrollTop = c.scrollHeight;
    } catch (e) {
      alert("Error loading session: " + e.message);
    }
  };

  window.deleteSession = async function (sessionId) {
    if (!confirm("Are you sure you want to delete this conversation?")) return;
    try {
      await fetch(`/api/sessions/${sessionId}`, { method: "DELETE" });
      loadSessionHistory();
    } catch (e) {
      alert("Delete failed: " + e.message);
    }
  };

  function jsonParse(str) {
    try {
      return JSON.parse(str);
    } catch (e) {
      return null;
    }
  }

  function formatMarkdown(text) {
    if (!text) return "";
    let s = text;

    // Code blocks
    s = s.replace(/```([a-z0-9]*)\n([\s\S]*?)```/g, (match, lang, code) => {
      const cleanCode = code.trim().replace(/"/g, '&quot;');
      return `<div style="background:#0b0f19; border:1px solid #334155; border-radius:6px; padding:10px; margin:8px 0; font-family:var(--font-mono); font-size:0.78rem; position:relative;">
        <button type="button" class="btn-runner-primary" style="position:absolute; right:8px; top:8px; padding:2px 8px; font-size:0.7rem;" onclick="navigator.clipboard.writeText('${cleanCode}'); alert('Copied!');">Copy</button>
        <pre style="margin:0; overflow-x:auto; color:#38bdf8;"><code>${cleanCode}</code></pre>
      </div>`;
    });

    // Headers
    s = s.replace(/^### (.*$)/gim, '<h4 style="color:#f1f5f9; margin:12px 0 6px 0; font-size:0.95rem; font-weight:700;">$1</h4>');
    s = s.replace(/^#### (.*$)/gim, '<h5 style="color:#e2e8f0; margin:10px 0 4px 0; font-size:0.9rem; font-weight:600;">$1</h5>');

    // Bold
    s = s.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');

    // Code spans
    s = s.replace(/`([^`]+)`/g, '<code style="background:#0b0f19; color:#38bdf8; padding:2px 6px; border-radius:4px; font-family:var(--font-mono); font-size:0.8rem; border:1px solid rgba(56,189,248,0.2);">$1</code>');

    // Tables
    const tableRegex = /((?:\|.+?\|\r?\n)+)/g;
    s = s.replace(tableRegex, (match) => {
      const lines = match.trim().split(/\r?\n/).filter(l => l.trim().startsWith('|'));
      if (lines.length < 2) return match;
      let html = '<table style="width:100%; border-collapse:collapse; margin:10px 0; font-size:0.82rem; background:#0b1120; border-radius:6px; overflow:hidden; border:1px solid #334155;">';
      let isHeader = true;
      for (const line of lines) {
        if (line.includes('---')) {
          isHeader = false;
          continue;
        }
        const cells = line.split('|').map(c => c.trim()).filter((_, idx, arr) => idx > 0 && idx < arr.length - 1);
        if (isHeader) {
          html += '<tr style="background:#1e293b; color:#cbd5e1; font-weight:600;">' + cells.map(c => `<th style="padding:8px 10px; border:1px solid #334155; text-align:left;">${c}</th>`).join('') + '</tr>';
        } else {
          html += '<tr style="border-bottom:1px solid #1e293b;">' + cells.map(c => `<td style="padding:6px 10px; border:1px solid #334155;">${c}</td>`).join('') + '</tr>';
        }
      }
      html += '</table>';
      return html;
    });

    // Lists (- item)
    s = s.replace(/^- (.*$)/gim, '<div style="margin:4px 0 4px 8px; display:flex; align-items:center; gap:6px;">&bull; <span>$1</span></div>');

    // CVE links
    s = s.replace(/\b(CVE-\d{4}-\d{4,7})\b/gi, '<a href="javascript:void(0)" onclick="window.askAboutCVE(\'$1\')" class="ta-cve-link">$1</a>');

    // Double line breaks into paragraphs
    s = s.replace(/\n\n+/g, '<div style="height:8px;"></div>');
    s = s.replace(/\n/g, '<br/>');

    return s;
  }

  function showToast(message, type = "success") {
    let toast = document.getElementById("taToastNotification");
    if (!toast) {
      toast = document.createElement("div");
      toast.id = "taToastNotification";
      toast.style.cssText = "position:fixed; bottom:28px; right:28px; z-index:999999; padding:12px 20px; border-radius:8px; font-size:0.86rem; font-weight:600; box-shadow:0 12px 30px rgba(0,0,0,0.6); transition:all 0.3s cubic-bezier(0.16, 1, 0.3, 1); display:flex; align-items:center; gap:10px; font-family:var(--font-sans, sans-serif);";
      document.body.appendChild(toast);
    }
    const isSuccess = type === "success";
    toast.style.background = isSuccess ? "rgba(6, 95, 70, 0.95)" : "rgba(153, 27, 27, 0.95)";
    toast.style.border = isSuccess ? "1px solid #10b981" : "1px solid #ef4444";
    toast.style.color = "#ffffff";
    toast.innerHTML = (isSuccess ? "✓ " : "⚠️ ") + message;
    toast.style.opacity = "1";
    toast.style.transform = "translateY(0)";

    setTimeout(() => {
      toast.style.opacity = "0";
      toast.style.transform = "translateY(12px)";
    }, 3800);
  }

  // Inject animation keyframes if not present
  if (!document.getElementById("taKeyframesSpin")) {
    const styleEl = document.createElement("style");
    styleEl.id = "taKeyframesSpin";
    styleEl.textContent = `@keyframes ta-spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }`;
    document.head.appendChild(styleEl);
  }
})();
