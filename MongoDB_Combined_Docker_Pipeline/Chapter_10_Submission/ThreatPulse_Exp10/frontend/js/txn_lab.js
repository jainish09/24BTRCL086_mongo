/**
 * ThreatPulse SOC Platform - Transaction Lab Sandbox
 * Controls the interactive ACID test suites for Experiment 10:
 * 10.1 Bank Transfer (Atomicity)
 * 10.1-try WriteConflict Backoff Retry
 * 10.2 Anti-overselling Inventory Reservation
 * 10.2-bench Multi-worker Throughput Benchmark
 */

import { API } from "./api.js";

export function initTxnLab(refreshHudCallback) {
  // 1. Bank Transfer Atomicity Runner
  const btnNonTxn = document.getElementById("btn-sim-non-txn");
  const btnTxn = document.getElementById("btn-sim-txn");
  const transferOutput = document.getElementById("transfer-lab-output");

  if (btnNonTxn) {
    btnNonTxn.addEventListener("click", async () => {
      btnNonTxn.disabled = true;
      transferOutput.innerHTML = `<div class="timeline-item"><span class="badge-step">SIMULATING</span><span class="detail">Executing non-transactional transfer with simulated network crash...</span></div>`;
      try {
        const res = await API.simulateTransferFail("non_transactional", 10);
        renderTransferResult(res, "danger");
      } catch (err) {
        transferOutput.innerHTML = `<div style="color: var(--accent-rose)">Error: ${err.message}</div>`;
      } finally {
        btnNonTxn.disabled = false;
        if (refreshHudCallback) refreshHudCallback();
      }
    });
  }

  if (btnTxn) {
    btnTxn.addEventListener("click", async () => {
      btnTxn.disabled = true;
      transferOutput.innerHTML = `<div class="timeline-item"><span class="badge-step">SIMULATING</span><span class="detail">Starting MongoDB Multi-Document Transaction with Snapshot Isolation...</span></div>`;
      try {
        const res = await API.simulateTransferFail("transactional", 10);
        renderTransferResult(res, "success");
      } catch (err) {
        transferOutput.innerHTML = `<div style="color: var(--accent-rose)">Error: ${err.message}</div>`;
      } finally {
        btnTxn.disabled = false;
        if (refreshHudCallback) refreshHudCallback();
      }
    });
  }

  function renderTransferResult(data, theme) {
    let html = `
      <div style="padding: 1rem; border-radius: var(--radius-md); background: ${theme === 'danger' ? 'rgba(244, 63, 94, 0.1)' : 'rgba(16, 185, 129, 0.1)'}; border: 1px solid ${theme === 'danger' ? 'rgba(244, 63, 94, 0.3)' : 'rgba(16, 185, 129, 0.3)'}; margin-bottom: 1rem;">
        <div style="font-weight: 700; font-size: 1rem; color: ${theme === 'danger' ? 'var(--accent-rose)' : 'var(--accent-emerald)'}; margin-bottom: 0.35rem;">
          ${data.mode} &rarr; ${data.result}
        </div>
        <p style="font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 0.75rem;">${data.explanation}</p>
        <div style="display: flex; gap: 1.5rem; font-family: var(--font-mono); font-size: 0.8rem;">
          <div>Sender Before: <strong>${data.sender_balance_before} cr</strong></div>
          <div>Sender After Crash: <strong>${data.sender_balance_after !== undefined ? data.sender_balance_after : data.sender_balance_after_crash} cr</strong></div>
          <div style="color: ${theme === 'danger' ? 'var(--accent-rose)' : 'var(--accent-emerald)'}">
            ${theme === 'danger' ? `Credits Lost: -${data.credits_lost_due_to_crash} cr (CORRUPTION)` : `Net Loss: 0 cr (100% PRESERVED)`}
          </div>
        </div>
      </div>
    `;

    if (data.receipt && data.receipt.steps) {
      html += `<div class="receipt-timeline">`;
      data.receipt.steps.forEach(s => {
        html += `
          <div class="timeline-item">
            <span class="badge-step">${s.step}</span>
            <span class="detail">${s.reason || s.detail || s.status || JSON.stringify(s)}</span>
          </div>
        `;
      });
      html += `</div>`;
    } else if (data.timeline) {
      html += `<div class="receipt-timeline">`;
      data.timeline.forEach(s => {
        html += `
          <div class="timeline-item">
            <span class="badge-step" style="color: ${s.status.includes('ERROR') ? 'var(--accent-rose)' : 'var(--accent-cyan)'}">${s.step}</span>
            <span class="detail">${s.detail} (${s.status})</span>
          </div>
        `;
      });
      html += `</div>`;
    }

    transferOutput.innerHTML = html;
  }

  // 2. Anti-Overselling Inventory Reservation Runner
  const btnOversellNonTxn = document.getElementById("btn-oversell-non-txn");
  const btnOversellTxn = document.getElementById("btn-oversell-txn");
  const oversellOutput = document.getElementById("oversell-lab-output");

  if (btnOversellNonTxn) {
    btnOversellNonTxn.addEventListener("click", async () => {
      btnOversellNonTxn.disabled = true;
      oversellOutput.innerHTML = `<div class="timeline-item"><span class="badge-step">SPAWNING</span><span class="detail">Firing 15 concurrent non-transactional workers against 5 stock items...</span></div>`;
      try {
        const res = await API.simulateOversell("non_transactional", 5, 15);
        renderOversellResult(res);
      } catch (err) {
        oversellOutput.innerHTML = `<div style="color: var(--accent-rose)">Error: ${err.message}</div>`;
      } finally {
        btnOversellNonTxn.disabled = false;
      }
    });
  }

  if (btnOversellTxn) {
    btnOversellTxn.addEventListener("click", async () => {
      btnOversellTxn.disabled = true;
      oversellOutput.innerHTML = `<div class="timeline-item"><span class="badge-step">SPAWNING</span><span class="detail">Firing 15 concurrent transactional workers with {available_units: {$gte: 1}} guard...</span></div>`;
      try {
        const res = await API.simulateOversell("transactional", 5, 15);
        renderOversellResult(res);
      } catch (err) {
        oversellOutput.innerHTML = `<div style="color: var(--accent-rose)">Error: ${err.message}</div>`;
      } finally {
        btnOversellTxn.disabled = false;
      }
    });
  }

  function renderOversellResult(data) {
    const isDanger = data.oversold_occurred;
    oversellOutput.innerHTML = `
      <div style="padding: 1.25rem; border-radius: var(--radius-md); background: ${isDanger ? 'rgba(244, 63, 94, 0.1)' : 'rgba(16, 185, 129, 0.1)'}; border: 1px solid ${isDanger ? 'rgba(244, 63, 94, 0.3)' : 'rgba(16, 185, 129, 0.3)'}; margin-bottom: 1rem;">
        <div style="font-weight: 700; font-size: 1.1rem; color: ${isDanger ? 'var(--accent-rose)' : 'var(--accent-emerald)'}; margin-bottom: 0.5rem;">
          ${data.verdict}
        </div>
        <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; font-family: var(--font-mono); font-size: 0.85rem; margin-top: 0.75rem;">
          <div style="background: rgba(0,0,0,0.3); padding: 0.5rem; border-radius: 6px;">
            <div style="color: var(--text-muted); font-size: 0.7rem;">Initial Pool</div>
            <strong>${data.initial_stock} units</strong>
          </div>
          <div style="background: rgba(0,0,0,0.3); padding: 0.5rem; border-radius: 6px;">
            <div style="color: var(--text-muted); font-size: 0.7rem;">Concurrent Requests</div>
            <strong>${data.concurrent_attempts} requests</strong>
          </div>
          <div style="background: rgba(0,0,0,0.3); padding: 0.5rem; border-radius: 6px;">
            <div style="color: var(--text-muted); font-size: 0.7rem;">Reserved / Success</div>
            <strong style="color: ${isDanger ? 'var(--accent-rose)' : 'var(--accent-emerald)'};">${data.successful_reservations}</strong>
          </div>
          <div style="background: rgba(0,0,0,0.3); padding: 0.5rem; border-radius: 6px;">
            <div style="color: var(--text-muted); font-size: 0.7rem;">Rejected Cleanly</div>
            <strong>${data.rejected_requests}</strong>
          </div>
        </div>
        <div style="margin-top: 0.75rem; font-size: 0.8rem; color: var(--text-secondary);">
          Final Stock Count: <strong style="color: ${data.final_available_units < 0 ? 'var(--accent-rose)' : 'var(--accent-emerald)'}">${data.final_available_units}</strong> (Should NEVER be less than 0)
        </div>
      </div>
    `;
  }

  // 3. Transient Error Retry Runner
  const btnRetry = document.getElementById("btn-sim-retry");
  const retryOutput = document.getElementById("retry-lab-output");

  if (btnRetry) {
    btnRetry.addEventListener("click", async () => {
      btnRetry.disabled = true;
      retryOutput.innerHTML = `<div class="timeline-item"><span class="badge-step">EXECUTING</span><span class="detail">Simulating concurrent overlapping transactions to induce WriteConflict (Code 112)...</span></div>`;
      try {
        const res = await API.demoRetryConflict();
        let html = `
          <div style="padding: 1rem; border-radius: var(--radius-md); background: rgba(0, 240, 255, 0.08); border: 1px solid rgba(0, 240, 255, 0.3); margin-bottom: 1rem;">
            <div style="font-weight: 700; color: var(--accent-cyan); font-size: 0.95rem;">TransientTransactionError Handled with Exponential Backoff</div>
            <p style="font-size: 0.8rem; color: var(--text-secondary); margin-top: 0.25rem;">${res.description}</p>
            <div style="display: flex; gap: 1.5rem; font-family: var(--font-mono); font-size: 0.8rem; margin-top: 0.5rem;">
              <div>Worker 1 Attempts: <strong>${res.worker_1_attempts}</strong></div>
              <div>Worker 2 Attempts: <strong>${res.worker_2_attempts}</strong></div>
              <div>Final Value: <strong>${res.final_counter}</strong></div>
            </div>
          </div>
        `;

        if (res.receipt_worker_1 && res.receipt_worker_1.steps) {
          html += `<div style="font-size: 0.75rem; color: var(--text-muted); margin-bottom: 0.25rem;">Worker 1 Timeline:</div><div class="receipt-timeline">`;
          res.receipt_worker_1.steps.forEach(s => {
            html += `<div class="timeline-item"><span class="badge-step">${s.step}</span><span class="detail">${s.status || s.error_label || ''} (Backoff: ${s.backoff_sec || 0}s)</span></div>`;
          });
          html += `</div>`;
        }

        retryOutput.innerHTML = html;
      } catch (err) {
        retryOutput.innerHTML = `<div style="color: var(--accent-rose)">Error: ${err.message}</div>`;
      } finally {
        btnRetry.disabled = false;
      }
    });
  }

  // 4. Benchmark Runner
  const btnBench = document.getElementById("btn-run-benchmark");
  const benchOutput = document.getElementById("benchmark-lab-output");

  if (btnBench) {
    btnBench.addEventListener("click", async () => {
      btnBench.disabled = true;
      benchOutput.innerHTML = `<div class="timeline-item"><span class="badge-step">BENCHMARKING</span><span class="detail">Running throughput suite with 1, 2, and 4 parallel worker threads...</span></div>`;
      try {
        const res = await API.runBenchmark(25, [1, 2, 4]);
        let html = `
          <div style="margin-bottom: 1rem; font-size: 0.85rem; color: var(--text-secondary);">
            ${res.benchmark_summary}
          </div>
          <table style="width: 100%; border-collapse: collapse; font-family: var(--font-mono); font-size: 0.8rem; text-align: left;">
            <thead>
              <tr style="border-bottom: 1px solid var(--border-color); color: var(--text-muted);">
                <th style="padding: 0.5rem;">Threads</th>
                <th style="padding: 0.5rem;">Non-Txn Throughput</th>
                <th style="padding: 0.5rem;">Txn Throughput</th>
                <th style="padding: 0.5rem;">Avg Latency (Txn)</th>
                <th style="padding: 0.5rem;">Overhead</th>
              </tr>
            </thead>
            <tbody>
        `;

        res.results.forEach(r => {
          html += `
            <tr style="border-bottom: 1px solid rgba(255,255,255,0.04);">
              <td style="padding: 0.65rem;"><strong>${r.workers} Workers</strong></td>
              <td style="padding: 0.65rem; color: var(--accent-emerald);">${r.non_transactional.ops_per_second} ops/s</td>
              <td style="padding: 0.65rem; color: var(--accent-cyan);">${r.transactional.ops_per_second} ops/s</td>
              <td style="padding: 0.65rem;">${r.transactional.avg_latency_ms} ms</td>
              <td style="padding: 0.65rem; color: var(--accent-amber);">+${r.overhead_percentage}%</td>
            </tr>
          `;
        });

        html += `</tbody></table>`;
        benchOutput.innerHTML = html;
      } catch (err) {
        benchOutput.innerHTML = `<div style="color: var(--accent-rose)">Error: ${err.message}</div>`;
      } finally {
        btnBench.disabled = false;
      }
    });
  }
}
