/**
 * TraceX Email Threat Sentinel — Manifest V3 Background Service Worker
 * 
 * Runs in the extension origin (chrome-extension://<id>) with full host_permissions.
 * Bypasses page CSP and Mixed Content blocks to communicate directly with:
 * - TraceX AWS Cloud Gateway (http://13.200.242.110:8000)
 * - Localhost Gateway Fallback (http://127.0.0.1:8000)
 */

importScripts("config.js");

const cfg = self.TRACEX_CONFIG || {};
const GATEWAY_HOSTS = [
  cfg.LOCAL_GATEWAY_URL || "http://127.0.0.1:8000",
  cfg.LOCAL_GATEWAY_FALLBACK || "http://localhost:8000",
  cfg.AWS_GATEWAY_URL || "http://13.200.242.110:8000",
  cfg.AWS_GATEWAY_HTTP || "http://13.200.242.110",
  cfg.AWS_DNS_URL || "http://ec2-13-200-242-110.ap-south-1.compute.amazonaws.com:8000",
];
const SANDBOX_HOSTS = [
  cfg.LOCAL_SANDBOX_URL || "http://127.0.0.1:8002",
  cfg.SANDBOX_URL || "http://13.200.242.110:8002",
];

// Cache recent scans in memory (subject/hash -> scan record)
const memoryCache = new Map();

/**
 * Robust fetch helper that tries primary IP then fallback host
 */
async function resilientFetch(hosts, path, options = {}, timeoutMs = 2500) {
  let lastErr = null;
  for (const host of hosts) {
    try {
      const url = `${host}${path}`;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      const reqOpts = { ...options, signal: controller.signal };
      const resp = await fetch(url, reqOpts);
      clearTimeout(timer);
      if (resp.ok || resp.status === 202) {
        return { response: resp, host };
      }
      lastErr = new Error(`HTTP ${resp.status} from ${url}`);
    } catch (err) {
      lastErr = err;
    }
  }
  throw lastErr || new Error("All endpoints unreachable");
}

/**
 * Handle scan email request:
 * 1. Uploads RFC 822 EML to Gateway /api/scan
 * 2. Receives task_id
 * 3. Polls /api/scans/{task_id} until completion
 * 4. Returns complete forensic verdict
 */
async function handleScanEmail(payload) {
  const { rawEml, subject, sender, body_text, links, fileName } = payload;

  const cacheKey = (subject || "").toLowerCase().trim();
  if (memoryCache.has(cacheKey)) {
    const cached = memoryCache.get(cacheKey);
    // Cache valid for 5 minutes
    if (Date.now() - cached.timestamp < 300000) {
      console.log("[TraceX SW] Returning memory cached scan for:", subject);
      return cached.data;
    }
  }

  // 1. Prepare EML Blob and FormData
  const emlBlob = new Blob([rawEml], { type: "message/rfc822" });
  const formData = new FormData();
  formData.append("file", emlBlob, fileName || "gmail_intercepted.eml");

  console.log("[TraceX SW] Uploading EML to TraceX Gateway...");
  const uploadResult = await resilientFetch(GATEWAY_HOSTS, "/api/scan", {
    method: "POST",
    body: formData
  });

  const uploadJson = await uploadResult.response.json();
  const taskId = uploadJson.task_id;
  const activeHost = uploadResult.host;

  if (!taskId) {
    throw new Error("No task_id returned from TraceX Gateway");
  }

  console.log(`[TraceX SW] Scan accepted. Task ID: ${taskId}. Polling for verdict...`);

  // 2. Poll for completion (speedy 350ms intervals)
  const scanData = await pollForVerdict(activeHost, taskId);

  // 3. Cache and return
  memoryCache.set(cacheKey, {
    timestamp: Date.now(),
    data: scanData
  });

  return scanData;
}

/**
 * Polls the Gateway until status === ANALYZED or scores exist (speedy 350ms interval)
 */
async function pollForVerdict(host, taskId, maxAttempts = 35, intervalMs = 350) {
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    await new Promise(r => setTimeout(r, intervalMs));

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 1500);
      const resp = await fetch(`${host}/api/scans/${taskId}`, { signal: controller.signal });
      clearTimeout(timer);
      if (resp.status === 202) {
        // Still processing in gateway pipeline; continue polling
        continue;
      }
      if (!resp.ok) continue;

      const data = await resp.json();
      const scan = data.scan || data;

      const hasValidScore = (scan.fraud_score !== undefined && scan.fraud_score !== null) ||
                            (scan.score !== undefined && scan.score !== null);
      const isAnalyzed = scan.status === "ANALYZED" || (scan.status !== "processing" && hasValidScore);

      if (scan && isAnalyzed && hasValidScore) {
        const rawScore = scan.fraud_score !== undefined && scan.fraud_score !== null ? scan.fraud_score : scan.score;
        const score = Number(rawScore);
        const riskLevel = scan.risk_level ?? (score >= 80 ? "CRITICAL" : score >= 60 ? "HIGH" : score >= 40 ? "MEDIUM" : "LOW");

        // Format direct download and view links
        const reportUrl = `${host}/api/scans/${taskId}/report`;
        const emlUrl = `${host}/api/scans/${taskId}/eml`;
        const screenshotUrl = scan.screenshot_url || scan.s3_screenshot_uri || null;

        return {
          task_id: taskId,
          scan_id: scan.scan_id || taskId,
          fraud_score: score,
          score: score,
          risk_level: riskLevel,
          classification: scan.classification || (score >= 60 ? "PHISHING" : "LEGITIMATE"),
          confidence: scan.confidence ?? 0.95,
          reasons: Array.isArray(scan.reasons) && scan.reasons.length ? scan.reasons : ["Scan completed without critical anomalies"],
          forensic_breakdown: scan.forensic_breakdown || {
            spf: "UNKNOWN",
            dkim: "UNKNOWN",
            dmarc: "UNKNOWN",
            relay_hops: 1
          },
          s3_eml_uri: scan.s3_eml_uri || null,
          s3_screenshot_uri: scan.s3_screenshot_uri || null,
          screenshot_url: screenshotUrl,
          s3_report_uri: scan.s3_report_uri || null,
          evidence_id: scan.evidence_id || `EV-${taskId.slice(0, 8).toUpperCase()}`,
          cryptographic_seal: scan.cryptographic_seal || null,
          download_report_url: reportUrl,
          download_eml_url: emlUrl,
          gateway_host: host
        };
      }
    } catch (err) {
      // transient network error while pipeline is running
    }
  }

  throw new Error(`Pipeline timed out after ${Math.round((maxAttempts * intervalMs) / 1000)}s`);
}

/**
 * Handle direct detonation sandbox escalation
 */
async function handleDetonateSandbox(payload) {
  console.log("[TraceX SW] Escalating to Detonation Sandbox...");
  const result = await resilientFetch(SANDBOX_HOSTS, "/api/v1/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  return await result.response.json();
}

/**
 * Handle backend health check
 */
async function checkHealth() {
  const result = await resilientFetch(GATEWAY_HOSTS, "/api/health");
  return await result.response.json();
}

// ── Message Dispatcher ────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (!request || !request.action) return false;

  console.log(`[TraceX SW] Received action: ${request.action}`);

  if (request.action === "SCAN_EMAIL") {
    handleScanEmail(request.payload)
      .then(data => sendResponse({ success: true, data }))
      .catch(err => {
        console.error("[TraceX SW] SCAN_EMAIL failed:", err);
        sendResponse({ success: false, error: err.message || "Failed to scan email" });
      });
    return true; // Keep channel open for async response
  }

  if (request.action === "DETONATE_SANDBOX") {
    handleDetonateSandbox(request.payload)
      .then(data => sendResponse({ success: true, data }))
      .catch(err => {
        console.error("[TraceX SW] DETONATE_SANDBOX failed:", err);
        sendResponse({ success: false, error: err.message || "Sandbox unreachable" });
      });
    return true;
  }

  if (request.action === "CHECK_HEALTH") {
    checkHealth()
      .then(data => sendResponse({ success: true, data }))
      .catch(err => sendResponse({ success: false, error: err.message }));
    return true;
  }

  return false;
});

console.log("[TraceX Sentinel] Background Service Worker initialized and ready.");
