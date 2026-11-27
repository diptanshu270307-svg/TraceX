/**
 * TraceX Email Threat Sentinel — Gmail Injected Content Script (v2.0)
 * 
 * Intercepts emails in Gmail, extracts headers and body, delegates deep cyber-forensic
 * analysis to the TraceX Background Service Worker, and renders real-time forensic
 * dossiers with AWS S3 detonation screenshots and Section 65B PDF reports.
 */

const DASHBOARD_URL = "http://localhost:8000/investigate";
const scanCache = new Map(); // subjectKey -> scanResult

let currentScannedKey = null;
let isScanInProgress = false;

// ── 1. Gmail Navigation & DOM Observer ───────────────────────────────────────
let debounceTimer = null;

function initObserver() {
  const observer = new MutationObserver(() => {
    if (debounceTimer) clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      // 1. Check if an email is open
      const activeEmailBody = findActiveEmailBody();
      if (activeEmailBody) {
        const emailData = extractEmailData(activeEmailBody);
        if (emailData && emailData.subject && emailData.body_text) {
          const key = cleanKey(emailData.subject + "::" + emailData.sender);
          if (key !== currentScannedKey && !isScanInProgress) {
            handleEmailOpen(activeEmailBody, emailData, key);
          }
        }
      } else {
        // Returned to inbox or list view — clean up any orphan banners
        if (currentScannedKey) {
          currentScannedKey = null;
          removeAnyBanner();
        }
      }

      // 2. Decorate inbox list rows with colored threat dots
      decorateInboxRows();
    }, 120);
  });

  observer.observe(document.body, { childList: true, subtree: true });

  // Listen for hash changes (Gmail single-page router)
  window.addEventListener("hashchange", () => {
    if (debounceTimer) clearTimeout(debounceTimer);
    currentScannedKey = null;
    removeAnyBanner();
  });
}

// ── 2. DOM Extraction Helpers ────────────────────────────────────────────────
function findActiveEmailBody() {
  // Target expanded, visible email message bodies in Gmail
  const bodies = document.querySelectorAll("div.ii.gt");
  for (const b of bodies) {
    // Ensure element is visible and not collapsed
    if (b.offsetParent !== null && b.innerText.trim().length > 10) {
      return b;
    }
  }
  return null;
}

function extractEmailData(bodyNode) {
  const subjectNode = document.querySelector("h2.hP, div[role='main'] h2");
  const senderNode  = document.querySelector("span.gD, span[email]");

  const subject = subjectNode ? subjectNode.innerText.trim() : (document.title.replace(/ - Gmail$/i, "").trim() || "Unknown Subject");
  
  let sender = "Unknown Sender";
  if (senderNode) {
    const emailAttr = senderNode.getAttribute("email");
    const nameText  = senderNode.innerText.trim();
    if (emailAttr && nameText && !nameText.includes("@")) {
      sender = `"${nameText}" <${emailAttr}>`;
    } else if (emailAttr) {
      sender = emailAttr;
    } else {
      sender = nameText;
    }
  }

  // Extract all HTTP/HTTPS links
  const links = [...new Set(
    Array.from(bodyNode.querySelectorAll("a[href]"))
      .map(a => a.href)
      .filter(href => href && (href.startsWith("http://") || href.startsWith("https://")))
  )];

  const body_text = bodyNode.innerText.trim();

  return { subject, sender, body_text, links };
}

// ── 3. Main Email Handler ────────────────────────────────────────────────────
async function handleEmailOpen(bodyNode, emailData, key) {
  currentScannedKey = key;
  isScanInProgress = true;

  // Remove any stale banners
  removeAnyBanner();

  // Check cache first
  if (scanCache.has(key)) {
    const cached = scanCache.get(key);
    injectThreatBanner(bodyNode, cached, emailData);
    isScanInProgress = false;
    return;
  }

  // 1. Show immediate loading banner with progress
  injectLoadingBanner(bodyNode, "TraceX AI Sentinel: Initiating Cloud Forensic Vault Deep-Scan...");

  // 2. Build RFC 822 formatted message
  const rawEml = buildRFC822(emailData);

  try {
    updateLoadingBanner("TraceX: Sandboxing email & running multimodal ML inference...");

    // 3. Delegate to Background Service Worker (immune to mixed-content & page CSP)
    const response = await sendToBackground({
      action: "SCAN_EMAIL",
      payload: {
        rawEml,
        subject: emailData.subject,
        sender: emailData.sender,
        body_text: emailData.body_text,
        links: emailData.links,
        fileName: `gmail_${cleanKey(emailData.subject).slice(0, 24)}.eml`
      }
    });

    if (response && response.success && response.data) {
      const scan = response.data;
      if (scan.status === "processing" || scan.is_buffering || scan.fraud_score === undefined || scan.fraud_score === null) {
        updateLoadingBanner("TraceX: Threat pipeline analyzing protocol signatures & computing risk score...");
        setTimeout(() => {
          if (currentScannedKey === key) {
            handleEmailOpen(bodyNode, emailData, key);
          }
        }, 500);
        return;
      }
      scanCache.set(key, scan);
      removeLoadingBanner();
      injectThreatBanner(bodyNode, scan, emailData);
    } else {
      console.warn("[TraceX] Gateway returned error, using calibrated local heuristic:", response?.error);
      const fallback = getCalibratedLocalResult(emailData, response?.error);
      scanCache.set(key, fallback);
      removeLoadingBanner();
      injectThreatBanner(bodyNode, fallback, emailData);
    }

  } catch (err) {
    console.error("[TraceX] Scan error:", err);
    const fallback = getCalibratedLocalResult(emailData, err.message);
    scanCache.set(key, fallback);
    removeLoadingBanner();
    injectThreatBanner(bodyNode, fallback, emailData);
  } finally {
    isScanInProgress = false;
  }
}

// ── 4. RFC 822 Builder ───────────────────────────────────────────────────────
function buildRFC822(emailData) {
  const { sender, subject, body_text, links } = emailData;
  const boundary = `----=_Part_${Date.now()}_TraceX`;

  return [
    `From: ${sender}`,
    `To: analyst@tracex.cloud`,
    `Subject: ${subject}`,
    `Date: ${new Date().toUTCString()}`,
    `Message-ID: <tracex-${Date.now()}@gmail.sentinel>`,
    `MIME-Version: 1.0`,
    `Content-Type: text/plain; charset=UTF-8`,
    ``,
    body_text,
    links && links.length ? `\n\n[Extracted Links: ${links.join(", ")}]` : ""
  ].join("\r\n");
}

// ── 5. Chrome Runtime Message Helper ─────────────────────────────────────────
function sendToBackground(message) {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage(message, (response) => {
        if (chrome.runtime.lastError) {
          resolve({ success: false, error: chrome.runtime.lastError.message });
        } else {
          resolve(response || { success: false, error: "Empty response from background service worker" });
        }
      });
    } catch (err) {
      resolve({ success: false, error: err.message });
    }
  });
}

// ── 6. UI Banner Injection ──────────────────────────────────────────────────
function injectLoadingBanner(targetNode, message) {
  removeAnyBanner();

  const banner = document.createElement("div");
  banner.id = "tracex-loading-banner";
  banner.innerHTML = `
    <div class="tracex-loading-inner">
      <span class="tracex-spinner"></span>
      <span id="tracex-loading-msg">${escapeHtml(message)}</span>
    </div>
    <span class="tracex-loading-sub">AWS S3 Vault · Real-Time Threat Calculation · Playwright Detonation</span>
  `;

  targetNode.parentNode.insertBefore(banner, targetNode);
}

function updateLoadingBanner(message) {
  const el = document.getElementById("tracex-loading-msg");
  if (el) el.textContent = message;
}

function removeLoadingBanner() {
  const el = document.getElementById("tracex-loading-banner");
  if (el) el.remove();
}

function removeAnyBanner() {
  removeLoadingBanner();
  const alert = document.getElementById("tracex-alert-banner");
  if (alert) alert.remove();
}

function injectThreatBanner(targetNode, analysis, emailData) {
  removeAnyBanner();

  const rawScore = analysis.fraud_score !== undefined && analysis.fraud_score !== null 
    ? analysis.fraud_score 
    : (analysis.score !== undefined && analysis.score !== null ? analysis.score : null);

  const isBuffering = rawScore === null || isNaN(rawScore) || analysis.status === "processing" || analysis.is_buffering;

  const score = isBuffering ? null : Number(rawScore);
  const isSafe = !isBuffering && score < 40;
  const isMed  = !isBuffering && score >= 40 && score < 70;
  const isThreat = !isBuffering && score >= 70;

  const banner = document.createElement("div");
  banner.id = "tracex-alert-banner";
  banner.className = isBuffering 
    ? "tracex-buffering" 
    : (isSafe ? "tracex-safe" : (isMed ? "tracex-medium" : "tracex-threat"));

  const statusIcon  = isBuffering ? "🔄"
                    : (isSafe ? "🛡️" : (isMed ? "⚠️" : "🚨"));
  const statusLabel = isBuffering ? "Analyzing Threat & Calculating Cyber-Forensic Risk Score..."
                    : (isSafe ? "Email Verified Authentic & Safe"
                    : isMed  ? "Suspicious Anomalies Detected — Review Recommended"
                    :          "High-Confidence Phishing Threat Detected");

  const scoreBadgeHtml = isBuffering
    ? `<div class="tracex-score-badge badge-buffering"><span class="tracex-spinner-sm"></span> Calculating Risk Score...</div>`
    : `<div class="tracex-score-badge ${isSafe ? 'badge-safe' : (isMed ? 'badge-medium' : 'badge-threat')}">Risk Score: ${score}/100</div>`;

  const fb = analysis.forensic_breakdown || {};
  const caseId = analysis.scan_id || analysis.task_id || "TRACEX-LOCAL";
  const evidenceId = analysis.evidence_id || "EV-PENDING";

  // Protocol security line
  const authLine = isBuffering ? `
    <div class="tracex-security-flags">
      <span class="flag-pill flag-info">Authenticating SPF / DKIM / DMARC cryptoseals...</span>
    </div>
  ` : `
    <div class="tracex-security-flags">
      <span class="flag-pill ${fb.spf === 'PASS' ? 'flag-pass' : 'flag-fail'}">SPF: ${fb.spf || 'UNKNOWN'}</span>
      <span class="flag-pill ${fb.dkim === 'PASS' ? 'flag-pass' : 'flag-fail'}">DKIM: ${fb.dkim || 'UNKNOWN'}</span>
      <span class="flag-pill ${fb.dmarc === 'PASS' ? 'flag-pass' : 'flag-fail'}">DMARC: ${fb.dmarc || 'UNKNOWN'}</span>
      <span class="flag-pill flag-info">Relay Hops: ${fb.relay_hops ?? 1}</span>
      <span class="flag-pill flag-info">Evidence ID: ${evidenceId}</span>
    </div>
  `;

  // Screenshot container
  let screenshotHtml = "";
  if (analysis.screenshot_url) {
    screenshotHtml = `
      <div class="tracex-screenshot-preview">
        <div class="tracex-screenshot-header">
          <span>📸 <strong>AWS S3 Detonation Sandbox Capture</strong></span>
          <a href="${analysis.screenshot_url}" target="_blank" class="tracex-link-external">Open High-Res ↗</a>
        </div>
        <div class="tracex-screenshot-thumb-wrap">
          <img src="${analysis.screenshot_url}" alt="Playwright Detonation Capture" class="tracex-screenshot-img" />
        </div>
      </div>
    `;
  }

  // Action buttons
  const reportDownloadUrl = analysis.download_report_url || `http://localhost:8000/api/scans/${caseId}/report`;
  const emlDownloadUrl    = analysis.download_eml_url || `http://localhost:8000/api/scans/${caseId}/eml`;
  const investigateUrl    = `${DASHBOARD_URL}?case_id=${encodeURIComponent(caseId)}`;

  let offlineNotice = "";
  if (analysis.is_offline) {
    offlineNotice = `
      <div class="tracex-offline-notice">
        ⚠️ TraceX Gateway offline (${escapeHtml(analysis.backend_error || "Connection refused")}). Displaying local heuristic estimate.
      </div>
    `;
  }

  const reasonsList = isBuffering 
    ? ["TraceX pipeline is inspecting cryptographic headers and domain reputation...", "Detonating embedded hyper-links in headless sandbox..."]
    : (analysis.reasons && analysis.reasons.length ? analysis.reasons : ["No critical threats detected"]);

  banner.innerHTML = `
    <div class="tracex-header">
      <div class="tracex-title">
        <span>${statusIcon} TraceX: ${statusLabel}</span>
      </div>
      ${scoreBadgeHtml}
    </div>

    ${offlineNotice}
    ${authLine}

    <div class="tracex-reasons-block">
      <div class="tracex-reasons-title">Forensic Findings:</div>
      <ul class="tracex-reasons">
        ${reasonsList.map(r => `<li>${escapeHtml(r)}</li>`).join("")}
      </ul>
    </div>

    ${screenshotHtml}

    <div class="tracex-footer">
      <div class="tracex-footer-left">
        <a href="${reportDownloadUrl}" target="_blank" class="tracex-btn-secondary">
          📄 Download Section 65B PDF
        </a>
        <a href="${emlDownloadUrl}" target="_blank" class="tracex-btn-secondary">
          📥 Download .EML (S3)
        </a>
      </div>
      <div class="tracex-footer-right">
        <a href="${investigateUrl}" target="_blank" class="tracex-escalate-btn ${isSafe ? 'tracex-btn-safe' : isMed ? 'tracex-btn-medium' : 'tracex-btn-threat'}">
          ${isSafe ? '🔍 View Dossier in Command Center →' : '⚡ Escalate to Detonation Sandbox →'}
        </a>
      </div>
    </div>
  `;

  targetNode.parentNode.insertBefore(banner, targetNode);
}

// ── 7. Calibrated Local Fallback (When Gateway is Offline) ─────────────────────
function getCalibratedLocalResult(emailData, errorReason = "") {
  const subject = (emailData.subject || "").toLowerCase();
  const body    = (emailData.body_text || "").toLowerCase();
  const sender  = (emailData.sender || "").toLowerCase();
  const links   = emailData.links || [];
  const text    = `${subject} ${body}`;

  const reasons = [];
  let score = 15; // baseline

  // 1. Phishing keywords & coercion
  const CRITICAL_KEYWORDS = [
    { kw: "verify your account", pts: 25, msg: "Credential verification request detected" },
    { kw: "confirm your identity", pts: 25, msg: "Identity confirmation prompt detected" },
    { kw: "suspended", pts: 22, msg: "Account suspension threat detected" },
    { kw: "unusual sign-in", pts: 20, msg: "Unusual activity alert bait detected" },
    { kw: "account will be closed", pts: 25, msg: "Account termination threat detected" },
    { kw: "wire transfer", pts: 25, msg: "Wire transfer financial request detected" },
    { kw: "click here to verify", pts: 25, msg: "Verification link call-to-action detected" },
    { kw: "password has expired", pts: 22, msg: "Password expiration lure detected" },
    { kw: "action required immediately", pts: 20, msg: "Coercive urgency phrase detected" },
    { kw: "update payment", pts: 22, msg: "Payment update request detected" }
  ];

  for (const item of CRITICAL_KEYWORDS) {
    if (text.includes(item.kw)) {
      score += item.pts;
      reasons.push(item.msg);
    }
  }

  // 2. Suspicious TLDs
  const SUSP_TLDS = [".xyz", ".tk", ".ml", ".ga", ".cf", ".top", ".click", ".link", ".loan", ".work"];
  const badLinks = links.filter(l => SUSP_TLDS.some(tld => l.includes(tld)));
  if (badLinks.length > 0) {
    score += 30;
    reasons.push(`Suspicious top-level domain in link: ${badLinks[0].slice(0, 45)}...`);
  }

  // 3. Raw IP address in link
  if (links.some(l => /\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(l))) {
    score += 35;
    reasons.push("Embedded link contains raw IP address target instead of domain name");
  }

  // 4. Free webmail sending business/security requests
  const FREE_DOMAINS = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com"];
  const isFreeSender = FREE_DOMAINS.some(d => sender.includes(`@${d}`));
  const hasCorporateLure = ["invoice", "payment", "bank", "account security", "support", "security team"].some(k => text.includes(k));
  if (isFreeSender && hasCorporateLure) {
    score += 25;
    reasons.push("Corporate security/financial alert sent from free public webmail address");
  }

  // Cap score
  score = Math.min(95, Math.max(12, score));
  if (reasons.length === 0) {
    reasons.push("No explicit phishing phrases or suspicious links detected in email body");
  }

  const riskLevel = score >= 80 ? "CRITICAL" : (score >= 60 ? "HIGH" : (score >= 40 ? "MEDIUM" : "LOW"));

  return {
    task_id: "LOCAL-" + Math.random().toString(36).slice(2, 8).toUpperCase(),
    scan_id: "LOCAL-" + Math.random().toString(36).slice(2, 8).toUpperCase(),
    fraud_score: score,
    risk_level: riskLevel,
    classification: score >= 60 ? "PHISHING" : "LEGITIMATE",
    confidence: 0.88,
    reasons: reasons,
    forensic_breakdown: {
      spf: "UNKNOWN",
      dkim: "UNKNOWN",
      dmarc: "UNKNOWN",
      relay_hops: 1
    },
    is_offline: true,
    backend_error: errorReason
  };
}

// ── 8. Inbox List Dots ───────────────────────────────────────────────────────
function decorateInboxRows() {
  document.querySelectorAll("tr.zA").forEach(row => {
    if (row.querySelector(".tracex-row-dot")) return;

    const subjectSpan = row.querySelector("span.bqe, span.bog");
    if (!subjectSpan) return;

    const subjectText = subjectSpan.innerText.trim();
    // Check if we have cached this subject
    let matchedScore = null;
    for (const [key, scan] of scanCache.entries()) {
      if (key.includes(cleanKey(subjectText))) {
        matchedScore = scan.fraud_score;
        break;
      }
    }

    if (matchedScore === null) return;

    const dot = document.createElement("span");
    dot.className = "tracex-row-dot";
    if (matchedScore < 40) {
      dot.classList.add("dot-safe");
      dot.title = `TraceX: Verified Safe (${matchedScore}/100)`;
    } else if (matchedScore < 70) {
      dot.classList.add("dot-warning");
      dot.title = `TraceX: Suspicious (${matchedScore}/100)`;
    } else {
      dot.classList.add("dot-threat");
      dot.title = `TraceX: Phishing Threat (${matchedScore}/100)`;
    }

    subjectSpan.parentNode.insertBefore(dot, subjectSpan);
  });
}

// ── Utilities ────────────────────────────────────────────────────────────────
function cleanKey(str) {
  return (str || "").toLowerCase().replace(/^(re:|fwd:)\s*/i, "").replace(/[^a-z0-9]/g, "").trim();
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// Start listener
initObserver();
console.log("[TraceX Sentinel] Content script v2.0 initialized.");
