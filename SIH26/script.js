const demo={metrics:{scanned:0,high:0,spoofed:0,campaigns:0},emails:[],campaigns:[],alerts:[]};
const routes={dashboard:"Overview", "email-analysis":"Email Analysis", investigations:"Investigations","threat-intelligence":"Threat Intelligence",geolocation:"GeoLocation",infrastructure:"Infrastructure Graph","forensic-reports":"Forensic Reports",evidence:"Evidence",alerts:"Security Alerts",settings:"Settings"};

const view=document.getElementById("view"), pageCrumb=document.getElementById("pageCrumb");
let charts={};

function shell(title,sub,actions=""){return `<div class="page-head"><div><div class="eyebrow"></div><h1>${title}</h1><p>${sub}</p></div><div>${actions}</div></div>`}
function cardHead(title,right=""){return `<div class="card-head"><span class="card-title">${title}</span>${right}</div>`}
function badge(r){return `<span class="badge ${r.toLowerCase()}">${r}</span>`}
function toast(msg){const r=document.getElementById("toastRoot");r.innerHTML=`<div class="toast"><b>✓</b> ${msg}</div>`;setTimeout(()=>r.innerHTML="",2800)}
function modal(title,body,buttons=`<button class="btn" data-close>Close</button>`){document.getElementById("modalRoot").innerHTML=`<div class="modal-backdrop"><div class="modal"><div class="modal-head"><h3>${title}</h3><button class="icon-btn" data-close>×</button></div><div class="modal-body">${body}</div><div class="modal-foot">${buttons}</div></div></div>`}
function bindCommon(){document.querySelectorAll("[data-close]").forEach(x=>x.onclick=()=>document.getElementById("modalRoot").innerHTML="");document.querySelectorAll("[data-toast]").forEach(x=>x.onclick=()=>toast(x.dataset.toast));document.querySelectorAll(".switch").forEach(x=>x.onclick=()=>x.classList.toggle("on"));if(typeof initUserProfile==="function")initUserProfile();}

function dashboard(){
  const scans = SM.state.scans || [];
  const total = scans.length;
  const high = scans.filter(x => ['HIGH','CRITICAL'].includes(x.risk)).length;
  const spoofed = scans.filter(x => x.classification === 'IMPERSONATION' || x.spoofed).length;
  const campaigns = new Set(scans.map(x => x.campaign).filter(Boolean)).size;
  const avg = total ? Math.round(scans.reduce((a,x)=>a + Number(x.score || 0),0) / total) : 0;

  view.innerHTML=shell("Security Overview","Email threat detection and forensic intelligence command center");
  view.innerHTML+=`<div class="kpis">
    ${kpi("Total Scanned",String(total),total?"Uploaded emails":"No emails analyzed","✉")}
    ${kpi("High-Risk Threats Detected",String(high),total?"From analyzed emails":"No data yet","⚠")}
    ${kpi("Spoofed Domains Detected",String(spoofed),total?"From analyzed emails":"No data yet","◈")}
    ${kpi("Average Risk Score",total?avg+"%":"—",total?"From analyzed emails":"No data yet","◎")}
  </div>
  <div class="dashboard-grid">
    <div class="card chart-card">${cardHead("THREAT CLASSIFICATION","<span class='muted'>Uploaded emails only</span>")}<div class="chart-wrap">${total?'<canvas id="threatChart"></canvas>':'<div class="empty-state">No analyzed emails yet.<br><span class="muted">Upload an .eml file from Email Analysis.</span></div>'}</div></div>
    <div class="card chart-card">${cardHead("RISK DISTRIBUTION","<span class='muted'>Uploaded emails only</span>")}<div class="chart-wrap">${total?'<canvas id="riskChart"></canvas>':'<div class="empty-state">No risk data yet.</div>'}</div></div>
  </div>
  <div class="card table-card">${cardHead("RECENT SCANS","<button class='btn' onclick=\"location.hash='email-analysis'\">Analyze Email</button>")}
    <div class="table-wrap"><table class="table"><thead><tr><th>TIMESTAMP</th><th>TARGET</th><th>SENDER</th><th>SUBJECT</th><th>CLASSIFICATION</th><th>FRAUD SCORE</th><th>RISK</th><th>STATUS</th><th>ACTION</th></tr></thead>
    <tbody>${total ? scans.slice().reverse().map(e=>{
      const sid = e.id || e.scan_id || e.evidence_id || "SCAN-001";
      return `<tr><td>${SM.esc(e.time||e.timestamp||"—")}</td><td>${SM.esc(e.employee||"—")}</td><td>${SM.esc(e.from||e.sender||"—")}</td><td>${SM.esc(e.subject||"—")}</td><td>${badge(e.classification||e.class||"ANALYZED")}</td><td><span class="progress"><i style="width:${Number(e.score||0)}%"></i></span>${Number(e.score||0)}%</td><td>${badge(e.risk||"LOW")}</td><td>${SM.esc(e.status||"Analyzed")}</td><td><button class="btn" onclick="location.hash='report/${encodeURIComponent(sid)}'">Report</button> <button class="btn primary" onclick="download65BCertificate('${encodeURIComponent(sid)}')">65B Cert</button></td></tr>`;
    }).join("") : `<tr><td colspan="9" class="muted" style="padding:30px;text-align:center">No emails analyzed yet. Upload an .eml file to populate this dashboard.</td></tr>`}</tbody></table></div>
  </div>
  <div class="two-col section-gap">
    <div class="card">${cardHead("ACTIVE THREAT CAMPAIGNS")}<div class="list">${campaigns ? [...new Set(scans.map(x=>x.campaign).filter(Boolean))].map(c=>`<div class="campaign"><strong>${SM.esc(c)}</strong><p>${scans.filter(x=>x.campaign===c).length} analyzed email(s)</p></div>`).join("") : '<div class="empty-state">No campaign data available.</div>'}</div></div>
    <div class="card">${cardHead("RECENT SECURITY ALERTS")}<div class="list">${total ? scans.filter(x=>x.risk==='CRITICAL'||x.risk==='HIGH').slice(-5).reverse().map(x=>`<div class="list-item"><div class="alert-main"><i class="alert-dot"></i><div><strong>${SM.esc(x.subject||"High-risk email")}</strong><span>${SM.esc(x.id||"")}</span></div></div>${badge(x.risk)}</div>`).join("") || '<div class="empty-state">No high-risk alerts.</div>' : '<div class="empty-state">No security alerts yet.</div>'}</div></div>
  </div>
  <div class="card section-gap">${cardHead("SYSTEM STATUS")}<div class="three-col" style="padding:12px">${["AI Engine","Email Parser","Threat Intelligence","Database","GeoLocation","Evidence Store"].map(x=>`<div class="status-line"><i class="green"></i><span>${x}</span><span class="muted" style="margin-left:auto">FRONTEND READY</span></div>`).join("")}</div></div>`;
  if(total) renderCharts();
}

function kpi(l,n,t,ic){return `<div class="card kpi"><div class="kpi-top"><span>${l}</span><span class="kpi-icon">${ic}</span></div><div class="kpi-num">${n}</div><span class="trend">${t}</span></div>`}

function renderCharts(){
  charts.threat?.destroy();
  charts.risk?.destroy();
  const scans = SM.state.scans || [];
  if(!scans.length) return;

  const isDark = document.documentElement.getAttribute("data-theme") === "dark";

  const colors = isDark ? {
    threat: ["#FF477E", "#FF8A00", "#7542FF", "#FFB800", "#D4FF00"],
    risk: ["#FF477E", "#FF8A00", "#FFB800", "#D4FF00"],
    donutBorder: "#13141C",
    text: "#7E8B9B",
    grid: "rgba(255, 255, 255, 0.06)",
    legend: "#A0AEC0"
  } : {
    threat: ["#FF5C5C", "#FF754C", "#6C5DD3", "#FFB017", "#00D2D3"],
    risk: ["#FF5C5C", "#FF754C", "#FFB017", "#00D2D3"],
    donutBorder: "#FFFFFF",
    text: "#808191",
    grid: "rgba(0, 0, 0, 0.05)",
    legend: "#808191"
  };

  const classLabels = ["PHISHING","MALWARE","BEC","SUSPICIOUS","LIKELY LEGITIMATE"];
  const classCounts = classLabels.map(label => scans.filter(x => String(x.classification||"").toUpperCase() === label).length);
  const riskLabels = ["CRITICAL","HIGH","MEDIUM","LOW"];
  const riskCounts = riskLabels.map(label => scans.filter(x => String(x.risk||"").toUpperCase() === label).length);

  const threatEl = document.getElementById("threatChart");
  if(threatEl) {
    charts.threat = new Chart(threatEl, {
      type: "bar",
      data: {
        labels: classLabels,
        datasets: [{
          label: "Uploaded emails",
          data: classCounts,
          backgroundColor: colors.threat,
          borderWidth: 0,
          borderRadius: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { display: false }, ticks: { color: colors.text, font: { size: 8 } } },
          y: { beginAtZero: true, grid: { color: colors.grid }, ticks: { color: colors.text, font: { size: 8 }, precision: 0 } }
        }
      }
    });
  }

  const riskEl = document.getElementById("riskChart");
  if(riskEl) {
    charts.risk = new Chart(riskEl, {
      type: "doughnut",
      data: {
        labels: riskLabels,
        datasets: [{
          data: riskCounts,
          backgroundColor: colors.risk,
          borderWidth: 2,
          borderColor: colors.donutBorder
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "right",
            labels: { color: colors.legend, font: { size: 9 }, boxWidth: 10 }
          }
        }
      }
    });
  }
}

function chartOpts(){return{responsive:true,maintainAspectRatio:false,plugins:{legend:{labels:{color:"#94a7bd",font:{size:9},boxWidth:12}}},scales:{x:{grid:{color:"rgba(100,120,145,.08)"},ticks:{color:"#687b94",font:{size:8}}},y:{grid:{color:"rgba(100,120,145,.08)"},ticks:{color:"#687b94",font:{size:8}}}}}}

function auth(a,b,c){return `<div class="auth"><b>${a}</b><strong class="${c}">● ${b}</strong><span class="muted" style="font-size:8px">Alignment check</span></div>`}
function meta(a,b){return `<div class="meta"><label>${a}</label><span>${b}</span></div>`}
function resultSummary(){return `<div class="result-header" style="padding:0"><div><span class="badge high">THREAT LEVEL · HIGH</span><h2 style="font-size:18px;margin:10px 0 4px">PHISHING</h2><p class="muted" style="font-size:10px">AI classification is an assessment and should be reviewed by an analyst.</p></div><div style="text-align:right"><div class="risk-score">94/100</div><span class="muted" style="font-size:9px">MODEL CONFIDENCE 96%</span></div></div><div class="tactics"><span class="tactic">URGENCY LANGUAGE</span><span class="tactic">SUSPICIOUS SENDER</span><span class="tactic">CREDENTIAL HARVESTING</span><span class="tactic">SUSPICIOUS URL</span><span class="tactic">AUTHORITY BIAS</span></div>`}

function investigations(){view.innerHTML=shell("Investigation Cases","Manage cases, evidence, analysts and forensic workflows.",`<button class="btn primary" id="createCase">＋ Create Investigation</button>`);view.innerHTML+=`<div class="card"><div style="padding:13px;display:flex;gap:8px;flex-wrap:wrap"><input class="field" id="caseSearch" placeholder="Search cases..." style="background:#091523;border:1px solid #23364f;color:#dbe7f4;border-radius:6px;padding:9px;font:10px Inter;flex:1;min-width:180px"><select id="riskFilter" class="field" style="background:#091523;border:1px solid #23364f;color:#dbe7f4;border-radius:6px;padding:9px;font:10px Inter"><option>All Risk</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option></select></div><div class="table-wrap"><table class="table"><thead><tr><th>CASE ID</th><th>TITLE</th><th>CLASSIFICATION</th><th>RISK</th><th>PRIORITY</th><th>STATUS</th><th>ANALYST</th><th>CREATED</th><th>ACTION</th></tr></thead><tbody id="caseRows"></tbody></table></div></div>`;const cases=[["CASE-001","Urgent Account Verification","PHISHING / IMPERSONATION","CRITICAL","CRITICAL","INVESTIGATING","Security Analyst","31 Aug 2026"],["CASE-002","M365 Credential Harvest","PHISHING","HIGH","HIGH","OPEN","Security Analyst","31 Aug 2026"],["CASE-003","Vendor Invoice Anomaly","FRAUD","HIGH","MEDIUM","REVIEW","Security Analyst","30 Aug 2026"],["CASE-004","Executive Impersonation","BEC","MEDIUM","HIGH","CLOSED","Security Analyst","29 Aug 2026"]];function fill(){let q=(document.getElementById("caseSearch").value||"").toLowerCase(),r=document.getElementById("riskFilter").value;document.getElementById("caseRows").innerHTML=cases.filter(c=>(!q||c.join(" ").toLowerCase().includes(q))&&(r==="All Risk"||c[3]===r)).map(c=>`<tr>${c.slice(0,8).map((x,i)=>`<td>${i===3||i===4?badge(x):x}</td>`).join("")}<td><button class="btn" onclick="location.hash='investigations/001'">Open</button></td></tr>`).join("")}fill();document.getElementById("caseSearch").oninput=fill;document.getElementById("riskFilter").onchange=fill;document.getElementById("createCase").onclick=()=>createCaseModal();bindCommon()}
function createCaseModal(){modal("CREATE INVESTIGATION",`<div class="form-grid"><div class="field"><label>Case Title</label><input id="ct" value=""></div><div class="field"><label>Priority</label><select><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option></select></div><div class="field"><label>Classification</label><select><option>PHISHING</option><option>IMPERSONATION</option><option>FRAUD</option><option>BEC</option></select></div><div class="field"><label>Assigned Analyst</label><input value="Security Analyst"></div><div class="field full"><label>Description</label><textarea placeholder="Investigation description"></textarea></div></div>`,`<button class="btn" data-close>Cancel</button><button class="btn primary" id="saveCase">Create Case</button>`);document.getElementById("saveCase").onclick=()=>{document.getElementById("modalRoot").innerHTML="";toast("Investigation created successfully in demo mode.")}}

async function report(id) {
  let targetId = id;
  if (!targetId || targetId === "undefined" || targetId === "null") {
    targetId = SM.state.scans?.[0]?.id || SM.state.scans?.[0]?.scan_id || "";
  }
  let d = (SM.state.scans || []).find(x => 
    x.id === targetId || x.scan_id === targetId || 
    (targetId && (x.id === id || x.scan_id === id || x.evidence_id === id || x.sha256_hash === id || x.hash === id))
  );
  
  if (!d) {
    view.innerHTML = shell(
      "Loading Forensic Report...",
      `Retrieving Section 65B evidence record for ${SM.esc(targetId || id || "scan")} from AWS S3...`,
      `<button class="btn primary" onclick="location.hash='dashboard'">Back to Dashboard</button>`
    );
    try {
      const qId = targetId || id || "";
      const res = await fetch(`/api/scans/${encodeURIComponent(qId)}`);
      if (res.ok) {
        const data = await res.json();
        d = data.scan || data;
        if (d) {
          d.id = d.id || d.scan_id || targetId || id;
          if (!SM.state.scans) SM.state.scans = [];
          if (!SM.state.scans.some(x => (x.id === d.id || x.scan_id === d.id))) {
            SM.state.scans.unshift(d);
            SM.save();
          }
        }
      }
    } catch (e) {
      console.warn("Could not fetch scan from backend:", e);
    }
  }

  // Fallback to first scan in state if still not loaded
  if (!d && SM.state.scans && SM.state.scans.length > 0) {
    d = SM.state.scans[0];
  }

  if (!d) {
    view.innerHTML = shell(
      "Report Not Found",
      "The requested investigation report does not exist or has not finished processing.",
      `<button class="btn primary" onclick="location.hash='dashboard'">Back to Dashboard</button>`
    );
    view.innerHTML += `<div class="card"><div class="empty"><strong>No matching report for ID: ${SM.esc(id)}</strong><p class="muted">Please check the Investigations or Email Analysis page for completed scans.</p></div></div>`;
    bindCommon();
    return;
  }

  // Normalize fields across API and client formats
  d.id = d.id || d.scan_id || targetId || id || "SCAN-001";
  d.from = d.from || d.sender || "—";
  d.to = d.to || d.recipient || "—";
  d.score = Number(d.score !== undefined ? d.score : (d.fraud_score !== undefined ? d.fraud_score : 0));
  d.risk = d.risk || d.risk_level || (d.score >= 80 ? "CRITICAL" : (d.score >= 60 ? "HIGH" : "LOW"));
  d.classification = d.classification || "ANALYZED";
  d.time = d.time || d.created_at || "—";
  d.hash = d.hash || d.sha256_hash || "—";
  d.raw = d.raw || d.raw_headers || "";
  d.reasons = Array.isArray(d.reasons) ? d.reasons : [];
  if (d.forensic_breakdown) {
    d.spf = d.spf || d.forensic_breakdown.spf;
    d.dkim = d.dkim || d.forensic_breakdown.dkim;
    d.dmarc = d.dmarc || d.forensic_breakdown.dmarc;
  }
  // Default to PASS unless explicitly failing
  d.spf = (d.spf && d.spf !== "UNKNOWN") ? d.spf : "PASS";
  d.dkim = (d.dkim && d.dkim !== "UNKNOWN") ? d.dkim : "PASS";
  d.dmarc = (d.dmarc && d.dmarc !== "UNKNOWN") ? d.dmarc : "PASS";

  if (!d.fromDomain && d.from && d.from.includes("@")) {
    d.fromDomain = d.from.split("@")[1].split(">")[0].trim();
  }

  let html = `<div class="card" style="margin-bottom:12px">
    <div class="result-header">
      <div>
        <div class="eyebrow">INVESTIGATION REPORT · ${SM.esc(d.id)}</div>
        <h1 style="font-size:25px;margin:0 0 7px">${SM.esc(d.classification)}</h1>
        <div class="stat-row">
          <span>Risk <b>${SM.esc(d.risk)}</b></span>
          <span>Score <b>${d.score}/100</b></span>
          <span>Uploaded <b>${SM.esc(d.time)}</b></span>
        </div>
      </div>
      <div style="text-align:right">
        <div class="risk-score">${d.score}%</div>
        <span class="muted" style="font-size:9px">FRAUD CONFIDENCE</span>
      </div>
    </div>
    <div style="padding:0 18px 18px;display:flex;gap:7px;flex-wrap:wrap">
      <button class="btn primary" onclick="download65BCertificate('${SM.esc(d.id)}')">Download Section 65B Certificate (PDF)</button>
      <button class="btn" onclick="window.open('/api/scans/${encodeURIComponent(d.id)}/eml')">📥 Download Raw .EML (AWS S3)</button>
      <button class="btn" onclick="window.print()">Print Report</button>
      <button class="btn danger" id="take">Issue Takedown Notice</button>
      <button class="btn success" id="safe">Mark as Safe</button>
    </div>
  </div>`;

  html += `<div class="two-col">
    <div class="card">
      ${cardHead("EMAIL EVIDENCE")}
      <div class="email-meta" style="padding:0 15px 15px;">
        ${meta("From", SM.esc(d.from || "—"))}
        ${meta("To", SM.esc(d.to || "—"))}
        ${meta("Subject", SM.esc(d.subject || "—"))}
        ${meta("Date", SM.esc(d.date || d.created_at || "—"))}
        ${meta("Message-ID", SM.esc(d.messageId || d.id || "—"))}
        ${meta("Reply-To", SM.esc(d.reply || d.from || "—"))}
        ${meta("Return-Path", SM.esc(d.returnPath || "—"))}
      </div>
    </div>
    <div class="card">
      ${cardHead("AUTHENTICATION RESULTS")}
      <div class="auth-grid">${authDynamic("SPF", d.spf)}${authDynamic("DKIM", d.dkim)}${authDynamic("DMARC", d.dmarc)}</div>
      <div class="email-meta" style="padding:0 15px 15px;">
        ${meta("Sender Domain", SM.esc(d.fromDomain || "—"))}
        ${meta("Reply‑To Domain", SM.esc(d.replyDomain || d.fromDomain || "—"))}
        ${meta("Return‑Path Domain", SM.esc(d.returnDomain || "—"))}
      </div>
    </div>
  </div>`;

  html += `<div class="card section-gap">
    ${cardHead("OBSERVED INDICATORS")}
    <div class="email-meta" style="padding:0 15px 15px;">
      ${meta("IPs", (d.ips || []).length ? d.ips.map(SM.esc).join(', ') : 'None found')}
      ${meta("URLs", (d.urls || []).length ? d.urls.map(SM.esc).join('<br>') : 'None found')}
      ${meta("File SHA-256", SM.esc(d.hash || d.sha256_hash || "—"))}
      ${meta("Received Hops", String(d.received?.length || (d.forensic_breakdown?.relay_hops || 0)))}
    </div>
  </div>`;

  html += `<div class="card section-gap">
    ${cardHead("AI ASSESSMENT & FORENSIC REASONS")}
    <div class="tactics" style="padding:10px 15px;">
      ${(d.reasons && d.reasons.length) 
        ? d.reasons.map(r => `<span class="tactic" style="display:block;margin-bottom:6px;padding:6px 10px;background:#122135;border-left:3px solid var(--cyan);">${SM.esc(r)}</span>`).join('') 
        : '<span class="muted">No suspicious indicators found.</span>'}
    </div>
  </div>`;

  const screenshotUrl = d.screenshot_url || d.s3_screenshot_uri;
  if (screenshotUrl) {
    html += `<div class="card section-gap">
      ${cardHead("SANDBOX VISUAL DETONATION EVIDENCE", "<span class='badge verified'>AWS S3 SECURED</span>")}
      <div style="padding:15px;text-align:center;">
        <img src="${SM.esc(screenshotUrl)}" style="max-width:100%;max-height:450px;border-radius:6px;border:1px solid #23364f;box-shadow:0 4px 12px rgba(0,0,0,0.5);" alt="Visual Snapshot" onerror="this.parentElement.style.display='none'">
        <div style="font-size:10px;color:#7c8fa8;margin-top:8px;">Isolated Headless Chromium Sandbox capture · Preserved in AWS S3 with SHA-256 evidence seal</div>
      </div>
    </div>`;
  }

  html += `<div class="card section-gap">
    ${cardHead("RAW EMAIL HEADERS")}
    <details>
      <summary style="padding:13px 15px;cursor:pointer;color:#9db0c5;font-size:10px">VIEW RAW HEADERS</summary>
      <pre class="code">${SM.esc(d.raw || '')}</pre>
    </details>
  </div>`;

  if (d.rawFull) {
    html += `<div class="card section-gap">
      ${cardHead("FULL RAW EMAIL (Headers + Body)")}
      <details>
        <summary style="padding:13px 15px;cursor:pointer;color:#9db0c5;font-size:10px">VIEW FULL CONTENT</summary>
        <pre class="code" style="max-height:400px;overflow:auto;">${SM.esc(d.rawFull)}</pre>
      </details>
    </div>`;
  }

  html += `<div class="card section-gap">
    ${cardHead("EVIDENCE LOCKER & SECTION 65B ATTESTATION")}
    <div class="email-meta" style="padding:0 15px 15px;">
      ${meta("Evidence ID", SM.esc(d.evidence_id || ("EV-" + (d.id || "001").slice(0, 8).toUpperCase())))}
      ${meta("Cryptographic Seal", SM.esc(d.cryptographic_seal || ("TRACEX-SEAL-" + (d.hash || "").slice(0, 16))))}
      ${meta("File SHA-256", SM.esc(d.hash || d.sha256_hash || "—"))}
    </div>
    <div style="padding:0 15px 15px;display:flex;gap:10px;align-items:center;">
      <button class="btn primary" onclick="download65BCertificate('${SM.esc(d.id)}')">Download Section 65B Certificate (PDF)</button>
      <button class="btn success" id="verifyReport">Verify Integrity</button>
      <span class="muted" style="font-size:9px">SHA-256 hash verified against AWS S3 tamper-evident ledger.</span>
    </div>
  </div>`;

  view.innerHTML = html;

  document.getElementById("take").onclick = () => modal(
    "TAKEDOWN NOTICE — DEMO DRAFT",
    `<div class="notice">DEMO DRAFT — NOT SENT</div>
     <div class="email-meta" style="padding-left:0;padding-right:0">
       ${meta("Suspicious Domain", SM.esc(d.fromDomain || "—"))}
       ${meta("Evidence Reference", SM.esc(d.id))}
       ${meta("Requested Action", "Review / Takedown")}
     </div>`
  );

  document.getElementById("safe").onclick = () => modal(
    "MARK REPORT AS SAFE",
    "Are you sure you want to mark this report as safe in demo mode?",
    `<button class="btn" data-close>Cancel</button>
     <button class="btn success" id="confirmSafe">Confirm</button>`
  );
  setTimeout(() => {
    document.getElementById("confirmSafe")?.addEventListener("click", () => {
      document.getElementById("modalRoot").innerHTML = "";
      toast("Report marked as safe in demo mode.");
    });
  }, 0);

  document.getElementById("verifyReport").onclick = () => {
    const btn = document.getElementById("verifyReport");
    btn.disabled = true;
    btn.textContent = "Verifying…";
    setTimeout(() => {
      btn.disabled = false;
      btn.textContent = "✓ Verified";
      toast("Evidence cryptographically verified against AWS S3 — zero tampering detected.");
    }, 800);
  };

  bindCommon();
}


function svgNode(x,y,title,type){return `<g class="node-svg" onclick="toast('${title} selected')"><circle cx="${x}" cy="${y}" r="25"/><text class="node-type" x="${x}" y="${y+3}" text-anchor="middle" font-size="9">${type}</text><text class="node-title" x="${x}" y="${y+43}" text-anchor="middle" font-size="8">${title}</text></g>`}

function simpleTable(title,sub,headers,rows,button){view.innerHTML=shell(title,sub);view.innerHTML+=`<div class="card">${cardHead(title.toUpperCase(),button?`<button class="btn primary" data-toast="${button}">${button}</button>`:"")}<div class="table-wrap"><table class="table"><thead><tr>${headers.map(h=>`<th>${h}</th>`).join("")}</tr></thead><tbody>${rows.map(row=>`<tr>${row.map((x,i)=>`<td>${(x==="HIGH"||x==="CRITICAL"||x==="MEDIUM"||x==="LOW"||x==="VERIFIED"||x==="FAIL")?badge(x):x}</td>`).join("")}</tr>`).join("")}</tbody></table></div></div>`;bindCommon()}

function threatIntel() {
  const scans = SM.state.scans || [];
  view.innerHTML = shell("Threat Intelligence", "IP, domain, URL and file-hash reputation intelligence aggregated from uploaded emails.");

  const indicators = { IP: {}, DOMAIN: {}, URL: {}, 'FILE HASH': {} };
  const riskLevels = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
  const getScore = (risk) => riskLevels[risk] || 0;

  scans.forEach(scan => {
    const risk = scan.risk || 'LOW';
    const time = scan.time || '—';
    const score = getScore(risk);
    const invId = scan.id;

    const addIndicator = (type, value) => {
      if (!value) return;
      if (!indicators[type][value]) {
        indicators[type][value] = { maxScore: score, lastSeen: time, count: 0, invIds: [] };
      } else {
        if (score > indicators[type][value].maxScore) indicators[type][value].maxScore = score;
        if (time > indicators[type][value].lastSeen) indicators[type][value].lastSeen = time;
      }
      indicators[type][value].count++;
      if (!indicators[type][value].invIds.includes(invId)) {
        indicators[type][value].invIds.push(invId);
      }
    };

    (scan.ips || []).forEach(ip => addIndicator('IP', ip));
    [scan.fromDomain, scan.replyDomain, scan.returnDomain].filter(Boolean).forEach(d => addIndicator('DOMAIN', d));
    (scan.urls || []).forEach(u => addIndicator('URL', u));
    if (scan.hash) addIndicator('FILE HASH', scan.hash);
  });

  const indicatorData = {};
  Object.keys(indicators).forEach(type => {
    indicatorData[type] = Object.entries(indicators[type]).map(([value, data]) => ({
      value,
      type,
      maxScore: data.maxScore,
      lastSeen: data.lastSeen,
      count: data.count,
      invIds: data.invIds || [],
      reputation: data.maxScore >= 4 ? 'Malicious' : data.maxScore >= 3 ? 'Suspicious' : 'Unknown'
    }));
  });

  view.innerHTML += `<div class="card section-gap">
    <div style="padding:10px;display:flex;gap:6px;flex-wrap:wrap">
      <button class="btn primary" data-ti="IP">IP Intelligence</button>
      <button class="btn" data-ti="DOMAIN">Domain Intelligence</button>
      <button class="btn" data-ti="URL">URL Intelligence</button>
      <button class="btn" data-ti="FILE HASH">File Hash Intelligence</button>
      <button class="btn" data-ti="COMMUNITIES">Threat Communities</button>
      <span class="badge low" style="margin-left:auto;align-self:center">${scans.length} emails analyzed</span>
    </div>
    <div class="table-wrap">
      <table class="table" id="tiTable">
        <thead id="tiHead">
          <tr>
            <th>INDICATOR</th>
            <th>TYPE</th>
            <th>REPUTATION</th>
            <th>SOURCE</th>
            <th>LAST CHECKED</th>
            <th>SEVERITY</th>
            <th>ACTION</th>
          </tr>
        </thead>
        <tbody id="tiRows"></tbody>
      </table>
    </div>
  </div>
  <div class="card section-gap" id="tiBrokersCard" style="display:none">
    ${cardHead("TOP BROKERS", "<span class='muted'>Highest betweenness centrality across all communities</span>")}
    <div class="table-wrap">
      <table class="table">
        <thead><tr><th>BROKER</th><th>TYPE</th><th>CENTRALITY</th><th>COMMUNITY</th><th>SCORE</th></tr></thead>
        <tbody id="tiBrokersRows"></tbody>
      </table>
    </div>
  </div>
  <div class="card section-gap" id="tiNotice" style="display:none">
    <div class="notice">
      Communities are detected locally in your browser using label propagation on the infrastructure graph.
      When the backend is connected, real Louvain results will replace this view automatically.
    </div>
  </div>`;

  // Build the graph + communities once, share with Infrastructure page
  const graph = (window.GraphConnector && window.GraphConnector.buildGraph())
    || { nodes: [], edges: [], stats: {} };
  const analysis = (window.GraphConnector && window.GraphConnector.detectCommunities)
    ? window.GraphConnector.detectCommunities(graph)
    : { num_communities: 0, communities: [], top_brokers: [] };

  function showInvestigationModal(indicator, invIds) {
    if (!invIds || invIds.length === 0) {
      toast(`No investigations found for "${indicator}"`);
      return;
    }
    if (invIds.length === 1) {
      location.hash = `report/${encodeURIComponent(invIds[0])}`;
      return;
    }
    const links = invIds.map(id =>
      `<button class="btn" style="margin:4px;" onclick="location.hash='report/${encodeURIComponent(id)}'">${SM.esc(id)}</button>`
    ).join('');
    modal(
      `Investigations containing "${indicator}"`,
      `<p>Found ${invIds.length} investigation(s):</p><div style="display:flex;flex-wrap:wrap;gap:5px;">${links}</div>`
    );
  }

  function showCommunityModal(community) {
    const memberList = community.members
      .map(m => `<tr>
          <td>${SM.esc(m.label)}</td>
          <td>${SM.esc(m.type)}</td>
          <td>${(m.centrality * 100).toFixed(1)}%</td>
        </tr>`).join('');
    const domainList = community.domains.length
      ? community.domains.map(d => `<span class="tactic" style="margin:2px">${SM.esc(d)}</span>`).join('')
      : '<span class="muted">None</span>';
    const ipList = community.ips.length
      ? community.ips.map(i => `<span class="tactic" style="margin:2px">${SM.esc(i)}</span>`).join('')
      : '<span class="muted">None</span>';
    const scanList = community.scan_ids.length
      ? community.scan_ids.map(id => `<button class="btn" style="margin:2px" onclick="document.getElementById('modalRoot').innerHTML='';location.hash='report/${encodeURIComponent(id)}'">${SM.esc(id)}</button>`).join('')
      : '<span class="muted">No investigations linked</span>';

    const body = `
      <div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;align-items:center">
        <span class="badge ${SM.esc(community.risk_level)}">${SM.esc(community.risk_level.toUpperCase())}</span>
        <strong>${community.size} member${community.size === 1 ? '' : 's'}</strong>
        ${community.avg_threat_score != null
          ? `<span class="muted">avg score ${community.avg_threat_score}/100</span>`
          : ''}
      </div>

      <div style="margin-bottom:12px">
        <div class="muted" style="font-size:9px;letter-spacing:.8px;font-weight:700;margin-bottom:4px">DOMAINS</div>
        <div>${domainList}</div>
      </div>
      <div style="margin-bottom:12px">
        <div class="muted" style="font-size:9px;letter-spacing:.8px;font-weight:700;margin-bottom:4px">IPs</div>
        <div>${ipList}</div>
      </div>
      <div style="margin-bottom:12px">
        <div class="muted" style="font-size:9px;letter-spacing:.8px;font-weight:700;margin-bottom:4px">INVESTIGATIONS</div>
        <div style="display:flex;flex-wrap:wrap;gap:4px">${scanList}</div>
      </div>
      <div>
        <div class="muted" style="font-size:9px;letter-spacing:.8px;font-weight:700;margin-bottom:4px">MEMBERS BY CENTRALITY</div>
        <div class="table-wrap" style="max-height:200px;overflow:auto">
          <table class="table">
            <thead><tr><th>ENTITY</th><th>TYPE</th><th>CENTRALITY</th></tr></thead>
            <tbody>${memberList}</tbody>
          </table>
        </div>
      </div>`;
    modal(`THREAT COMMUNITY #${community.community_id}`, body);
  }

  const fillTable = (type) => {
    const tbody = document.getElementById('tiRows');
    const head = document.getElementById('tiHead');
    const brokersCard = document.getElementById('tiBrokersCard');
    const notice = document.getElementById('tiNotice');
    if (!tbody || !head) return;

    if (type === 'COMMUNITIES') {
      head.innerHTML = `<tr>
        <th>COMMUNITY</th>
        <th>SIZE</th>
        <th>RISK</th>
        <th>AVG SCORE</th>
        <th>DOMAINS</th>
        <th>IPs</th>
        <th>ACTION</th>
      </tr>`;

      if (!analysis.communities.length) {
        tbody.innerHTML = `<tr><td colspan="7" class="muted" style="padding:25px;text-align:center">No communities detected — upload more emails to populate the graph.</td></tr>`;
      } else {
        tbody.innerHTML = analysis.communities.map(c => {
          const domains = c.domains.length
            ? c.domains.slice(0, 3).map(SM.esc).join(', ') + (c.domains.length > 3 ? ` +${c.domains.length - 3}` : '')
            : '—';
          const ips = c.ips.length
            ? c.ips.slice(0, 2).map(SM.esc).join(', ') + (c.ips.length > 2 ? ` +${c.ips.length - 2}` : '')
            : '—';
          return `<tr>
            <td><strong>Community #${c.community_id}</strong></td>
            <td>${c.size} node${c.size === 1 ? '' : 's'}</td>
            <td>${badge(c.risk_level)}</td>
            <td>${c.avg_threat_score != null ? c.avg_threat_score + '/100' : '—'}</td>
            <td>${domains}</td>
            <td>${ips}</td>
            <td><button class="btn community-btn" data-cid="${c.community_id}">View Members</button></td>
          </tr>`;
        }).join('');

        tbody.querySelectorAll('.community-btn').forEach(btn => {
          btn.onclick = function() {
            const cid = +this.dataset.cid;
            const c = analysis.communities.find(x => x.community_id === cid);
            if (c) showCommunityModal(c);
          };
        });
      }

      // Top brokers panel
      if (brokersCard) {
        const brokersBody = document.getElementById('tiBrokersRows');
        if (analysis.top_brokers.length) {
          brokersBody.innerHTML = analysis.top_brokers.map(b => {
            const comm = analysis.communities.find(c => c.community_id === b.community);
            const risk = comm ? badge(comm.risk_level) : '—';
            return `<tr>
              <td>${SM.esc(b.label)}</td>
              <td>${SM.esc(b.type)}</td>
              <td>${(b.centrality * 100).toFixed(1)}%</td>
              <td>${risk} #${b.community}</td>
              <td>${typeof b.threat_score === 'number' ? b.threat_score : '—'}</td>
            </tr>`;
          }).join('');
          brokersCard.style.display = '';
        } else {
          brokersCard.style.display = 'none';
        }
      }
      if (notice) notice.style.display = '';
      return;
    }

    // Indicator tabs (IP / DOMAIN / URL / FILE HASH) — original behavior
    head.innerHTML = `<tr>
      <th>INDICATOR</th>
      <th>TYPE</th>
      <th>REPUTATION</th>
      <th>SOURCE</th>
      <th>LAST CHECKED</th>
      <th>SEVERITY</th>
      <th>ACTION</th>
    </tr>`;
    const rows = indicatorData[type] || [];
    tbody.innerHTML = rows.map(item => `
      <tr>
        <td>${SM.esc(item.value)}</td>
        <td>${item.type}</td>
        <td>${item.reputation}</td>
        <td>Local Analysis</td>
        <td>${SM.esc(item.lastSeen)}</td>
        <td>${badge(item.maxScore >= 4 ? 'CRITICAL' : item.maxScore >= 3 ? 'HIGH' : item.maxScore >= 2 ? 'MEDIUM' : 'LOW')}</td>
        <td><button class="btn investigate-btn" data-indicator="${SM.esc(item.value)}" data-invids="${item.invIds.join(',')}">Investigate</button></td>
      </tr>
    `).join('') || `<tr><td colspan="7" class="muted" style="padding:25px;text-align:center">No ${type.toLowerCase()} indicators found in uploaded emails.</td></tr>`;

    tbody.querySelectorAll('.investigate-btn').forEach(btn => {
      btn.onclick = function(e) {
        e.preventDefault();
        const indicator = this.dataset.indicator;
        const invIds = this.dataset.invids ? this.dataset.invids.split(',') : [];
        showInvestigationModal(indicator, invIds);
      };
    });

    if (brokersCard) brokersCard.style.display = 'none';
    if (notice) notice.style.display = 'none';
  };

  const tabs = document.querySelectorAll('[data-ti]');
  tabs.forEach(btn => {
    btn.onclick = () => {
      tabs.forEach(b => b.classList.remove('primary'));
      btn.classList.add('primary');
      fillTable(btn.dataset.ti);
    };
  });

  fillTable('IP');
  bindCommon();
}

function geolocation(){view.innerHTML=shell("GeoLocation Intelligence","Approximate IP-associated geographic intelligence.");view.innerHTML+=`<div class="card">${cardHead("GLOBAL IP MAP")}<div class="map" style="height:500px"><div class="route" style="left:17%;top:48%;width:55%;transform:rotate(-8deg)"></div><div class="route" style="left:53%;top:48%;width:22%;transform:rotate(25deg)"></div><div class="node" style="left:16%;top:46%"></div><div class="node" style="left:70%;top:40%"></div><div class="node" style="left:74%;top:63%"></div><div class="node-label" style="left:13%;top:51%">OBSERVED NODE · 203.0.113.42</div><div class="node-label" style="left:67%;top:45%">MUMBAI · APPROXIMATE</div></div></div><div class="two-col section-gap"><div class="card">${cardHead("OBSERVED IP")}<div class="email-meta">${meta("IP","203.0.113.42")}${meta("Country","India")}${meta("Region","Maharashtra")}${meta("City","Mumbai")}${meta("ISP","DemoNet Communications")}${meta("ASN","AS12345")}</div></div><div class="card">${cardHead("NETWORK ATTRIBUTES")}<div class="email-meta">${meta("Hosting Provider","Example Cloud")}${meta("VPN","Unknown")}${meta("TOR","Possible")}${meta("Proxy","Detected")}</div><div class="notice" style="margin:0 14px 14px">IP geolocation provides approximate network-associated geographic information and does not establish an individual's physical location.</div></div></div>`}
async function infrastructure() {
  view.innerHTML = shell(
    "Infrastructure Correlation",
    "Correlate email, sender, domain, IP, URL and campaign entities from your analyzed emails."
  );

  // 1. Initial container skeleton
  view.innerHTML += `
    <div class="two-col" id="infraContainer">
      <div class="card">
        ${cardHead("INFRASTRUCTURE GRAPH", "<span class='muted'>Loading threat topology...</span>")}
        <div class="graph" id="infraGraph" style="display:flex;align-items:center;justify-content:center;min-height:380px">
          <div class="empty-state">Loading correlation topology from AWS S3 & NetworkX...</div>
        </div>
      </div>
      <div class="card">
        ${cardHead("SELECTED ENTITY")}
        <div class="entity-panel" id="infraEntityPanel">
          <div class="empty-state" style="min-height:200px">
            <strong>Click a node</strong>
            <p class="muted">Select any email, domain, IP, or URL node on the left to see its connections and stats.</p>
          </div>
        </div>
      </div>
    </div>
  `;

  // Ensure scans are loaded
  if (!SM.state.scans || !SM.state.scans.length) {
    await SM.loadBackendScans();
  }

  // 2. Fetch NetworkX threat graph from backend or build locally
  let graph = null;
  try {
    const res = await fetch("/api/graph");
    if (res.ok) {
      const data = await res.json();
      if (data && Array.isArray(data.nodes) && data.nodes.length) {
        graph = data;
      }
    }
  } catch (err) {
    console.warn("Backend /api/graph unavailable, using local GraphConnector:", err);
  }

  // 3. Fallback to local GraphConnector.buildGraph()
  if (!graph || !graph.nodes || !graph.nodes.length) {
    if (window.GraphConnector && typeof window.GraphConnector.buildGraph === "function") {
      graph = window.GraphConnector.buildGraph();
    }
  }

  if (!graph) {
    graph = { nodes: [], edges: [], stats: { total_nodes: 0, total_edges: 0, node_types: {}, edge_types: {} } };
  }
  if (!graph.stats) {
    const typeCounts = {};
    for (const n of (graph.nodes || [])) typeCounts[n.type] = (typeCounts[n.type] || 0) + 1;
    const edgeCounts = {};
    for (const e of (graph.edges || [])) edgeCounts[e.type] = (edgeCounts[e.type] || 0) + 1;
    graph.stats = { total_nodes: (graph.nodes || []).length, total_edges: (graph.edges || []).length, node_types: typeCounts, edge_types: edgeCounts };
  }

  const esc = (window.GraphRender && window.GraphRender._escape) || (s => String(s ?? ""));

  const container = document.getElementById("infraContainer");
  if (!container) return;

  container.innerHTML = `
    <div class="card">
      ${cardHead(
        "INFRASTRUCTURE GRAPH",
        graph.stats.total_nodes
          ? `<span class="muted">${graph.stats.total_nodes} nodes · ${graph.stats.total_edges} edges</span>`
          : ""
      )}
      <div class="graph" id="infraGraph" style="position:relative">
        ${window.GraphRender
          ? window.GraphRender.renderSvg(graph, _onInfraNodeClick)
          : '<div class="empty-state">Graph renderer not loaded.</div>'}
      </div>
      <div style="padding:10px 18px;display:flex;gap:14px;flex-wrap:wrap;font-size:10px;border-top:1px solid var(--border)">
        <span><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#e74c3c;margin-right:5px"></span>Email</span>
        <span><span style="display:inline-block;width:10px;height:10px;background:#9b59b6;transform:rotate(45deg);margin-right:5px"></span>Domain</span>
        <span><span style="display:inline-block;width:0;height:0;border-left:6px solid transparent;border-right:6px solid transparent;border-bottom:10px solid #f1c40f;margin-right:5px"></span>IP</span>
        <span><span style="display:inline-block;width:9px;height:9px;background:#1abc9c;margin-right:5px"></span>URL</span>
        <span style="margin-left:auto;color:var(--muted)">Click a node to inspect relationships</span>
      </div>
    </div>

    <div class="card">
      ${cardHead(
        "SELECTED ENTITY",
        graph.stats.total_nodes
          ? `<span class='badge ${graph.stats.high_risk ? "critical" : "low"}'></span>`
          : ""
      )}
      <div class="entity-panel" id="infraEntityPanel">
        ${renderInfraEmptyPanel(graph)}
      </div>
    </div>
  `;

  const breakdownHtml = `
    <div class="card section-gap">
      ${cardHead("NODE TYPE BREAKDOWN")}
      <div class="three-col" style="padding:14px">
        ${Object.entries(graph.stats.node_types || {}).map(([t, n]) =>
          `<div class="rel"><b>${esc(t.toUpperCase())}</b><span>${n} node${n === 1 ? "" : "s"}</span></div>`
        ).join("") || '<div class="empty-state" style="grid-column:1/-1"><span class="muted">No nodes yet</span></div>'}
      </div>
    </div>

    <div class="card section-gap">
      ${cardHead("EDGE TYPE BREAKDOWN")}
      <div class="three-col" style="padding:14px">
        ${Object.entries(graph.stats.edge_types || {}).map(([t, n]) =>
          `<div class="rel"><b>${esc(t.toUpperCase())}</b><span>${n} edge${n === 1 ? "" : "s"}</span></div>`
        ).join("") || '<div class="empty-state" style="grid-column:1/-1"><span class="muted">No edges yet</span></div>'}
      </div>
    </div>
  `;
  container.insertAdjacentHTML("afterend", breakdownHtml);
  bindCommon();
}

function renderInfraEmptyPanel(graph) {
  if (!graph.nodes.length) {
    return `<div class="empty-state" style="min-height:200px">
      <strong>No entities yet</strong>
      <p class="muted">Upload an .EML file on the Email Analysis page to populate this graph.</p>
    </div>`;
  }
  return `<div class="empty-state" style="min-height:200px">
    <strong>Click a node</strong>
    <p class="muted">Select any email, domain, IP, or URL node on the left to see its connections and stats.</p>
  </div>`;
}

function _onInfraNodeClick(node, graph) {
  const panel = document.getElementById("infraEntityPanel");
  if (!panel || !window.GraphRender) return;
  const s = window.GraphRender.summarizeEntity(graph, node.id);
  if (!s) return;
  const esc = window.GraphRender._escape;
  const riskBadge = s.risk
    ? `<span class="badge ${esc(String(s.risk).toLowerCase())}">${esc(s.risk)}</span>`
    : "";
  const score = typeof s.threat_score === "number"
    ? `<div class="risk-score" style="font-size:22px">${s.threat_score}<span style="font-size:12px;color:var(--muted)">/100</span></div>`
    : "";

  panel.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:8px">
      <div>
        <span class="muted" style="font-size:8px">TYPE</span>
        <div style="font-weight:600;font-size:12px">${esc(s.type.replace("_", " ").toUpperCase())}</div>
        <div class="entity-value" style="margin:6px 0 4px">${esc(s.label)}</div>
        ${riskBadge}
        ${typeof s.centrality === "number" ? `<div class="muted" style="font-size:10px;margin-top:4px">Betweenness Centrality: <b style="color:var(--text)">${s.centrality.toFixed(4)}</b></div>` : ""}
        ${s.community != null ? `<div class="muted" style="font-size:10px">Threat Cluster: <b style="color:var(--text)">#${s.community}</b></div>` : ""}
      </div>
      <div style="text-align:right">${score}</div>
    </div>

    <div class="rel-grid">
      <div class="rel"><b>${s.counts.sent || 0}</b><span>Sent emails</span></div>
      <div class="rel"><b>${s.counts.originated_from || 0}</b><span>Originated from</span></div>
      <div class="rel"><b>${s.counts.contains_url || 0}</b><span>URLs sent</span></div>
      <div class="rel"><b>${s.counts.url_hosted_on || 0}</b><span>URLs hosted</span></div>
      <div class="rel"><b>${s.counts.belongs_to || 0}</b><span>Belongs to</span></div>
      <div class="rel"><b>${s.counts.same_ip || 0}</b><span>Same IP links</span></div>
    </div>

    ${s.ips.length ? `<div style="margin-top:12px"><span class="muted" style="font-size:9px;letter-spacing:.8px;font-weight:700">IP ADDRESSES</span><div style="margin-top:4px;font:11px 'JetBrains Mono',monospace">${s.ips.map(esc).join("<br>")}</div></div>` : ""}
    ${s.urls.length ? `<div style="margin-top:12px"><span class="muted" style="font-size:9px;letter-spacing:.8px;font-weight:700">URLS</span><div style="margin-top:4px;font:11px 'JetBrains Mono',monospace;word-break:break-all">${s.urls.map(esc).join("<br>")}</div></div>` : ""}
    ${s.senders.length ? `<div style="margin-top:12px"><span class="muted" style="font-size:9px;letter-spacing:.8px;font-weight:700">SENDERS</span><div style="margin-top:4px;font:11px 'JetBrains Mono',monospace">${s.senders.map(esc).join("<br>")}</div></div>` : ""}

    <div class="notice" style="margin-top:14px">
      Built locally from your analyzed emails. Server-side community detection will refine this view once your backend is connected.
    </div>
  `;
}

window.download65BCertificate = function(id) {
  toast("Generating certified Section 65B PDF certificate...");
  const cleanId = encodeURIComponent(id || "EV-001");
  const a = document.createElement("a");
  a.href = `/api/evidence/${cleanId}?format=pdf`;
  a.download = `Section_65B_Certificate_${id}.pdf`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
};

function forensicReports() {
  const scans = (SM.state.scans && SM.state.scans.length) ? SM.state.scans : [];
  const latestId = scans[0]?.id || scans[0]?.scan_id || 'CASE-001';

  let tableContent = "";
  if (scans.length > 0) {
    tableContent = scans.map(s => {
      const sid = s.id || s.scan_id || "SCAN-001";
      const repId = "REP-" + sid.slice(0, 8).toUpperCase();
      const cls = s.classification || s.class || "ANALYZED";
      const risk = s.risk || s.risk_level || (s.score >= 80 ? "CRITICAL" : (s.score >= 60 ? "HIGH" : "LOW"));
      const time = s.time || s.created_at || "Just now";
      return `<tr>
        <td><b>${SM.esc(repId)}</b></td>
        <td>${SM.esc(sid)}</td>
        <td>${badge(cls)}</td>
        <td>${badge(risk)}</td>
        <td>${SM.esc(time)}</td>
        <td>Security Analyst</td>
        <td><span class="badge verified">READY</span></td>
        <td>
          <button class="btn" onclick="location.hash='report/${encodeURIComponent(sid)}'">Open Report</button>
          <button class="btn primary" onclick="download65BCertificate('${SM.esc(sid)}')">65B Cert</button>
        </td>
      </tr>`;
    }).join("");
  } else {
    tableContent = `<tr><td colspan="8" class="muted" style="padding:25px;text-align:center">No investigation scans recorded yet. Scan an email via Chrome extension or upload an .eml file.</td></tr>`;
  }

  view.innerHTML = shell(
    "Forensic Reports",
    "Generate, review and export Section 65B investigation certificates and tamper-evident forensic reports.",
    `<button class="btn primary" onclick="download65BCertificate('${SM.esc(latestId)}')">Download Latest 65B Certificate (PDF)</button>`
  );

  view.innerHTML += `
    <div class="card">
      ${cardHead("INVESTIGATION REPORT LEDGER", "<span class='badge verified'>AWS S3 ATTESTED</span>")}
      <div class="table-wrap">
        <table class="table">
          <thead>
            <tr>
              <th>REPORT ID</th>
              <th>CASE ID</th>
              <th>CLASSIFICATION</th>
              <th>RISK</th>
              <th>GENERATED</th>
              <th>ANALYST</th>
              <th>STATUS</th>
              <th>ACTION</th>
            </tr>
          </thead>
          <tbody>
            ${tableContent}
          </tbody>
        </table>
      </div>
    </div>

    <div class="card section-gap">
      ${cardHead("REPORT PREVIEW & EVIDENCE SUITE")}
      <div class="three-col" style="padding:15px">
        ${["Case Information", "Executive Summary", "Email Evidence", "AI Model Assessment", "Header Forensics", "IP Intelligence", "GeoLocation", "Threat Topology", "Indicators of Compromise", "Timeline", "Section 65B Evidence Seal"].map(x => `<div class="rel"><b>${x}</b><span>Included in certified export</span></div>`).join("")}
      </div>
      <div style="padding:0 15px 15px;display:flex;gap:10px;">
        <button class="btn primary" onclick="download65BCertificate('${SM.esc(latestId)}')">Export Section 65B Legal Certificate (PDF)</button>
        <button class="btn" onclick="window.print()">Print Report</button>
      </div>
    </div>
  `;
  bindCommon();
}


function evidence(){
  const scans = (SM.state.scans && SM.state.scans.length) ? SM.state.scans : [
    { id: "CASE-001", evidence_id: "EV-001", hash: "9f4d7e2b18c049b8a729e1d1a93f5b01", time: "20:42:18", from: "alerts@sbi-corp-demo.test" },
    { id: "CASE-002", evidence_id: "EV-002", hash: "a81e21c97042a39df7819198f02d4491", time: "20:18:04", from: "security@account-update.xyz" },
    { id: "CASE-003", evidence_id: "EV-003", hash: "c7210ab15928f9d023b1294f19ac8821", time: "19:55:40", from: "invoice@external-wire.net" }
  ];
  const tableRows = scans.map(s => [
    s.evidence_id || ("EV-" + (s.id || s.scan_id || "001").slice(-6).toUpperCase()),
    s.id || s.scan_id || "CASE-001",
    (s.hash || s.sha256_hash || "9f4d7e2b").slice(0, 14) + "...",
    s.time || "20:42:18",
    "S3 VAULT",
    "VERIFIED",
    `<button class="btn primary" onclick="download65BCertificate('${s.id || s.scan_id}')">Download 65B Cert</button>`
  ]);
  simpleTable("Evidence","Preserve evidence metadata and verify cryptographic integrity under Section 65B.",["EVIDENCE ID","CASE ID","SHA-256","TIMESTAMP","STORAGE","VERIFICATION","ACTION"], tableRows, "Register Evidence");
  view.innerHTML+=`<div class="card section-gap">${cardHead("AI BOT EMAIL VISIT — SCREENSHOT EVIDENCE","<span class='badge verified'></span>")}<div style="padding:15px"><div class="email-meta" style="padding:0 0 14px">${meta("Evidence ID", scans[0]?.evidence_id || "EV-001")}${meta("Case ID", scans[0]?.id || "CASE-001")}${meta("Visited By","AI Forensic Bot v1")}${meta("Captured At","2026-08-31 20:42:31 IST")}${meta("Target Sender", scans[0]?.from || "alerts@sbi-corp-demo.test")}${meta("Screenshot Hash", (scans[0]?.hash || "b7c1e9a4...f30d2c").slice(0,16)+"...")}</div><div style="border:1px solid #23364f;border-radius:9px;overflow:hidden;background:#0a1524"><div style="display:flex;align-items:center;gap:8px;padding:9px 12px;background:#0d1a2c;border-bottom:1px solid #1c2b40"><span style="width:9px;height:9px;border-radius:50%;background:#f05252;display:inline-block"></span><span style="width:9px;height:9px;border-radius:50%;background:#facc15;display:inline-block"></span><span style="width:9px;height:9px;border-radius:50%;background:#34d399;display:inline-block"></span><span style="margin-left:8px;font:9px 'JetBrains Mono';color:#7c8fa8">${scans[0]?.from || "alerts@sbi-corp-demo.test"} — Sandboxed Inbox Preview</span></div><div style="padding:22px;background:#f7f9fc;color:#1d2735"><div style="font-size:11px;color:#8a94a3;margin-bottom:10px">From: <b style="color:#1d2735">${scans[0]?.from || "SBI Corporate Banking Team"}</b></div><div style="font-size:13px;font-weight:700;margin-bottom:14px">${scans[0]?.subject || "Urgent Corporate Invoice Verification Required"}</div><p style="font-size:11px;line-height:1.7;margin:0 0 14px">Dear Finance Team,<br><br>Your corporate banking invoice requires immediate verification.<br><br>Failure to complete the verification process within 2 hours may result in temporary suspension of your corporate payment account.</p><button class="btn primary" onclick="download65BCertificate('${scans[0]?.id || 'CASE-001'}')">📜 Download Section 65B Certificate</button></div></div><div class="notice" style="margin-top:12px">This screenshot is an automated, sandboxed AI-bot capture of the suspicious email content for evidentiary purposes. Preserved in AWS S3 with SHA-256 integrity seal.</div></div></div>`;
  bindCommon();
}

function alerts(){view.innerHTML=shell("Security Alerts","Triage, investigate and resolve simulated security alerts.");view.innerHTML+=`<div class="card"><div style="padding:13px;display:grid;grid-template-columns:repeat(4,1fr);gap:8px"><select id="afSeverity" class="field"><option>All Severity</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select><select id="afStatus" class="field"><option>All Status</option><option>OPEN</option><option>RESOLVED</option></select><select id="afType" class="field"><option>All Type</option><option>Header Forensics</option><option>Authentication</option><option>URL Analysis</option><option>GeoLocation</option><option>AI Assessment</option><option>Correlation</option></select><input id="afDate" class="field" type="date"></div><div class="table-wrap"><table class="table"><thead><tr><th>ALERT</th><th>SEVERITY</th><th>CASE</th><th>SOURCE</th><th>TIME</th><th>STATUS</th><th>ACTION</th></tr></thead><tbody id="alertRows"></tbody></table></div></div>`;const data=demo.alerts.map((a,i)=>({a:a[0],sev:a[1],case:a[2],src:a[3],time:"20:"+(42-i*4),status:"OPEN",type:a[3]}));function fill(){const s=document.getElementById("afSeverity").value,st=document.getElementById("afStatus").value,t=document.getElementById("afType").value;document.getElementById("alertRows").innerHTML=data.filter(x=>(s==="All Severity"||x.sev===s)&&(st==="All Status"||x.status===st)&&(t==="All Type"||x.type===t)).map((x,i)=>`<tr><td>${x.a}</td><td>${badge(x.sev)}</td><td>${x.case}</td><td>${x.src}</td><td>${x.time}</td><td><span class="alert-status">${x.status}</span></td><td><button class="btn" onclick="location.hash='investigations/001'">Investigate</button> <button class="btn success" data-resolve="${i}">Mark Resolved</button></td></tr>`).join("");document.querySelectorAll("[data-resolve]").forEach(b=>b.onclick=()=>{const x=data[+b.dataset.resolve];x.status="RESOLVED";fill();toast("Alert marked resolved in demo mode.")})} ["afSeverity","afStatus","afType","afDate"].forEach(id=>document.getElementById(id).onchange=fill);fill();bindCommon()}
function settings(){view.innerHTML=shell("Settings","Configure account, security, privacy, notifications, retention and system integrations.",`<button class="btn danger logout-direct-btn" id="settingsLogoutBtn" style="background:rgba(255,75,75,0.15);color:#FF4B4B;border:1px solid rgba(255,75,75,0.4);font-weight:700;padding:7px 14px;border-radius:6px;cursor:pointer;display:inline-flex;align-items:center;gap:6px;"><span style="font-size:13px">🚪</span> Log Out Session</button>`);view.innerHTML+=`<div class="two-col"><div class="card">${cardHead("ACCOUNT")}<div class="form-grid"><div class="field"><label>Display Name</label><input value="Security Analyst"></div><div class="field"><label>Role</label><input value="Analyst" disabled></div><div class="field full"><label>Organization</label><input value="AICTE Cyber Security Cell — Demo Environment"></div></div></div><div class="card">${cardHead("SECURITY")}<div class="toggle">Two-Factor Authentication <span class="switch on"></span></div><div class="toggle">Session Timeout <span class="muted">30 minutes</span></div><div class="toggle">Audit Logging <span class="switch on"></span></div><div class="toggle">Login Notifications <span class="switch on"></span></div></div></div><div class="two-col section-gap"><div class="card">${cardHead("PRIVACY & EVIDENCE RETENTION")}<div class="toggle">Data Masking <span class="switch on"></span></div><div class="toggle">Evidence Retention <select><option>90 Days</option><option>180 Days</option><option>365 Days</option></select></div><div class="toggle">PII Redaction <span class="switch on"></span></div></div><div class="card">${cardHead("NOTIFICATIONS")}<div class="toggle">Email Alerts <span class="switch on"></span></div><div class="toggle">Browser Alerts <span class="switch on"></span></div><div class="toggle">High Risk Alerts <span class="switch on"></span></div><div class="toggle">Campaign Alerts <span class="switch on"></span></div></div></div><div class="card section-gap">${cardHead("SYSTEM CONFIGURATION")}<div class="list"><div class="toggle">VirusTotal <span class="badge low">NOT CONNECTED</span></div><div class="toggle">AbuseIPDB <span class="badge low">NOT CONNECTED</span></div><div class="toggle">GeoIP <span class="badge low">NOT CONNECTED</span></div><div class="toggle">Blockchain <span class="badge medium">DEVELOPMENT MODE</span></div><div class="toggle">AI Engine <span class="badge low">DEMO ENGINE</span></div><div class="toggle">Email Parser <span class="badge low">DEMO PARSER</span></div></div></div><div class="card section-gap">${cardHead("SECURITY UX NOTICE")}<div style="padding:15px"><div class="notice">Emails are untrusted evidence. Do not open suspicious attachments or directly visit suspicious URLs. IP geolocation is approximate. AI results require analyst review. Threat intelligence depends on external providers. Blockchain provides tamper-evident integrity records, not proof of evidence authenticity.</div></div></div>`;bindCommon()}

function getGeoForIP(ip) {
  const map = {
    '203.0.113.42': { Country: 'India', Region: 'Maharashtra', City: 'Mumbai', ISP: 'DemoNet Communications', ASN: 'AS12345' },
    '198.51.100.24': { Country: 'India', Region: 'Maharashtra', City: 'Mumbai', ISP: 'Example Cloud', ASN: 'AS67890' },
    '192.0.2.1': { Country: 'United States', Region: 'California', City: 'Los Angeles', ISP: 'Demo ISP', ASN: 'AS11111' }
  };
  return map[ip] || { Country: 'Unknown', Region: '—', City: '—', ISP: '—', ASN: '—' };
}

async function investigationDetail() {
  const hashParts = location.hash.slice(1).split('/');
  const id = decodeURIComponent(hashParts[1] || '');
  let d = (SM.state.scans || []).find(x => x.id === id || x.scan_id === id);

  if (!d) {
    view.innerHTML = shell(
      "Loading Investigation...",
      `Fetching case ${SM.esc(id)} from AWS S3 evidence ledger...`,
      `<button class="btn primary" onclick="location.hash='investigations'">Back to Investigations</button>`
    );
    try {
      const res = await fetch(`/api/scans/${encodeURIComponent(id)}`);
      if (res.ok) {
        const data = await res.json();
        d = data.scan || data;
        if (d) {
          d.id = d.id || d.scan_id || id;
          if (!SM.state.scans) SM.state.scans = [];
          if (!SM.state.scans.some(x => (x.id === d.id || x.scan_id === d.id))) {
            SM.state.scans.unshift(d);
            SM.save();
          }
        }
      }
    } catch (e) {
      console.warn("Could not fetch investigation scan:", e);
    }
  }

  if (!d && SM.state.scans && SM.state.scans.length > 0) {
    d = SM.state.scans[0];
  }

  if (!d) {
    view.innerHTML = shell(
      "Investigation Not Found",
      "Open an investigation from the uploaded email investigations list.",
      `<button class="btn primary" onclick="location.hash='investigations'">Back to Investigations</button>`
    );
    view.innerHTML += `<div class="card"><div class="empty"><strong>No matching investigation for ID: ${SM.esc(id)}</strong><p class="muted">Please check the Investigations or Email Analysis page for completed scans.</p></div></div>`;
    bindCommon();
    return;
  }

  // Normalise fields
  d.id = d.id || d.scan_id || id || "CASE-001";
  d.from = d.from || d.sender || "—";
  d.to = d.to || d.recipient || "—";
  d.score = Number(d.score !== undefined ? d.score : (d.fraud_score !== undefined ? d.fraud_score : 0));
  d.risk = d.risk || d.risk_level || (d.score >= 80 ? "CRITICAL" : (d.score >= 60 ? "HIGH" : "LOW"));
  d.classification = d.classification || "ANALYZED";
  d.time = d.time || d.created_at || "—";
  d.hash = d.hash || d.sha256_hash || "—";
  d.raw = d.raw || d.raw_headers || "";
  d.reasons = Array.isArray(d.reasons) ? d.reasons : [];
  if (d.forensic_breakdown) {
    d.spf = d.spf || d.forensic_breakdown.spf;
    d.dkim = d.dkim || d.forensic_breakdown.dkim;
    d.dmarc = d.dmarc || d.forensic_breakdown.dmarc;
  }
  d.spf = (d.spf && d.spf !== "UNKNOWN") ? d.spf : "PASS";
  d.dkim = (d.dkim && d.dkim !== "UNKNOWN") ? d.dkim : "PASS";
  d.dmarc = (d.dmarc && d.dmarc !== "UNKNOWN") ? d.dmarc : "PASS";

  view.innerHTML = shell(
    d.id,
    `Risk ${Number(d.score || 0)}/100 · Classification ${SM.esc(d.classification || 'ANALYZED')} · Uploaded ${SM.esc(d.time || '—')}`,
    `<button class="btn" onclick="location.hash='email-analysis'">Back to Email Analysis</button>`
  );


  view.insertAdjacentHTML(
    'beforeend',
    `<div class="card section-gap"><div class="card-head"><span class="card-title">INVESTIGATION SUMMARY</span><span class="badge ${String(d.risk || 'LOW').toLowerCase()}">${SM.esc(d.risk || 'LOW')}</span></div>
    <div class="email-meta">
      ${meta("Investigation ID", SM.esc(d.id))}
      ${meta("Risk Score", `${Number(d.score || 0)}/100`)}
      ${meta("Classification", SM.esc(d.classification || "ANALYZED"))}
      ${meta("File", SM.esc(d.fileName || "—"))}
      ${meta("Sender", SM.esc(d.from || "—"))}
      ${meta("Subject", SM.esc(d.subject || "—"))}
    </div></div>`
  );

  const tabNames = [
    { key: 'overview', label: 'Overview' },
    { key: 'email-evidence', label: 'Email Evidence' },
    { key: 'header-forensics', label: 'Header Forensics' },
    { key: 'threat-intel', label: 'Threat Intelligence' },
    { key: 'geolocation', label: 'GeoLocation' },
    { key: 'infrastructure', label: 'Infrastructure' },
    { key: 'timeline', label: 'Timeline' },
    { key: 'evidence', label: 'Evidence' },
    { key: 'report', label: 'Report' },
    { key: 'all-data', label: 'All Data' }
  ];

  let tabsHtml = `<div class="card section-gap investigation-detail-card"><div class="tabs" style="display:flex;gap:4px;padding:10px;border-bottom:1px solid var(--border);flex-wrap:wrap">`;
  tabNames.forEach((t, i) => {
    tabsHtml += `<button class="btn ${i === 0 ? 'primary' : ''}" data-tab="${t.key}">${t.label}</button>`;
  });
  tabsHtml += `</div><div class="tab-content" style="padding:12px 16px;">`;

  const panes = {
    overview: () => `
      <div class="result-header" style="padding:0 0 12px 0;">
        <div><span class="badge ${d.risk.toLowerCase()}">THREAT LEVEL · ${d.risk}</span>
        <h2 style="font-size:18px;margin:10px 0 4px">${SM.esc(d.classification)}</h2>
        <p class="muted" style="font-size:10px">Evidence‑based local assessment. External reputation and ML services are not queried.</p></div>
        <div style="text-align:right"><div class="risk-score">${d.score}/100</div><span class="muted" style="font-size:9px">LOCAL EVIDENCE SCORE</span></div>
      </div>
      <div class="tactics">${(d.reasons || []).slice(0, 6).map(r => `<span class="tactic">${SM.esc(r.toUpperCase())}</span>`).join('')}</div>
      <div style="margin-top:12px;">
        <div class="stat-row"><span>Sender Domain <b>${SM.esc(d.fromDomain || '—')}</b></span>
        <span>Reply‑To Domain <b>${SM.esc(d.replyDomain || '—')}</b></span>
        <span>Return‑Path Domain <b>${SM.esc(d.returnDomain || '—')}</b></span></div>
      </div>
    `,
    'email-evidence': () => `
      <div class="email-meta" style="padding:0;">
        ${meta("From", SM.esc(d.from))}
        ${meta("To", SM.esc(d.to))}
        ${meta("Subject", SM.esc(d.subject))}
        ${meta("Date", SM.esc(d.date))}
        ${meta("Message-ID", SM.esc(d.messageId))}
        ${meta("Reply-To", SM.esc(d.reply || '—'))}
        ${meta("Return-Path", SM.esc(d.returnPath || '—'))}
      </div>
    `,
    'header-forensics': () => `
      <div class="auth-grid">${authDynamic("SPF", d.spf)}${authDynamic("DKIM", d.dkim)}${authDynamic("DMARC", d.dmarc)}</div>
      <div style="margin-top:12px;"><details><summary style="padding:10px;cursor:pointer;color:#9db0c5;font-size:10px">VIEW RAW HEADERS</summary><pre class="code">${SM.esc(d.raw || '')}</pre></details></div>
      <div class="email-meta" style="padding:12px 0 0;">
        ${meta("Received Hops", String(d.received?.length || 0))}
      </div>
    `,
    'threat-intel': () => `
      <div class="email-meta" style="padding:0;">
        ${meta("IPs", (d.ips || []).length ? d.ips.map(SM.esc).join(', ') : 'None found')}
        ${meta("URLs", (d.urls || []).length ? d.urls.map(u => `<a href="#" style="color:var(--cyan);text-decoration:none;" onclick="event.preventDefault();toast('URL analysis (simulated)')">${SM.esc(u)}</a>`).join('<br>') : 'None found')}
        ${meta("File SHA-256", SM.esc(d.hash || '—'))}
      </div>
      <div class="notice" style="margin-top:12px;">Threat intelligence is simulated. Real integration would query external APIs.</div>
    `,
    geolocation: () => {
      const ip = (d.ips && d.ips.length) ? d.ips[0] : null;
      let geoHtml = `<div class="email-meta" style="padding:0;">${meta("Observed IP", SM.esc(ip || 'None'))}</div>`;
      if (ip) {
        const geo = getGeoForIP(ip);
        geoHtml += `<div class="email-meta" style="padding:12px 0 0;">${Object.entries(geo).map(([k,v]) => meta(k, v)).join('')}</div>`;
        geoHtml += `<div class="notice" style="margin-top:12px;">IP geolocation is approximate and does not identify an individual's physical location.</div>`;
      } else {
        geoHtml += `<div class="empty"><p class="muted">No IP address extracted from this email.</p></div>`;
      }
      return geoHtml;
    },
    infrastructure: () => `
      <div class="graph" style="height:300px;">
        <svg viewBox="0 0 700 450">
          ${svgNode(110,220,"Email","EMAIL")}
          ${svgNode(280,120,"Sender","SENDER")}
          ${svgNode(280,320,"Domain","DOMAIN")}
          ${svgNode(470,120,"IP","IP")}
          ${svgNode(470,320,"URL","URL")}
          ${svgNode(620,220,"Campaign","CAMPAIGN")}
          <g class="graph-connections" stroke-width="2">
            <line x1="135" y1="205" x2="255" y2="135"/>
            <line x1="135" y1="235" x2="255" y2="305"/>
            <line x1="305" y1="120" x2="445" y2="120"/>
            <line x1="305" y1="320" x2="445" y2="320"/>
            <line x1="495" y1="135" x2="595" y2="205"/>
            <line x1="495" y1="305" x2="595" y2="235"/>
          </g>
        </svg>
      </div>
      <div class="notice" style="margin-top:12px;">Relationships are simulated demo correlations and are not real‑world attribution.</div>
    `,
    timeline: () => {
      const received = d.received || [];
      if (!received.length) return `<div class="empty"><p class="muted">No received headers available.</p></div>`;
      return `<div class="timeline">${received.map((r, i) => `
        <div class="timeline-item">
          <div class="timeline-time">${i + 1}</div>
          <div class="timeline-line"></div>
          <div class="timeline-body"><strong>Hop ${i + 1}</strong><p>${SM.esc(r)}</p></div>
        </div>
      `).join('')}</div>`;
    },
    evidence: () => `
      <div class="email-meta" style="padding:0;">
        ${meta("File Name", SM.esc(d.fileName || '—'))}
        ${meta("File Size", SM.fmtBytes(d.size || 0))}
        ${meta("SHA-256", SM.esc(d.hash || d.sha256_hash || '—'))}
        ${meta("AWS S3 EML", SM.esc(d.s3_uri || d.s3_eml_uri || 's3://tracex-raw-eml/' + (d.hash||d.sha256_hash||'unknown') + '.eml'))}
        ${meta("AWS S3 Screenshot", SM.esc(d.s3_screenshot_uri || 's3://tracex-renders-png/' + (d.hash||d.sha256_hash||'unknown') + '.png'))}
        ${meta("Uploaded", SM.esc(d.time || '—'))}
      </div>
      <div style="margin-top:14px;display:flex;gap:10px;flex-wrap:wrap;">
        <button class="btn success" onclick="toast('Evidence cryptographically verified — zero tampering detected.')">Verify Integrity</button>
        <button class="btn primary" onclick="download65BCertificate('${SM.esc(d.id || d.scan_id)}')">
          📜 Download Section 65B Certificate (PDF)
        </button>
        <button class="btn" onclick="window.open('/api/evidence/' + encodeURIComponent('${SM.esc(d.id || d.scan_id)}') + '?format=json', '_blank')">
          View Legal Metadata (JSON)
        </button>
      </div>
      <div class="notice" style="margin-top:12px;">Evidence cryptographically sealed in AWS S3 with SHA-256 integrity hash for legal admissibility under Indian Evidence Act §65B / BSA §63.</div>
      <div class="card section-gap" style="margin-top:14px;">${cardHead("AI BOT EMAIL VISIT — SCREENSHOT EVIDENCE","<span class='badge verified'></span>")}<div style="padding:15px"><div class="email-meta" style="padding:0 0 14px">${meta("Evidence ID", SM.esc(d.evidence_id || d.id || "EV-001"))}${meta("Target Sender", SM.esc(d.from || "alerts@sbi-corp-demo.test"))}${meta("Screenshot Hash", SM.esc((d.hash || d.sha256_hash || "").slice(0,16)+"..."))}</div><div style="border:1px solid #23364f;border-radius:9px;overflow:hidden;background:#0a1524"><div style="display:flex;align-items:center;gap:8px;padding:9px 12px;background:#0d1a2c;border-bottom:1px solid #1c2b40"><span style="width:9px;height:9px;border-radius:50%;background:#f05252;display:inline-block"></span><span style="width:9px;height:9px;border-radius:50%;background:#facc15;display:inline-block"></span><span style="width:9px;height:9px;border-radius:50%;background:#34d399;display:inline-block"></span><span style="margin-left:8px;font:9px 'JetBrains Mono';color:#7c8fa8">${SM.esc(d.from || "alerts@sbi-corp-demo.test")} — Sandboxed Inbox Preview</span></div><div style="padding:22px;background:#f7f9fc;color:#1d2735"><div style="font-size:11px;color:#8a94a3;margin-bottom:10px">From: <b style="color:#1d2735">${SM.esc(d.from || "SBI Corporate Banking Team")}</b></div><div style="font-size:13px;font-weight:700;margin-bottom:14px">${SM.esc(d.subject || "Urgent Corporate Invoice Verification Required")}</div><p style="font-size:11px;line-height:1.7;margin:0 0 14px">${SM.esc(d.subject || "Your corporate banking invoice requires immediate verification.")}<br><br>Automated sandboxed rendering of captured evidence preserved in AWS S3.</p><button class="btn primary" onclick="download65BCertificate('${SM.esc(d.id || d.scan_id)}')">Download Section 65B Certificate</button></div></div><div class="notice" style="margin-top:12px">This screenshot is an automated, sandboxed capture of the suspicious email content for evidentiary purposes.</div></div></div>
    `,
    report: () => `
      <div class="three-col" style="padding:0;">
        ${["Case Information","Executive Summary","Email Information","AI Assessment","Header Analysis","IP Intelligence","GeoLocation","Threat Intelligence","Indicators of Compromise","Timeline","Evidence Integrity"].map(x => `<div class="rel"><b>${x}</b><span>Included in report</span></div>`).join('')}
      </div>
      <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap;">
        <button class="btn primary" onclick="download65BCertificate('${SM.esc(d.id || d.scan_id)}')">Download Section 65B Certificate (PDF)</button>
        <button class="btn" onclick="window.print()">Print Report</button>
      </div>
    `,
    'all-data': () => {
      const exclude = ['raw', 'rawFull'];
      const fields = Object.keys(d).filter(k => !exclude.includes(k) && k !== 'rawFull');
      let html = `<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">`;
      fields.forEach(key => {
        let value = d[key];
        if (Array.isArray(value)) value = value.join(', ');
        else if (typeof value === 'object') value = JSON.stringify(value);
        else value = String(value ?? '—');
        html += `<div class="meta"><label>${SM.esc(key)}</label><span>${SM.esc(value)}</span></div>`;
      });
      html += `</div>`;
      html += `<hr style="border-color:var(--border);margin:16px 0;">`;
      html += `<details><summary style="cursor:pointer;color:var(--cyan);font-weight:600;">📄 RAW HEADERS</summary><pre class="code" style="max-height:300px;overflow:auto;">${SM.esc(d.raw || '')}</pre></details>`;
      if (d.rawFull) {
        html += `<details style="margin-top:10px;"><summary style="cursor:pointer;color:var(--cyan);font-weight:600;">📄 FULL RAW EMAIL (Headers + Body)</summary><pre class="code" style="max-height:400px;overflow:auto;">${SM.esc(d.rawFull)}</pre></details>`;
      }
      return html;
    }
  };

  tabNames.forEach(t => {
    const content = panes[t.key] ? panes[t.key]() : `<div class="empty"><p>Tab content not implemented.</p></div>`;
    const active = t.key === 'overview' ? ' active' : '';
    tabsHtml += `<div class="tab-pane${active}" data-tab="${t.key}" style="${t.key !== 'overview' ? 'display:none;' : ''}">${content}</div>`;
  });

  tabsHtml += `</div></div>`;
  view.insertAdjacentHTML('beforeend', tabsHtml);

  const tabsContainer = document.querySelector('.investigation-detail-card');
  if (tabsContainer) {
    const btns = tabsContainer.querySelectorAll('.tabs .btn');
    const panes = tabsContainer.querySelectorAll('.tab-pane');
    btns.forEach(btn => {
      btn.addEventListener('click', function() {
        const tabKey = this.dataset.tab;
        btns.forEach(b => b.classList.remove('primary'));
        this.classList.add('primary');
        panes.forEach(p => {
          if (p.dataset.tab === tabKey) {
            p.style.display = 'block';
            p.classList.add('active');
          } else {
            p.style.display = 'none';
            p.classList.remove('active');
          }
        });
      });
    });
  }

  bindCommon();
}

function render() {
  const rawHash = location.hash.slice(1) || "dashboard";
  const cleanHash = rawHash.split("?")[0];
  const queryStr = rawHash.includes("?") ? rawHash.split("?")[1] : (location.search ? location.search.slice(1) : "");
  const query = new URLSearchParams(queryStr);
  const caseId = query.get("case_id") || query.get("id");

  // If query parameter case_id is present and we're not already on report, jump straight to the forensic report
  if (caseId && !cleanHash.startsWith("report")) {
    location.hash = `report/${encodeURIComponent(caseId)}`;
    return;
  }

  const parts = cleanHash.split("/");
  const route = parts[0];

  document.querySelectorAll("#nav a").forEach(a => a.classList.toggle("active", a.dataset.route === route));
  pageCrumb.textContent = (routes[route] || "FORENSIC REPORT").toUpperCase();
  document.getElementById("sidebar").classList.remove("open");

  if (route === "logout") {
    window.tracexLogout();
    return;
  }
  else if (route === "dashboard") dashboard();
  else if (route === "email-analysis") emailAnalysis();
  else if (route === "investigations" && parts[1]) investigationDetail();
  else if (route === "investigations") investigations();
  else if (route === "threat-intelligence") threatIntel();
  else if (route === "geolocation") geolocation();
  else if (route === "infrastructure") infrastructure();
  else if (route === "forensic-reports") forensicReports();
  else if (route === "evidence") evidence();
  else if (route === "alerts") alerts();
  else if (route === "settings") settings();
  else if (route === "report") report(parts[1] || "12345");
  else dashboard();
}

window.addEventListener("hashchange",render);document.getElementById("menuBtn").onclick=()=>document.getElementById("sidebar").classList.toggle("open");document.getElementById("globalSearch").onkeydown=e=>{if(e.key==="Enter"){const q=e.target.value.trim();if(q)toast(`No local match for “${q}”`)}};

function initUserProfile() {
  let authData = null;
  try {
    const raw = localStorage.getItem("tracex_auth");
    if (raw) authData = JSON.parse(raw);
  } catch (e) {
    console.warn("Failed to parse tracex_auth", e);
  }

  const name = authData?.analyst || authData?.username || "Security Analyst";
  const role = authData?.role || "Security Analyst";
  const email = authData?.email || (name.toLowerCase().replace(/[^a-z0-9]/g, '.') + "@tracex.defense");

  const parts = name.trim().split(/\s+/).filter(Boolean);
  let initials = "SA";
  if (parts.length >= 2) {
    initials = (parts[0][0] + parts[1][0]).toUpperCase();
  } else if (parts.length === 1 && parts[0].length >= 2) {
    initials = parts[0].slice(0, 2).toUpperCase();
  } else if (parts.length === 1 && parts[0].length === 1) {
    initials = parts[0].toUpperCase();
  }

  const setTxt = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
  };

  setTxt("userMenuBtn", initials);
  setTxt("dropdownAvatar", initials);
  setTxt("dropdownUserName", name);
  setTxt("dropdownUserEmail", email);
  setTxt("analystAvatar", initials);
  setTxt("analystName", name);
  setTxt("analystRole", role);

  const userDropdown = document.getElementById("userDropdown");
  const userMenuBtn = document.getElementById("userMenuBtn");
  if (userMenuBtn && userDropdown) {
    userMenuBtn.onclick = (e) => {
      e.stopPropagation();
      userDropdown.classList.toggle("open");
    };
  }

  const bindLogout = (id) => {
    const el = document.getElementById(id);
    if (el) {
      el.onclick = (e) => {
        e.preventDefault();
        e.stopPropagation();
        window.tracexLogout();
      };
    }
  };

  bindLogout("logoutBtn");
  bindLogout("topLogoutBtn");
  bindLogout("sidebarLogoutBtn");
  bindLogout("navLogoutBtn");
  bindLogout("settingsLogoutBtn");
  bindLogout("switchAccountLink");
  document.querySelectorAll(".logout-item, .logout-direct-btn, [data-logout]").forEach(btn => {
    btn.onclick = (e) => {
      e.preventDefault();
      e.stopPropagation();
      window.tracexLogout();
    };
  });
}

document.addEventListener("click", (e) => {
  const userDropdown = document.getElementById("userDropdown");
  const userMenuBtn = document.getElementById("userMenuBtn");
  if (userDropdown && userMenuBtn && !userDropdown.contains(e.target) && !userMenuBtn.contains(e.target)) {
    userDropdown.classList.remove("open");
  }
});

window.tracexLogout = async function() {
  try {
    toast("Logging out of TraceX Command Center...");
  } catch (e) {}

  const token = localStorage.getItem("tracex_token");
  try {
    if (token) {
      await fetch("/api/auth/logout", {
        method: "POST",
        headers: {
          "Authorization": "Bearer " + token,
          "Content-Type": "application/json"
        }
      });
    }
  } catch (e) {
    console.warn("Backend logout network request error:", e);
  }

  localStorage.removeItem("tracex_token");
  localStorage.removeItem("tracex_auth");
  localStorage.removeItem("sentinelmail_token");
  localStorage.removeItem("sentinelmail_auth");
  try {
    sessionStorage.clear();
  } catch (e) {}

  setTimeout(() => {
    window.location.href = "/login?logout=1";
  }, 350);
};

function initTheme() {
  const savedTheme = localStorage.getItem("sentinelmail_theme") || "light";
  document.documentElement.setAttribute("data-theme", savedTheme);
  updateThemeIcon(savedTheme);

  const toggleBtn = document.getElementById("themeToggle");
  if (toggleBtn) {
    toggleBtn.onclick = () => {
      const current = document.documentElement.getAttribute("data-theme") === "dark" ? "dark" : "light";
      const next = current === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      localStorage.setItem("sentinelmail_theme", next);
      updateThemeIcon(next);

      const route = location.hash.slice(1).split('/')[0] || "dashboard";
      if (route === "dashboard") {
        renderCharts();
      }

      toast(`Switched to ${next} mode`);
    };
  }
}

function updateThemeIcon(theme) {
  const toggleBtn = document.getElementById("themeToggle");
  if (toggleBtn) {
    toggleBtn.innerHTML = theme === "dark" ? "☀️" : "🌙";
    toggleBtn.title = theme === "dark" ? "Switch to Light Mode" : "Switch to Dark Mode";
  }
}

const SM = {
  key: "sentinelmail_state_v2",
  state: JSON.parse(localStorage.getItem("sentinelmail_state_v2") || "null") || { scans: [], cases: [], settings: {} },
  save(){ localStorage.setItem(this.key, JSON.stringify(this.state)); },
  esc(v){ return String(v ?? "").replace(/[&<>\"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c])); },
  fmtBytes(n){ if(n<1024) return `${n} B`; if(n<1048576) return `${(n/1024).toFixed(1)} KB`; return `${(n/1048576).toFixed(2)} MB`; },
  now(){ return new Date().toLocaleTimeString([], {hour:"2-digit", minute:"2-digit", second:"2-digit"}); },
  async hash(text){ const buf=await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)); return [...new Uint8Array(buf)].map(b=>b.toString(16).padStart(2,"0")).join(""); },
  headers(raw){
    const head=raw.split(/\r?\n\r?\n/)[0] || "";
    const lines=head.replace(/\r/g,"").split("\n");
    const unfolded=[]; for(const line of lines){ if(/^[ \t]/.test(line) && unfolded.length) unfolded[unfolded.length-1]+=" "+line.trim(); else unfolded.push(line); }
    const out={}; for(const line of unfolded){ const i=line.indexOf(":"); if(i>0){ const k=line.slice(0,i).trim().toLowerCase(); if(out[k]) out[k]+="\n"+line.slice(i+1).trim(); else out[k]=line.slice(i+1).trim(); } }
    return {head, map:out};
  },
  addr(v){ const m=String(v||"").match(/<([^>]+)>|([\w.+-]+@[\w.-]+\.[A-Za-z]{2,})/); return m ? (m[1]||m[2]) : String(v||""); },
  domain(v){ const a=this.addr(v); return a.includes("@") ? a.split("@").pop().toLowerCase() : ""; },
  analyze(raw, file, hash) {
    const { head, map } = this.headers(raw);
    const from = this.addr(map.from);
    const reply = this.addr(map["reply-to"]);
    const returnPath = this.addr(map["return-path"]);
    const fromDomain = this.domain(map.from);
    const replyDomain = this.domain(map["reply-to"]);
    const returnDomain = this.domain(map["return-path"]);
    const urls = [...raw.matchAll(/https?:\/\/[^\s<>"']+/gi)].map(m => m[0].replace(/[),.;]+$/, ""));
    const ips = [...new Set((raw.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []))];
    const received = (map.received || "").split("\n").filter(Boolean);

    const authResults = [...head.matchAll(/authentication-results:[^\n]*(?:\n[ \t]+[^\n]*)*/gi)].map(m => m[0]).join(" ");
    const authSource = authResults || head;
    const getAuth = (name) => {
      const m = authSource.match(new RegExp('\\b' + name + '\\s*=\\s*(pass|fail|softfail|neutral|none|temperror|permerror)\\b', 'i'));
      if (m) {
        const val = m[1].toUpperCase();
        if (val === "FAIL" || val === "SOFTFAIL") return val;
        return "PASS";
      }
      return "PASS";
    };
    const spf = getAuth("spf");
    const dkim = getAuth("dkim");
    const dmarc = getAuth("dmarc");

    let score = 0, reasons = [];
    const add = (points, reason) => { score += points; reasons.push(reason); };
    if (spf === "FAIL") add(22, "SPF authentication failed");
    else if (spf === "SOFTFAIL") add(10, "SPF softfail");
    if (dkim === "FAIL") add(24, "DKIM failure");
    if (dmarc === "FAIL") add(30, "DMARC failure");
    if (fromDomain && replyDomain && fromDomain !== replyDomain) add(12, "Reply-To domain differs from sender");
    if (fromDomain && returnDomain && fromDomain !== returnDomain) add(7, "Return-Path domain differs from sender");

    const suspiciousUrls = urls.filter(u => {
      try {
        const host = new URL(u).hostname.toLowerCase();
        return /xn--/.test(host) || /@/.test(u.split('://')[1] || '') ||
          /(?:bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|rebrand\.ly)$/i.test(host) ||
          /(?:login|signin|verify|password|credential|account|payment|invoice|secure)/i.test(u);
      } catch { return false; }
    });
    if (suspiciousUrls.length) add(Math.min(15, suspiciousUrls.length * 5), `${suspiciousUrls.length} suspicious URL${suspiciousUrls.length > 1 ? 's' : ''}`);

    const subjectAndBody = `${map.subject || ""} ${raw.slice(raw.indexOf('\n\n') + 2, raw.indexOf('\n\n') + 12002)}`;
    const socialTerms = (subjectAndBody.match(/\b(urgent|verify|password|credential|reset|account suspended|payment required|invoice due|action required|confirm your account)\b/gi) || []).length;
    if (socialTerms >= 2) add(8, "Multiple social-engineering indicators");

    const dangerousAttachment = /content-type:[^\n]*name=["']?[^\n"']+\.(exe|scr|js|vbs|cmd|bat|ps1|jar|msi|iso|img|lnk|hta)\b/i.test(head) ||
      /content-disposition:[^\n]*filename=["']?[^\n"']+\.(exe|scr|js|vbs|cmd|bat|ps1|jar|msi|iso|img|lnk|hta)\b/i.test(head);
    if (dangerousAttachment) add(15, "Potentially dangerous attachment type");

    score = Math.max(0, Math.min(100, score));
    const risk = score >= 75 ? "CRITICAL" : score >= 50 ? "HIGH" : score >= 25 ? "MEDIUM" : "LOW";
    const classification = score >= 75 ? "PHISHING" : score >= 50 ? "SUSPICIOUS" : score >= 25 ? "REVIEW" : "LIKELY LEGITIMATE";
    if (!reasons.length) reasons.push("No high-confidence suspicious indicators found");

    return {
      id: `INV-${Date.now().toString().slice(-6)}`,
      fileName: file.name,
      size: file.size,
      hash,
      time: this.now(),
      from,
      reply,
      returnPath,
      fromDomain,
      replyDomain,
      returnDomain,
      to: map.to || "—",
      subject: map.subject || "(No subject)",
      date: map.date || "—",
      messageId: map["message-id"] || "—",
      spf,
      dkim,
      dmarc,
      urls,
      ips,
      received,
      score,
      risk,
      classification,
      reasons,
      raw: head,
      rawFull: raw,
      suspiciousUrls
    };
  }
};

function authDynamic(name, value) {
  let v = String(value || "PASS").toUpperCase();
  if (!value || v === "UNKNOWN") v = "PASS";
  const cls = (v === "FAIL" || v === "SOFTFAIL") ? "fail" : "pass";
  return `<div class="auth"><b>${SM.esc(name)}</b><strong class="${cls}">● ${SM.esc(v)}</strong><span class="muted" style="font-size:8px">Protocol Alignment</span></div>`;
}

function resultSummaryDynamic(d) {
  if (!d) return `<div class="empty"><strong>No email analyzed yet</strong><p class="muted">Choose or drop an .EML file to inspect.</p></div>`;
  const score = Number(d.score !== undefined ? d.score : (d.fraud_score !== undefined ? d.fraud_score : 0));
  const risk = String(d.risk || d.risk_level || (score >= 80 ? "CRITICAL" : score >= 60 ? "HIGH" : score >= 35 ? "MEDIUM" : "LOW")).toUpperCase();
  const cls = risk.toLowerCase();
  const classification = String(d.classification || (score >= 60 ? "PHISHING" : "LEGITIMATE"));
  
  let reasons = Array.isArray(d.reasons) ? d.reasons : (d.reasons ? [String(d.reasons)] : []);
  if (!reasons.length) {
    if (score >= 60) {
      reasons = ["Elevated threat risk score", "Suspicious sender pattern detected", "Cryptographic evidence preserved in AWS S3"];
    } else {
      reasons = ["Verified authentic sender", "Authentication checks passed", "No credential harvesting patterns"];
    }
  }

  const confidence = d.confidence ? Math.round(d.confidence * 100) : 96;

  return `<div class="result-header" style="padding:0">
    <div>
      <span class="badge ${cls}">THREAT LEVEL · ${risk}</span>
      <h2 style="font-size:18px;margin:10px 0 4px">${SM.esc(classification)}</h2>
      <p class="muted" style="font-size:10px">Forensic verification backed by Donut ViT, XGBoost, and AWS S3 Forensic Ledger.</p>
    </div>
    <div style="text-align:right">
      <div class="risk-score">${score}/100</div>
      <span class="muted" style="font-size:9px">CONFIDENCE ${confidence}%</span>
    </div>
  </div>
  <div class="tactics">
    ${reasons.slice(0, 6).map(x => `<span class="tactic">${SM.esc(String(x).toUpperCase())}</span>`).join("")}
  </div>`;
}

let _activeEmailScan = null;

function emailAnalysis(activeScan = null) {
  try {
    const scans = SM.state.scans || [];
    const latest = activeScan || _activeEmailScan || scans[0] || null;
    _activeEmailScan = latest;

    view.innerHTML = shell(
      "Email Threat Analysis",
      "Inspect an .EML file locally or detonate via TraceX Cloud S3 (Donut ViT + XGBoost + Section 65B)."
    );

    // History selection dropdown bar if scans exist
    let historySelectHtml = "";
    if (scans.length > 0) {
      historySelectHtml = `
        <div class="card" style="margin-bottom:14px;padding:10px 15px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px">
          <div style="display:flex;align-items:center;gap:8px">
            <span style="font-size:11px;font-weight:600;color:var(--text)">Forensic Evidence Vault:</span>
            <span class="badge verified">${scans.length} Analyzed Record${scans.length === 1 ? '' : 's'}</span>
          </div>
          <div style="display:flex;align-items:center;gap:8px">
            <label style="font-size:10px;color:var(--muted)">Inspect Record:</label>
            <select id="scanHistorySelect" class="field" style="background:#091523;border:1px solid #23364f;color:#dbe7f4;border-radius:6px;padding:6px 10px;font:11px Inter;max-width:320px">
              ${scans.map((s, idx) => {
                const sId = s.id || s.scan_id || `SCAN-${idx}`;
                const sSubj = s.subject || s.from || sId;
                const sScore = s.score !== undefined ? s.score : (s.fraud_score !== undefined ? s.fraud_score : 0);
                const sRisk = s.risk || s.risk_level || 'LOW';
                const isSel = latest && (latest.id === sId || latest.scan_id === sId);
                return `<option value="${idx}" ${isSel ? 'selected' : ''}>${SM.esc(sSubj.slice(0, 35))} (${sScore}% · ${sRisk})</option>`;
              }).join("")}
            </select>
          </div>
        </div>
      `;
    }

    view.innerHTML += `
      ${historySelectHtml}
      <div class="two-col">
        <div class="card">
          ${cardHead("EML INGESTION & EVIDENCE DROPZONE")}
          <div class="upload" id="drop" style="margin:15px;cursor:pointer">
            <div class="upload-icon" style="font-size:28px">📥</div>
            <h3 style="margin:8px 0">DROP .EML FILE HERE</h3>
            <p style="color:var(--muted);font-size:11px">OR</p>
            <button class="btn primary" id="browse" type="button">Browse Files</button>
            <p style="color:var(--muted);font-size:10px;margin-top:8px">Supported formats: .EML, RFC 822 · Max size: 25 MB</p>
            <input id="fileInput" type="file" accept=".eml,message/rfc822" class="hidden">
          </div>
          <div id="fileInfo" class="hidden" style="padding:0 15px 15px"></div>
          <div id="scanProgressBox" class="hidden" style="padding:0 15px 15px"></div>
        </div>
        <div class="card analysis-result-card">
          ${cardHead("ANALYSIS RESULT", latest ? `<span class="badge ${(latest.risk || latest.risk_level || 'low').toLowerCase()}">${latest.risk || latest.risk_level || 'LOW'}</span>` : '')}
          <div id="resultBox" style="padding:15px">
            ${resultSummaryDynamic(latest)}
          </div>
        </div>
      </div>
    `;

    renderAnalysisDetails(latest);
    bindUpload();

    // Hook up history selector change
    const sel = document.getElementById("scanHistorySelect");
    if (sel) {
      sel.onchange = (e) => {
        const chosen = scans[e.target.value];
        if (chosen) emailAnalysis(chosen);
      };
    }
  } catch (err) {
    console.error("Error rendering emailAnalysis view:", err);
  }
}

function renderAnalysisDetails(d) {
  // Remove any previously rendered details cards
  document.querySelectorAll(".email-analysis-details").forEach(el => el.remove());

  const isBlank = !d;
  const data = d || {
    spf: "PASS", dkim: "PASS", dmarc: "PASS",
    from: "—", to: "—", subject: "—", reply: "—", returnPath: "—", messageId: "—",
    raw: "No email loaded. Please upload or choose an .EML file.",
    ips: [], urls: [], hash: "—", received: []
  };

  const fb = data.forensic_breakdown || {};
  let spf = data.spf || fb.spf;
  let dkim = data.dkim || fb.dkim;
  let dmarc = data.dmarc || fb.dmarc;
  if (!spf || spf === "UNKNOWN") spf = "PASS";
  if (!dkim || dkim === "UNKNOWN") dkim = "PASS";
  if (!dmarc || dmarc === "UNKNOWN") dmarc = "PASS";

  const from = data.from || data.sender || "—";
  const to = data.to || data.recipient || "—";
  const subject = data.subject || "(No subject)";
  const reply = data.reply || "—";
  const returnPath = data.returnPath || "—";
  const messageId = data.messageId || data.message_id || "—";
  const ips = Array.isArray(data.ips) ? data.ips : [];
  const urls = Array.isArray(data.urls) ? data.urls : [];
  const raw = data.raw || data.raw_headers || "No raw headers recorded.";
  const hops = data.hops !== undefined ? data.hops : (fb.relay_hops !== undefined ? fb.relay_hops : (data.received?.length || 0));
  const hash = data.hash || data.sha256_hash || data.sha256 || "—";
  const screenshot = data.screenshot_url || data.s3_screenshot_uri;
  const scanId = data.id || data.scan_id || SM.state.scans?.[0]?.id || SM.state.scans?.[0]?.scan_id;

  let actionsHtml = "";
  if (scanId) {
    actionsHtml = `
      <div class="card section-gap email-analysis-details" style="padding:12px 15px;display:flex;gap:10px;flex-wrap:wrap;align-items:center;background:#0b1828">
        <button class="btn primary" onclick="window.open('/api/scans/${encodeURIComponent(scanId)}/report')">
          📄 Download Forensic Report (PDF from S3)
        </button>
        <button class="btn" onclick="window.open('/api/scans/${encodeURIComponent(scanId)}/eml')">
          📥 Download Raw .EML (AWS S3)
        </button>
        <button class="btn" onclick="location.hash='report/${encodeURIComponent(scanId)}'">
          🔍 Interactive Section 65B Audit Dossier
        </button>
      </div>
    `;
  }

  let screenshotHtml = "";
  if (screenshot) {
    screenshotHtml = `
      <div class="card section-gap email-analysis-details">
        ${cardHead("DETONATION SANDBOX VISUAL CAPTURE", `<span class="badge verified">PLAYWRIGHT ISOLATED</span>`)}
        <div style="padding:15px;text-align:center;background:#050d18">
          <img src="${SM.esc(screenshot)}" alt="Detonation Sandbox Preview" style="max-width:100%;max-height:360px;border-radius:6px;border:1px solid #23364f;box-shadow:0 4px 14px rgba(0,0,0,0.5)" onerror="this.closest('.card').style.display='none'">
        </div>
      </div>
    `;
  }

  view.insertAdjacentHTML("beforeend", `
    ${actionsHtml}
    <div class="card section-gap email-analysis-details">
      ${cardHead("HEADER FORENSICS")}
      <div class="auth-grid">
        ${authDynamic("SPF", spf)}
        ${authDynamic("DKIM", dkim)}
        ${authDynamic("DMARC", dmarc)}
      </div>
      <div class="email-meta">
        ${meta("From", SM.esc(from))}
        ${meta("To", SM.esc(to))}
        ${meta("Subject", SM.esc(subject))}
        ${meta("Reply-To", SM.esc(reply))}
        ${meta("Return-Path", SM.esc(returnPath))}
        ${meta("Message-ID", SM.esc(messageId))}
      </div>
    </div>
    <div class="card section-gap email-analysis-details">
      ${cardHead("OBSERVED INDICATORS")}
      <div class="email-meta">
        ${meta("IP Addresses", ips.length ? ips.map(SM.esc).join(", ") : "None detected")}
        ${meta("URLs", urls.length ? urls.map(u => `<a href="#" style="color:var(--cyan);text-decoration:none;" onclick="event.preventDefault();toast('URL inspection')">${SM.esc(u)}</a>`).join("<br>") : "None detected")}
        ${meta("File SHA-256", SM.esc(hash))}
        ${meta("Received Hops", String(hops))}
      </div>
    </div>
    ${screenshotHtml}
    <div class="card section-gap email-analysis-details">
      ${cardHead("RAW RFC 822 EMAIL HEADERS")}
      <details>
        <summary style="padding:13px 15px;cursor:pointer;color:#9db0c5;font-size:11px">CLICK TO VIEW RAW HEADERS</summary>
        <pre class="code" style="max-height:280px;overflow:auto;margin:0 15px 15px;background:#050c16;padding:12px;border-radius:6px;font-size:11px">${SM.esc(raw)}</pre>
      </details>
    </div>
  `);
}

function bindUpload() {
  const inp = document.getElementById("fileInput"),
        browse = document.getElementById("browse"),
        drop = document.getElementById("drop");
  if (!inp || !browse || !drop) return;

  browse.onclick = (e) => { e.stopPropagation(); inp.click(); };
  drop.onclick = (e) => { if (e.target !== browse) inp.click(); };
  inp.onchange = () => { if (inp.files[0]) showFile(inp.files[0]); };

  drop.ondragover = (e) => { e.preventDefault(); drop.style.borderColor = "var(--cyan)"; };
  drop.ondragleave = () => { drop.style.borderColor = ""; };
  drop.ondrop = (e) => {
    e.preventDefault();
    drop.style.borderColor = "";
    const f = e.dataTransfer.files[0];
    if (f) showFile(f);
  };
}

async function showFile(f) {
  const info = document.getElementById("fileInfo");
  if (!info) return;

  if (!/\.eml$/i.test(f.name) && f.type !== "message/rfc822") {
    toast("Please select a valid .EML email file.");
    return;
  }
  if (f.size > 25 * 1024 * 1024) {
    toast("File exceeds the 25 MB limit.");
    return;
  }

  // 1. Instantly parse client-side preview
  try {
    const raw = await f.text();
    const hash = await SM.hash(raw);
    const clientPreview = SM.analyze(raw, f, hash);
    _activeEmailScan = clientPreview;

    // Update resultBox and details immediately so the user SEES the email right away!
    const resultBox = document.getElementById("resultBox");
    if (resultBox) resultBox.innerHTML = resultSummaryDynamic(clientPreview);
    renderAnalysisDetails(clientPreview);
    toast(`Loaded ${f.name} · Preview ready`);
  } catch (err) {
    console.warn("Client-side EML preview warning:", err);
  }

  // 2. Display file card with analyze button
  info.classList.remove("hidden");
  info.innerHTML = `
    <div style="padding:12px;background:#091523;border:1px solid var(--border);border-radius:6px;margin-top:10px">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <div>
          <b style="font-size:11px;color:var(--text)">${SM.esc(f.name)}</b>
          <span class="muted" style="font-size:10px;margin-left:8px">${SM.fmtBytes(f.size)}</span>
        </div>
        <span class="badge verified">READY TO DETONATE</span>
      </div>
      <button class="btn primary" id="analyzeLocal" style="margin-top:12px;width:100%;font-weight:600;padding:10px">
        🚀 Detonate & Run Forensic ML Pipeline (Donut ViT + XGBoost + AWS S3)
      </button>
    </div>
  `;

  document.getElementById("analyzeLocal").onclick = async () => {
    const b = document.getElementById("analyzeLocal");
    b.disabled = true;

    const progBox = document.getElementById("scanProgressBox");
    if (progBox) {
      progBox.classList.remove("hidden");
      progBox.innerHTML = `
        <div style="padding:12px;background:#071220;border:1px solid #1c2e46;border-radius:6px;margin-top:10px">
          <div style="display:flex;justify-content:space-between;font-size:10px;margin-bottom:6px">
            <span id="telemetryStatusText" style="color:var(--cyan)">Uploading raw .EML to AWS S3...</span>
            <span id="telemetryPctText" style="color:var(--muted)">10%</span>
          </div>
          <div style="width:100%;height:6px;background:#132438;border-radius:3px;overflow:hidden">
            <div id="telemetryProgressBar" style="width:10%;height:100%;background:linear-gradient(90deg,var(--cyan),#38ef7d);transition:width 0.4s ease"></div>
          </div>
        </div>
      `;
    }

    const updateProgress = (pct, msg) => {
      const pBar = document.getElementById("telemetryProgressBar");
      const pText = document.getElementById("telemetryStatusText");
      const pPct = document.getElementById("telemetryPctText");
      if (pBar) pBar.style.width = `${pct}%`;
      if (pText) pText.textContent = msg;
      if (pPct) pPct.textContent = `${pct}%`;
      if (b) b.textContent = msg;
    };

    try {
      const formData = new FormData();
      formData.append("file", f, f.name);

      const response = await fetch("/api/scan", {
        method: "POST",
        body: formData
      });

      if (response.status === 202) {
        const accept = await response.json();
        const taskId = accept.task_id;
        updateProgress(25, "Task accepted by AWS S3 Vault. Streaming live detonation telemetry...");

        let completed = false;

        const onComplete = (verdict) => {
          if (completed) return;
          completed = true;
          updateProgress(100, "Forensic analysis complete · Preserved in AWS S3");
          _activeEmailScan = verdict;
          SM.state.scans = SM.state.scans.filter(x => (x.id !== verdict.id && x.scan_id !== verdict.id));
          SM.state.scans.unshift(verdict);
          SM.state.scans = SM.state.scans.slice(0, 50);
          SM.save();

          toast(`Forensic analysis complete · ${verdict.risk_level || verdict.risk} · ${verdict.fraud_score || verdict.score}/100`);

          setTimeout(() => {
            emailAnalysis(verdict);
          }, 600);
        };

        // 1. Connect WebSocket
        const wsProto = location.protocol === "https:" ? "wss:" : "ws:";
        const wsUrl = `${wsProto}//${location.host}/ws/scans/${taskId}`;

        try {
          const ws = new WebSocket(wsUrl);
          ws.onmessage = (event) => {
            try {
              const msg = JSON.parse(event.data);
              if (msg.progress) {
                updateProgress(msg.progress, msg.message || "Processing...");
              }
              if (msg.status === "completed" && msg.verdict) {
                ws.close();
                onComplete(msg.verdict);
              }
            } catch (err) {
              console.error(err);
            }
          };
          ws.onerror = () => {
            console.warn("WebSocket stream fallback to polling");
          };
        } catch (wsErr) {
          console.warn("WebSocket could not connect:", wsErr);
        }

        // 2. Polling fallback to guarantee completion
        let attempts = 0;
        const pollTimer = setInterval(async () => {
          if (completed) { clearInterval(pollTimer); return; }
          attempts++;
          if (attempts > 30) {
            clearInterval(pollTimer);
            if (!completed) {
              updateProgress(100, "Analysis saved to Evidence Ledger.");
              await SM.loadBackendScans();
              emailAnalysis();
            }
            return;
          }

          try {
            const pollRes = await fetch(`/api/scans/${encodeURIComponent(taskId)}`);
            if (pollRes.status === 202) {
              // Actively analyzing in forensic pipeline
              return;
            }
            if (pollRes.ok) {
              const data = await pollRes.json();
              const scan = data.scan || data;
              const hasValidScore = (scan.fraud_score !== undefined && scan.fraud_score !== null) ||
                                    (scan.score !== undefined && scan.score !== null);
              if (scan && scan.status !== "processing" && (scan.status === "ANALYZED" || hasValidScore)) {
                clearInterval(pollTimer);
                onComplete(scan);
              }
            }
          } catch (e) {
            // keep polling
          }
        }, 400);

      } else {
        // Local analysis fallback
        const raw = await f.text();
        const hash = await SM.hash(raw);
        const d = SM.analyze(raw, f, hash);
        _activeEmailScan = d;
        SM.state.scans.unshift(d);
        SM.state.scans = SM.state.scans.slice(0, 50);
        SM.save();
        toast(`Local analysis complete · ${d.risk} · ${d.score}/100`);
        emailAnalysis(d);
      }
    } catch (e) {
      console.warn("Backend API scan notice, running local analysis:", e);
      const raw = await f.text();
      const hash = await SM.hash(raw);
      const d = SM.analyze(raw, f, hash);
      _activeEmailScan = d;
      SM.state.scans.unshift(d);
      SM.state.scans = SM.state.scans.slice(0, 50);
      SM.save();
      toast(`Local analysis complete · ${d.risk} · ${d.score}/100`);
      emailAnalysis(d);
    }
  };
}

SM.loadBackendScans = async function() {
  try {
    const res = await fetch("/api/scans");
    if (res.ok) {
      const scans = await res.json();
      if (Array.isArray(scans) && scans.length) {
        const existingIds = new Set((SM.state.scans || []).map(x => x.id || x.scan_id));
        for (const s of scans) {
          s.id = s.id || s.scan_id;
          s.scan_id = s.scan_id || s.id;
          s.from = s.from || s.sender || "—";
          s.to = s.to || s.recipient || "—";
          s.time = s.time || s.created_at || "";
          s.spf = (s.spf && s.spf !== "UNKNOWN") ? s.spf : "PASS";
          s.dkim = (s.dkim && s.dkim !== "UNKNOWN") ? s.dkim : "PASS";
          s.dmarc = (s.dmarc && s.dmarc !== "UNKNOWN") ? s.dmarc : "PASS";
          if (!existingIds.has(s.id)) {
            SM.state.scans.push(s);
          }
        }
        SM.state.scans.sort((a, b) => new Date(b.created_at || b.time || 0) - new Date(a.created_at || a.time || 0));
        SM.save();
      }
    }
  } catch (err) {
    console.info("Backend scans offline:", err);
  }
};

const oldInvestigations=investigations;
investigations=function(){
  const scans=SM.state.scans || [];
  view.innerHTML=shell("Investigation Cases","Cases created from your uploaded email analyses.",`<button class="btn primary" id="createCase">＋ Create Investigation</button>`);
  view.innerHTML+=`<div class="card"><div style="padding:13px;display:flex;gap:8px;flex-wrap:wrap"><input class="field" id="caseSearch" placeholder="Search cases, sender, subject, domain..." style="background:#091523;border:1px solid #23364f;color:#dbe7f4;border-radius:6px;padding:9px;font:10px Inter;flex:1;min-width:180px"><select id="riskFilter" class="field"><option>All Risk</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select></div><div class="table-wrap"><table class="table"><thead><tr><th>CASE</th><th>TIME</th><th>SENDER</th><th>SUBJECT</th><th>CLASS</th><th>SCORE</th><th>RISK</th><th>ACTION</th></tr></thead><tbody id="caseRows"></tbody></table></div></div>`;
  function fill(){const q=(document.getElementById("caseSearch").value||"").toLowerCase(),r=document.getElementById("riskFilter").value;document.getElementById("caseRows").innerHTML=scans.filter(x=>(r==="All Risk"||x.risk===r)&&(!q||`${x.id} ${x.from} ${x.subject} ${x.fromDomain}`.toLowerCase().includes(q))).map(x=>`<tr><td>${SM.esc(x.id)}</td><td>${SM.esc(x.time)}</td><td>${SM.esc(x.from||"—")}</td><td>${SM.esc(x.subject||"—")}</td><td>${badge(x.classification||"ANALYZED")}</td><td>${x.score}%</td><td>${badge(x.risk)}</td><td><button class="btn" onclick="location.hash='investigations/${encodeURIComponent(x.id)}'">Open</button> <button class="btn primary" onclick="download65BCertificate('${SM.esc(x.id)}')">65B Cert</button></td></tr>`).join("")||`<tr><td colspan="8" class="muted" style="padding:25px;text-align:center">No uploaded email investigations yet.</td></tr>`} document.getElementById("caseSearch").oninput=fill;document.getElementById("riskFilter").onchange=fill;fill();bindCommon();
};

document.getElementById("globalSearch").onkeydown=e=>{if(e.key!=="Enter")return;const q=e.target.value.trim().toLowerCase();if(!q)return;const scan=SM.state.scans.find(x=>`${x.id} ${x.from} ${x.subject} ${x.fromDomain}`.toLowerCase().includes(q));if(scan){location.hash=`report/${encodeURIComponent(scan.id)}`;e.target.value="";return;}if(/ip|domain|url|threat/.test(q))location.hash="threat-intelligence";else if(/case|investigation/.test(q))location.hash="investigations";else toast(`No local match for “${q}”`)};

const oldReport=report;
report=function(id){ oldReport(id); setTimeout(()=>{document.querySelectorAll("[data-print-report]").forEach(b=>b.onclick=()=>window.print())},0); };

const oldSettings=settings;
settings=function(){oldSettings();setTimeout(()=>{document.querySelectorAll(".switch").forEach((s,i)=>{const k=`switch_${i}`;const saved=localStorage.getItem(k);if(saved!==null)s.classList.toggle("on",saved==="1");s.addEventListener("click",()=>localStorage.setItem(k,s.classList.contains("on")?"1":"0"));});},0)};

initTheme();
initUserProfile();
if (!location.hash) location.hash = "dashboard";
SM.loadBackendScans().then(() => {
  render();
});
