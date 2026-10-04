
const isLocal =
  window.location.hostname === "localhost" ||
  window.location.hostname === "127.0.0.1";

const API_URL = isLocal
  ? "http://127.0.0.1:8000"
  : "https://aegis-4lcw.onrender.com";
function getUser(){
  try { return JSON.parse(localStorage.getItem("aegisUser") || "null"); }
  catch(e){ return null; }
}
function getUID(){
  const u=getUser(); return u ? Number(u.id ?? u.user_id ?? u.userId) : null;
}
function requireAuth(){
  if(!getUser()) location.href="login.html";
}
function logout(){
  localStorage.removeItem("aegisUser");
  localStorage.removeItem("aegisUserId");
  location.href="login.html";
}
function esc(v){
  return String(v ?? "").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[c]));
}
function severityBadge(v){
  const x=String(v||"Low").toLowerCase();
  const cls=x==="critical"?"critical":x==="high"?"high":x==="medium"?"medium":x==="low"?"low":"safe";
  return `<span class="badge ${cls}">${esc(v||"Low")}</span>`;
}
function paintUser(){
  const u=getUser(); if(!u) return;
  document.querySelectorAll("[data-name]").forEach(e=>e.textContent=u.name||"User");
  document.querySelectorAll("[data-email]").forEach(e=>e.textContent=u.email||"");
  document.querySelectorAll("[data-role]").forEach(e=>e.textContent=String(u.role||"user").toLowerCase()==="admin"?"Administrator":"User");
  const name=u.name||"User";
  document.querySelectorAll("[data-avatar]").forEach(e=>e.textContent=(name[0]||"U").toUpperCase());
}
function setActive(){
  const current=location.pathname.split("/").pop() || "index.html";
  document.querySelectorAll(".side-nav a[data-page]").forEach(a=>{
    a.classList.toggle("active",a.dataset.page===current);
  });
}
function initShell(){
  paintUser(); setActive();
  const menu=document.querySelector(".mobile-menu");
  const side=document.querySelector(".sidebar");
  if(menu && side) menu.onclick=()=>side.classList.toggle("open");
  const close=()=>side&&side.classList.remove("open");
  document.querySelectorAll(".side-nav a").forEach(a=>a.addEventListener("click",close));
  const search=document.getElementById("globalSearch");
  if(search) search.addEventListener("keydown",e=>{
    if(e.key==="Enter"){
      const q=search.value.trim().toLowerCase();
      if(!q)return;
      const map={url:"url-scanner.html",scan:"url-scanner.html",email:"email-analyzer.html",incident:"report-threat.html",report:"report-threat.html",alert:"alerts.html",assistant:"security-assistant.html",monitor:"security-monitor.html",setting:"settings.html"};
      const hit=Object.keys(map).find(k=>q.includes(k));
      if(hit) location.href=map[hit];
    }
  });
}
function notify(text,kind="success"){
  const e=document.getElementById("notice");
  if(!e)return;
  e.textContent=text;e.className="notice show "+kind;
}


/* =========================================================
   AEGIS PAGE CONTROLLERS
   These controllers keep the existing HTML/UI and connect
   each page to the REST backend.
   ========================================================= */

async function apiJSON(path, options = {}) {
  const r = await fetch(API_URL + path, options);
  let d = {};
  try { d = await r.json(); } catch (_) {}
  if (!r.ok) throw new Error(d.detail || d.message || `Request failed (${r.status})`);
  return d;
}

function firstArray(obj, keys = []) {
  if (Array.isArray(obj)) return obj;
  for (const k of keys) {
    if (Array.isArray(obj?.[k])) return obj[k];
  }
  return [];
}

function firstNumber(obj, keys = [], fallback = 0) {
  for (const k of keys) {
    const n = Number(obj?.[k]);
    if (Number.isFinite(n)) return n;
  }
  return fallback;
}

function riskLevel(v) {
  return String(v ?? "").toLowerCase();
}

function dateLabel() {
  return new Intl.DateTimeFormat(undefined, {
    weekday: "long", year: "numeric", month: "long", day: "numeric"
  }).format(new Date());
}

/* ---------- Dashboard ---------- */
async function loadDashboard() {
  requireAuth();
  initShell();

  const u = getUser();
  const nameEl = document.getElementById("heroName");
  const dateEl = document.getElementById("dateText");
  if (nameEl) nameEl.textContent = u?.name || "User";
  if (dateEl) dateEl.textContent = dateLabel();

  try {
    const d = await apiJSON("/dashboard/overview");

    const overview = d.overview || d.dashboard || d;
    const threats = firstArray(overview, ["recent_threats","threats","recentThreats"]);
    const activity = firstArray(overview, ["activity","audit_activity","recent_activity","recentActivity"]);
    const alerts = firstArray(overview, ["alerts","security_alerts","securityAlerts"]);

    const total = firstNumber(overview, ["total_threats","totalThreats","threat_count"], threats.length);
    const high = firstNumber(overview, ["high_risk_urls","highRisk","high_risk"], 
      threats.filter(x => ["high","critical"].includes(riskLevel(x.risk_level ?? x.severity))).length);
    const safe = firstNumber(overview, ["safe_urls","safeUrls","safe_count"],
      threats.filter(x => ["low","safe","minimal"].includes(riskLevel(x.risk_level ?? x.severity))).length);
    const failed = firstNumber(overview, ["failed_logins","failedLogins"], 0);

    const score = firstNumber(overview, ["security_score","securityScore","score"], 
      Math.max(0, Math.min(100, 100 - Math.min(100, high * 5))));

    const setText = (id, value) => {
      const e = document.getElementById(id);
      if (e) e.textContent = value;
    };

    setText("totalThreats", total);
    setText("highRisk", high);
    setText("safeUrls", safe);
    setText("failedLogins", failed);
    setText("donutTotal", firstNumber(overview, ["url_scans","urlScans","total_url_scans"], total));
    setText("scoreNumber", `${Math.round(score)}%`);
    setText("scoreStatus", score >= 80 ? "Healthy" : score >= 50 ? "Watch" : "At risk");
    setText("heroStatus", score >= 80 ? "Protected" : score >= 50 ? "Monitoring" : "Attention needed");
    setText("scoreNote", overview.security_score_note || "Calculated from current AEGIS activity.");

    const ring = document.getElementById("scoreRing");
    if (ring) ring.style.setProperty("--score", Math.max(0, Math.min(100, score)));

    const levels = [
      ["Critical", firstNumber(overview, ["critical","critical_count"], threats.filter(x => riskLevel(x.risk_level ?? x.severity)==="critical").length), "critical"],
      ["High", high, "high"],
      ["Medium", firstNumber(overview, ["medium","medium_count"], threats.filter(x => riskLevel(x.risk_level ?? x.severity)==="medium").length), "medium"],
      ["Low / Safe", safe, "safe"]
    ];
    const totalURL = levels.reduce((a,x) => a + Number(x[1] || 0), 0);

    const donut = document.getElementById("donut");
    if (donut) {
      const values = levels.map(x => Number(x[1] || 0));
      const colors = ["var(--critical)","var(--high)","var(--medium)","var(--safe)"];
      let start = 0;
      const stops = [];
      values.forEach((v,i) => {
        const end = totalURL ? start + (v / totalURL) * 360 : start;
        stops.push(`${colors[i]} ${start}deg ${end}deg`);
        start = end;
      });
      donut.style.background = totalURL
        ? `conic-gradient(${stops.join(",")})`
        : "conic-gradient(var(--line) 0deg 360deg)";
    }

    const legend = document.getElementById("legend");
    if (legend) {
      legend.innerHTML = levels.map(([label,value,cls]) =>
        `<div class="legend-row"><span class="legend-dot ${cls}" style="background:currentColor"></span><span>${esc(label)}</span><span>${Number(value || 0)}</span></div>`
      ).join("");
    }

    const bars = document.getElementById("bars");
    if (bars) {
      const max = Math.max(1, ...levels.map(x => Number(x[1] || 0)));
      bars.innerHTML = levels.map(([label,value,cls]) =>
        `<div class="bar-col"><div class="bar-stack"><div class="bar-seg ${cls}" style="height:${Math.max(3,(Number(value||0)/max)*100)}%"></div></div><div class="bar-label">${esc(label)}</div></div>`
      ).join("");
    }

    const alertBox = document.getElementById("alerts");
    if (alertBox) {
      alertBox.innerHTML = alerts.slice(0,5).map(x =>
        `<div class="alert"><div class="alert-icon">!</div><div><div class="alert-title">${esc(x.title || x.type || x.threat_type || "Security alert")}</div><div class="alert-desc">${esc(x.description || x.message || x.recommendation || "Review this security event.")}</div></div>${severityBadge(x.severity || x.risk_level || "Medium")}</div>`
      ).join("") || `<div class="empty">No active alerts.</div>`;
    }

    const rows = document.getElementById("threatRows");
    if (rows) {
      rows.innerHTML = threats.slice(0,12).map(x => {
        const sev = x.severity || x.risk_level || "Low";
        return `<tr><td>${esc(x.id ?? x.scan_id ?? "—")}</td><td>${esc(x.type || x.threat_type || "URL")}</td><td title="${esc(x.target || x.url || x.description || "")}">${esc(String(x.target || x.url || x.description || "—").slice(0,55))}</td><td>${severityBadge(sev)}</td><td>${esc(x.status || "Analyzed")}</td></tr>`;
      }).join("") || `<tr><td colspan="5" class="empty">No recent threats.</td></tr>`;
    }
    setText("threatCountLabel", `${threats.length} records`);

    const act = document.getElementById("activity");
    if (act) {
      act.innerHTML = activity.slice(0,10).map(x =>
        `<div class="activity"><div class="activity-icon">${x.success === false ? "!" : "✓"}</div><div class="activity-main"><div class="activity-title">${esc(x.action || x.title || x.event || "Security activity")}</div><div class="activity-meta">${esc(x.details || x.description || x.created_at || x.time || "")}</div></div></div>`
      ).join("") || `<div class="empty">No recent activity.</div>`;
    }
  } catch (e) {
    const status = document.getElementById("heroStatus");
    if (status) status.textContent = "Backend unavailable";
    notify("Dashboard data could not be loaded. Check that the AEGIS backend is running.", "error");
  }
}

/* ---------- Email Analyzer ---------- */
async function analyze() {
  requireAuth();
  const input = document.getElementById("file");
  const notice = document.getElementById("notice");
  const summary = document.getElementById("summary");
  const links = document.getElementById("links");
  const btn = document.getElementById("emailBtn");

  if (!input?.files?.length) {
    notify("Choose an .eml file first.", "error");
    return;
  }

  const file = input.files[0];
  if (!file.name.toLowerCase().endsWith(".eml")) {
    notify("Only .eml files are supported.", "error");
    return;
  }
  if (file.size > 10 * 1024 * 1024) {
    notify("The email file must be 10 MB or smaller.", "error");
    return;
  }

  const fd = new FormData();
  fd.append("file", file);
  fd.append("user_id", String(getUID()));

  btn.disabled = true;
  btn.textContent = "Analyzing…";

  try {
    let d;
    const candidates = ["/analyze-email", "/email-analyzer", "/analyze-email-file"];
    let lastError;
    for (const endpoint of candidates) {
      try {
        d = await apiJSON(endpoint, { method:"POST", body:fd });
        break;
      } catch (e) { lastError = e; }
    }
    if (!d) throw lastError || new Error("Email analysis endpoint is unavailable.");

    const x = d.result || d;
    const found = firstArray(x, ["links","urls","extracted_urls","extractedUrls"]);
    const risk = x.risk_level || x.risk || x.severity || "Unknown";

    summary.style.display = "block";
    summary.innerHTML = `
      <div class="section-title"><h2>Analysis Result</h2>${severityBadge(risk)}</div>
      <div class="kpi-grid" style="margin-top:12px">
        <div class="kpi"><div class="label">Risk score</div><div class="value">${esc(x.risk_score ?? x.score ?? "—")}</div></div>
        <div class="kpi"><div class="label">URLs extracted</div><div class="value">${found.length}</div></div>
        <div class="kpi"><div class="label">Recommendation</div><div class="value" style="font-size:13px">${esc(x.recommendation || x.explanation || "Review the detected indicators.")}</div></div>
      </div>`;
    links.innerHTML = found.length
      ? `<section class="card"><div class="section-title"><h2>Extracted URLs</h2></div><div class="table-wrap"><table class="threat-table"><thead><tr><th>URL</th><th>Risk</th></tr></thead><tbody>${found.map(u => {
          const url = typeof u === "string" ? u : (u.url || u.link || "");
          return `<tr><td>${esc(url)}</td><td>${severityBadge(typeof u === "object" ? (u.risk_level || u.severity || "Unknown") : "Unknown")}</td></tr>`;
        }).join("")}</tbody></table></div></section>`
      : `<section class="card"><div class="empty">No URLs were extracted from this email.</div></section>`;
    notify("Email analysis completed.", "success");
  } catch (e) {
    notify(e.message || "Email analysis failed.", "error");
  } finally {
    btn.disabled = false;
    btn.textContent = "Analyze email";
  }
}

/* ---------- Incident Alerts ---------- */
async function loadAlerts() {
  requireAuth();
  initShell();
  const rows = document.getElementById("rows");
  try {
    const uid = getUID();
    const candidates = [`/threat-reports/${uid}`, `/incident-reports/${uid}`, `/reports/user/${uid}`];
    let d, last;
    for (const endpoint of candidates) {
      try { d = await apiJSON(endpoint); break; } catch(e) { last = e; }
    }
    if (!d) throw last || new Error("Incident report endpoint is unavailable.");
    const reports = firstArray(d, ["reports","incident_reports","incidentReports","data"]);
    rows.innerHTML = reports.map(x =>
      `<tr><td>${esc(x.id ?? x.report_id ?? "—")}</td><td>${esc(x.threat_type || x.type || x.category || "—")}</td><td>${severityBadge(x.severity || "Low")}</td><td>${esc(x.status || "Open")}</td><td>${esc(x.description || "—")}</td></tr>`
    ).join("") || `<tr><td colspan="5" class="empty">No incident reports found.</td></tr>`;
  } catch (e) {
    rows.innerHTML = `<tr><td colspan="5" class="empty">${esc(e.message || "Unable to load incident reports.")}</td></tr>`;
  }
}

/* ---------- Administrator ---------- */
async function loadAdmin() {
  requireAuth();
  initShell();
  if (String(getUser()?.role || "").toLowerCase() !== "admin") {
    location.href = "dashboard.html";
    return;
  }

  const stats = document.getElementById("adminStats");
  const reportsEl = document.getElementById("reports");

  try {
    const candidates = ["/admin/reports", "/threat-reports", "/incident-reports"];
    let d, last;
    for (const endpoint of candidates) {
      try { d = await apiJSON(endpoint); break; } catch(e) { last = e; }
    }
    if (!d) throw last || new Error("Administrator report endpoint is unavailable.");

    const reports = firstArray(d, ["reports","incident_reports","incidentReports","data"]);
    const open = reports.filter(x => !["closed","resolved"].includes(String(x.status || "").toLowerCase())).length;
    const critical = reports.filter(x => riskLevel(x.severity) === "critical").length;

    stats.innerHTML = [
      ["Total reports", reports.length],
      ["Open reports", open],
      ["Critical", critical]
    ].map(x => `<div class="kpi"><div class="label">${esc(x[0])}</div><div class="value">${x[1]}</div></div>`).join("");

    reportsEl.innerHTML = reports.map(x => {
      const id = x.id ?? x.report_id;
      const status = String(x.status || "Open");
      return `<tr>
        <td>${esc(id ?? "—")}</td>
        <td>${esc(x.threat_type || x.type || x.category || "—")}</td>
        <td>${severityBadge(x.severity || "Low")}</td>
        <td>${esc(status)}</td>
        <td><select onchange="updateReportStatus('${esc(id)}',this.value)">
          ${["Open","Investigating","Assigned","Resolved","Closed"].map(s => `<option ${s.toLowerCase()===status.toLowerCase()?"selected":""}>${s}</option>`).join("")}
        </select></td>
      </tr>`;
    }).join("") || `<tr><td colspan="5" class="empty">No incident reports.</td></tr>`;
  } catch (e) {
    reportsEl.innerHTML = `<tr><td colspan="5" class="empty">${esc(e.message || "Unable to load administrator reports.")}</td></tr>`;
    notify("Administrator data could not be loaded.", "error");
  }
}

async function updateReportStatus(id, status) {
  try {
    const payload = JSON.stringify({ status });
    const endpoints = [
      `/admin/reports/${encodeURIComponent(id)}/status`,
      `/threat-reports/${encodeURIComponent(id)}`,
      `/incident-reports/${encodeURIComponent(id)}`
    ];
    let done = false, last;
    for (const endpoint of endpoints) {
      try {
        await apiJSON(endpoint, {method:"PATCH", headers:{"Content-Type":"application/json"}, body:payload});
        done = true; break;
      } catch(e) { last = e; }
    }
    if (!done) throw last || new Error("Status update endpoint is unavailable.");
    notify("Incident status updated.", "success");
    loadAdmin();
  } catch (e) {
    notify(e.message || "Status update failed.", "error");
    loadAdmin();
  }
}

/* Keep existing onclick="load()" buttons working on the pages
   that originally expected a page-local load function. */
window.load = function() {
  const page = location.pathname.split("/").pop();
  if (page === "dashboard.html") return loadDashboard();
  if (page === "alerts.html") return loadAlerts();
  if (page === "admin.html") return loadAdmin();
  if (page === "security-monitor.html") return window.__aegisMonitorLoad?.();
};

document.addEventListener("DOMContentLoaded", () => {
  const page = location.pathname.split("/").pop();

  if (page === "dashboard.html") loadDashboard();
  else if (page === "alerts.html") loadAlerts();
  else if (page === "admin.html") loadAdmin();
  else if (page === "email-analyzer.html") { requireAuth(); initShell(); }
  else if (page === "url-scanner.html") { requireAuth(); initShell(); }
  else if (page === "report-threat.html") { requireAuth(); initShell(); }
  else if (page === "security-assistant.html") { requireAuth(); initShell(); }
  else if (page === "settings.html") { requireAuth(); initShell(); }
});
