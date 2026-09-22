if (!api.token()) window.location.href = "index.html";

const severityLabel = { critical: "Critique", high: "Élevée", medium: "Moyenne", low: "Faible" };
const vulnStatusLabel = { open: "Ouverte", in_progress: "En cours", fixed: "Corrigée", false_positive: "Faux positif" };
let currentScanId = null;
const severityColor = { critical: "#a32d2d", high: "#854f0b", medium: "#854f0b", low: "#185fa5" };
const statusLabel = { running: "En cours", done: "Terminé", failed: "Échoué", pending: "En attente" };

function identifierBadge(v) {
  if (v.cve_id) {
    return `<span style="font-family:var(--mono); font-size:10px; background:rgba(163,45,45,0.12); color:var(--danger); padding:1px 6px; border-radius:4px; margin-right:5px;">CVE</span><span class="cve-tag">${v.cve_id}</span>`;
  }
  if (v.cwe_id) {
    return `<span style="font-family:var(--mono); font-size:10px; background:rgba(24,95,165,0.12); color:var(--accent); padding:1px 6px; border-radius:4px; margin-right:5px;">CWE</span><span class="cve-tag">${v.cwe_id}</span>`;
  }
  return `<span style="color:var(--text-muted);">—</span>`;
}

function fmtDate(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleDateString("fr-FR", { day: "2-digit", month: "short", year: "numeric" });
}
function fmtDateTime(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString("fr-FR", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" });
}
function fmtDuration(startIso, endIso) {
  if (!startIso || !endIso) return "—";
  const seconds = Math.round((new Date(endIso) - new Date(startIso)) / 1000);
  if (seconds < 60) return `${seconds}s`;
  return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
}

// ============ GROUPES DE CASES À COCHER À CHOIX UNIQUE ============
// Visuellement des cases à cocher, mais un seul scanner actif à la fois :
// cocher une case décoche automatiquement les autres, et décocher la seule
// case active est ignoré (on garde toujours un choix sélectionné).
function setupSingleCheckboxGroup(groupId) {
  const group = document.getElementById(groupId);
  const boxes = Array.from(group.querySelectorAll('input[type="checkbox"]'));
  boxes.forEach((box) => {
    box.addEventListener("change", () => {
      if (box.checked) {
        boxes.forEach((b) => { if (b !== box) b.checked = false; });
      } else {
        box.checked = true;
      }
    });
  });
}
function getCheckedValue(groupId) {
  const group = document.getElementById(groupId);
  const checked = group.querySelector('input[type="checkbox"]:checked');
  return checked ? checked.value : null;
}
setupSingleCheckboxGroup("scan-tool-group");
setupSingleCheckboxGroup("sched-tool-group");

// ============ NAVIGATION ============
document.querySelectorAll(".nav-item").forEach((btn) => {
  btn.addEventListener("click", () => switchView(btn.dataset.view));
});

function switchView(view) {
  document.querySelectorAll(".nav-item").forEach((b) => b.classList.toggle("active", b.dataset.view === view));
  document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
  const target = document.getElementById(`view-${view}`);
  target.classList.add("active");
  target.classList.remove("fade-in");
  void target.offsetWidth; // force reflow pour rejouer l'animation
  target.classList.add("fade-in");

  if (view === "dashboard") loadDashboard();
  if (view === "scans") { showScanList(); loadScans(); }
  if (view === "vulns") loadAllVulns();
  if (view === "schedules") loadSchedules();
  if (view === "audit") loadAuditLog();
}

function showToast(message, isError) {
  const el = document.createElement("div");
  el.className = "toast" + (isError ? " toast-error" : "");
  el.textContent = message;
  document.body.appendChild(el);
  requestAnimationFrame(() => el.classList.add("show"));
  setTimeout(() => {
    el.classList.remove("show");
    setTimeout(() => el.remove(), 250);
  }, 3200);
}

document.getElementById("logout-btn").addEventListener("click", () => api.logout());

// ============ USER INFO ============
async function loadUserInfo() {
  try {
    const me = await api.getMe();
    document.getElementById("user-avatar").textContent = me.username.slice(0, 2).toUpperCase();
    document.getElementById("user-name").textContent = me.username;
    document.getElementById("user-role").textContent = me.role === "admin" ? "Administrateur" : "Utilisateur";
    if (me.role === "admin") document.getElementById("nav-audit").style.display = "flex";
  } catch (e) { /* pas grave, page continue */ }
}

// ============ DASHBOARD ============
let trendChartInstance = null;
let doughnutChartInstance = null;

async function loadDashboard() {
  const stats = await api.getDashboardStats();

  const cards = [
    { val: stats.total_scans, lbl: "Scans totaux", color: "var(--accent)" },
    { val: stats.scans_in_progress, lbl: "En cours", color: "var(--accent)" },
    { val: stats.total_vulnerabilities, lbl: "Vulnérabilités", color: "var(--text)" },
    { val: stats.severity_breakdown.critical, lbl: "Critiques", color: "var(--danger)" },
  ];
  document.getElementById("stats-row").innerHTML = cards.map((c) => `
    <div class="stat-card2">
      <div class="val" style="color:${c.color};">${c.val}</div>
      <div class="lbl">${c.lbl}</div>
    </div>
  `).join("");

  if (trendChartInstance) trendChartInstance.destroy();
  const timeline = stats.vulnerabilities_over_time || [];
  trendChartInstance = new Chart(document.getElementById("trend-chart"), {
    type: "line",
    data: {
      labels: timeline.map((p) => p.date),
      datasets: [
        { label: "Critique", data: timeline.map((p) => p.critical), borderColor: severityColor.critical, tension: 0.3 },
        { label: "Élevée", data: timeline.map((p) => p.high), borderColor: severityColor.high, tension: 0.3 },
        { label: "Moyenne", data: timeline.map((p) => p.medium), borderColor: "#a08b3a", tension: 0.3 },
        { label: "Faible", data: timeline.map((p) => p.low), borderColor: severityColor.low, tension: 0.3 },
      ],
    },
    options: {
      plugins: { legend: { position: "bottom", labels: { boxWidth: 10, font: { size: 11 } } } },
      scales: { y: { beginAtZero: true, ticks: { stepSize: 1 } } },
    },
  });

  if (doughnutChartInstance) doughnutChartInstance.destroy();
  doughnutChartInstance = new Chart(document.getElementById("severity-doughnut"), {
    type: "doughnut",
    data: {
      labels: ["Critique", "Élevée", "Moyenne", "Faible"],
      datasets: [{
        data: [stats.severity_breakdown.critical, stats.severity_breakdown.high, stats.severity_breakdown.medium, stats.severity_breakdown.low],
        backgroundColor: [severityColor.critical, severityColor.high, "#a08b3a", severityColor.low],
        borderWidth: 0,
      }],
    },
    options: { plugins: { legend: { position: "bottom", labels: { boxWidth: 10, font: { size: 11 } } } }, cutout: "65%" },
  });

  const scans = await api.getScans();
  const recent = scans.slice(0, 5);
  document.getElementById("recent-scans-list").innerHTML = recent.length
    ? recent.map((s) => `
        <div class="scan-row" onclick="switchView('scans'); setTimeout(()=>viewScan(${s.id}), 50);">
          <span>${s.url}</span>
          <span style="color:var(--text-secondary);">${fmtDate(s.date)}</span>
          <span class="badge badge-${s.status}">${statusLabel[s.status] || s.status}</span>
          <span style="color:var(--accent); text-align:right;">Voir →</span>
        </div>
      `).join("")
    : `<p style="color:var(--text-secondary); font-size:14px;">Aucun scan pour l'instant.</p>`;
}

// ============ SCANS ============
let pollTimer = null;
let listPollTimer = null;
let scanDetailChartInstance = null;

function showScanList() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  document.getElementById("scans-list-panel").style.display = "block";
  document.getElementById("scan-detail-panel").style.display = "none";
}

async function loadScans() {
  const scans = await api.getScans();
  renderScanList(scans);

  const hasRunning = scans.some((s) => s.status === "running");
  if (hasRunning && !listPollTimer) {
    listPollTimer = setInterval(async () => {
      const refreshed = await api.getScans();
      if (!refreshed.some((s) => s.status === "running")) {
        clearInterval(listPollTimer);
        listPollTimer = null;
      }
      if (document.getElementById("scans-list-panel").style.display !== "none") {
        renderScanList(refreshed);
      }
    }, 3000);
  }
}

function renderScanList(scans) {
  const list = document.getElementById("scan-list");
  list.innerHTML = scans.length
    ? scans.map((s) => `
        <div class="scan-row" style="grid-template-columns: 2fr 1.5fr 1fr 1fr auto;" onclick="viewScan(${s.id})">
          <span>${s.url}</span>
          <span style="color:var(--text-secondary);">${fmtDate(s.date)}</span>
          <span class="badge badge-${s.status}">${statusLabel[s.status] || s.status}</span>
          <span style="color:${s.status === "running" ? "var(--accent)" : "var(--text-secondary)"}; text-align:right; font-size:12px;">
            ${s.status === "running" ? s.current_step : "Voir →"}
          </span>
          <button class="row-delete-btn" title="Supprimer ce scan" onclick="event.stopPropagation(); deleteScanRow(${s.id})">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m3 0-1 14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2L4 6"/></svg>
          </button>
        </div>
      `).join("")
    : `<p style="color:var(--text-secondary); font-size:14px;">Aucun scan pour l'instant.</p>`;
}

async function deleteScanRow(id) {
  if (!confirm("Supprimer définitivement ce scan et toutes ses vulnérabilités associées ?")) return;
  try {
    await api.deleteScan(id);
    showToast("Scan supprimé.");
    loadScans();
    loadStats();
  } catch (err) {
    showToast(err.message || "Impossible de supprimer ce scan.", true);
  }
}

const SCAN_STEPS = ["Initialisation", "Scan en cours", "Analyse par l'IA", "Terminé"];
function stepIndex(currentStep) {
  if (!currentStep) return 0;
  if (currentStep.startsWith("Scan en cours")) return 1;
  const idx = SCAN_STEPS.findIndex((s) => currentStep.startsWith(s));
  return idx === -1 ? 0 : idx;
}
function renderStepTracker(scan) {
  const failed = scan.status === "failed";
  const active = failed ? SCAN_STEPS.length : stepIndex(scan.current_step);
  return `
    <div style="display:flex; align-items:center; margin-bottom:1.25rem;">
      ${SCAN_STEPS.map((label, i) => `
        <div style="display:flex; align-items:center; flex:${i < SCAN_STEPS.length - 1 ? "1" : "0"};">
          <div style="display:flex; align-items:center; gap:8px;">
            <div style="width:10px; height:10px; border-radius:50%; flex-shrink:0;
              background:${failed && i === SCAN_STEPS.length - 1 ? "var(--danger)" : i <= active ? "var(--accent)" : "var(--border)"};"></div>
            <span style="font-family:var(--mono); font-size:11px; text-transform:uppercase; letter-spacing:.03em;
              color:${i <= active ? "var(--text)" : "var(--text-muted)"};">${label}</span>
          </div>
          ${i < SCAN_STEPS.length - 1 ? `<div style="flex:1; height:1px; background:${i < active ? "var(--accent)" : "var(--border)"}; margin:0 10px;"></div>` : ""}
        </div>
      `).join("")}
    </div>
  `;
}

async function viewScan(id) {
  if (listPollTimer) { clearInterval(listPollTimer); listPollTimer = null; }
  if (pollTimer) clearInterval(pollTimer);
  document.getElementById("scans-list-panel").style.display = "none";
  document.getElementById("scan-detail-panel").style.display = "block";

  await renderScanDetail(id);
  pollTimer = setInterval(async () => {
    const scan = await api.pollScan(id);
    if (scan.status !== "running") clearInterval(pollTimer);
    renderScanDetail(id, scan);
  }, 2000);
}

async function renderScanDetail(id, preloaded) {
  const scan = preloaded || await api.getScan(id);
  currentScanId = scan.id;
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  scan.vulnerabilities.forEach((v) => { if (counts[v.severity] !== undefined) counts[v.severity]++; });

  let comparison = null;
  if (scan.status === "done" && scan.scanner !== "recon") {
    try { comparison = await api.compareScan(scan.id); } catch (e) { /* pas grave, pas de comparaison affichée */ }
  }

  let rawParsed = [];
  try { rawParsed = scan.raw_output ? JSON.parse(scan.raw_output) : []; } catch (e) { /* ignore */ }

  const panel = document.getElementById("scan-detail-panel");
  panel.innerHTML = `
    <button class="btn btn-secondary" onclick="showScanList(); loadScans();" style="margin-bottom:1rem;">← Retour aux scans</button>

    <div class="card">
      <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:1rem;">
        <div>
          <h2 style="margin:0 0 4px; font-size:18px;">${scan.url}</h2>
          <p style="color:var(--text-secondary); font-size:13px; margin:0;">
            ${scan.scanner} · ${fmtDate(scan.date)} · statut :
            <span class="badge badge-${scan.status}">${statusLabel[scan.status] || scan.status}</span>
          </p>
        </div>
        <div style="display:flex; gap:8px;">
          ${scan.status !== "running" ? `
            <button class="btn btn-secondary" id="download-report-btn" style="display:flex; align-items:center; gap:6px;">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3v12m0 0l-4-4m4 4l4-4M4 19h16"/></svg>
              Rapport PDF
            </button>
          ` : ""}
          <button class="btn btn-secondary" id="delete-scan-btn" style="display:flex; align-items:center; gap:6px; color:var(--danger);">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m3 0-1 14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2L4 6"/></svg>
            Supprimer
          </button>
        </div>
      </div>

      ${renderStepTracker(scan)}

      <div class="tab-bar">
        <button class="tab-btn active" data-tab="overview">Overview</button>
        <button class="tab-btn" data-tab="vulns">Vulnérabilités (${scan.vulnerabilities.length})</button>
        ${scan.scanner === "recon" ? `<button class="tab-btn" data-tab="surface">Surface d'attaque (${scan.attack_surface.length})</button>` : ""}
        <button class="tab-btn" data-tab="raw">Résultats bruts</button>
        <button class="tab-btn" data-tab="timeline">Timeline</button>
      </div>

      <div class="tab-panel active" data-panel="overview">
        ${comparison ? `
          <div style="display:flex; align-items:center; gap:16px; padding:12px 14px; margin-bottom:1rem; background:var(--surface-1); border-radius:var(--radius);">
            ${comparison.previous_scan_id ? `
              <div style="font-size:20px; font-weight:600; font-family:var(--mono);">
                ${comparison.previous_score} → ${comparison.current_score}
                <span style="font-size:13px; font-weight:500; color:${comparison.score_delta >= 0 ? "var(--success)" : "var(--danger)"};">
                  (${comparison.score_delta >= 0 ? "+" : ""}${comparison.score_delta})
                </span>
              </div>
              <div style="font-size:12px; color:var(--text-secondary); line-height:1.5;">
                Score de sécurité — comparé au scan du ${fmtDate(comparison.previous_scan_date)}<br/>
                ${comparison.new_vulnerabilities.length} nouvelle(s) · ${comparison.resolved_vulnerabilities.length} corrigée(s) · ${comparison.still_open_count} toujours ouverte(s)
              </div>
            ` : `
              <div style="font-size:20px; font-weight:600; font-family:var(--mono);">${comparison.current_score}/100</div>
              <div style="font-size:12px; color:var(--text-secondary);">Score de sécurité — premier scan sur cette cible, pas encore de comparaison possible</div>
            `}
          </div>
        ` : ""}
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:1rem;">
          <div>
            <p style="font-size:13px; color:var(--text-secondary); margin:0 0 10px;">
              ${scan.scanner === "recon"
                ? `${scan.attack_surface.length} actif(s) découvert(s)`
                : `${scan.vulnerabilities.length} vulnérabilité(s) détectée(s)`} — durée : ${fmtDuration(scan.date, scan.finished_at)}
            </p>
            ${["critical","high","medium","low"].map((s) => `
              <div style="display:flex; justify-content:space-between; font-size:13px; padding:5px 0; border-bottom:0.5px solid var(--border);">
                <span><span class="badge badge-${s}">${severityLabel[s]}</span></span>
                <span style="font-family:var(--mono);">${counts[s]}</span>
              </div>
            `).join("")}
          </div>
          <div class="chart-wrap" style="height:180px;">${scan.vulnerabilities.length ? '<canvas id="scan-detail-chart"></canvas>' : '<p style="color:var(--text-secondary); font-size:13px;">Pas encore de données.</p>'}</div>
        </div>
      </div>

      <div class="tab-panel" data-panel="vulns">
        ${scan.vulnerabilities.length ? `
          <table class="vuln-table">
            <thead><tr><th>Sévérité</th><th>Vulnérabilité</th><th>Statut</th><th>CVE</th><th>Outil</th></tr></thead>
            <tbody>
              ${scan.vulnerabilities.map((v) => `
                <tr onclick='openVulnPanel(${JSON.stringify(v).replace(/'/g, "&apos;")})'>
                  <td><span class="badge badge-${v.severity}">${severityLabel[v.severity] || v.severity}</span></td>
                  <td>${v.name}</td>
                  <td><span class="badge badge-status-${v.status || "open"}">${vulnStatusLabel[v.status] || "Ouverte"}</span></td>
                  <td>${identifierBadge(v)}</td>
                  <td style="color:var(--text-secondary);">${v.source_tool || "—"}</td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        ` : scan.status === "running"
          ? `<p style="color:var(--text-secondary); font-size:14px;">Scan en cours, les résultats apparaîtront ici automatiquement...</p>`
          : `<p style="color:var(--text-secondary); font-size:14px;">Aucune vulnérabilité détectée.</p>`}
      </div>

      ${scan.scanner === "recon" ? `
      <div class="tab-panel" data-panel="surface">
        ${scan.attack_surface.length ? `
          <table class="vuln-table">
            <thead><tr><th>Sous-domaine</th><th>Statut</th><th>Titre</th><th>Technologies</th><th>IP</th></tr></thead>
            <tbody>
              ${scan.attack_surface.map((a) => `
                <tr>
                  <td>${a.url ? `<a href="${a.url}" target="_blank" rel="noopener" style="color:var(--accent);">${a.subdomain}</a>` : a.subdomain}</td>
                  <td>${a.http_status ?? "—"}</td>
                  <td style="color:var(--text-secondary);">${a.title || "—"}</td>
                  <td style="color:var(--text-secondary);">${a.technologies || "—"}</td>
                  <td style="color:var(--text-secondary); font-family:var(--mono);">${a.ip_address || "—"}</td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        ` : scan.status === "running"
          ? `<p style="color:var(--text-secondary); font-size:14px;">Reconnaissance en cours, les actifs découverts apparaîtront ici automatiquement...</p>`
          : `<p style="color:var(--text-secondary); font-size:14px;">Aucun actif découvert.</p>`}
      </div>
      ` : ""}

      <div class="tab-panel" data-panel="raw">
        ${rawParsed.length ? `
          <pre style="background:var(--surface-2); border:0.5px solid var(--border); border-radius:8px; padding:12px; font-size:11px; overflow-x:auto; max-height:400px;">${JSON.stringify(rawParsed, null, 2).replace(/</g, "&lt;")}</pre>
        ` : `<p style="color:var(--text-secondary); font-size:14px;">Pas encore de résultats bruts disponibles.</p>`}
      </div>

      <div class="tab-panel" data-panel="timeline">
        <div class="timeline-list">
          <div class="timeline-item">
            <div class="t">${fmtDateTime(scan.date)}</div>
            <div class="d">Scan créé — cible ${scan.url}</div>
          </div>
          <div class="timeline-item">
            <div class="t">${scan.status === "running" ? "En cours..." : fmtDateTime(scan.finished_at)}</div>
            <div class="d">${scan.status === "running" ? scan.current_step : (statusLabel[scan.status] || scan.status)}</div>
          </div>
        </div>
      </div>
    </div>
  `;

  panel.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      panel.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
      panel.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
      btn.classList.add("active");
      panel.querySelector(`[data-panel="${btn.dataset.tab}"]`).classList.add("active");
    });
  });

  const deleteBtn = document.getElementById("delete-scan-btn");
  if (deleteBtn) {
    deleteBtn.addEventListener("click", async () => {
      if (!confirm("Supprimer définitivement ce scan et toutes ses vulnérabilités associées ?")) return;
      try {
        await api.deleteScan(scan.id);
        if (pollTimer) clearInterval(pollTimer);
        showToast("Scan supprimé.");
        showScanList();
        loadScans();
        loadStats();
      } catch (err) {
        showToast(err.message || "Impossible de supprimer ce scan.", true);
      }
    });
  }

  const downloadBtn = document.getElementById("download-report-btn");
  if (downloadBtn) {
    downloadBtn.addEventListener("click", async () => {
      downloadBtn.disabled = true;
      const originalText = downloadBtn.innerHTML;
      downloadBtn.innerHTML = "Génération...";
      try {
        await api.downloadReport(scan.id, scan.url);
        showToast("Rapport téléchargé.");
      } catch (err) {
        showToast(err.message || "Erreur lors de la génération du rapport.", true);
      } finally {
        downloadBtn.disabled = false;
        downloadBtn.innerHTML = originalText;
      }
    });
  }

  if (scanDetailChartInstance) { scanDetailChartInstance.destroy(); scanDetailChartInstance = null; }
  if (scan.vulnerabilities.length) {
    scanDetailChartInstance = new Chart(document.getElementById("scan-detail-chart"), {
      type: "doughnut",
      data: {
        labels: ["Critique", "Élevée", "Moyenne", "Faible"],
        datasets: [{ data: [counts.critical, counts.high, counts.medium, counts.low], backgroundColor: [severityColor.critical, severityColor.high, "#a08b3a", severityColor.low], borderWidth: 0 }],
      },
      options: { plugins: { legend: { position: "right", labels: { boxWidth: 10, font: { size: 11 } } } }, cutout: "65%" },
    });
  }
}

// ============ VULN SIDE PANEL ============
function openVulnPanel(v) {
  const cveLine = v.cve_id
    ? `${identifierBadge(v)}${v.cvss_score ? ` · CVSS ${v.cvss_score}` : ""} <span style="color:var(--text-muted); font-size:12px;">— vulnérabilité identifiée avec précision</span>`
    : v.cwe_id
      ? `${identifierBadge(v)} <span style="color:var(--text-muted); font-size:12px;">— classification de faiblesse générale, pas de CVE exploitable précis</span>`
      : `<span style="color:var(--text-muted); font-size:12px;">Aucun CVE ni CWE identifié pour cet élément</span>`;

  document.getElementById("vuln-panel").innerHTML = `
    <button class="side-panel-close" onclick="closeVulnPanel()">✕</button>
    <span class="badge badge-${v.severity}">${severityLabel[v.severity] || v.severity}</span>
    <h3 style="margin:10px 0 4px;">${v.name}</h3>
    <p style="margin:0 0 10px;">${cveLine}</p>

    <div class="side-block" style="margin-bottom:14px;">
      <div class="h">Statut de traitement</div>
      <select id="vuln-status-select" style="margin:6px 0 0;">
        ${Object.entries(vulnStatusLabel).map(([val, label]) =>
          `<option value="${val}" ${v.status === val ? "selected" : ""}>${label}</option>`
        ).join("")}
      </select>
    </div>

    <div class="side-tab-bar">
      <button class="side-tab-btn active" data-stab="ai">Analyse IA</button>
      <button class="side-tab-btn" data-stab="tech">Détails techniques</button>
    </div>

    <div class="side-tab-panel active" data-spanel="ai">
      <div class="side-block">
        <div class="h">Explication</div>
        <p>${v.description || "Pas de description disponible."}</p>
      </div>
      <div class="side-block">
        <div class="h">Remédiation recommandée</div>
        <p>${v.solution || "—"}</p>
      </div>
    </div>

    <div class="side-tab-panel" data-spanel="tech">
      <div class="side-block"><div class="h">Outil source</div><p>${v.source_tool || "—"}</p></div>
      <div class="side-block"><div class="h">CVE</div><p>${v.cve_id || (v.cwe_id ? "Non applicable — voir CWE ci-dessous" : "Non identifié")}</p></div>
      <div class="side-block"><div class="h">CWE (classification de faiblesse)</div><p>${v.cwe_id || "—"}</p></div>
      <div class="side-block"><div class="h">Score CVSS</div><p>${v.cvss_score != null ? v.cvss_score : "Non disponible"}</p></div>
      <div class="side-block"><div class="h">Détecté le</div><p>${fmtDateTime(v.detected_at)}</p></div>
    </div>
  `;

  document.getElementById("vuln-panel").querySelectorAll(".side-tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".side-tab-btn").forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".side-tab-panel").forEach((p) => p.classList.remove("active"));
      btn.classList.add("active");
      document.querySelector(`[data-spanel="${btn.dataset.stab}"]`).classList.add("active");
    });
  });

  const statusSelect = document.getElementById("vuln-status-select");
  const previousStatus = v.status;
  statusSelect.addEventListener("change", async (e) => {
    const newStatus = e.target.value;
    try {
      await api.updateVulnerabilityStatus(v.id, newStatus);
      showToast("Statut mis à jour.");
      if (currentScanId) await renderScanDetail(currentScanId);
    } catch (err) {
      showToast(err.message || "Impossible de mettre à jour le statut.", true);
      statusSelect.value = previousStatus;
    }
  });

  document.getElementById("vuln-overlay").classList.add("open");
  document.getElementById("vuln-panel").classList.add("open");
}
function closeVulnPanel() {
  document.getElementById("vuln-overlay").classList.remove("open");
  document.getElementById("vuln-panel").classList.remove("open");
}

document.getElementById("scan-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const url = document.getElementById("scan-target").value;
  const scanner = getCheckedValue("scan-tool-group");
  try {
    const created = await api.createScan(url, scanner);
    document.getElementById("scan-target").value = "";
    viewScan(created.id);
  } catch (err) {
    showToast(err.message || "Cible invalide. Utilise une IP ou un domaine valide.", true);
  }
});

// ============ VULNÉRABILITÉS (vue globale) ============
async function loadAllVulns() {
  const vulns = await api.getAllVulnerabilities();
  document.getElementById("all-vulns-tbody").innerHTML = vulns.length
    ? vulns.map((v) => `
        <tr onclick='openVulnPanel(${JSON.stringify(v).replace(/'/g, "&apos;")})'>
          <td><span class="badge badge-${v.severity}">${severityLabel[v.severity] || v.severity}</span></td>
          <td>${v.name}</td>
          <td>${identifierBadge(v)}</td>
          <td style="color:var(--text-secondary);">${v.source_tool || "—"}</td>
          <td style="color:var(--text-secondary);">${v.scan_target}</td>
        </tr>
      `).join("")
    : `<tr><td colspan="5" style="color:var(--text-secondary); padding:1rem 10px;">Aucune vulnérabilité pour l'instant.</td></tr>`;
}

// ============ SCHEDULES ============
const frequencyLabel = { once: "Une fois", daily: "Quotidien", weekly: "Hebdomadaire" };

async function loadSchedules() {
  const schedules = await api.getSchedules();
  const list = document.getElementById("schedule-list");
  list.innerHTML = schedules.length
    ? schedules.map((s) => `
        <div class="scan-row" style="grid-template-columns: 1.6fr 1fr 1.4fr 1fr 1fr; cursor:default;">
          <span>${s.target}</span>
          <span style="color:var(--text-secondary);">${frequencyLabel[s.frequency] || s.frequency}</span>
          <span style="color:${s.is_active ? "var(--accent)" : "var(--text-muted)"}; font-size:12px;">
            ${s.is_active ? (s.next_run_at ? "Prochain : " + fmtDateTime(s.next_run_at) : "En attente") : "Terminé"}
          </span>
          <span style="color:var(--text-secondary);">${s.scanner}</span>
          <button class="btn btn-secondary" style="justify-self:end;" onclick="cancelSchedule(${s.id})">Annuler</button>
        </div>
      `).join("")
    : `<p style="color:var(--text-secondary); font-size:14px;">Aucun scan planifié.</p>`;
}
async function cancelSchedule(id) { await api.cancelSchedule(id); loadSchedules(); }

document.getElementById("schedule-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const target = document.getElementById("sched-target").value;
  const frequency = document.getElementById("sched-frequency").value;
  const scanner = getCheckedValue("sched-tool-group");
  const datetimeValue = document.getElementById("sched-datetime").value; // ex: 2026-07-25T14:30
  const scheduledAt = datetimeValue ? new Date(datetimeValue).toISOString() : null;
  try {
    await api.createSchedule(target, frequency, scanner, scheduledAt);
    document.getElementById("sched-target").value = "";
    document.getElementById("sched-datetime").value = "";
    loadSchedules();
    showToast("Scan planifié avec succès.");
  } catch (err) {
    showToast(err.message || "Cible ou date invalide.", true);
  }
});

// ============ AUDIT ============
async function loadAuditLog() {
  try {
    const logs = await api.getAuditLogs();
    document.getElementById("audit-list").innerHTML = logs.length
      ? logs.map((l) => `
          <div class="scan-row" style="grid-template-columns: 1fr 2fr 1fr; cursor:default;">
            <span style="color:var(--text-secondary);">${fmtDateTime(l.timestamp)}</span>
            <span>${l.action}${l.details ? " — " + l.details : ""}</span>
            <span style="color:var(--text-secondary); text-align:right;">user #${l.user_id ?? "—"}</span>
          </div>
        `).join("")
      : `<p style="color:var(--text-secondary); font-size:14px;">Aucune entrée pour l'instant.</p>`;
  } catch (e) { /* pas admin, silencieux */ }
}

// ============ INIT ============
loadUserInfo();
loadDashboard();
