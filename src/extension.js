// VulnRadar VS Code Extension
// Detects vulnerable Python packages as you type and shows alerts

const vscode = require('vscode');
const https = require('https');

// ─── OSV API ────────────────────────────────────────────────────────────────

function queryOSV(packageName, version) {
  return new Promise((resolve) => {
    const body = JSON.stringify({
      package: { name: packageName, ecosystem: 'PyPI' },
      ...(version && { version })
    });

    const options = {
      hostname: 'api.osv.dev',
      path: '/v1/query',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body)
      }
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch { resolve({}); }
      });
    });

    req.on('error', () => resolve({}));
    req.setTimeout(6000, () => { req.destroy(); resolve({}); });
    req.write(body);
    req.end();
  });
}

// ─── PARSERS ─────────────────────────────────────────────────────────────────

/**
 * Extract packages from requirements.txt style content
 * e.g. django==1.2, flask>=0.10, requests
 */
function parseRequirements(text) {
  const results = [];
  const lines = text.split('\n');

  lines.forEach((line, lineIndex) => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) return;

    // Match: package==version  OR  package>=version  OR  package
    const match = trimmed.match(/^([a-zA-Z0-9_\-\.]+)\s*([><=!~]{1,2})\s*([\d\.]+[a-zA-Z0-9\.\-]*)/);
    if (match) {
      results.push({
        name: match[1],
        version: match[3],
        op: match[2],
        line: lineIndex,
        colStart: line.indexOf(match[1]),
        colEnd: line.indexOf(match[1]) + trimmed.length
      });
      return;
    }

    // Just a package name (no version)
    const nameOnly = trimmed.match(/^([a-zA-Z0-9_\-\.]{2,})/);
    if (nameOnly && !trimmed.includes('(') && !trimmed.includes('=')) {
      results.push({
        name: nameOnly[1],
        version: null,
        op: null,
        line: lineIndex,
        colStart: line.indexOf(nameOnly[1]),
        colEnd: line.indexOf(nameOnly[1]) + nameOnly[1].length
      });
    }
  });

  return results;
}

/**
 * Extract imports from Python files
 * e.g. import django, from flask import Flask
 */
function parsePythonImports(text) {
  const results = [];
  const lines = text.split('\n');

  // Map common import names to PyPI package names
  const importToPackage = {
    'django': 'django', 'flask': 'flask', 'requests': 'requests',
    'numpy': 'numpy', 'pandas': 'pandas', 'PIL': 'Pillow',
    'cv2': 'opencv-python', 'sklearn': 'scikit-learn',
    'yaml': 'PyYAML', 'cryptography': 'cryptography',
    'paramiko': 'paramiko', 'sqlalchemy': 'SQLAlchemy',
    'aiohttp': 'aiohttp', 'urllib3': 'urllib3',
    'jinja2': 'Jinja2', 'werkzeug': 'Werkzeug',
    'lxml': 'lxml', 'boto3': 'boto3', 'celery': 'celery',
    'fastapi': 'fastapi', 'pydantic': 'pydantic',
    'httpx': 'httpx', 'twisted': 'Twisted',
  };

  lines.forEach((line, lineIndex) => {
    const trimmed = line.trim();

    // import X  OR  import X as Y
    let match = trimmed.match(/^import\s+([a-zA-Z0-9_]+)/);
    if (match) {
      const imp = match[1];
      const pkg = importToPackage[imp] || imp;
      results.push({
        name: pkg,
        version: null,
        line: lineIndex,
        colStart: line.indexOf(imp),
        colEnd: line.indexOf(imp) + imp.length,
        isImport: true
      });
      return;
    }

    // from X import Y
    match = trimmed.match(/^from\s+([a-zA-Z0-9_]+)\s+import/);
    if (match) {
      const imp = match[1];
      if (imp === '__future__' || imp === 'typing') return;
      const pkg = importToPackage[imp] || imp;
      results.push({
        name: pkg,
        version: null,
        line: lineIndex,
        colStart: line.indexOf(imp),
        colEnd: line.indexOf(imp) + imp.length,
        isImport: true
      });
    }
  });

  // Deduplicate by package name
  const seen = new Set();
  return results.filter(r => {
    if (seen.has(r.name)) return false;
    seen.add(r.name);
    return true;
  });
}

// ─── RISK SCORING ────────────────────────────────────────────────────────────

function computeRisk(vulns) {
  if (!vulns || vulns.length === 0) {
    return { level: 'SAFE', score: 0 };
  }

  let maxCvss = 0;

  vulns.forEach(v => {
    (v.severity || []).forEach(s => {
      const score = parseFloat(s.score || 0);
      if (score > maxCvss) maxCvss = score;
    });
  });

  const count = vulns.length;

  if (maxCvss >= 9.0) {
    return { level: 'CRITICAL', score: 90 + count };
  }

  if (maxCvss >= 7.0) {
    return { level: 'HIGH', score: 75 + count };
  }

  if (maxCvss === 0) {
    if (count >= 5) return { level: 'HIGH', score: 70 };
    if (count >= 3) return { level: 'MEDIUM', score: 55 };
    return { level: 'LOW', score: 30 };
  }

  if (count >= 1) {
    return { level: 'MEDIUM', score: 50 };
  }

  return { level: 'LOW', score: 20 };
}


function extractCVEs(vulns) {
  const cves = new Set();
  (vulns || []).forEach(v => {
    if (v.id?.startsWith('CVE-')) cves.add(v.id);
    (v.aliases || []).forEach(a => { if (a.startsWith('CVE-')) cves.add(a); });
  });
  return [...cves];
}

// ─── SAFE VERSIONS ───────────────────────────────────────────────────────────

const SAFE_VERSIONS = {
  'django': '4.2', 'flask': '3.0', 'requests': '2.31.0',
  'numpy': '1.26.0', 'pillow': '10.2.0', 'cryptography': '42.0.0',
  'sqlalchemy': '2.0.0', 'urllib3': '2.2.0', 'paramiko': '3.4.0',
  'aiohttp': '3.9.0', 'jinja2': '3.1.3', 'werkzeug': '3.0.1',
  'pyyaml': '6.0.1', 'lxml': '5.1.0', 'twisted': '24.3.0',
};

function getSafeVersion(name) {
  return SAFE_VERSIONS[name.toLowerCase()] || 'latest';
}

// ─── DIAGNOSTICS ─────────────────────────────────────────────────────────────

/** VS Code diagnostic collection (red/yellow squiggles) */
const diagnosticCollection = vscode.languages.createDiagnosticCollection('vulnradar');

/**
 * Scan all packages in a document and update diagnostics + show alerts
 * 
 * 
 */
console.log("SCAN STARTED");


async function scanDocument(document, statusBar) {
  const config = vscode.workspace.getConfiguration('vulnradar');
  if (!config.get('enabled')) return;

  const text = document.getText();
  const fileName = document.fileName;
  const isRequirements = fileName.endsWith('.txt') || fileName.endsWith('.cfg');
  const isPython = fileName.endsWith('.py');

  if (!isRequirements && !isPython) return;

  const packages = isRequirements
    ? parseRequirements(text)
    : parsePythonImports(text);

  if (packages.length === 0) return;

  statusBar.text = '$(sync~spin) VulnRadar: Scanning...';
  statusBar.show();

  const diagnostics = [];
  const vulnerablePackages = [];

  // Scan all packages in parallel
  await Promise.all(packages.map(async (pkg) => {
    const result = await queryOSV(pkg.name, pkg.version);
    const vulns = result.vulns || [];
    const risk = computeRisk(vulns);
    const cves = extractCVEs(vulns);

    if (risk.level === 'SAFE') return;

    const safeVer = getSafeVersion(pkg.name);
    const pkgData = { ...pkg, risk, cves, vulns, safeVer, vuln_count: vulns.length };
    vulnerablePackages.push(pkgData);

    // Create diagnostic squiggle
    const range = new vscode.Range(
      pkg.line, pkg.colStart,
      pkg.line, pkg.colEnd
    );

    const severity =
      risk.level === 'CRITICAL' ? vscode.DiagnosticSeverity.Error :
        risk.level === 'HIGH' ? vscode.DiagnosticSeverity.Error :
          vscode.DiagnosticSeverity.Warning;

    const diag = new vscode.Diagnostic(
      range,
      `⚠️ VulnRadar [${risk.level}] ${pkg.name}${pkg.version ? '@' + pkg.version : ''}: ${vulns.length} vulnerabilities found. ${cves.slice(0, 2).join(', ')}${cves.length > 2 ? '...' : ''}. Safe version: ${safeVer}`,
      severity
    );

    diag.source = 'VulnRadar';
    diag.code = {
      value: 'VIEW_DASHBOARD',
      target: vscode.Uri.parse(`command:vulnradar.openDashboardForPackage?${encodeURIComponent(JSON.stringify(pkgData))}`)
    };

    diagnostics.push(diag);
  }));

  diagnosticCollection.set(document.uri, diagnostics);

  // Update status bar
  if (vulnerablePackages.length > 0) {
    const critCount = vulnerablePackages.filter(p => p.risk.level === 'CRITICAL').length;
    statusBar.text = `$(shield) VulnRadar: ${vulnerablePackages.length} vulnerable (${critCount} critical)`;
    statusBar.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
    statusBar.command = 'vulnradar.openDashboard';
    statusBar.tooltip = 'Click to open VulnRadar Dashboard';

    // Show alert notification
    showVulnAlert(vulnerablePackages);
  } else {
    statusBar.text = '$(pass) VulnRadar: All clear';
    statusBar.backgroundColor = undefined;
  }

  // Store results for dashboard
  lastScanResults = vulnerablePackages;
}

// ─── ALERT NOTIFICATION ──────────────────────────────────────────────────────

let alertCooldown = false;

function showVulnAlert(vulnerablePackages) {
  if (alertCooldown) return;
  alertCooldown = true;
  setTimeout(() => alertCooldown = false, 5000);

  const critical = vulnerablePackages.filter(p => p.risk.level === 'CRITICAL');
  const top = critical.length > 0 ? critical[0] : vulnerablePackages[0];

  const msg = `⚠️ VulnRadar: ${top.name}${top.version ? '@' + top.version : ''} is ${top.risk.level} risk! (${top.vuln_count} vulns, ${top.cves.slice(0, 2).join(', ')}). Total: ${vulnerablePackages.length} vulnerable packages.`;

  vscode.window.showWarningMessage(msg, 'Open Dashboard', 'Ignore')
    .then(action => {
      if (action === 'Open Dashboard') {
        openDashboard(top);
      }
    });
}

// ─── DASHBOARD WEBVIEW ───────────────────────────────────────────────────────

let lastScanResults = [];
let dashboardPanel = null;

function openDashboard(pkg) {
  if (dashboardPanel) {
    dashboardPanel.reveal(vscode.ViewColumn.Beside);
  } else {
    dashboardPanel = vscode.window.createWebviewPanel(
      'vulnradar',
      'VulnRadar Dashboard',
      vscode.ViewColumn.Beside,
      { enableScripts: true, retainContextWhenHidden: true }
    );

    dashboardPanel.onDidDispose(() => {
      dashboardPanel = null;
    });
  }

  dashboardPanel.webview.html = getDashboardHTML(pkg || lastScanResults[0]);
  dashboardPanel.iconPath = vscode.Uri.file('media/icon.png');
}

// ─── DASHBOARD HTML ──────────────────────────────────────────────────────────

function getDashboardHTML(pkg) {
  if (!pkg) {
    return `<!DOCTYPE html><html><body style="background:#020608;color:#4a7a8a;font-family:monospace;padding:40px;text-align:center">
      <h2 style="color:#ff2d55">No scan data available</h2>
      <p>Open a Python file or requirements.txt and start typing to trigger a scan.</p>
    </body></html>`;
  }

  const riskColor = {
    CRITICAL: '#ff2d55', HIGH: '#ff6b35', MEDIUM: '#ffae00',
    LOW: '#39ff14', SAFE: '#00d4ff'
  }[pkg.risk.level] || '#00d4ff';

  const cveRows = pkg.cves.length > 0
    ? pkg.cves.map(c => `<div class="cve-tag">${c}</div>`).join('')
    : '<span style="color:#4a7a8a;font-size:0.8rem">No CVE IDs found</span>';

  const vulnRows = (pkg.vulns || []).slice(0, 8).map(v => `
    <div class="vuln-row">
      <span class="vuln-id">${v.id || '—'}</span>
      <span class="vuln-summary">${(v.summary || 'No summary').substring(0, 120)}${(v.summary || '').length > 120 ? '...' : ''}</span>
    </div>
  `).join('');

  const attackSim = pkg.risk.level === 'SAFE' ? '' : `
    <div class="section">
      <div class="section-title">// ATTACK SIMULATION</div>
      <div class="terminal">${generateAttackSim(pkg)}</div>
    </div>
  `;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VulnRadar — ${pkg.name}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@700;900&family=Rajdhani:wght@300;400;600&display=swap');

  :root {
    --bg: #020608; --bg2: #060d12; --bg3: #0a1520;
    --panel: #0d1f2d; --border: #0f3a52;
    --accent: #00d4ff; --dim: #4a7a8a; --text: #c8e6f0;
    --risk: ${riskColor};
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'Rajdhani', sans-serif;
    padding: 0;
    min-height: 100vh;
  }

  body::before {
    content: '';
    position: fixed; inset: 0;
    background-image:
      linear-gradient(rgba(0,212,255,0.02) 1px, transparent 1px),
      linear-gradient(90deg, rgba(0,212,255,0.02) 1px, transparent 1px);
    background-size: 32px 32px;
    pointer-events: none; z-index: 0;
  }

  .content { position: relative; z-index: 1; padding: 0 0 40px; }

  /* HERO */
  .hero {
    padding: 28px 28px 24px;
    border-bottom: 1px solid var(--border);
    background: linear-gradient(180deg, rgba(13,31,45,0.8) 0%, transparent 100%);
    display: flex; align-items: center; gap: 20px;
    position: relative; overflow: hidden;
  }

  .hero::after {
    content: '';
    position: absolute; top: 0; left: 0; right: 0; height: 2px;
    background: linear-gradient(90deg, transparent, var(--risk), transparent);
  }

  .risk-orb {
    width: 80px; height: 80px; border-radius: 50%; flex-shrink: 0;
    display: flex; flex-direction: column; align-items: center; justify-content: center;
    background: radial-gradient(circle at 40% 40%, color-mix(in srgb, var(--risk) 30%, transparent), transparent);
    border: 2px solid var(--risk);
    box-shadow: 0 0 24px color-mix(in srgb, var(--risk) 50%, transparent);
    animation: orbPulse 2.5s ease-in-out infinite;
  }

  @keyframes orbPulse {
    0%,100% { box-shadow: 0 0 24px color-mix(in srgb, var(--risk) 40%, transparent); }
    50% { box-shadow: 0 0 40px color-mix(in srgb, var(--risk) 70%, transparent); }
  }

  .orb-score {
    font-family: 'Orbitron', monospace;
    font-size: 1.3rem; font-weight: 900; color: var(--risk); line-height: 1;
  }

  .orb-label {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.55rem; color: var(--dim); margin-top: 2px;
  }

  .hero-info { flex: 1; min-width: 0; }

  .breadcrumb {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.65rem; color: var(--dim); letter-spacing: 2px;
    text-transform: uppercase; margin-bottom: 6px;
  }

  .pkg-name {
    font-family: 'Orbitron', monospace;
    font-size: 1.4rem; font-weight: 900; color: #fff;
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  }

  .pkg-ver {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.78rem; color: var(--dim); margin: 4px 0 12px;
  }

  .badge-row { display: flex; gap: 8px; flex-wrap: wrap; }

  .badge {
    font-family: 'Orbitron', monospace;
    font-size: 0.6rem; font-weight: 700;
    padding: 4px 10px; border-radius: 2px;
    letter-spacing: 1.5px; text-transform: uppercase;
    background: color-mix(in srgb, var(--risk) 12%, transparent);
    color: var(--risk);
    border: 1px solid color-mix(in srgb, var(--risk) 40%, transparent);
  }

  .badge-neutral {
    background: rgba(255,255,255,0.04); color: var(--text);
    border: 1px solid var(--border); font-family: 'Orbitron', monospace;
    font-size: 0.6rem; padding: 4px 10px; border-radius: 2px;
  }

  /* SECTIONS */
  .sections { padding: 20px 28px; display: flex; flex-direction: column; gap: 16px; }

  .section {
    background: var(--panel);
    border: 1px solid var(--border); border-radius: 4px;
    overflow: hidden;
    animation: fadeUp 0.4s ease backwards;
  }

  @keyframes fadeUp {
    from { opacity: 0; transform: translateY(10px); }
    to { opacity: 1; transform: translateY(0); }
  }

  .section:nth-child(1) { animation-delay: 0.05s; }
  .section:nth-child(2) { animation-delay: 0.1s; }
  .section:nth-child(3) { animation-delay: 0.15s; }
  .section:nth-child(4) { animation-delay: 0.2s; }
  .section:nth-child(5) { animation-delay: 0.25s; }

  .section-title {
    padding: 10px 16px;
    border-bottom: 1px solid var(--border);
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.7rem; color: var(--accent);
    letter-spacing: 2px; text-transform: uppercase;
    background: rgba(0,212,255,0.02);
  }

  .section-body { padding: 16px; }

  /* Score gauge */
  .score-row {
    display: flex; align-items: center; gap: 16px; margin-bottom: 14px;
  }

  .score-num {
    font-family: 'Orbitron', monospace;
    font-size: 2.2rem; font-weight: 900;
    color: var(--risk); line-height: 1; flex-shrink: 0;
  }

  .score-bar-wrap { flex: 1; }

  .score-bar-track {
    height: 8px; background: var(--bg3); border-radius: 4px; overflow: hidden; margin-bottom: 6px;
  }

  .score-bar-fill {
    height: 100%; border-radius: 4px;
    background: var(--risk);
    box-shadow: 0 0 8px var(--risk);
    transition: width 1s ease;
    width: 0;
  }

  .score-meta {
    display: flex; justify-content: space-between;
    font-family: 'Share Tech Mono', monospace; font-size: 0.68rem; color: var(--dim);
  }

  /* CVE tags */
  .cve-row { display: flex; flex-wrap: wrap; gap: 8px; }
  .cve-tag {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.72rem; color: #ff2d55;
    background: rgba(255,45,85,0.08); border: 1px solid rgba(255,45,85,0.3);
    padding: 4px 10px; border-radius: 2px;
  }

  /* Vuln rows */
  .vuln-row {
    padding: 10px 0; border-bottom: 1px solid rgba(15,58,82,0.5);
    display: flex; gap: 12px; align-items: flex-start;
  }
  .vuln-row:last-child { border-bottom: none; }
  .vuln-id {
    font-family: 'Share Tech Mono', monospace; font-size: 0.72rem;
    color: var(--accent); white-space: nowrap; flex-shrink: 0; padding-top: 1px;
  }
  .vuln-summary { font-size: 0.82rem; color: var(--text); font-weight: 300; line-height: 1.5; }

  /* Explanation */
  .explanation { font-size: 0.9rem; line-height: 1.7; font-weight: 300; }

  /* Terminal */
  .terminal {
    background: #000; border: 1px solid var(--border); border-radius: 3px;
    padding: 14px; font-family: 'Share Tech Mono', monospace;
    font-size: 0.75rem; line-height: 1.8; white-space: pre-wrap;
    color: #39ff14;
  }

  /* Recommendation */
  .rec-box {
    background: rgba(57,255,20,0.04); border: 1px solid rgba(57,255,20,0.2);
    border-radius: 3px; padding: 14px; margin-bottom: 14px;
  }

  .safe-ver {
    font-family: 'Share Tech Mono', monospace; font-size: 1.1rem; color: #39ff14; margin: 8px 0;
  }

  .cmd-box {
    background: #000; border: 1px solid var(--border); border-radius: 3px;
    padding: 10px 14px; font-family: 'Share Tech Mono', monospace;
    font-size: 0.8rem; color: #39ff14;
    display: flex; justify-content: space-between; align-items: center;
  }

  .copy-btn {
    background: none; border: 1px solid var(--border); color: var(--dim);
    font-family: 'Share Tech Mono', monospace; font-size: 0.62rem; padding: 3px 8px;
    border-radius: 2px; cursor: pointer; letter-spacing: 1px;
  }
  .copy-btn:hover { border-color: var(--accent); color: var(--accent); }

  /* Details table */
  .detail-table { width: 100%; }
  .detail-row { display: flex; justify-content: space-between; padding: 7px 0; border-bottom: 1px solid rgba(15,58,82,0.4); font-size: 0.85rem; }
  .detail-row:last-child { border-bottom: none; }
  .detail-label { color: var(--dim); font-weight: 300; }
  .detail-val { font-family: 'Share Tech Mono', monospace; font-size: 0.78rem; color: var(--text); }

  ::-webkit-scrollbar { width: 4px; }
  ::-webkit-scrollbar-track { background: var(--bg2); }
  ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }
</style>
</head>
<body>
<div class="content">

  <!-- Hero -->
  <div class="hero">
    <div class="risk-orb">
      <div class="orb-score">${pkg.risk.score}</div>
      <div class="orb-label">/ 100</div>
    </div>
    <div class="hero-info">
      <div class="breadcrumb">// vulnerability analysis report</div>
      <div class="pkg-name">${pkg.name}</div>
      <div class="pkg-ver">@ version ${pkg.version || 'unspecified'}</div>
      <div class="badge-row">
        <span class="badge">${pkg.risk.level}</span>
        <span class="badge-neutral">${pkg.vuln_count} VULNS</span>
        <span class="badge-neutral">${pkg.cves.length} CVES</span>
        ${pkg.isImport ? '<span class="badge-neutral">IMPORT</span>' : ''}
      </div>
    </div>
  </div>

  <div class="sections">

    <!-- Risk Score -->
    <div class="section">
      <div class="section-title">// RISK SCORE</div>
      <div class="section-body">
        <div class="score-row">
          <div class="score-num" id="score-num">0</div>
          <div class="score-bar-wrap">
            <div class="score-bar-track">
              <div class="score-bar-fill" id="score-bar"></div>
            </div>
            <div class="score-meta">
              <span>SAFE</span><span>MEDIUM</span><span>HIGH</span><span>CRITICAL</span>
            </div>
          </div>
        </div>
        <div class="detail-table">
          <div class="detail-row"><span class="detail-label">Severity Level</span><span class="detail-val" style="color:${riskColor}">${pkg.risk.level}</span></div>
          <div class="detail-row"><span class="detail-label">Vulnerabilities Found</span><span class="detail-val">${pkg.vuln_count}</span></div>
          <div class="detail-row"><span class="detail-label">CVE IDs</span><span class="detail-val">${pkg.cves.length}</span></div>
          <div class="detail-row"><span class="detail-label">Package</span><span class="detail-val">${pkg.name}</span></div>
          <div class="detail-row"><span class="detail-label">Scanned Version</span><span class="detail-val">${pkg.version || 'any'}</span></div>
        </div>
      </div>
    </div>

    <!-- CVE IDs -->
    <div class="section">
      <div class="section-title">// CVE IDENTIFIERS</div>
      <div class="section-body">
        <div class="cve-row">${cveRows}</div>
      </div>
    </div>

    <!-- Vulnerabilities -->
    ${vulnRows ? `
    <div class="section">
      <div class="section-title">// VULNERABILITY DETAILS</div>
      <div class="section-body">${vulnRows}</div>
    </div>` : ''}

    <!-- Explanation -->
    <div class="section">
      <div class="section-title">// ATTACK EXPLANATION</div>
      <div class="section-body">
        <p class="explanation">${generateExplanation(pkg)}</p>
      </div>
    </div>

    ${attackSim}

    <!-- Recommendation -->
    <div class="section">
      <div class="section-title">// RECOMMENDATION</div>
      <div class="section-body">
        <div class="rec-box">
          <div style="font-family:'Share Tech Mono',monospace;font-size:0.65rem;color:#39ff14;letter-spacing:2px;margin-bottom:6px">✓ SAFE VERSION</div>
          <div class="safe-ver">${pkg.safeVer}</div>
          <div style="font-size:0.85rem;color:var(--text);font-weight:300;line-height:1.6;margin-top:8px">
            Upgrade <strong>${pkg.name}</strong> from ${pkg.version || 'current'} to <strong>${pkg.safeVer}</strong> immediately to fix ${pkg.vuln_count} known vulnerabilities.
          </div>
        </div>
        <div class="cmd-box">
          <span id="cmd-text">pip install --upgrade "${pkg.name}>=${pkg.safeVer}"</span>
          <button class="copy-btn" onclick="copyCmd()">COPY</button>
        </div>
      </div>
    </div>

  </div>
</div>

<script>
  // Animate score bar
  setTimeout(() => {
    const score = ${pkg.risk.score};
    document.getElementById('score-bar').style.width = score + '%';
    // Count up
    let current = 0;
    const el = document.getElementById('score-num');
    const interval = setInterval(() => {
      current = Math.min(current + Math.ceil(score / 30), score);
      el.textContent = current;
      if (current >= score) clearInterval(interval);
    }, 30);
  }, 200);

  function copyCmd() {
    const text = document.getElementById('cmd-text').textContent;
    navigator.clipboard.writeText(text).then(() => {
      const btn = document.querySelector('.copy-btn');
      btn.textContent = 'COPIED!';
      btn.style.color = '#39ff14';
      setTimeout(() => { btn.textContent = 'COPY'; btn.style.color = ''; }, 2000);
    });
  }
</script>
</body>
</html>`;
}

function generateExplanation(pkg) {
  if (pkg.risk.level === 'SAFE') return `No known vulnerabilities found for ${pkg.name}. Continue monitoring.`;
  const level = pkg.risk.level;
  const desc = pkg.vulns?.[0]?.summary || '';
  const intros = {
    CRITICAL: `⚠️ CRITICAL: ${pkg.name} has severe known vulnerabilities that can allow complete system compromise, remote code execution, or full data breach.`,
    HIGH: `🔴 HIGH RISK: ${pkg.name} contains significant security flaws enabling unauthorized access, data exfiltration, or privilege escalation.`,
    MEDIUM: `🟡 MEDIUM RISK: ${pkg.name} has exploitable vulnerabilities that may be leveraged under specific conditions.`,
  };
  return `${intros[level] || ''} ${desc ? desc.substring(0, 300) : ''}`;
}

function generateAttackSim(pkg) {
  const sims = {
    CRITICAL: `ATTACK SCENARIO [${pkg.name}]:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Attacker identifies target using vulnerable ${pkg.name}@${pkg.version || '?'}
2. Locates known exploit code for ${pkg.cves[0] || 'identified CVE'}
3. Crafts malicious payload → Remote Code Execution achieved
4. Lateral movement across internal network begins
5. Data exfiltration / ransomware deployment
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠ IMPACT: Full system compromise. PATCH IMMEDIATELY.`,
    HIGH: `ATTACK SCENARIO [${pkg.name}]:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Attacker finds application using ${pkg.name}@${pkg.version || '?'}
2. Exploits injection or auth bypass vulnerability  
3. Unauthorized access to sensitive application data
4. Session hijacking or privilege escalation possible
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠ IMPACT: Significant data breach risk. Upgrade within 48hrs.`,
    MEDIUM: `ATTACK SCENARIO [${pkg.name}]:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Attacker identifies misconfigured deployment using ${pkg.name}
2. Limited exploit under specific conditions
3. Potential for partial data access or DoS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠ IMPACT: Moderate risk. Upgrade in next maintenance window.`,
  };
  return sims[pkg.risk.level] || 'Vulnerability detected. Review and upgrade.';
}

// ─── EXTENSION ACTIVATE ──────────────────────────────────────────────────────

function activate(context) {
  // Status bar item
  const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusBar.text = '$(shield) VulnRadar: Ready';
  statusBar.show();
  context.subscriptions.push(statusBar);

  // Debounce map per document
  const timers = new Map();

  // Scan on text change (real-time)
  const changeDisposable = vscode.workspace.onDidChangeTextDocument(event => {
    const doc = event.document;
    if (!doc.fileName.endsWith('.py') &&
      !doc.fileName.endsWith('.txt') &&
      !doc.fileName.endsWith('.cfg')) return;

    const config = vscode.workspace.getConfiguration('vulnradar');
    const delay = config.get('debounceMs') || 1000;

    // Debounce per document
    if (timers.has(doc.uri.toString())) {
      clearTimeout(timers.get(doc.uri.toString()));
    }
    timers.set(doc.uri.toString(), setTimeout(() => {
      scanDocument(doc, statusBar);
    }, delay));
  });

  // Scan on file open
  const openDisposable = vscode.workspace.onDidOpenTextDocument(doc => {
    setTimeout(() => scanDocument(doc, statusBar), 500);
  });

  // Scan active file on activation
  if (vscode.window.activeTextEditor) {
    setTimeout(() => scanDocument(vscode.window.activeTextEditor.document, statusBar), 1000);
  }

  // Commands
  const scanCmd = vscode.commands.registerCommand('vulnradar.scanFile', () => {
    const editor = vscode.window.activeTextEditor;
    if (editor) scanDocument(editor.document, statusBar);
  });

  const dashboardCmd = vscode.commands.registerCommand('vulnradar.openDashboard', () => {
    openDashboard(lastScanResults[0]);
  });

  const dashboardForPkgCmd = vscode.commands.registerCommand('vulnradar.openDashboardForPackage', (pkg) => {
    openDashboard(pkg);
  });

  context.subscriptions.push(
    changeDisposable, openDisposable,
    scanCmd, dashboardCmd, dashboardForPkgCmd,
    diagnosticCollection
  );

  console.log('✅ VulnRadar extension activated');
}

function deactivate() {
  diagnosticCollection.clear();
  diagnosticCollection.dispose();
}

module.exports = { activate, deactivate };
