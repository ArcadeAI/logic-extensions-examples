package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// serveDashboard serves the web dashboard UI.
func (s *HookServer) serveDashboard(c *gin.Context) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusOK, dashboardHTML)
}

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Hook Server Dashboard</title>
<style>
  :root {
    --bg: #f5f7fa;
    --sidebar-bg: #1e293b;
    --sidebar-text: #cbd5e1;
    --sidebar-active: #3b82f6;
    --card-bg: #ffffff;
    --text: #1e293b;
    --text-muted: #64748b;
    --border: #e2e8f0;
    --primary: #3b82f6;
    --primary-hover: #2563eb;
    --danger: #ef4444;
    --success: #22c55e;
    --warning: #f59e0b;
    --radius: 8px;
    --shadow: 0 1px 3px rgba(0,0,0,0.1);
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); display: flex; min-height: 100vh; }

  /* Sidebar */
  .sidebar { width: 220px; background: var(--sidebar-bg); color: var(--sidebar-text); padding: 20px 0; flex-shrink: 0; display: flex; flex-direction: column; }
  .sidebar h1 { font-size: 16px; padding: 0 20px 20px; color: #fff; border-bottom: 1px solid rgba(255,255,255,0.1); margin-bottom: 10px; }
  .sidebar nav a { display: flex; align-items: center; gap: 10px; padding: 10px 20px; color: var(--sidebar-text); text-decoration: none; font-size: 14px; transition: all 0.15s; }
  .sidebar nav a:hover { background: rgba(255,255,255,0.05); color: #fff; }
  .sidebar nav a.active { background: rgba(59,130,246,0.15); color: var(--sidebar-active); border-right: 3px solid var(--sidebar-active); }
  .sidebar .status-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-left: auto; }
  .sidebar .status-dot.online { background: var(--success); }
  .sidebar .status-dot.offline { background: var(--danger); }

  /* Main Content */
  .main { flex: 1; padding: 24px; overflow-y: auto; }
  .main h2 { font-size: 20px; margin-bottom: 16px; }
  .main h3 { font-size: 16px; margin-bottom: 12px; color: var(--text-muted); }

  /* Cards */
  .card { background: var(--card-bg); border: 1px solid var(--border); border-radius: var(--radius); padding: 20px; margin-bottom: 16px; box-shadow: var(--shadow); }
  .card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
  .card-header h3 { margin-bottom: 0; }

  /* Tabs */
  .tab-content { display: none; }
  .tab-content.active { display: block; }

  /* Forms */
  label { display: block; font-size: 13px; font-weight: 600; margin-bottom: 4px; color: var(--text-muted); }
  input[type="text"], input[type="number"], input[type="password"], select, textarea {
    width: 100%; padding: 8px 12px; border: 1px solid var(--border); border-radius: 6px; font-size: 14px; margin-bottom: 12px;
    background: var(--bg); transition: border 0.15s;
  }
  input:focus, select:focus, textarea:focus { outline: none; border-color: var(--primary); }
  textarea { min-height: 80px; resize: vertical; font-family: 'SF Mono', monospace; font-size: 13px; }

  /* Buttons */
  .btn { padding: 8px 16px; border: none; border-radius: 6px; font-size: 13px; font-weight: 600; cursor: pointer; transition: all 0.15s; display: inline-flex; align-items: center; gap: 6px; }
  .btn-primary { background: var(--primary); color: #fff; }
  .btn-primary:hover { background: var(--primary-hover); }
  .btn-danger { background: var(--danger); color: #fff; }
  .btn-danger:hover { background: #dc2626; }
  .btn-outline { background: transparent; border: 1px solid var(--border); color: var(--text); }
  .btn-outline:hover { background: var(--bg); }
  .btn-sm { padding: 4px 10px; font-size: 12px; }
  .btn-group { display: flex; gap: 8px; }

  /* Toggle Switch */
  .toggle { position: relative; display: inline-block; width: 44px; height: 24px; }
  .toggle input { opacity: 0; width: 0; height: 0; }
  .toggle .slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background: #cbd5e1; border-radius: 24px; transition: 0.2s; }
  .toggle .slider:before { content: ""; position: absolute; height: 18px; width: 18px; left: 3px; bottom: 3px; background: white; border-radius: 50%; transition: 0.2s; }
  .toggle input:checked + .slider { background: var(--primary); }
  .toggle input:checked + .slider:before { transform: translateX(20px); }

  /* Toggle Row */
  .toggle-row { display: flex; justify-content: space-between; align-items: center; padding: 8px 0; border-bottom: 1px solid var(--border); }
  .toggle-row:last-child { border-bottom: none; }
  .toggle-label { font-size: 14px; }

  /* Table */
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; padding: 8px 12px; background: var(--bg); color: var(--text-muted); font-weight: 600; border-bottom: 2px solid var(--border); }
  td { padding: 8px 12px; border-bottom: 1px solid var(--border); }
  tr:hover td { background: #f8fafc; }

  /* Rules List */
  .rule-item { background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 12px; margin-bottom: 8px; position: relative; }
  .rule-item .rule-action { position: absolute; top: 8px; right: 8px; display: flex; gap: 4px; }
  .rule-item .rule-field { font-size: 12px; color: var(--text-muted); }
  .rule-item .rule-value { font-size: 14px; font-weight: 500; }

  /* Grid */
  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  .grid-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px; }

  /* Badge */
  .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; }
  .badge-success { background: #dcfce7; color: #166534; }
  .badge-danger { background: #fee2e2; color: #991b1b; }
  .badge-warning { background: #fef3c7; color: #92400e; }
  .badge-info { background: #dbeafe; color: #1e40af; }

  /* Stats */
  .stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 16px; }
  .stat-card { background: var(--bg); border-radius: 6px; padding: 12px; text-align: center; }
  .stat-value { font-size: 24px; font-weight: 700; }
  .stat-label { font-size: 12px; color: var(--text-muted); }

  /* Log Entries */
  .log-entry { padding: 8px 12px; border-left: 3px solid var(--primary); margin-bottom: 4px; background: var(--bg); border-radius: 0 6px 6px 0; font-size: 13px; cursor: pointer; transition: background 0.15s; }
  .log-entry:hover { background: var(--border); }
  .log-entry.log-access { border-left-color: var(--primary); }
  .log-entry.log-pre { border-left-color: var(--warning); }
  .log-entry.log-post { border-left-color: var(--success); }
  .log-entry.log-health { border-left-color: var(--text-muted); }
  .log-summary { display: flex; align-items: center; gap: 4px; flex-wrap: wrap; }
  .log-time { color: var(--text-muted); font-size: 11px; font-family: monospace; }
  .log-endpoint { font-weight: 600; margin: 0 8px; }
  .log-details { margin-top: 4px; font-size: 12px; color: var(--text-muted); }
  .log-expand-icon { margin-left: auto; color: var(--text-muted); font-size: 11px; transition: transform 0.2s; }
  .log-entry.expanded .log-expand-icon { transform: rotate(90deg); }
  .log-body { display: none; margin-top: 8px; }
  .log-entry.expanded .log-body { display: block; }
  .log-body-section { margin-bottom: 8px; }
  .log-body-label { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-muted); margin-bottom: 4px; }
  .log-body-json { background: #1e293b; color: #e2e8f0; padding: 10px 12px; border-radius: 6px; font-family: 'SF Mono', 'Consolas', monospace; font-size: 12px; line-height: 1.5; overflow-x: auto; white-space: pre-wrap; word-break: break-word; max-height: 400px; overflow-y: auto; }

  /* Toast */
  .toast { position: fixed; bottom: 20px; right: 20px; padding: 12px 20px; border-radius: 8px; color: #fff; font-size: 14px; z-index: 1000; animation: slideIn 0.3s ease; }
  .toast-success { background: var(--success); }
  .toast-error { background: var(--danger); }
  @keyframes slideIn { from { transform: translateY(20px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }

  /* Inline Forms */
  .inline-form { background: #f0f4ff; border: 2px dashed var(--primary); border-radius: var(--radius); padding: 20px; margin-bottom: 12px; animation: slideIn 0.2s ease; }
  .inline-form h4 { font-size: 14px; font-weight: 600; margin-bottom: 16px; color: var(--primary); }
  .inline-form .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  .inline-form .form-row-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 12px; }
  .inline-form .form-section { border-top: 1px solid var(--border); padding-top: 12px; margin-top: 4px; }
  .inline-form .form-section-title { font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-muted); margin-bottom: 8px; }
  .inline-form .form-actions { display: flex; gap: 8px; margin-top: 8px; padding-top: 12px; border-top: 1px solid var(--border); }

  /* Responsive */
  @media (max-width: 768px) {
    body { flex-direction: column; }
    .sidebar { width: 100%; flex-direction: row; padding: 10px; overflow-x: auto; }
    .sidebar h1 { display: none; }
    .sidebar nav { display: flex; flex-direction: row; }
    .sidebar nav a { padding: 8px 14px; border-right: none; border-bottom: 3px solid transparent; }
    .sidebar nav a.active { border-right: none; border-bottom: 3px solid var(--sidebar-active); }
    .grid-2, .grid-3 { grid-template-columns: 1fr; }
    .inline-form .form-row, .inline-form .form-row-3 { grid-template-columns: 1fr; }
  }
</style>
</head>
<body>

<div class="sidebar">
  <h1>Hook Server</h1>
  <nav>
    <a href="#" class="active" data-tab="rules">Rules</a>
    <a href="#" data-tab="pii">PII Redaction</a>
    <a href="#" data-tab="ab">A/B Testing</a>
    <a href="#" data-tab="logs">Logs</a>
    <a href="#" data-tab="config">Config <span class="status-dot online" id="statusDot"></span></a>
  </nav>
</div>

<div class="main">
  <!-- RULES TAB -->
  <div class="tab-content active" id="tab-rules">
    <h2>Access & Execution Rules</h2>

    <!-- Access Rules -->
    <div class="card">
      <div class="card-header">
        <h3>Access Control</h3>
        <div class="btn-group">
          <select id="accessDefaultAction" onchange="updateAccessDefault()">
            <option value="allow">Default: Allow</option>
            <option value="deny">Default: Deny</option>
          </select>
          <button class="btn btn-primary btn-sm" onclick="addAccessRule()">+ Add Rule</button>
        </div>
      </div>
      <div id="accessRules"></div>
    </div>

    <!-- Pre-Execution Rules -->
    <div class="card">
      <div class="card-header">
        <h3>Pre-Execution Rules</h3>
        <div class="btn-group">
          <select id="preDefaultAction" onchange="updatePreDefault()">
            <option value="proceed">Default: Proceed</option>
            <option value="block">Default: Block</option>
            <option value="rate_limit">Default: Rate Limit</option>
          </select>
          <button class="btn btn-primary btn-sm" onclick="addPreRule()">+ Add Rule</button>
        </div>
      </div>
      <div id="preRules"></div>
    </div>

    <!-- Post-Execution Rules -->
    <div class="card">
      <div class="card-header">
        <h3>Post-Execution Rules</h3>
        <div class="btn-group">
          <select id="postDefaultAction" onchange="updatePostDefault()">
            <option value="proceed">Default: Proceed</option>
            <option value="block">Default: Block</option>
          </select>
          <button class="btn btn-primary btn-sm" onclick="addPostRule()">+ Add Rule</button>
        </div>
      </div>
      <div id="postRules"></div>
    </div>

    <button class="btn btn-primary" onclick="saveConfig()">Save Configuration</button>
  </div>

  <!-- PII TAB -->
  <div class="tab-content" id="tab-pii">
    <h2>PII Redaction</h2>

    <div class="card">
      <div class="card-header">
        <h3>Settings</h3>
        <label class="toggle">
          <input type="checkbox" id="piiEnabled" onchange="savePIIConfig()">
          <span class="slider"></span>
        </label>
      </div>

      <label>Action when PII is detected:</label>
      <select id="piiAction" onchange="savePIIConfig()">
        <option value="redact">Redact (replace with placeholder)</option>
        <option value="block">Block (reject the response)</option>
      </select>

      <h3 style="margin-top:16px; margin-bottom:12px;">PII Types to Detect</h3>
      <div class="toggle-row">
        <span class="toggle-label">Email Addresses</span>
        <label class="toggle"><input type="checkbox" id="pii-email" onchange="savePIIConfig()"><span class="slider"></span></label>
      </div>
      <div class="toggle-row">
        <span class="toggle-label">IPv4 Addresses</span>
        <label class="toggle"><input type="checkbox" id="pii-ipv4" onchange="savePIIConfig()"><span class="slider"></span></label>
      </div>
      <div class="toggle-row">
        <span class="toggle-label">Social Security Numbers (SSN)</span>
        <label class="toggle"><input type="checkbox" id="pii-ssn" onchange="savePIIConfig()"><span class="slider"></span></label>
      </div>
      <div class="toggle-row">
        <span class="toggle-label">Phone Numbers</span>
        <label class="toggle"><input type="checkbox" id="pii-phone" onchange="savePIIConfig()"><span class="slider"></span></label>
      </div>
      <div class="toggle-row">
        <span class="toggle-label">Credit Card Numbers</span>
        <label class="toggle"><input type="checkbox" id="pii-credit_card" onchange="savePIIConfig()"><span class="slider"></span></label>
      </div>
      <div class="toggle-row">
        <span class="toggle-label">Dates of Birth</span>
        <label class="toggle"><input type="checkbox" id="pii-date_of_birth" onchange="savePIIConfig()"><span class="slider"></span></label>
      </div>
    </div>

    <!-- PII Test -->
    <div class="card">
      <h3>Test PII Detection</h3>
      <textarea id="piiTestInput" placeholder="Enter text to test PII detection, e.g.: Contact john@example.com at 192.168.1.1, SSN 123-45-6789"></textarea>
      <button class="btn btn-primary" onclick="testPII()">Test</button>
      <div id="piiTestResult" style="margin-top:12px;"></div>
    </div>
  </div>

  <!-- A/B TESTING TAB -->
  <div class="tab-content" id="tab-ab">
    <h2>A/B & Canary Testing</h2>

    <div class="card">
      <div class="card-header">
        <h3>Settings</h3>
        <label class="toggle">
          <input type="checkbox" id="abEnabled" onchange="saveABConfig()">
          <span class="slider"></span>
        </label>
      </div>

      <h3 style="margin-bottom:8px;">Tool Registry</h3>
      <div>
        <label>Registry Base URL</label>
        <input type="text" id="registryUrl" placeholder="https://api.example.com">
      </div>
      <div>
        <label>API Key <span style="font-weight:400;color:var(--text-muted);">(optional)</span></label>
        <input type="password" id="registryKey" placeholder="Optional - for authenticated registries">
      </div>
      <button class="btn btn-outline btn-sm" onclick="fetchRegistryTools()">Fetch Available Tools</button>
      <div id="registryTools" style="margin-top:12px;"></div>
    </div>

    <!-- Experiments -->
    <div class="card">
      <div class="card-header">
        <h3>Experiments</h3>
        <button class="btn btn-primary btn-sm" onclick="addExperiment()">+ Add Experiment</button>
      </div>
      <div id="experiments"></div>
    </div>

    <!-- Stats -->
    <div class="card">
      <div class="card-header">
        <h3>Statistics</h3>
        <div class="btn-group">
          <button class="btn btn-outline btn-sm" onclick="refreshABStats()">Refresh</button>
          <button class="btn btn-danger btn-sm" onclick="resetABStats()">Reset</button>
        </div>
      </div>
      <div id="abStats"></div>
    </div>
  </div>

  <!-- LOGS TAB -->
  <div class="tab-content" id="tab-logs">
    <h2>Request Logs</h2>
    <div class="card">
      <div class="card-header">
        <h3>Recent Requests</h3>
        <div class="btn-group">
          <button class="btn btn-outline btn-sm" onclick="refreshLogs()">Refresh</button>
          <button class="btn btn-danger btn-sm" onclick="clearLogs()">Clear All</button>
        </div>
      </div>
      <div id="logEntries" style="max-height:600px; overflow-y:auto;"></div>
    </div>
  </div>

  <!-- CONFIG TAB -->
  <div class="tab-content" id="tab-config">
    <h2>Raw Configuration</h2>

    <div class="card">
      <div class="card-header">
        <h3>Server Status</h3>
        <button class="btn btn-outline btn-sm" onclick="refreshStatus()">Refresh</button>
      </div>
      <div id="serverStatus"></div>
    </div>

    <div class="card">
      <div class="card-header">
        <h3>YAML Configuration</h3>
        <div class="btn-group">
          <button class="btn btn-primary btn-sm" onclick="applyRawConfig()">Apply</button>
          <button class="btn btn-outline btn-sm" onclick="saveToFile()">Save to File</button>
        </div>
      </div>
      <textarea id="rawConfig" style="min-height:400px; font-family: 'SF Mono', 'Consolas', monospace; font-size: 13px;"></textarea>
    </div>
  </div>
</div>

<script>
let config = {};

// Tab switching
document.querySelectorAll('.sidebar nav a').forEach(a => {
  a.addEventListener('click', e => {
    e.preventDefault();
    document.querySelectorAll('.sidebar nav a').forEach(x => x.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(x => x.classList.remove('active'));
    a.classList.add('active');
    document.getElementById('tab-' + a.dataset.tab).classList.add('active');
    if (a.dataset.tab === 'logs') refreshLogs();
    if (a.dataset.tab === 'ab') refreshABStats();
    if (a.dataset.tab === 'config') { refreshStatus(); refreshRawConfig(); }
  });
});

// Toast notifications
function showToast(msg, type='success') {
  const toast = document.createElement('div');
  toast.className = 'toast toast-' + type;
  toast.textContent = msg;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 3000);
}

// API helpers
async function api(method, path, body) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch('/api' + path, opts);
  return res.json();
}

// Load config on startup
async function loadConfig() {
  config = await api('GET', '/config');
  renderAll();
}

function renderAll() {
  renderAccessRules();
  renderPreRules();
  renderPostRules();
  renderPII();
  renderAB();
}

// ==================== ACCESS RULES ====================
function renderAccessRules() {
  if (!config.access) return;
  document.getElementById('accessDefaultAction').value = config.access.default_action || 'allow';
  const container = document.getElementById('accessRules');
  const rules = config.access.rules || [];
  if (rules.length === 0) {
    container.innerHTML = '<p style="color:var(--text-muted);font-size:13px;">No rules configured. Default action applies to all tools.</p>';
    return;
  }
  container.innerHTML = rules.map((r, i) => ` + "`" + `
    <div class="rule-item" id="accessRule-${i}">
      <div class="rule-action">
        <button class="btn btn-outline btn-sm" onclick="editAccessRule(${i})">Edit</button>
        <button class="btn btn-danger btn-sm" onclick="removeAccessRule(${i})">Remove</button>
      </div>
      <div class="grid-3">
        <div><span class="rule-field">User</span><br><span class="rule-value">${escapeHtml(r.user_id || '*')}</span></div>
        <div><span class="rule-field">Toolkit</span><br><span class="rule-value">${escapeHtml(r.toolkit || '*')}</span></div>
        <div><span class="rule-field">Tool</span><br><span class="rule-value">${escapeHtml(r.tool || '*')}</span></div>
      </div>
      <div style="margin-top:8px;">
        <span class="badge ${r.action==='deny'?'badge-danger':'badge-success'}">${r.action}</span>
        ${r.reason ? '<span style="margin-left:8px;font-size:12px;color:var(--text-muted);">'+escapeHtml(r.reason)+'</span>' : ''}
      </div>
    </div>
  ` + "`" + `).join('');
}

function cancelInlineForm(el) {
  const form = el.closest('.inline-form');
  // Determine which container this form lives in to re-render after cancelling an edit
  const inAccess = form.closest('#accessRules');
  const inPre = form.closest('#preRules');
  const inPost = form.closest('#postRules');
  const inExp = form.closest('#experiments');
  form.remove();
  if (inAccess) renderAccessRules();
  else if (inPre) renderPreRules();
  else if (inPost) renderPostRules();
  else if (inExp) renderExperiments();
}

function accessRuleFormHTML(prefix, title, btnLabel, saveFn, r) {
  r = r || {};
  return '<h4>' + title + '</h4>'
    + '<div class="form-row"><div><label>User ID</label><input type="text" id="' + prefix + '_userId" value="' + escapeAttr(r.user_id||'') + '" placeholder="Empty for any, prefix ~ for regex"></div>'
    + '<div><label>Toolkit Pattern</label><input type="text" id="' + prefix + '_toolkit" value="' + escapeAttr(r.toolkit||'') + '" placeholder="Empty for any"></div></div>'
    + '<div class="form-row"><div><label>Tool Pattern</label><input type="text" id="' + prefix + '_tool" value="' + escapeAttr(r.tool||'') + '" placeholder="Empty for any"></div>'
    + '<div><label>Action</label><select id="' + prefix + '_action"><option value="deny"' + (r.action==='deny'?' selected':'') + '>Deny</option><option value="allow"' + (r.action==='allow'?' selected':'') + '>Allow</option></select></div></div>'
    + '<div><label>Reason</label><input type="text" id="' + prefix + '_reason" value="' + escapeAttr(r.reason||'') + '" placeholder="Optional reason for this rule"></div>'
    + '<div class="form-actions"><button class="btn btn-primary btn-sm" onclick="' + saveFn + '">' + btnLabel + '</button>'
    + '<button class="btn btn-outline btn-sm" onclick="cancelInlineForm(this)">Cancel</button></div>';
}

function addAccessRule() {
  if (!config.access) config.access = { default_action: 'allow', rules: [] };
  if (!config.access.rules) config.access.rules = [];
  const container = document.getElementById('accessRules');
  const existing = container.querySelector('.inline-form');
  if (existing) { existing.remove(); return; }
  const form = document.createElement('div');
  form.className = 'inline-form';
  form.innerHTML = accessRuleFormHTML('newAccess', 'New Access Rule', 'Add Rule', 'saveNewAccessRule()');
  container.insertBefore(form, container.firstChild);
  form.querySelector('input').focus();
}

function saveNewAccessRule() {
  const uid = document.getElementById('newAccess_userId').value;
  const toolkit = document.getElementById('newAccess_toolkit').value;
  const tool = document.getElementById('newAccess_tool').value;
  const action = document.getElementById('newAccess_action').value;
  const reason = document.getElementById('newAccess_reason').value;
  config.access.rules.push({ user_id: uid, toolkit, tool, action, reason });
  renderAccessRules();
}

function editAccessRule(i) {
  const container = document.getElementById('accessRules');
  const existing = container.querySelector('.inline-form');
  if (existing) existing.remove();
  const r = config.access.rules[i];
  const el = document.getElementById('accessRule-' + i);
  const form = document.createElement('div');
  form.className = 'inline-form';
  form.innerHTML = accessRuleFormHTML('editAccess', 'Edit Access Rule', 'Save', 'saveEditAccessRule(' + i + ')', r);
  el.replaceWith(form);
  form.querySelector('input').focus();
}

function saveEditAccessRule(i) {
  config.access.rules[i] = {
    user_id: document.getElementById('editAccess_userId').value,
    toolkit: document.getElementById('editAccess_toolkit').value,
    tool: document.getElementById('editAccess_tool').value,
    action: document.getElementById('editAccess_action').value,
    reason: document.getElementById('editAccess_reason').value
  };
  renderAccessRules();
}

function removeAccessRule(i) {
  config.access.rules.splice(i, 1);
  renderAccessRules();
}

function updateAccessDefault() {
  if (!config.access) config.access = { default_action: 'allow', rules: [] };
  config.access.default_action = document.getElementById('accessDefaultAction').value;
}

// ==================== PRE RULES ====================
function renderPreRules() {
  if (!config.pre) return;
  document.getElementById('preDefaultAction').value = config.pre.default_action || 'proceed';
  const container = document.getElementById('preRules');
  const rules = config.pre.rules || [];
  if (rules.length === 0) {
    container.innerHTML = '<p style="color:var(--text-muted);font-size:13px;">No pre-execution rules configured.</p>';
    return;
  }
  container.innerHTML = rules.map((r, i) => ` + "`" + `
    <div class="rule-item" id="preRule-${i}">
      <div class="rule-action">
        <button class="btn btn-outline btn-sm" onclick="editPreRule(${i})">Edit</button>
        <button class="btn btn-danger btn-sm" onclick="removePreRule(${i})">Remove</button>
      </div>
      <div class="grid-3">
        <div><span class="rule-field">Toolkit</span><br><span class="rule-value">${escapeHtml(r.toolkit || '*')}</span></div>
        <div><span class="rule-field">Tool</span><br><span class="rule-value">${escapeHtml(r.tool || '*')}</span></div>
        <div><span class="rule-field">Action</span><br><span class="badge ${r.action==='block'?'badge-danger':r.action==='rate_limit'?'badge-warning':'badge-success'}">${r.action}</span></div>
      </div>
      ${r.input_match ? '<div style="margin-top:4px;"><span class="rule-field">Input Match:</span> <code>'+escapeHtml(r.input_match)+'</code></div>' : ''}
      ${r.error_message ? '<div style="margin-top:4px;font-size:12px;color:var(--danger);">'+escapeHtml(r.error_message)+'</div>' : ''}
    </div>
  ` + "`" + `).join('');
}

function preRuleFormHTML(prefix, title, btnLabel, saveFn, r) {
  r = r || {};
  const selBlock = r.action==='block'?' selected':'';
  const selProceed = r.action==='proceed'||!r.action?' selected':'';
  const selRate = r.action==='rate_limit'?' selected':'';
  return '<h4>' + title + '</h4>'
    + '<div class="form-row"><div><label>Toolkit Pattern</label><input type="text" id="' + prefix + '_toolkit" value="' + escapeAttr(r.toolkit||'') + '" placeholder="Empty for any"></div>'
    + '<div><label>Tool Pattern</label><input type="text" id="' + prefix + '_tool" value="' + escapeAttr(r.tool||'') + '" placeholder="Empty for any"></div></div>'
    + '<div class="form-row"><div><label>Action</label><select id="' + prefix + '_action"><option value="block"' + selBlock + '>Block</option><option value="proceed"' + selProceed + '>Proceed</option><option value="rate_limit"' + selRate + '>Rate Limit</option></select></div>'
    + '<div><label>Input Match Expression</label><input type="text" id="' + prefix + '_inputMatch" value="' + escapeAttr(r.input_match||'') + '" placeholder="Optional, e.g. field contains value"></div></div>'
    + '<div><label>Error Message</label><input type="text" id="' + prefix + '_errorMsg" value="' + escapeAttr(r.error_message||'') + '" placeholder="Optional error message when rule triggers"></div>'
    + '<div class="form-actions"><button class="btn btn-primary btn-sm" onclick="' + saveFn + '">' + btnLabel + '</button>'
    + '<button class="btn btn-outline btn-sm" onclick="cancelInlineForm(this)">Cancel</button></div>';
}

function addPreRule() {
  if (!config.pre) config.pre = { default_action: 'proceed', rules: [] };
  if (!config.pre.rules) config.pre.rules = [];
  const container = document.getElementById('preRules');
  const existing = container.querySelector('.inline-form');
  if (existing) { existing.remove(); return; }
  const form = document.createElement('div');
  form.className = 'inline-form';
  form.innerHTML = preRuleFormHTML('newPre', 'New Pre-Execution Rule', 'Add Rule', 'saveNewPreRule()');
  container.insertBefore(form, container.firstChild);
  form.querySelector('input').focus();
}

function saveNewPreRule() {
  const toolkit = document.getElementById('newPre_toolkit').value;
  const tool = document.getElementById('newPre_tool').value;
  const action = document.getElementById('newPre_action').value;
  const inputMatch = document.getElementById('newPre_inputMatch').value;
  const errorMsg = document.getElementById('newPre_errorMsg').value;
  const rule = { toolkit, tool, action };
  if (inputMatch) rule.input_match = inputMatch;
  if (errorMsg) rule.error_message = errorMsg;
  config.pre.rules.push(rule);
  renderPreRules();
}

function editPreRule(i) {
  const container = document.getElementById('preRules');
  const existing = container.querySelector('.inline-form');
  if (existing) existing.remove();
  const r = config.pre.rules[i];
  const el = document.getElementById('preRule-' + i);
  const form = document.createElement('div');
  form.className = 'inline-form';
  form.innerHTML = preRuleFormHTML('editPre', 'Edit Pre-Execution Rule', 'Save', 'saveEditPreRule(' + i + ')', r);
  el.replaceWith(form);
  form.querySelector('input').focus();
}

function saveEditPreRule(i) {
  const rule = {
    toolkit: document.getElementById('editPre_toolkit').value,
    tool: document.getElementById('editPre_tool').value,
    action: document.getElementById('editPre_action').value
  };
  const inputMatch = document.getElementById('editPre_inputMatch').value;
  const errorMsg = document.getElementById('editPre_errorMsg').value;
  if (inputMatch) rule.input_match = inputMatch;
  if (errorMsg) rule.error_message = errorMsg;
  config.pre.rules[i] = rule;
  renderPreRules();
}

function removePreRule(i) {
  config.pre.rules.splice(i, 1);
  renderPreRules();
}

function updatePreDefault() {
  if (!config.pre) config.pre = { default_action: 'proceed', rules: [] };
  config.pre.default_action = document.getElementById('preDefaultAction').value;
}

// ==================== POST RULES ====================
function renderPostRules() {
  if (!config.post) return;
  document.getElementById('postDefaultAction').value = config.post.default_action || 'proceed';
  const container = document.getElementById('postRules');
  const rules = config.post.rules || [];
  if (rules.length === 0) {
    container.innerHTML = '<p style="color:var(--text-muted);font-size:13px;">No post-execution rules configured.</p>';
    return;
  }
  container.innerHTML = rules.map((r, i) => ` + "`" + `
    <div class="rule-item" id="postRule-${i}">
      <div class="rule-action">
        <button class="btn btn-outline btn-sm" onclick="editPostRule(${i})">Edit</button>
        <button class="btn btn-danger btn-sm" onclick="removePostRule(${i})">Remove</button>
      </div>
      <div class="grid-3">
        <div><span class="rule-field">Toolkit</span><br><span class="rule-value">${escapeHtml(r.toolkit || '*')}</span></div>
        <div><span class="rule-field">Tool</span><br><span class="rule-value">${escapeHtml(r.tool || '*')}</span></div>
        <div><span class="rule-field">Action</span><br><span class="badge ${r.action==='block'?'badge-danger':'badge-success'}">${r.action}</span></div>
      </div>
      ${r.output_match ? '<div style="margin-top:4px;"><span class="rule-field">Output Match:</span> <code>'+escapeHtml(r.output_match)+'</code></div>' : ''}
    </div>
  ` + "`" + `).join('');
}

function postRuleFormHTML(prefix, title, btnLabel, saveFn, r) {
  r = r || {};
  const selProceed = r.action==='proceed'||!r.action?' selected':'';
  const selBlock = r.action==='block'?' selected':'';
  return '<h4>' + title + '</h4>'
    + '<div class="form-row"><div><label>Toolkit Pattern</label><input type="text" id="' + prefix + '_toolkit" value="' + escapeAttr(r.toolkit||'') + '" placeholder="Empty for any"></div>'
    + '<div><label>Tool Pattern</label><input type="text" id="' + prefix + '_tool" value="' + escapeAttr(r.tool||'') + '" placeholder="Empty for any"></div></div>'
    + '<div class="form-row"><div><label>Action</label><select id="' + prefix + '_action"><option value="proceed"' + selProceed + '>Proceed</option><option value="block"' + selBlock + '>Block</option></select></div>'
    + '<div><label>Output Match Expression</label><input type="text" id="' + prefix + '_outputMatch" value="' + escapeAttr(r.output_match||'') + '" placeholder="Optional, e.g. field contains value"></div></div>'
    + '<div class="form-actions"><button class="btn btn-primary btn-sm" onclick="' + saveFn + '">' + btnLabel + '</button>'
    + '<button class="btn btn-outline btn-sm" onclick="cancelInlineForm(this)">Cancel</button></div>';
}

function addPostRule() {
  if (!config.post) config.post = { default_action: 'proceed', rules: [] };
  if (!config.post.rules) config.post.rules = [];
  const container = document.getElementById('postRules');
  const existing = container.querySelector('.inline-form');
  if (existing) { existing.remove(); return; }
  const form = document.createElement('div');
  form.className = 'inline-form';
  form.innerHTML = postRuleFormHTML('newPost', 'New Post-Execution Rule', 'Add Rule', 'saveNewPostRule()');
  container.insertBefore(form, container.firstChild);
  form.querySelector('input').focus();
}

function saveNewPostRule() {
  const toolkit = document.getElementById('newPost_toolkit').value;
  const tool = document.getElementById('newPost_tool').value;
  const action = document.getElementById('newPost_action').value;
  const outputMatch = document.getElementById('newPost_outputMatch').value;
  const rule = { toolkit, tool, action };
  if (outputMatch) rule.output_match = outputMatch;
  config.post.rules.push(rule);
  renderPostRules();
}

function editPostRule(i) {
  const container = document.getElementById('postRules');
  const existing = container.querySelector('.inline-form');
  if (existing) existing.remove();
  const r = config.post.rules[i];
  const el = document.getElementById('postRule-' + i);
  const form = document.createElement('div');
  form.className = 'inline-form';
  form.innerHTML = postRuleFormHTML('editPost', 'Edit Post-Execution Rule', 'Save', 'saveEditPostRule(' + i + ')', r);
  el.replaceWith(form);
  form.querySelector('input').focus();
}

function saveEditPostRule(i) {
  const rule = {
    toolkit: document.getElementById('editPost_toolkit').value,
    tool: document.getElementById('editPost_tool').value,
    action: document.getElementById('editPost_action').value
  };
  const outputMatch = document.getElementById('editPost_outputMatch').value;
  if (outputMatch) rule.output_match = outputMatch;
  config.post.rules[i] = rule;
  renderPostRules();
}

function removePostRule(i) {
  config.post.rules.splice(i, 1);
  renderPostRules();
}

function updatePostDefault() {
  if (!config.post) config.post = { default_action: 'proceed', rules: [] };
  config.post.default_action = document.getElementById('postDefaultAction').value;
}

// ==================== PII ====================
function renderPII() {
  if (!config.pii) config.pii = { enabled: false, action: 'redact', types: {} };
  document.getElementById('piiEnabled').checked = config.pii.enabled;
  document.getElementById('piiAction').value = config.pii.action || 'redact';
  const types = config.pii.types || {};
  ['email','ipv4','ssn','phone','credit_card','date_of_birth'].forEach(t => {
    const el = document.getElementById('pii-' + t);
    if (el) el.checked = !!types[t];
  });
}

async function savePIIConfig() {
  const types = {};
  ['email','ipv4','ssn','phone','credit_card','date_of_birth'].forEach(t => {
    const el = document.getElementById('pii-' + t);
    if (el) types[t] = el.checked;
  });
  config.pii = {
    enabled: document.getElementById('piiEnabled').checked,
    action: document.getElementById('piiAction').value,
    types: types,
    custom: (config.pii && config.pii.custom) || []
  };
  await saveConfig();
}

async function testPII() {
  const text = document.getElementById('piiTestInput').value;
  if (!text) return;
  const result = await api('POST', '/pii/test', { text });
  const el = document.getElementById('piiTestResult');
  if (result.scan && result.scan.contains_pii) {
    let html = '<div style="margin-bottom:8px;"><span class="badge badge-danger">PII Detected</span></div>';
    html += '<div style="margin-bottom:8px;"><strong>Redacted:</strong> <code>' + escapeHtml(result.redacted) + '</code></div>';
    html += '<table><tr><th>Type</th><th>Value Found</th></tr>';
    (result.scan.matches || []).forEach(m => {
      html += '<tr><td><span class="badge badge-warning">' + m.type + '</span></td><td><code>' + escapeHtml(m.value) + '</code></td></tr>';
    });
    html += '</table>';
    el.innerHTML = html;
  } else {
    el.innerHTML = '<span class="badge badge-success">No PII detected</span>';
  }
}

// ==================== A/B TESTING ====================
function renderAB() {
  if (!config.ab_testing) config.ab_testing = { enabled: false, tool_registry: {}, experiments: [] };
  document.getElementById('abEnabled').checked = config.ab_testing.enabled;
  document.getElementById('registryUrl').value = (config.ab_testing.tool_registry || {}).base_url || '';
  document.getElementById('registryKey').value = (config.ab_testing.tool_registry || {}).api_key || '';
  renderExperiments();
}

function renderExperiments() {
  const container = document.getElementById('experiments');
  const exps = (config.ab_testing && config.ab_testing.experiments) || [];
  if (exps.length === 0) {
    container.innerHTML = '<p style="color:var(--text-muted);font-size:13px;">No experiments configured.</p>';
    return;
  }
  container.innerHTML = exps.map((e, i) => ` + "`" + `
    <div class="rule-item" id="experiment-${i}">
      <div class="rule-action">
        <button class="btn btn-outline btn-sm" onclick="editExperiment(${i})">Edit</button>
        <button class="btn btn-danger btn-sm" onclick="removeExperiment(${i})">Remove</button>
      </div>
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">
        <strong>${escapeHtml(e.name)}</strong>
        <span class="badge ${e.enabled?'badge-success':'badge-danger'}">${e.enabled?'Active':'Inactive'}</span>
        <span class="badge badge-info">${e.mode || 'ab'}</span>
      </div>
      <div class="grid-2">
        <div><span class="rule-field">Toolkit:</span> ${escapeHtml(e.toolkit)}</div>
        <div><span class="rule-field">Tool:</span> ${escapeHtml(e.tool)}</div>
      </div>
      <div style="margin-top:8px;">
        <span class="rule-field">Variants:</span>
        <div style="display:flex;gap:8px;margin-top:4px;flex-wrap:wrap;">
          ${(e.variants||[]).map(v => ` + "`" + `
            <div style="background:var(--card-bg);border:1px solid var(--border);border-radius:4px;padding:6px 10px;font-size:12px;">
              <strong>${escapeHtml(v.name)}</strong> (${v.weight}%)
              ${v.version ? '<br>v' + escapeHtml(v.version) : ''}
              ${v.server ? '<br>' + escapeHtml(v.server.uri) : ''}
            </div>
          ` + "`" + `).join('')}
        </div>
      </div>
    </div>
  ` + "`" + `).join('');
}

function experimentFormHTML(prefix, title, btnLabel, saveFn, e) {
  e = e || {};
  const v1 = (e.variants && e.variants[0]) || {};
  const v2 = (e.variants && e.variants[1]) || {};
  const modeAb = (e.mode||'ab')==='ab'?' selected':'';
  const modeCanary = e.mode==='canary'?' selected':'';
  const enabledYes = e.enabled!==false?' selected':'';
  const enabledNo = e.enabled===false?' selected':'';
  return '<h4>' + title + '</h4>'
    + '<div class="form-row"><div><label>Experiment Name</label><input type="text" id="' + prefix + '_name" value="' + escapeAttr(e.name||'') + '" placeholder="e.g. my-experiment"></div>'
    + '<div><label>Mode</label><select id="' + prefix + '_mode"><option value="ab"' + modeAb + '>A/B Test</option><option value="canary"' + modeCanary + '>Canary</option></select></div></div>'
    + '<div class="form-row"><div><label>Toolkit Pattern</label><input type="text" id="' + prefix + '_toolkit" value="' + escapeAttr(e.toolkit||'*') + '" placeholder="* for any"></div>'
    + '<div><label>Tool Pattern</label><input type="text" id="' + prefix + '_tool" value="' + escapeAttr(e.tool||'*') + '" placeholder="* for any"></div></div>'
    + '<div class="form-row"><div><label>Enabled</label><select id="' + prefix + '_enabled"><option value="true"' + enabledYes + '>Yes</option><option value="false"' + enabledNo + '>No</option></select></div><div></div></div>'
    + '<div class="form-section"><div class="form-section-title">Variant 1 (Control)</div>'
    + '<div class="form-row-3"><div><label>Name</label><input type="text" id="' + prefix + '_v1name" value="' + escapeAttr(v1.name||'control') + '"></div>'
    + '<div><label>Weight (0-100)</label><input type="number" id="' + prefix + '_v1weight" value="' + (v1.weight!=null?v1.weight:80) + '" min="0" max="100"></div>'
    + '<div><label>Version</label><input type="text" id="' + prefix + '_v1version" value="' + escapeAttr(v1.version||'') + '" placeholder="Optional"></div></div></div>'
    + '<div class="form-section"><div class="form-section-title">Variant 2 (Treatment)</div>'
    + '<div class="form-row-3"><div><label>Name</label><input type="text" id="' + prefix + '_v2name" value="' + escapeAttr(v2.name||'treatment') + '"></div>'
    + '<div><label>Weight (0-100)</label><input type="number" id="' + prefix + '_v2weight" value="' + (v2.weight!=null?v2.weight:20) + '" min="0" max="100"></div>'
    + '<div><label>Version</label><input type="text" id="' + prefix + '_v2version" value="' + escapeAttr(v2.version||'') + '" placeholder="Optional"></div></div>'
    + '<div><label>Server URI</label><input type="text" id="' + prefix + '_v2uri" value="' + escapeAttr((v2.server&&v2.server.uri)||'') + '" placeholder="Optional - route to different server"></div></div>'
    + '<div class="form-actions"><button class="btn btn-primary btn-sm" onclick="' + saveFn + '">' + btnLabel + '</button>'
    + '<button class="btn btn-outline btn-sm" onclick="cancelInlineForm(this)">Cancel</button></div>';
}

function collectExperimentFromForm(prefix) {
  const name = document.getElementById(prefix + '_name').value;
  if (!name) { showToast('Experiment name is required', 'error'); return null; }
  const toolkit = document.getElementById(prefix + '_toolkit').value || '*';
  const tool = document.getElementById(prefix + '_tool').value || '*';
  const mode = document.getElementById(prefix + '_mode').value;
  const enabled = document.getElementById(prefix + '_enabled').value === 'true';

  const variants = [];
  const v1Name = document.getElementById(prefix + '_v1name').value || 'control';
  const v1Weight = parseInt(document.getElementById(prefix + '_v1weight').value) || 80;
  const v1Version = document.getElementById(prefix + '_v1version').value;
  variants.push({ name: v1Name, weight: v1Weight, version: v1Version });

  const v2Name = document.getElementById(prefix + '_v2name').value || 'treatment';
  const v2Weight = parseInt(document.getElementById(prefix + '_v2weight').value) || 20;
  const v2Version = document.getElementById(prefix + '_v2version').value;
  const v2Uri = document.getElementById(prefix + '_v2uri').value;
  const v2 = { name: v2Name, weight: v2Weight, version: v2Version };
  if (v2Uri) v2.server = { name: v2Name, uri: v2Uri, type: 'arcade' };
  variants.push(v2);

  return { name, enabled, toolkit, tool, mode, variants };
}

function addExperiment() {
  if (!config.ab_testing) config.ab_testing = { enabled: false, experiments: [] };
  if (!config.ab_testing.experiments) config.ab_testing.experiments = [];
  const container = document.getElementById('experiments');
  const existing = container.querySelector('.inline-form');
  if (existing) { existing.remove(); return; }
  const form = document.createElement('div');
  form.className = 'inline-form';
  form.innerHTML = experimentFormHTML('newExp', 'New Experiment', 'Add Experiment', 'saveNewExperiment()');
  container.insertBefore(form, container.firstChild);
  form.querySelector('input').focus();
}

function saveNewExperiment() {
  const exp = collectExperimentFromForm('newExp');
  if (!exp) return;
  config.ab_testing.experiments.push(exp);
  renderExperiments();
}

function editExperiment(i) {
  const container = document.getElementById('experiments');
  const existing = container.querySelector('.inline-form');
  if (existing) existing.remove();
  const e = config.ab_testing.experiments[i];
  const el = document.getElementById('experiment-' + i);
  const form = document.createElement('div');
  form.className = 'inline-form';
  form.innerHTML = experimentFormHTML('editExp', 'Edit Experiment', 'Save', 'saveEditExperiment(' + i + ')', e);
  el.replaceWith(form);
  form.querySelector('input').focus();
}

function saveEditExperiment(i) {
  const exp = collectExperimentFromForm('editExp');
  if (!exp) return;
  config.ab_testing.experiments[i] = exp;
  renderExperiments();
}

function removeExperiment(i) {
  config.ab_testing.experiments.splice(i, 1);
  renderExperiments();
}

async function saveABConfig() {
  config.ab_testing = config.ab_testing || {};
  config.ab_testing.enabled = document.getElementById('abEnabled').checked;
  config.ab_testing.tool_registry = {
    base_url: document.getElementById('registryUrl').value,
    api_key: document.getElementById('registryKey').value
  };
  await saveConfig();
}

async function fetchRegistryTools() {
  // Save registry config first
  config.ab_testing = config.ab_testing || {};
  config.ab_testing.tool_registry = {
    base_url: document.getElementById('registryUrl').value,
    api_key: document.getElementById('registryKey').value
  };
  await api('PUT', '/config', config);

  const el = document.getElementById('registryTools');
  el.innerHTML = '<p style="color:var(--text-muted);">Fetching tools...</p>';
  try {
    const result = await api('POST', '/registry/fetch');
    if (result.error) {
      el.innerHTML = '<p style="color:var(--danger);">' + escapeHtml(result.error) + '</p>';
      return;
    }
    if (!result.tools || result.tools.length === 0) {
      el.innerHTML = '<p style="color:var(--text-muted);">No tools found.</p>';
      return;
    }
    let html = '<p style="color:var(--text-muted);font-size:12px;margin-bottom:8px;">' + result.tools.length + ' tools found</p>';
    html += '<table><tr><th>Toolkit</th><th>Tool</th><th>Description</th><th>Versions</th></tr>';
    result.tools.forEach(t => {
      const desc = t.description ? (t.description.length > 80 ? t.description.substring(0, 80) + '...' : t.description) : '';
      html += '<tr><td>' + escapeHtml(t.toolkit) + '</td><td><strong>' + escapeHtml(t.name) + '</strong></td><td style="color:var(--text-muted);font-size:12px;">' + escapeHtml(desc) + '</td><td>' + (t.versions||[]).join(', ') + '</td></tr>';
    });
    html += '</table>';
    el.innerHTML = html;
  } catch (err) {
    el.innerHTML = '<p style="color:var(--danger);">Failed to fetch: ' + err.message + '</p>';
  }
}

async function refreshABStats() {
  const stats = await api('GET', '/ab/stats');
  const el = document.getElementById('abStats');
  const entries = Object.values(stats);
  if (entries.length === 0) {
    el.innerHTML = '<p style="color:var(--text-muted);font-size:13px;">No experiment data yet.</p>';
    return;
  }
  let html = '<p style="color:var(--text-muted);font-size:11px;margin-bottom:12px;">Consistent hashing: the same user always receives the same variant. Distribution only appears with multiple distinct users.</p>';
  entries.forEach(s => {
    html += '<div style="margin-bottom:12px;"><strong>' + escapeHtml(s.name) + '</strong> - ' + s.total_requests + ' total requests';
    if (s.last_request_time) html += ' (last: ' + new Date(s.last_request_time).toLocaleString() + ')';
    html += '<div class="stat-grid" style="margin-top:8px;">';
    const users = s.variant_users || {};
    Object.entries(s.variant_counts || {}).forEach(([name, count]) => {
      const pct = s.total_requests > 0 ? Math.round(count / s.total_requests * 100) : 0;
      const uCount = users[name] || 0;
      html += '<div class="stat-card"><div class="stat-value">' + pct + '%</div><div class="stat-label">' + escapeHtml(name) + '</div><div style="font-size:11px;color:var(--text-muted);">' + count + ' reqs &middot; ' + uCount + ' user' + (uCount !== 1 ? 's' : '') + '</div></div>';
    });
    html += '</div></div>';
  });
  el.innerHTML = html;
}

async function resetABStats() {
  await api('DELETE', '/ab/stats');
  showToast('A/B stats reset');
  refreshABStats();
}

// ==================== LOGS ====================
async function refreshLogs() {
  const result = await api('GET', '/logs');
  const el = document.getElementById('logEntries');
  const logs = (result.logs || []).reverse();
  if (logs.length === 0) {
    el.innerHTML = '<p style="color:var(--text-muted);font-size:13px;">No requests logged yet.</p>';
    return;
  }
  el.innerHTML = logs.map((l, i) => {
    const cls = l.endpoint.includes('access') ? 'log-access' : l.endpoint.includes('pre') ? 'log-pre' : l.endpoint.includes('post') ? 'log-post' : 'log-health';
    let badges = '';
    if (l.rule_match) badges += '<span class="badge badge-info">' + l.rule_match + '</span> ';
    if (l.pii_found) badges += '<span class="badge badge-warning">PII</span> ';
    if (l.ab_variant) badges += '<span class="badge badge-info">A/B: ' + l.ab_variant + '</span> ';

    const bodyJson = l.body ? JSON.stringify(l.body, null, 2) : null;
    const respJson = l.response ? JSON.stringify(l.response, null, 2) : null;

    let bodyHtml = '<div class="log-body">';
    if (bodyJson) {
      bodyHtml += '<div class="log-body-section"><div class="log-body-label">Request Body</div><pre class="log-body-json">' + escapeHtml(bodyJson) + '</pre></div>';
    }
    if (respJson) {
      bodyHtml += '<div class="log-body-section"><div class="log-body-label">Response</div><pre class="log-body-json">' + escapeHtml(respJson) + '</pre></div>';
    }
    if (!bodyJson && !respJson) {
      bodyHtml += '<div style="color:var(--text-muted);font-size:12px;">No request/response data recorded.</div>';
    }
    bodyHtml += '</div>';

    return '<div class="log-entry ' + cls + '" onclick="this.classList.toggle(\'expanded\')">'
      + '<div class="log-summary">'
      + '<span class="log-time">' + new Date(l.timestamp).toLocaleTimeString() + '</span>'
      + '<span class="log-endpoint">' + l.endpoint + '</span>'
      + badges
      + '<span class="log-expand-icon">&#9654;</span>'
      + '</div>'
      + bodyHtml
      + '</div>';
  }).join('');
}

async function clearLogs() {
  await api('DELETE', '/logs');
  showToast('Logs cleared');
  refreshLogs();
}

// ==================== CONFIG ====================
async function saveConfig() {
  const result = await api('PUT', '/config', config);
  if (result.message) {
    showToast('Configuration saved');
  } else {
    showToast('Error saving config', 'error');
  }
}

async function refreshRawConfig() {
  const cfg = await api('GET', '/config');
  document.getElementById('rawConfig').value = JSON.stringify(cfg, null, 2);
}

async function applyRawConfig() {
  try {
    const raw = document.getElementById('rawConfig').value;
    const cfg = JSON.parse(raw);
    config = cfg;
    await saveConfig();
    renderAll();
    showToast('Configuration applied');
  } catch (e) {
    showToast('Invalid JSON: ' + e.message, 'error');
  }
}

async function saveToFile() {
  const result = await api('POST', '/config/save');
  if (result.message) showToast(result.message);
  else showToast('Failed to save', 'error');
}

async function refreshStatus() {
  const status = await api('GET', '/status');
  const el = document.getElementById('serverStatus');
  el.innerHTML = '<div class="stat-grid">' +
    '<div class="stat-card"><div class="stat-value">' + status.port + '</div><div class="stat-label">Port</div></div>' +
    '<div class="stat-card"><div class="stat-value">' + (status.pii_enabled ? 'On' : 'Off') + '</div><div class="stat-label">PII Redaction</div></div>' +
    '<div class="stat-card"><div class="stat-value">' + (status.ab_enabled ? 'On' : 'Off') + '</div><div class="stat-label">A/B Testing</div></div>' +
    '<div class="stat-card"><div class="stat-value">' + (status.log_count || 0) + '</div><div class="stat-label">Requests</div></div>' +
    '</div>';
  const dot = document.getElementById('statusDot');
  if (dot) { dot.className = 'status-dot online'; }
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function escapeAttr(str) {
  if (!str) return '';
  return String(str).replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/'/g,'&#39;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// Initialize
loadConfig();
</script>
</body>
</html>`
