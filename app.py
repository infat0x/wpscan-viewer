from flask import Flask, request, jsonify
import re

app = Flask(__name__)

def classify_severity(title):
    t = title.lower()
    if any(x in t for x in ['rce', 'remote code execution', 'unauthenticated sql injection',
                              'file upload', 'php file upload', 'deserialization', 'admin+ php']):
        return "critical"
    elif any(x in t for x in ['sql injection', 'sqli', 'sql in ', 'ssrf', 'arbitrary file read',
                                'arbitrary file delete', 'blind ssrf', 'price manipulation',
                                'unauthenticated shortcode', 'arbitrary shortcode execution']):
        return "high"
    elif any(x in t for x in ['xss', 'csrf', 'cross-site', 'open redirect', 'disclosure',
                                'exposure', 'traversal', 'missing authorization', 'injection',
                                'content injection', 'information exposure']):
        return "medium"
    else:
        return "low"


def parse_wpscan(raw):
    result = {
        "target": "",
        "wordpress_version": "",
        "plugins": [],
        "users": [],
        "interesting_findings": [],
        "vulnerabilities": [],
        "summary": {"total_vulns": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "plugins_found": 0}
    }

    lines = raw.splitlines()
    i = 0
    current_plugin = None

    while i < len(lines):
        line = lines[i]

        # Target URL
        if re.search(r'\[\+\] URL:', line):
            m = re.search(r'https?://[^\s\]]+', line)
            if m:
                result["target"] = m.group(0).rstrip('/')

        # WordPress version
        if 'WordPress version' in line:
            m = re.search(r'(\d+\.\d+[\.\d]*)', line)
            if m:
                result["wordpress_version"] = m.group(1)

        # Plugin block: line like "[+] plugin-slug"
        pm = re.match(r'^\[+\+\]\s+([\w\-]+)\s*$', line)
        if pm:
            pname = pm.group(1)
            current_plugin = {"name": pname, "version": "", "vulns": []}
            result["plugins"].append(current_plugin)
            result["summary"]["plugins_found"] += 1

        # Plugin version detection
        if current_plugin:
            vm = re.search(r'\|\s+Version:\s+([\d.]+)', line)
            if vm and not current_plugin["version"]:
                current_plugin["version"] = vm.group(1)
            # Also from query parameter detection
            vm2 = re.search(r'\?ver=([\d.]+)', line)
            if vm2 and not current_plugin["version"]:
                current_plugin["version"] = vm2.group(1)

        # Vulnerability title line: " | [!] Title: ..."
        if re.search(r'\[!\] Title:', line):
            title_m = re.search(r'\[!\] Title:\s*(.+)', line)
            if title_m:
                title = title_m.group(1).strip()
                vuln = {
                    "title": title,
                    "severity": classify_severity(title),
                    "fixed_in": "",
                    "references": [],
                    "plugin": current_plugin["name"] if current_plugin else "WordPress Core"
                }
                # Look ahead for Fixed in + references
                j = i + 1
                while j < len(lines) and j < i + 25:
                    sub = lines[j]
                    # Stop at next vuln title or next [+] block
                    if re.search(r'\[!\] Title:', sub):
                        break
                    if re.match(r'^\[\+\]', sub) and not re.search(r'^\s*\|', sub):
                        break
                    # Fixed in
                    fi = re.search(r'Fixed in:\s*([\d.]+)', sub)
                    if fi:
                        vuln["fixed_in"] = fi.group(1)
                    # References
                    ref = re.search(r'-\s*(https?://\S+)', sub)
                    if ref:
                        vuln["references"].append(ref.group(1))
                    j += 1

                result["vulnerabilities"].append(vuln)
                sev = vuln["severity"]
                result["summary"][sev] = result["summary"].get(sev, 0) + 1
                if current_plugin:
                    current_plugin["vulns"].append(vuln)

        # Users
        if 'Login:' in line:
            um = re.search(r'Login:\s*(\S+)', line)
            if um:
                result["users"].append(um.group(1))

        # Interesting top-level findings
        if re.match(r'^\[\+\]', line):
            skip_words = ['URL:', 'Started:', 'Enumerating', 'Checking', 'Finished',
                          'WPScan DB', 'Requests', 'Data ', 'Memory', 'Elapsed']
            if not any(s in line for s in skip_words):
                # Skip pure plugin name lines
                if not re.match(r'^\[\+\]\s+[\w\-]+\s*$', line):
                    finding = re.sub(r'^\[\+\]\s*', '', line).strip()
                    if finding and len(finding) < 300:
                        result["interesting_findings"].append(finding)

        i += 1

    result["summary"]["total_vulns"] = len(result["vulnerabilities"])
    return result


HTML_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WPScan Viewer</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #0f1117; color: #e2e8f0; font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; min-height: 100vh; }

  .header { background: #161b27; border-bottom: 1px solid #2d3748; padding: 16px 24px; display: flex; align-items: center; gap: 12px; }
  .header h1 { font-size: 18px; font-weight: 600; color: #f8f9fa; }
  .badge { background: #1a2744; color: #60a5fa; font-size: 11px; padding: 3px 8px; border-radius: 4px; border: 1px solid #2563eb44; }

  .layout { display: grid; grid-template-columns: 1fr 1fr; gap: 0; height: calc(100vh - 57px); }

  .input-panel { padding: 20px; border-right: 1px solid #2d3748; display: flex; flex-direction: column; gap: 12px; }
  .input-panel label { font-size: 12px; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600; }
  textarea { flex: 1; background: #0a0e18; border: 1px solid #2d3748; border-radius: 8px; color: #94a3b8; font-family: 'Courier New', monospace; font-size: 12px; padding: 12px; resize: none; outline: none; line-height: 1.6; width: 100%; height: calc(100vh - 180px); }
  textarea:focus { border-color: #3b82f6; }
  textarea::placeholder { color: #374151; }
  .btn { background: #2563eb; color: #fff; border: none; border-radius: 8px; padding: 10px 20px; font-size: 13px; font-weight: 600; cursor: pointer; }
  .btn:hover { background: #1d4ed8; }
  .btn-clear { background: #1e2535; color: #94a3b8; border: 1px solid #2d3748; border-radius: 8px; padding: 10px 16px; font-size: 13px; cursor: pointer; }
  .btn-clear:hover { background: #2d3748; }
  .btn-row { display: flex; gap: 8px; }

  .output-panel { overflow-y: auto; padding: 20px; display: flex; flex-direction: column; gap: 14px; }

  .placeholder { display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100%; gap: 12px; color: #374151; text-align: center; }
  .placeholder p { font-size: 13px; line-height: 1.6; }

  .summary-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 8px; }
  .stat-card { background: #161b27; border: 1px solid #2d3748; border-radius: 8px; padding: 10px 8px; text-align: center; }
  .stat-card .num { font-size: 24px; font-weight: 700; line-height: 1; margin-bottom: 4px; }
  .stat-card .lbl { font-size: 10px; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; }
  .c-total .num { color: #e2e8f0; }
  .c-critical .num { color: #f87171; }
  .c-high .num { color: #fb923c; }
  .c-medium .num { color: #fcd34d; }
  .c-low .num { color: #60a5fa; }

  .section { background: #161b27; border: 1px solid #2d3748; border-radius: 8px; overflow: hidden; }
  .sec-header { padding: 11px 16px; border-bottom: 1px solid #2d3748; display: flex; align-items: center; justify-content: space-between; cursor: pointer; user-select: none; }
  .sec-header:hover { background: #1e2535; }
  .sec-title { font-size: 13px; font-weight: 600; color: #e2e8f0; display: flex; align-items: center; gap: 8px; }
  .cnt { background: #1e2535; color: #94a3b8; font-size: 11px; padding: 2px 7px; border-radius: 10px; font-weight: 400; }
  .chev { color: #64748b; font-size: 11px; transition: transform 0.2s; }
  .chev.open { transform: rotate(180deg); }
  .sec-body { display: none; }
  .sec-body.open { display: block; }

  /* Filter row */
  .filter-row { padding: 8px 14px; border-bottom: 1px solid #1e2535; display: flex; gap: 6px; flex-wrap: wrap; background: #0f1421; }
  .fb { font-size: 11px; padding: 3px 10px; border-radius: 10px; border: 1px solid #2d3748; background: transparent; color: #94a3b8; cursor: pointer; }
  .fb:hover { background: #1e2535; }
  .fb.active { background: #2563eb; color: #fff; border-color: #2563eb; }

  /* Vuln items */
  .vuln-item { padding: 10px 14px; border-bottom: 1px solid #1a2130; }
  .vuln-item:last-child { border-bottom: none; }
  .vuln-row { display: flex; align-items: flex-start; gap: 8px; margin-bottom: 5px; }
  .sev { font-size: 10px; font-weight: 700; padding: 2px 6px; border-radius: 3px; text-transform: uppercase; white-space: nowrap; margin-top: 2px; flex-shrink: 0; }
  .sev-critical { background: #7f1d1d; color: #fca5a5; border: 1px solid #991b1b; }
  .sev-high     { background: #7c2d12; color: #fdba74; border: 1px solid #9a3412; }
  .sev-medium   { background: #78350f; color: #fcd34d; border: 1px solid #92400e; }
  .sev-low      { background: #1e3a5f; color: #93c5fd; border: 1px solid #1d4ed8; }
  .vtitle { font-size: 12px; color: #e2e8f0; font-weight: 500; line-height: 1.4; }
  .vmeta { display: flex; flex-wrap: wrap; gap: 6px; padding-left: 2px; }
  .mtag { font-size: 11px; color: #64748b; background: #0f1117; padding: 2px 7px; border-radius: 4px; border: 1px solid #2d3748; }
  .mtag a { color: #60a5fa; text-decoration: none; }
  .mtag a:hover { text-decoration: underline; }
  .fixed { color: #34d399 !important; border-color: #065f46 !important; }
  .plugin-tag { color: #a78bfa !important; border-color: #4c1d95 !important; }

  /* Plugin accordion */
  .plugin-item { border-bottom: 1px solid #1a2130; }
  .plugin-item:last-child { border-bottom: none; }
  .plugin-header { padding: 9px 14px; display: flex; align-items: center; justify-content: space-between; cursor: pointer; }
  .plugin-header:hover { background: #1a2130; }
  .plugin-name { font-size: 12px; font-weight: 600; color: #a78bfa; font-family: monospace; }
  .plugin-ver { font-size: 11px; color: #64748b; margin-left: 8px; }
  .plugin-body { display: none; padding: 0 0 4px 0; border-top: 1px solid #1a2130; }
  .plugin-body.open { display: block; }

  .finding-item { padding: 7px 14px; border-bottom: 1px solid #1a2130; font-size: 12px; color: #94a3b8; line-height: 1.5; }
  .finding-item:last-child { border-bottom: none; }
  .user-item { padding: 8px 14px; border-bottom: 1px solid #1a2130; font-size: 13px; color: #fbbf24; font-family: monospace; }
  .user-item:last-child { border-bottom: none; }
  .target-bar { background: #0f172a; border: 1px solid #2d3748; border-radius: 8px; padding: 9px 14px; font-size: 12px; color: #94a3b8; font-family: monospace; display: flex; align-items: center; gap: 8px; }
  .dot { width: 7px; height: 7px; border-radius: 50%; background: #34d399; flex-shrink: 0; }
  .empty-msg { padding: 16px; text-align: center; color: #374151; font-size: 12px; }
</style>
</head>
<body>
<div class="header">
  <h1>WPScan Viewer</h1>
  <span class="badge">OSCP Helper</span>
</div>
<div class="layout">
  <div class="input-panel">
    <label>WPScan Output</label>
    <textarea id="raw" placeholder="wpscan output-unu bura yapışdır...&#10;&#10;wpscan --url http://target --enumerate vp --api-token TOKEN"></textarea>
    <div class="btn-row">
      <button class="btn" onclick="go()">Analyze</button>
      <button class="btn-clear" onclick="clr()">Clear</button>
    </div>
  </div>
  <div class="output-panel" id="out">
    <div class="placeholder">
      <p>WPScan output-unu sol tərəfə yapışdır<br>və <strong>Analyze</strong> düyməsinə bas.<br><br><code style="color:#4b5563;font-size:11px">Ctrl+Enter</code> ilə də işləyir.</p>
    </div>
  </div>
</div>
<script>
let ALL_VULNS = [];

function go() {
  const raw = document.getElementById('raw').value.trim();
  if (!raw) return;
  fetch('/parse', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({raw})})
    .then(r=>r.json()).then(render).catch(console.error);
}

function clr() {
  document.getElementById('raw').value = '';
  document.getElementById('out').innerHTML = '<div class="placeholder"><p>WPScan output-unu sol tərəfə yapışdır<br>və <strong>Analyze</strong> düyməsinə bas.</p></div>';
}

function render(d) {
  ALL_VULNS = d.vulnerabilities || [];
  const s = d.summary;
  let h = '';

  if (d.target) {
    h += `<div class="target-bar"><div class="dot"></div><span>${esc(d.target)}</span>${d.wordpress_version ? `<span style="margin-left:auto;color:#60a5fa">WP ${esc(d.wordpress_version)}</span>` : ''}</div>`;
  }

  h += `<div class="summary-grid">
    <div class="stat-card c-total"><div class="num">${s.total_vulns}</div><div class="lbl">Total</div></div>
    <div class="stat-card c-critical"><div class="num">${s.critical}</div><div class="lbl">Critical</div></div>
    <div class="stat-card c-high"><div class="num">${s.high}</div><div class="lbl">High</div></div>
    <div class="stat-card c-medium"><div class="num">${s.medium}</div><div class="lbl">Medium</div></div>
    <div class="stat-card c-low"><div class="num">${s.low}</div><div class="lbl">Low</div></div>
  </div>`;

  // All vulnerabilities with filter
  if (ALL_VULNS.length > 0) {
    h += `<div class="section">
      <div class="sec-header" onclick="tog('vb','vc')">
        <div class="sec-title">All Vulnerabilities <span class="cnt">${ALL_VULNS.length}</span></div>
        <span class="chev open" id="vc">▼</span>
      </div>
      <div class="filter-row">
        <button class="fb active" onclick="filt('all',this)">All</button>
        <button class="fb" onclick="filt('critical',this)" style="color:#fca5a5">Critical</button>
        <button class="fb" onclick="filt('high',this)" style="color:#fdba74">High</button>
        <button class="fb" onclick="filt('medium',this)" style="color:#fcd34d">Medium</button>
        <button class="fb" onclick="filt('low',this)" style="color:#93c5fd">Low</button>
        <button class="fb" onclick="filt('unauthenticated',this)" style="color:#f472b6">Unauth</button>
      </div>
      <div class="sec-body open" id="vb">${renderVulns(ALL_VULNS)}</div>
    </div>`;
  }

  // Plugins breakdown
  if (d.plugins && d.plugins.length > 0) {
    const pluginsHtml = d.plugins.map((p,idx) => {
      const pid = 'p'+idx;
      const vcount = p.vulns ? p.vulns.length : 0;
      return `<div class="plugin-item">
        <div class="plugin-header" onclick="togP('${pid}')">
          <div><span class="plugin-name">${esc(p.name)}</span>${p.version ? `<span class="plugin-ver">v${esc(p.version)}</span>` : ''}</div>
          <div style="display:flex;align-items:center;gap:8px">
            ${vcount > 0 ? `<span class="cnt" style="color:#f87171">${vcount} vuln</span>` : '<span class="cnt">0 vuln</span>'}
            <span class="chev" id="pc${idx}">▼</span>
          </div>
        </div>
        <div class="plugin-body" id="${pid}">
          ${vcount > 0 ? renderVulns(p.vulns) : '<div class="empty-msg">No vulnerabilities found.</div>'}
        </div>
      </div>`;
    }).join('');
    h += `<div class="section">
      <div class="sec-header" onclick="tog('pb','pc_h')">
        <div class="sec-title">Plugins <span class="cnt">${d.plugins.length}</span></div>
        <span class="chev" id="pc_h">▼</span>
      </div>
      <div class="sec-body" id="pb">${pluginsHtml}</div>
    </div>`;
  }

  // Interesting findings
  if (d.interesting_findings && d.interesting_findings.length > 0) {
    h += `<div class="section">
      <div class="sec-header" onclick="tog('fb2','fc2')">
        <div class="sec-title">Interesting Findings <span class="cnt">${d.interesting_findings.length}</span></div>
        <span class="chev" id="fc2">▼</span>
      </div>
      <div class="sec-body" id="fb2">
        ${d.interesting_findings.map(f=>`<div class="finding-item">${esc(f)}</div>`).join('')}
      </div>
    </div>`;
  }

  // Users
  if (d.users && d.users.length > 0) {
    h += `<div class="section">
      <div class="sec-header" onclick="tog('ub','uc')">
        <div class="sec-title">Users Found <span class="cnt">${d.users.length}</span></div>
        <span class="chev open" id="uc">▼</span>
      </div>
      <div class="sec-body open" id="ub">
        ${d.users.map(u=>`<div class="user-item">${esc(u)}</div>`).join('')}
      </div>
    </div>`;
  }

  document.getElementById('out').innerHTML = h || '<div class="placeholder"><p>Parse edilə bilmədi. Output-u tam yapışdırdığına əmin ol.</p></div>';
}

function renderVulns(vulns) {
  if (!vulns || vulns.length === 0) return '<div class="empty-msg">Heç bir vulnerability yoxdur.</div>';
  return vulns.map(v => {
    const sev = v.severity || 'low';
    const refs = (v.references || []).slice(0,3).map(r => {
      const lbl = r.includes('cve.mitre') ? 'CVE ↗' : r.includes('wpscan') ? 'WPScan ↗' : 'Ref ↗';
      return `<span class="mtag"><a href="${esc(r)}" target="_blank">${lbl}</a></span>`;
    }).join('');
    const fi = v.fixed_in ? `<span class="mtag fixed">Fixed in: ${esc(v.fixed_in)}</span>` : '';
    const plug = v.plugin ? `<span class="mtag plugin-tag">${esc(v.plugin)}</span>` : '';
    return `<div class="vuln-item" data-sev="${sev}" data-title="${esc(v.title.toLowerCase())}">
      <div class="vuln-row">
        <span class="sev sev-${sev}">${sev}</span>
        <span class="vtitle">${esc(v.title)}</span>
      </div>
      <div class="vmeta">${fi}${plug}${refs}</div>
    </div>`;
  }).join('');
}

function tog(bodyId, chevId) {
  const b = document.getElementById(bodyId);
  const c = document.getElementById(chevId);
  if (!b) return;
  b.classList.toggle('open');
  if (c) c.classList.toggle('open');
}

function togP(pid) {
  const b = document.getElementById(pid);
  if (!b) return;
  b.classList.toggle('open');
  // find chev by index
  const idx = pid.replace('p','');
  const c = document.getElementById('pc'+idx);
  if (c) c.classList.toggle('open');
}

function filt(sev, btn) {
  document.querySelectorAll('.fb').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  let filtered;
  if (sev === 'all') {
    filtered = ALL_VULNS;
  } else if (sev === 'unauthenticated') {
    filtered = ALL_VULNS.filter(v => v.title.toLowerCase().includes('unauthenticated'));
  } else {
    filtered = ALL_VULNS.filter(v => v.severity === sev);
  }
  document.getElementById('vb').innerHTML = renderVulns(filtered);
}

function esc(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

document.getElementById('raw').addEventListener('keydown', e => {
  if (e.ctrlKey && e.key === 'Enter') go();
});
</script>
</body>
</html>"""


@app.route("/")
def index():
    return HTML_PAGE, 200, {"Content-Type": "text/html; charset=utf-8"}


@app.route("/parse", methods=["POST"])
def parse():
    data = request.get_json()
    raw = data.get("raw", "")
    if not raw.strip():
        return jsonify({"error": "Empty input"}), 400
    return jsonify(parse_wpscan(raw))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9090, debug=False)