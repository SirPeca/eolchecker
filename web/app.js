/* =========================================
   EOL & CVE Checker — app.js
   ========================================= */

const $ = id => document.getElementById(id);

// ---- State ----
let scanHistory = loadHistory();

// ---- Boot ----
renderHistory();
bindEvents();

// ---- Event Binding ----
function bindEvents() {
  $('btn').addEventListener('click', doScan);
  $('btnClear').addEventListener('click', clearForm);

  // Quick tag examples
  document.querySelectorAll('.tag').forEach(t => {
    t.addEventListener('click', () => {
      $('tech').value = t.dataset.tech;
      $('version').value = t.dataset.ver;
      $('ecosystem').value = t.dataset.eco;
    });
  });

  // Enter key on inputs
  ['tech', 'version'].forEach(id => {
    $(id).addEventListener('keydown', e => {
      if (e.key === 'Enter') doScan();
    });
  });
}

// ---- Scan ----
async function doScan() {
  const tech      = $('tech').value.trim();
  const version   = $('version').value.trim();
  const ecosystem = $('ecosystem').value;

  if (!tech || !version) {
    shake($('tech').closest ? $('tech') : $('tech'));
    return;
  }

  $('results').classList.remove('visible');
  $('loading').classList.add('visible');
  $('btn').disabled = true;

  const msgs = [
    'Querying OSV vulnerability database...',
    'Checking CISA Known Exploited Vulnerabilities...',
    'Verifying end-of-life status...',
    'Computing risk score...',
    'Assembling report...'
  ];
  let mi = 0;
  const ticker = setInterval(() => {
    $('loadingText').textContent = msgs[mi++ % msgs.length];
  }, 950);

  try {
    const url = `/check?tech=${encodeURIComponent(tech)}&version=${encodeURIComponent(version)}&ecosystem=${encodeURIComponent(ecosystem)}`;
    const res  = await fetch(url);
    const text = await res.text();

    clearInterval(ticker);
    $('loading').classList.remove('visible');
    $('btn').disabled = false;

    let data;
    try {
      data = JSON.parse(text);
    } catch {
      showError('Backend returned HTML instead of JSON. Is the Cloudflare Worker running?');
      return;
    }

    if (!data.success) {
      showError(data.error || 'Unknown error from backend.');
      return;
    }

    renderResults(data);
    addToHistory(data);

  } catch (err) {
    clearInterval(ticker);
    $('loading').classList.remove('visible');
    $('btn').disabled = false;
    showError('Network error: ' + err.message);
  }
}

// ---- Render Results ----
function renderResults(data) {
  $('resTarget').textContent = `${data.target.tech} ${data.target.version}`;

  const badge = $('resBadge');
  badge.textContent = data.risk.level;
  badge.className   = 'risk-badge ' + riskClass(data.risk.level);

  const kevCount = data.vulns.list.filter(v => v.kev).length;

  // Metric: CVEs
  const metCves = $('metCves');
  metCves.textContent = data.vulns.total;
  metCves.className   = 'metric-val ' + (data.vulns.total > 0 ? 'col-bad' : 'col-ok');

  // Metric: KEV
  const metKev = $('metKev');
  metKev.textContent = kevCount;
  metKev.className   = 'metric-val ' + (kevCount > 0 ? 'col-bad' : 'col-ok');

  // Metric: EOL
  const eolV      = data.eol.status;
  const metEolVal = $('metEolVal');
  metEolVal.textContent = eolV === 'EOL' ? 'EOL' : eolV === 'supported' ? 'OK' : '?';
  metEolVal.className   = 'metric-val ' + (eolV === 'EOL' ? 'col-bad' : eolV === 'supported' ? 'col-ok' : 'col-warn');

  // EOL status
  const eolEl = $('eolStatus');
  eolEl.textContent = eolV === 'EOL' ? '✕ End of Life' : eolV === 'supported' ? '✓ Supported' : '? Unknown';
  eolEl.className   = 'eol-status ' + (eolV === 'EOL' ? 'eol-eol' : eolV === 'supported' ? 'eol-supported' : 'eol-unknown');

  $('eolLatest').innerHTML = data.eol.latest
    ? `Latest stable: <span>${data.eol.latest}</span>`
    : '';

  // CVE count badge in section title
  const cveCount = $('cveCount');
  if (data.vulns.list.length > 0) {
    cveCount.textContent = data.vulns.list.length + ' found';
    cveCount.style.display = '';
  } else {
    cveCount.style.display = 'none';
  }

  // CVE list
  const cveList = $('cveList');
  if (data.vulns.list.length === 0) {
    cveList.innerHTML = '<div class="no-cves">✓ No known vulnerabilities found</div>';
  } else {
    cveList.innerHTML = data.vulns.list.map((v, i) => `
      <div class="cve-item" style="animation-delay:${i * 0.03}s">
        <span class="cve-id">${escHtml(v.id)}</span>
        <span class="sev-badge ${sevClass(v.severity)}">${sevLabel(v.severity)}</span>
        ${v.kev ? '<span class="kev-badge">⚑ KEV</span>' : ''}
      </div>
    `).join('');
  }

  $('results').classList.add('visible');
  $('results').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// ---- History ----
function addToHistory(data) {
  const entry = {
    tech:    data.target.tech,
    version: data.target.version,
    eco:     $('ecosystem').value,
    risk:    data.risk.level,
    ts:      Date.now()
  };
  scanHistory = scanHistory.filter(h => !(h.tech === entry.tech && h.version === entry.version));
  scanHistory.unshift(entry);
  if (scanHistory.length > 8) scanHistory = scanHistory.slice(0, 8);
  saveHistory(scanHistory);
  renderHistory();
}

function renderHistory() {
  if (scanHistory.length === 0) {
    $('historySection').style.display = 'none';
    return;
  }
  $('historySection').style.display = 'block';
  $('historyList').innerHTML = scanHistory.map(h => `
    <div class="history-item" tabindex="0"
      data-tech="${escAttr(h.tech)}"
      data-ver="${escAttr(h.version)}"
      data-eco="${escAttr(h.eco || 'npm')}">
      <span class="history-tech">${escHtml(h.tech)}</span>
      <span class="history-ver">v${escHtml(h.version)}</span>
      <span class="history-risk risk-badge ${riskClass(h.risk)}">${escHtml(h.risk)}</span>
    </div>
  `).join('');

  $('historyList').querySelectorAll('.history-item').forEach(el => {
    el.addEventListener('click', () => {
      $('tech').value      = el.dataset.tech;
      $('version').value   = el.dataset.ver;
      $('ecosystem').value = el.dataset.eco;
      doScan();
    });
    el.addEventListener('keydown', e => {
      if (e.key === 'Enter') el.click();
    });
  });
}

function loadHistory() {
  try {
    const raw = localStorage.getItem('eolchecker_history');
    return raw ? JSON.parse(raw) : [];
  } catch { return []; }
}

function saveHistory(h) {
  try { localStorage.setItem('eolchecker_history', JSON.stringify(h)); } catch {}
}

// ---- Helpers ----
function clearForm() {
  $('tech').value    = '';
  $('version').value = '';
  $('results').classList.remove('visible');
}

function showError(msg) {
  alert('⚠ ' + msg);
}

function shake(el) {
  el.style.borderColor = 'rgba(255,82,82,0.55)';
  el.style.animation   = 'none';
  el.offsetHeight; // reflow
  el.style.animation = 'shake 0.35s ease';
  setTimeout(() => {
    el.style.borderColor = '';
    el.style.animation   = '';
  }, 1200);
}

function riskClass(level) {
  const map = { CRITICAL: 'risk-critical', HIGH: 'risk-high', MEDIUM: 'risk-medium', LOW: 'risk-low' };
  return map[level] || 'risk-low';
}

function sevClass(s) {
  if (!s || s === 'UNKNOWN') return 'sev-unknown';
  const v = parseFloat(s);
  if (!isNaN(v)) {
    if (v >= 9.0) return 'sev-critical';
    if (v >= 7.0) return 'sev-high';
    if (v >= 4.0) return 'sev-medium';
    return 'sev-low';
  }
  const u = s.toUpperCase();
  if (u === 'CRITICAL')                  return 'sev-critical';
  if (u === 'HIGH')                      return 'sev-high';
  if (u === 'MEDIUM' || u === 'MODERATE') return 'sev-medium';
  if (u === 'LOW')                        return 'sev-low';
  return 'sev-unknown';
}

function sevLabel(s) {
  if (!s || s === 'UNKNOWN') return 'UNKNOWN';
  const v = parseFloat(s);
  if (!isNaN(v)) {
    if (v >= 9.0) return `CRITICAL ${v.toFixed(1)}`;
    if (v >= 7.0) return `HIGH ${v.toFixed(1)}`;
    if (v >= 4.0) return `MEDIUM ${v.toFixed(1)}`;
    return `LOW ${v.toFixed(1)}`;
  }
  return s.toUpperCase();
}

function escHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function escAttr(s) {
  return String(s).replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
