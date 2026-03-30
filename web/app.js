/* =========================================
   EOL & CVE Checker — app.js  v3
   ========================================= */

const $ = id => document.getElementById(id);

let scanHistory = loadHistory();
renderHistory();
bindEvents();

// ---- Events ----

function bindEvents() {
  $('btn').addEventListener('click', doScan);
  $('btnClear').addEventListener('click', clearForm);

  document.querySelectorAll('.tag').forEach(t => {
    t.addEventListener('click', () => {
      $('tech').value      = t.dataset.tech;
      $('version').value   = t.dataset.ver;
      $('ecosystem').value = t.dataset.eco;
    });
  });

  ['tech', 'version'].forEach(id => {
    $(id).addEventListener('keydown', e => { if (e.key === 'Enter') doScan(); });
  });

  // CVE filter
  $('cveFilter').addEventListener('input', filterCVEs);
  $('sevFilter').addEventListener('change', filterCVEs);
}

// ---- Scan ----

let _lastData = null;

async function doScan() {
  const tech      = $('tech').value.trim();
  const version   = $('version').value.trim();
  const ecosystem = $('ecosystem').value;

  if (!tech || !version) {
    flashError($('tech'));
    return;
  }

  $('results').classList.remove('visible');
  $('loading').classList.add('visible');
  $('btn').disabled = true;

  const msgs = [
    'Querying OSV — with ecosystem...',
    'Querying OSV — system-level search...',
    'Checking CISA Known Exploited Vulnerabilities...',
    'Verifying end-of-life status...',
    'Deduplicating & scoring results...',
    'Building report...'
  ];
  let mi = 0;
  const ticker = setInterval(() => {
    $('loadingText').textContent = msgs[mi++ % msgs.length];
  }, 900);

  try {
    const url = `/check?tech=${encodeURIComponent(tech)}&version=${encodeURIComponent(version)}&ecosystem=${encodeURIComponent(ecosystem)}`;
    const res  = await fetch(url);
    const text = await res.text();

    clearInterval(ticker);
    $('loading').classList.remove('visible');
    $('btn').disabled = false;

    let data;
    try { data = JSON.parse(text); }
    catch {
      showBanner('Backend returned HTML instead of JSON. Is the Worker deployed?', 'error');
      return;
    }

    if (!data.success) {
      showBanner(data.error || 'Unknown backend error.', 'error');
      return;
    }

    _lastData = data;
    renderResults(data);
    addToHistory(data);

  } catch (err) {
    clearInterval(ticker);
    $('loading').classList.remove('visible');
    $('btn').disabled = false;
    showBanner('Network error: ' + err.message, 'error');
  }
}

// ---- Render ----

function renderResults(data) {
  $('resTarget').textContent = `${data.target.tech} ${data.target.version}`;

  const badge = $('resBadge');
  badge.textContent = data.risk.level;
  badge.className   = 'risk-badge ' + riskClass(data.risk.level);

  const kevCount  = data.vulns.list.filter(v => v.kev).length;
  const critCount = data.vulns.list.filter(v => isCriticalSev(v.severity)).length;

  // Metrics
  setMetric('metCves', data.vulns.total,  data.vulns.total > 0  ? 'col-bad' : 'col-ok');
  setMetric('metKev',  kevCount,           kevCount > 0          ? 'col-bad' : 'col-ok');
  setMetric('metCrit', critCount,          critCount > 0         ? 'col-bad' : 'col-ok');

  // EOL
  const eolV  = data.eol.status;
  const eolEl = $('eolStatus');
  eolEl.textContent = eolV === 'EOL' ? '✕ End of Life' : eolV === 'supported' ? '✓ Supported' : '? Unknown';
  eolEl.className   = 'eol-status ' + (eolV === 'EOL' ? 'eol-eol' : eolV === 'supported' ? 'eol-supported' : 'eol-unknown');

  let eolMeta = '';
  if (data.eol.latest)  eolMeta += `Latest stable: <span class="hl">${escHtml(data.eol.latest)}</span>`;
  if (data.eol.eolDate) eolMeta += `&nbsp;&nbsp;·&nbsp;&nbsp;EOL date: <span class="hl-warn">${escHtml(data.eol.eolDate)}</span>`;
  if (data.eol.lts)     eolMeta += `&nbsp;&nbsp;·&nbsp;&nbsp;<span class="badge-lts">LTS</span>`;
  $('eolLatest').innerHTML = eolMeta;

  // CVE count badge
  const cveCount = $('cveCount');
  if (data.vulns.list.length > 0) {
    cveCount.textContent = data.vulns.total > data.vulns.list.length
      ? `${data.vulns.list.length} shown / ${data.vulns.total} total`
      : `${data.vulns.total} found`;
    cveCount.style.display = '';
  } else {
    cveCount.style.display = 'none';
  }

  // Show/hide filter controls
  $('cveFilters').style.display = data.vulns.list.length > 3 ? 'flex' : 'none';
  $('cveFilter').value  = '';
  $('sevFilter').value  = 'all';

  renderCVEList(data.vulns.list);

  $('results').classList.add('visible');
  setTimeout(() => {
    $('results').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }, 50);
}

function setMetric(id, val, cls) {
  const el = $(id);
  el.textContent = val;
  el.className   = 'metric-val ' + cls;
}

// ---- CVE List rendering ----

function renderCVEList(list) {
  const cveList = $('cveList');

  if (list.length === 0) {
    cveList.innerHTML = '<div class="no-cves">✓ No known vulnerabilities found for this version</div>';
    return;
  }

  cveList.innerHTML = list.map((v, i) => {
    const sc  = sevClass(v.severity);
    const lbl = sevLabel(v.severity);
    const idDisplay = v.displayId || v.id;

    // If displayId differs from id, show both
    const idSecondary = (v.displayId && v.displayId !== v.id)
      ? `<span class="cve-alias">${escHtml(v.id)}</span>`
      : '';

    const summaryHtml = v.summary
      ? `<span class="cve-summary">${escHtml(v.summary.slice(0, 100))}${v.summary.length > 100 ? '…' : ''}</span>`
      : '';

    const linkHtml = v.link
      ? `<a class="cve-link" href="${escAttr(v.link)}" target="_blank" rel="noopener" title="View on NVD / GitHub Advisories">↗</a>`
      : '';

    const kevHtml = v.kev ? '<span class="kev-badge">⚑ KEV</span>' : '';

    return `
      <div class="cve-item" style="animation-delay:${Math.min(i,20) * 0.025}s"
           data-sev="${sc}" data-id="${escAttr(idDisplay)}" data-summary="${escAttr(v.summary||'')}">
        <div class="cve-main">
          <div class="cve-id-group">
            <span class="cve-id">${escHtml(idDisplay)}</span>
            ${idSecondary}
            ${kevHtml}
            <span class="sev-badge ${sc}">${lbl}</span>
          </div>
          ${summaryHtml}
        </div>
        ${linkHtml}
      </div>
    `;
  }).join('');
}

// ---- CVE filtering ----

function filterCVEs() {
  if (!_lastData) return;

  const text    = $('cveFilter').value.toLowerCase();
  const sevSel  = $('sevFilter').value;

  let list = _lastData.vulns.list;

  if (sevSel !== 'all') {
    list = list.filter(v => sevClass(v.severity) === 'sev-' + sevSel);
  }

  if (text) {
    list = list.filter(v => {
      const id  = (v.displayId || v.id).toLowerCase();
      const sum = (v.summary || '').toLowerCase();
      const all = (v.allIds || []).join(' ').toLowerCase();
      return id.includes(text) || sum.includes(text) || all.includes(text);
    });
  }

  renderCVEList(list);

  // Update shown count
  const cveCount = $('cveCount');
  cveCount.textContent = list.length < _lastData.vulns.total
    ? `${list.length} shown / ${_lastData.vulns.total} total`
    : `${_lastData.vulns.total} found`;
}

// ---- History ----

function addToHistory(data) {
  const entry = {
    tech:    data.target.tech,
    version: data.target.version,
    eco:     $('ecosystem').value,
    risk:    data.risk.level,
    total:   data.vulns.total,
    ts:      Date.now()
  };
  scanHistory = scanHistory.filter(h => !(h.tech === entry.tech && h.version === entry.version));
  scanHistory.unshift(entry);
  if (scanHistory.length > 10) scanHistory = scanHistory.slice(0, 10);
  saveHistory(scanHistory);
  renderHistory();
}

function renderHistory() {
  if (scanHistory.length === 0) { $('historySection').style.display = 'none'; return; }
  $('historySection').style.display = 'block';

  $('historyList').innerHTML = scanHistory.map(h => `
    <div class="history-item" tabindex="0"
      data-tech="${escAttr(h.tech)}"
      data-ver="${escAttr(h.version)}"
      data-eco="${escAttr(h.eco || 'npm')}">
      <span class="history-tech">${escHtml(h.tech)}</span>
      <span class="history-ver">v${escHtml(h.version)}</span>
      <span class="history-eco">${escHtml(h.eco || 'npm')}</span>
      <span class="history-count">${h.total != null ? h.total + ' CVEs' : ''}</span>
      <span class="history-risk risk-badge ${riskClass(h.risk)}">${escHtml(h.risk)}</span>
    </div>
  `).join('');

  $('historyList').querySelectorAll('.history-item').forEach(el => {
    const go = () => {
      $('tech').value      = el.dataset.tech;
      $('version').value   = el.dataset.ver;
      $('ecosystem').value = el.dataset.eco;
      doScan();
    };
    el.addEventListener('click', go);
    el.addEventListener('keydown', e => { if (e.key === 'Enter') go(); });
  });
}

function loadHistory() {
  try { return JSON.parse(localStorage.getItem('eolchecker_history') || '[]'); }
  catch { return []; }
}

function saveHistory(h) {
  try { localStorage.setItem('eolchecker_history', JSON.stringify(h)); } catch {}
}

// ---- Misc helpers ----

function clearForm() {
  $('tech').value = '';
  $('version').value = '';
  $('results').classList.remove('visible');
  _lastData = null;
}

function showBanner(msg, type = 'error') {
  const b = $('banner');
  b.textContent = '⚠ ' + msg;
  b.className   = 'banner banner-' + type + ' visible';
  setTimeout(() => b.classList.remove('visible'), 6000);
}

function flashError(el) {
  el.style.borderColor = 'rgba(255,82,82,0.6)';
  el.focus();
  setTimeout(() => { el.style.borderColor = ''; }, 1400);
}

function riskClass(level) {
  const m = { CRITICAL:'risk-critical', HIGH:'risk-high', MEDIUM:'risk-medium', LOW:'risk-low' };
  return m[level] || 'risk-low';
}

function isCriticalSev(s) {
  const n = parseFloat(s);
  return !isNaN(n) ? n >= 9.0 : s === 'CRITICAL';
}

function sevClass(s) {
  if (!s || s === 'UNKNOWN') return 'sev-unknown';
  const n = parseFloat(s);
  if (!isNaN(n)) {
    if (n >= 9.0) return 'sev-critical';
    if (n >= 7.0) return 'sev-high';
    if (n >= 4.0) return 'sev-medium';
    return 'sev-low';
  }
  const u = s.toUpperCase();
  if (u === 'CRITICAL')                   return 'sev-critical';
  if (u === 'HIGH')                        return 'sev-high';
  if (u === 'MEDIUM' || u === 'MODERATE')  return 'sev-medium';
  if (u === 'LOW')                         return 'sev-low';
  return 'sev-unknown';
}

function sevLabel(s) {
  if (!s || s === 'UNKNOWN') return 'UNKNOWN';
  const n = parseFloat(s);
  if (!isNaN(n)) {
    if (n >= 9.0) return `CRITICAL ${n.toFixed(1)}`;
    if (n >= 7.0) return `HIGH ${n.toFixed(1)}`;
    if (n >= 4.0) return `MEDIUM ${n.toFixed(1)}`;
    return `LOW ${n.toFixed(1)}`;
  }
  return s.toUpperCase();
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function escAttr(s) {
  return String(s).replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
