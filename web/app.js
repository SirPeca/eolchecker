/* =========================================
   EOL & CVE Checker — app.js  v4
   ========================================= */

const $ = id => document.getElementById(id);
let _lastData = null;
let scanHistory = loadHistory();
renderHistory();
bindEvents();

// ---- Events ----

function bindEvents() {
  $('btn').addEventListener('click', doScan);
  $('btnClear').addEventListener('click', clearForm);
  $('btnExport').addEventListener('click', exportReport);

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

  $('cveFilter').addEventListener('input', filterCVEs);
  $('sevFilter').addEventListener('change', filterCVEs);
}

// ---- Scan ----

async function doScan() {
  const tech      = $('tech').value.trim();
  const version   = $('version').value.trim();
  const ecosystem = $('ecosystem').value;

  if (!tech || !version) { flashError($('tech')); return; }

  $('results').classList.remove('visible');
  $('versionWarning').style.display = 'none';
  $('loading').classList.add('visible');
  $('btn').disabled = true;

  const msgs = [
    'Validating version against registry...',
    'Querying OSV — with ecosystem...',
    'Querying OSV — system-level search...',
    'Checking CISA Known Exploited Vulnerabilities...',
    'Verifying end-of-life status...',
    'Computing risk score...',
    'Building report...'
  ];
  let mi = 0;
  const ticker = setInterval(() => { $('loadingText').textContent = msgs[mi++ % msgs.length]; }, 850);

  try {
    const url = `/check?tech=${encodeURIComponent(tech)}&version=${encodeURIComponent(version)}&ecosystem=${encodeURIComponent(ecosystem)}`;
    const res  = await fetch(url);
    const text = await res.text();

    clearInterval(ticker);
    $('loading').classList.remove('visible');
    $('btn').disabled = false;

    let data;
    try { data = JSON.parse(text); }
    catch { showBanner('Backend returned HTML instead of JSON. Is the Worker deployed?', 'error'); return; }

    if (!data.success) { showBanner(data.error || 'Unknown backend error.', 'error'); return; }

    _lastData = data;
    renderVersionWarning(data);
    renderResults(data);
    addToHistory(data);

  } catch (err) {
    clearInterval(ticker);
    $('loading').classList.remove('visible');
    $('btn').disabled = false;
    showBanner('Network error: ' + err.message, 'error');
  }
}

// ---- Version Intelligence warning ----

function renderVersionWarning(data) {
  const vi = data.versionInfo;
  if (!vi || vi.exists === true) { $('versionWarning').style.display = 'none'; return; }

  const box = $('versionWarning');
  let html = `<span class="vw-icon">⚠</span>
    <div class="vw-body">
      <strong>Version not found in ${escHtml(data.target.ecosystem)} registry.</strong>
      Results may be inaccurate or based on the closest available version.`;

  if (vi.closest) {
    html += `<br>Closest version found: <button class="vw-btn" onclick="useVersion('${escAttr(vi.closest)}')">${escHtml(vi.closest)}</button>`;
  }

  if (vi.recentVersions?.length) {
    html += `<br><span class="vw-label">Recent versions:</span> ` +
      vi.recentVersions.map(v =>
        `<button class="vw-btn" onclick="useVersion('${escAttr(v)}')">${escHtml(v)}</button>`
      ).join(' ');
  }

  html += '</div>';
  box.innerHTML = html;
  box.style.display = 'flex';
}

window.useVersion = function(v) {
  $('version').value = v;
  $('versionWarning').style.display = 'none';
  doScan();
};

// ---- Render Results ----

function renderResults(data) {
  $('resTarget').textContent = `${data.target.tech} ${data.target.version}`;

  const badge = $('resBadge');
  badge.textContent = data.risk.level;
  badge.className   = 'risk-badge ' + riskClass(data.risk.level);

  // Risk score dial
  const score = data.risk.score || 0;
  $('riskScore').textContent = score;
  $('riskScoreBar').style.width = score + '%';
  $('riskScoreBar').className = 'risk-bar-fill ' + riskClass(data.risk.level).replace('risk-','bar-');

  // Metrics
  const kevCount  = data.vulns.list.filter(v => v.kev).length;
  const critCount = data.vulns.list.filter(v => numSev(v.severity) >= 9.0).length;
  setMetric('metCves', data.vulns.total,  data.vulns.total > 0 ? 'col-bad'  : 'col-ok');
  setMetric('metCrit', critCount,          critCount > 0        ? 'col-bad'  : 'col-ok');
  setMetric('metKev',  kevCount,           kevCount > 0         ? 'col-bad'  : 'col-ok');

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

  // Risk breakdown factors
  renderRiskBreakdown(data.risk.factors || []);

  // CVE count
  const cveCount = $('cveCount');
  if (data.vulns.list.length > 0) {
    cveCount.textContent = data.vulns.total > data.vulns.list.length
      ? `${data.vulns.list.length} shown / ${data.vulns.total} total`
      : `${data.vulns.total} found`;
    cveCount.style.display = '';
  } else {
    cveCount.style.display = 'none';
  }

  $('cveFilters').style.display = data.vulns.list.length > 3 ? 'flex' : 'none';
  $('cveFilter').value = '';
  $('sevFilter').value = 'all';

  renderCVEList(data.vulns.list);

  // Show export button
  $('btnExport').style.display = '';

  $('results').classList.add('visible');
  setTimeout(() => $('results').scrollIntoView({ behavior: 'smooth', block: 'nearest' }), 50);
}

function setMetric(id, val, cls) {
  const el = $(id);
  el.textContent = val;
  el.className   = 'metric-val ' + cls;
}

// ---- Risk Breakdown ----

function renderRiskBreakdown(factors) {
  const box = $('riskBreakdown');
  if (!factors.length) { box.style.display = 'none'; return; }
  box.style.display = '';
  box.innerHTML = factors.map(f => `
    <div class="factor-row">
      <span class="factor-dot factor-${f.level}"></span>
      <span class="factor-label">${escHtml(f.label)}</span>
      <span class="factor-pts">+${f.points}</span>
    </div>
  `).join('');
}

// ---- CVE List ----

function renderCVEList(list) {
  const cveList = $('cveList');
  if (list.length === 0) {
    cveList.innerHTML = '<div class="no-cves">✓ No known vulnerabilities found for this version</div>';
    return;
  }

  cveList.innerHTML = list.map((v, i) => {
    const sc        = sevClass(v.severity);
    const lbl       = sevLabel(v.severity);
    const idDisplay = v.displayId || v.id;
    const idSecondary = (v.displayId && v.displayId !== v.id)
      ? `<span class="cve-alias">${escHtml(v.id)}</span>` : '';
    const summaryHtml = v.summary
      ? `<span class="cve-summary">${escHtml(v.summary.slice(0, 110))}${v.summary.length > 110 ? '…' : ''}</span>` : '';
    const linkHtml = v.link
      ? `<a class="cve-link" href="${escAttr(v.link)}" target="_blank" rel="noopener" title="View on NVD / GitHub Advisories">↗</a>` : '';
    const kevHtml  = v.kev ? '<span class="kev-badge">⚑ KEV</span>' : '';
    const pubDate  = v.published ? `<span class="cve-date">${v.published.slice(0,10)}</span>` : '';

    return `
      <div class="cve-item" style="animation-delay:${Math.min(i,20)*0.025}s"
           data-sev="${sc}" data-id="${escAttr(idDisplay)}" data-summary="${escAttr(v.summary||'')}">
        <div class="cve-main">
          <div class="cve-id-group">
            <span class="cve-id">${escHtml(idDisplay)}</span>
            ${idSecondary}
            ${kevHtml}
            <span class="sev-badge ${sc}">${lbl}</span>
            ${pubDate}
          </div>
          ${summaryHtml}
        </div>
        ${linkHtml}
      </div>`;
  }).join('');
}

// ---- CVE filter ----

function filterCVEs() {
  if (!_lastData) return;
  const text   = $('cveFilter').value.toLowerCase();
  const sevSel = $('sevFilter').value;
  let list = _lastData.vulns.list;
  if (sevSel !== 'all') list = list.filter(v => sevClass(v.severity) === 'sev-' + sevSel);
  if (text) list = list.filter(v => {
    return (v.displayId||v.id).toLowerCase().includes(text) ||
           (v.summary||'').toLowerCase().includes(text) ||
           (v.allIds||[]).join(' ').toLowerCase().includes(text);
  });
  renderCVEList(list);
  $('cveCount').textContent = list.length < _lastData.vulns.total
    ? `${list.length} shown / ${_lastData.vulns.total} total`
    : `${_lastData.vulns.total} found`;
}

// ---- Export Report ----

function exportReport() {
  if (!_lastData) return;
  const s = _lastData.summary;
  const r = _lastData.risk;
  const vulns = _lastData.vulns.list;

  const lines = [
    '='.repeat(60),
    '  SECURITY ASSESSMENT REPORT',
    '  EOL & CVE Checker',
    '='.repeat(60),
    '',
    `Date:          ${s.date}`,
    `Target:        ${s.target}`,
    '',
    '-'.repeat(60),
    'EXECUTIVE SUMMARY',
    '-'.repeat(60),
    '',
    `Risk Level:    ${s.riskLevel}`,
    `Risk Score:    ${s.riskScore}/100`,
    `Max CVSS:      ${s.maxCvss || 'N/A'}`,
    '',
    `Total CVEs:    ${s.totalVulns}`,
    `  Critical:    ${s.criticalVulns}`,
    `  High:        ${s.highVulns}`,
    `  KEV (active):${s.kevVulns}`,
    '',
    `EOL Status:    ${s.eolStatus.toUpperCase()}`,
    s.eolDate      ? `EOL Date:      ${s.eolDate}` : '',
    s.latestVersion? `Latest Ver:    ${s.latestVersion}` : '',
    '',
    '-'.repeat(60),
    'RISK FACTORS',
    '-'.repeat(60),
    '',
    ...(r.factors||[]).map(f => `  [${f.level.toUpperCase().padEnd(8)}] ${f.label} (+${f.points} pts)`),
    '',
    '-'.repeat(60),
    'RECOMMENDATION',
    '-'.repeat(60),
    '',
    ...wordWrap(s.recommendation, 58).map(l => `  ${l}`),
    '',
    '-'.repeat(60),
    `VULNERABILITIES (${vulns.length} shown)`,
    '-'.repeat(60),
    '',
    ...vulns.map((v, i) => [
      `${String(i+1).padStart(3)}. ${v.displayId || v.id}`,
      `     Severity: ${v.severity}${v.kev ? '  ⚑ ACTIVELY EXPLOITED (KEV)' : ''}`,
      v.summary ? `     Summary:  ${v.summary.slice(0, 100)}` : '',
      `     Link:     ${v.link || 'N/A'}`,
      ''
    ].filter(Boolean)).flat(),
    '='.repeat(60),
    'Generated by EOL & CVE Checker — https://theeolchecker.pages.dev',
    '='.repeat(60),
  ].filter(l => l !== undefined).join('\n');

  const blob = new Blob([lines], { type: 'text/plain;charset=utf-8' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = `security-report-${_lastData.target.tech}-${_lastData.target.version}-${s.date}.txt`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);

  showBanner('Report downloaded ✓', 'info');
}

function wordWrap(text, width) {
  const words = text.split(' ');
  const lines = [];
  let current = '';
  for (const w of words) {
    if ((current + ' ' + w).trim().length > width) { lines.push(current); current = w; }
    else current = (current + ' ' + w).trim();
  }
  if (current) lines.push(current);
  return lines;
}

// ---- History ----

function addToHistory(data) {
  const entry = {
    tech: data.target.tech, version: data.target.version,
    eco:  $('ecosystem').value, risk: data.risk.level,
    score: data.risk.score, total: data.vulns.total, ts: Date.now()
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
      data-tech="${escAttr(h.tech)}" data-ver="${escAttr(h.version)}" data-eco="${escAttr(h.eco||'npm')}">
      <span class="history-tech">${escHtml(h.tech)}</span>
      <span class="history-ver">v${escHtml(h.version)}</span>
      <span class="history-eco">${escHtml(h.eco||'npm')}</span>
      <span class="history-count">${h.total != null ? h.total+' CVEs' : ''}</span>
      <span class="history-risk risk-badge ${riskClass(h.risk)}">${escHtml(h.risk)}</span>
    </div>`).join('');

  $('historyList').querySelectorAll('.history-item').forEach(el => {
    const go = () => {
      $('tech').value = el.dataset.tech; $('version').value = el.dataset.ver;
      $('ecosystem').value = el.dataset.eco; doScan();
    };
    el.addEventListener('click', go);
    el.addEventListener('keydown', e => { if (e.key === 'Enter') go(); });
  });
}

function loadHistory()  { try { return JSON.parse(localStorage.getItem('eolchecker_history')||'[]'); } catch { return []; } }
function saveHistory(h) { try { localStorage.setItem('eolchecker_history', JSON.stringify(h)); } catch {} }

// ---- Misc ----

function clearForm() {
  $('tech').value = ''; $('version').value = '';
  $('results').classList.remove('visible');
  $('versionWarning').style.display = 'none';
  $('btnExport').style.display = 'none';
  _lastData = null;
}

function showBanner(msg, type = 'error') {
  const b = $('banner');
  b.textContent = (type === 'error' ? '⚠ ' : '✓ ') + msg;
  b.className   = 'banner banner-' + type + ' visible';
  setTimeout(() => b.classList.remove('visible'), 5000);
}

function flashError(el) {
  el.style.borderColor = 'rgba(255,82,82,0.6)'; el.focus();
  setTimeout(() => { el.style.borderColor = ''; }, 1400);
}

function numSev(s) {
  const n = parseFloat(s);
  return !isNaN(n) ? n : (s==='CRITICAL'?9.5:s==='HIGH'?7.5:s==='MEDIUM'?5:0);
}

function riskClass(level) {
  return { CRITICAL:'risk-critical', HIGH:'risk-high', MEDIUM:'risk-medium', LOW:'risk-low' }[level] || 'risk-low';
}

function sevClass(s) {
  if (!s || s==='UNKNOWN') return 'sev-unknown';
  const n = parseFloat(s);
  if (!isNaN(n)) { if(n>=9) return 'sev-critical'; if(n>=7) return 'sev-high'; if(n>=4) return 'sev-medium'; return 'sev-low'; }
  const u = s.toUpperCase();
  if (u==='CRITICAL') return 'sev-critical'; if (u==='HIGH') return 'sev-high';
  if (u==='MEDIUM'||u==='MODERATE') return 'sev-medium'; if (u==='LOW') return 'sev-low';
  return 'sev-unknown';
}

function sevLabel(s) {
  if (!s || s==='UNKNOWN') return 'UNKNOWN';
  const n = parseFloat(s);
  if (!isNaN(n)) { if(n>=9) return `CRITICAL ${n.toFixed(1)}`; if(n>=7) return `HIGH ${n.toFixed(1)}`; if(n>=4) return `MEDIUM ${n.toFixed(1)}`; return `LOW ${n.toFixed(1)}`; }
  return s.toUpperCase();
}

function escHtml(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function escAttr(s) { return String(s).replace(/"/g,'&quot;').replace(/'/g,'&#39;'); }
