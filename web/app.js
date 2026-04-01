/* =========================================
   EOL & CVE Checker — app.js  v8

   FIXES vs v7:
   - BUG1: Removed ALL inline onclick= from HTML.
           All handlers wired here via addEventListener.
           CSP 'script-src self' no longer blocks anything.
   - BUG2: Lang switch now always re-fetches with correct lang.
           Backend rebuilds tactical from cached vuln data.
   - BUG3: Bar animation uses setTimeout(100ms) instead of
           double rAF — reliably fires after fadeIn settles.
   - BUG4: markdownToHtml skips |---| separator rows.
   ========================================= */

const $ = id => document.getElementById(id);

let _lastData   = null;
let _tacLang    = 'en';
let _tacTab     = 'red';
let scanHistory = loadHistory();

renderHistory();
bindEvents();
loadVisitCounter();

// =========================================
// VISIT COUNTER
// =========================================

async function loadVisitCounter() {
  try {
    const data = await (await fetch('/visits')).json();
    if (data.total != null) {
      $('visitCounter').textContent = formatNum(data.total) + ' scans';
      $('visitCounter').style.display = '';
    }
  } catch {}
}

function formatNum(n) {
  if (n >= 1e6) return (n/1e6).toFixed(1)+'M';
  if (n >= 1e3) return (n/1e3).toFixed(1)+'K';
  return String(n);
}

// =========================================
// EVENT BINDING — zero inline handlers in HTML
// =========================================

function bindEvents() {
  // Scan form
  $('btn').addEventListener('click', doScan);
  $('btnClear').addEventListener('click', clearForm);
  $('btnExport').addEventListener('click', exportReport);

  // Quick tags
  document.querySelectorAll('.tag').forEach(t => {
    t.addEventListener('click', () => {
      $('tech').value      = t.dataset.tech;
      $('version').value   = t.dataset.ver;
      $('ecosystem').value = t.dataset.eco;
    });
  });

  // Enter key
  ['tech','version'].forEach(id =>
    $(id).addEventListener('keydown', e => { if (e.key === 'Enter') doScan(); })
  );

  // CVE filters
  $('cveFilter').addEventListener('input',  filterCVEs);
  $('sevFilter').addEventListener('change', filterCVEs);

  // ---- TACTICAL TABS (event delegation on the tab bar) ----
  // BUG1 FIX: was onclick="switchTacTab(...)" — blocked by CSP
  $('tabRed').addEventListener('click',  () => switchTacTab('red'));
  $('tabBlue').addEventListener('click', () => switchTacTab('blue'));

  // ---- LANGUAGE BUTTONS ----
  // BUG1 FIX: was onclick="switchLang(...)" — blocked by CSP
  $('langEN').addEventListener('click', () => switchLang('en'));
  $('langES').addEventListener('click', () => switchLang('es'));

  // ---- COPY BUTTON ----
  // BUG1 FIX: was onclick="copyTactical()" — blocked by CSP
  $('tacCopyBtn').addEventListener('click', copyTactical);
}

// =========================================
// SCAN
// =========================================

async function doScan() {
  const tech      = $('tech').value.trim();
  const version   = $('version').value.trim();
  const ecosystem = $('ecosystem').value;
  if (!tech || !version) { flashError($('tech')); return; }

  $('results').classList.remove('visible');
  hideBoxes();
  $('loading').classList.add('visible');
  $('btn').disabled = true;

  const msgs = [
    'Validating version against registry...',
    ecosystem === 'auto' ? 'Auto-detecting ecosystem…' : `Querying OSV [${ecosystem}]…`,
    'Checking NVD & GitHub Advisories...',
    'Checking CISA KEV...',
    'Verifying end-of-life status...',
    'Computing risk score...',
    'Building tactical analysis...'
  ];
  let mi = 0;
  const ticker = setInterval(() => { $('loadingText').textContent = msgs[mi++ % msgs.length]; }, 850);
  const ctrl   = new AbortController();
  const tmout  = setTimeout(() => ctrl.abort(), 25000);

  try {
    const url  = `/check?tech=${enc(tech)}&version=${enc(version)}&ecosystem=${enc(ecosystem)}&lang=${_tacLang}`;
    const res  = await fetch(url, { signal: ctrl.signal });
    clearTimeout(tmout);
    clearInterval(ticker);
    $('loading').classList.remove('visible');
    $('btn').disabled = false;

    let data;
    try { data = await res.json(); }
    catch { showBanner('Backend returned invalid JSON. Is the Worker deployed?', 'error'); return; }

    if (!data.success) { showBanner(data.error || 'Unknown backend error.', 'error'); return; }

    // Update live counter
    if (data.visitTotal != null) {
      $('visitCounter').textContent = formatNum(data.visitTotal) + ' scans';
      $('visitCounter').style.display = '';
    }

    if (data.nonTrackable) { renderNonTrackable(data); return; }

    _lastData = data;
    renderDidYouMean(data);
    renderVersionWarning(data);
    renderResults(data);
    addToHistory(data);

  } catch (err) {
    clearTimeout(tmout);
    clearInterval(ticker);
    $('loading').classList.remove('visible');
    $('btn').disabled = false;
    showBanner(err.name === 'AbortError' ? 'Request timed out. Try again.' : 'Network error: '+err.message, 'error');
  }
}

// =========================================
// TACTICAL PANEL
// =========================================

function switchTacTab(tab) {
  _tacTab = tab;
  $('tabRed').className  = 'tac-tab' + (tab === 'red'  ? ' active-red'  : '');
  $('tabBlue').className = 'tac-tab' + (tab === 'blue' ? ' active-blue' : '');
  renderTactical();
}

function switchLang(lang) {
  _tacLang = lang;
  $('langEN').className = 'lang-btn' + (lang === 'en' ? ' active' : '');
  $('langES').className = 'lang-btn' + (lang === 'es' ? ' active' : '');

  if (!_lastData) return;

  // BUG2 FIX: always re-fetch — backend rebuilds tactical for requested lang
  // (if result is cached, it still rebuilds tactical fresh from cached vuln data)
  fetchTacticalForLang(lang);
}

async function fetchTacticalForLang(lang) {
  if (!_lastData) return;
  const { tech, version, ecosystem } = _lastData.target;

  // Show loading state in tactical panel
  $('tacContent').innerHTML = '<p style="color:var(--muted);font-size:0.8rem">Loading…</p>';

  try {
    const url  = `/check?tech=${enc(tech)}&version=${enc(version)}&ecosystem=${enc(ecosystem)}&lang=${lang}`;
    const data = await (await fetch(url)).json();
    if (data.tactical) {
      _lastData.tactical = data.tactical;
      renderTactical();
    } else {
      $('tacContent').innerHTML = '<p style="color:var(--muted);font-size:0.8rem">No tactical data available.</p>';
    }
  } catch {
    $('tacContent').innerHTML = '<p style="color:var(--bad);font-size:0.8rem">Failed to load. Try again.</p>';
  }
}

function renderTactical() {
  if (!_lastData?.tactical) { $('tacticalPanel').style.display = 'none'; return; }

  const content = _tacTab === 'red' ? _lastData.tactical.red : _lastData.tactical.blue;
  $('tacContent').className = `tac-content tac-panel-${_tacTab}`;
  $('tacContent').innerHTML = markdownToHtml(content || '');
  $('tacticalPanel').style.display = '';
}

function copyTactical() {
  if (!_lastData?.tactical) return;
  const raw = _tacTab === 'red' ? _lastData.tactical.red : _lastData.tactical.blue;
  const btn = $('tacCopyBtn');

  const done = () => {
    btn.textContent = '✓ Copied!';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = '⎘ Copy'; btn.classList.remove('copied'); }, 2000);
  };

  if (navigator.clipboard?.writeText) {
    navigator.clipboard.writeText(raw).then(done).catch(() => fallbackCopy(raw, done));
  } else {
    fallbackCopy(raw, done);
  }
}

function fallbackCopy(text, cb) {
  const ta = Object.assign(document.createElement('textarea'), {
    value: text, style: 'position:fixed;opacity:0'
  });
  document.body.appendChild(ta);
  ta.select();
  try { document.execCommand('copy'); cb(); } catch {}
  document.body.removeChild(ta);
}

// BUG4 FIX: proper markdown renderer that skips separator rows
function markdownToHtml(md) {
  const lines  = md.split('\n');
  const out    = [];
  let inTable  = false;
  let inList   = false;

  const flushList = () => { if (inList) { out.push('</ul>'); inList = false; } };
  const flushTable= () => { if (inTable){ out.push('</table>'); inTable = false; } };

  for (let i = 0; i < lines.length; i++) {
    let line = lines[i]
      .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
      .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');

    // h2 / h3
    if (line.startsWith('## '))  { flushList(); flushTable(); out.push(`<h2>${line.slice(3)}</h2>`); continue; }
    if (line.startsWith('### ')) { flushList(); flushTable(); out.push(`<h3>${line.slice(4)}</h3>`); continue; }

    // Table row
    if (line.trimStart().startsWith('|') && line.trimEnd().endsWith('|')) {
      flushList();
      const cells = line.split('|').slice(1,-1).map(c => c.trim());
      // BUG4 FIX: skip separator rows (all dashes/colons)
      if (cells.every(c => /^[-: ]+$/.test(c))) continue;
      if (!inTable) { out.push('<table>'); inTable = true; }
      // First row becomes header if next line is separator
      const nextLine = (lines[i+1] || '').split('|').slice(1,-1).map(c=>c.trim());
      const isHeader = !inTable || (nextLine.length > 0 && nextLine.every(c => /^[-: ]+$/.test(c)));
      const tag = isHeader && out[out.length-1] === '<table>' ? 'th' : 'td';
      out.push('<tr>' + cells.map(c => `<${tag}>${c}</${tag}>`).join('') + '</tr>');
      continue;
    }

    // List item
    if (line.startsWith('- ') || line.startsWith('• ')) {
      flushTable();
      if (!inList) { out.push('<ul>'); inList = true; }
      out.push(`<li>${line.slice(2)}</li>`);
      continue;
    }

    // Empty line
    if (line.trim() === '') {
      flushList(); flushTable();
      out.push('<br>');
      continue;
    }

    // Regular paragraph
    flushList(); flushTable();
    out.push(`<p>${line}</p>`);
  }

  flushList();
  flushTable();
  return out.join('');
}

// =========================================
// RENDER RESULTS
// =========================================

function renderResults(data) {
  // Target
  let thtml = `${esc(data.target.tech)} ${esc(data.target.version)}`;
  if (data.target.ecosystem === 'auto') thtml += ' <span class="badge-auto">auto</span>';
  $('resTarget').innerHTML = thtml;

  $('cacheHit').style.display = data.cached ? '' : 'none';
  if (data.meta?.ms) { $('scanMs').textContent = `${data.meta.ms}ms`; $('scanMs').style.display = ''; }

  // Risk badge
  const badge = $('resBadge');
  badge.textContent = data.risk.level;
  badge.className   = 'risk-badge ' + riskClass(data.risk.level);

  // Metrics
  const kevCount  = (data.vulns.list||[]).filter(v => v.kev).length;
  const critCount = (data.vulns.list||[]).filter(v => numSev(v.severity) >= 9.0).length;
  setMetric('metCves', data.vulns.total, data.vulns.total > 0 ? 'col-bad' : 'col-ok');
  setMetric('metCrit', critCount,         critCount > 0        ? 'col-bad' : 'col-ok');
  setMetric('metKev',  kevCount,          kevCount  > 0        ? 'col-bad' : 'col-ok');

  // BUG3 FIX: set bar to 0, make visible, then animate after 100ms
  // setTimeout(100) is more reliable than double-rAF when parent has fadeIn animation
  const score = data.risk.score || 0;
  $('riskScore').textContent = score;
  const bar = $('riskScoreBar');
  bar.className   = 'risk-bar-fill ' + riskClass(data.risk.level).replace('risk-','bar-');
  bar.style.width = '0%';
  bar.style.transition = 'none';   // disable transition while resetting

  renderRiskBreakdown(data.risk.factors || []);

  // EOL
  const eol = data.eol;
  $('eolStatus').textContent = eol.status==='EOL' ? '✕ End of Life' : eol.status==='supported' ? '✓ Supported' : '? Unknown';
  $('eolStatus').className   = 'eol-status ' + (eol.status==='EOL' ? 'eol-eol' : eol.status==='supported' ? 'eol-supported' : 'eol-unknown');

  let em = '';
  if (eol.globalLatest) {
    em += `Latest (global): <span class="hl">${esc(eol.globalLatest)}</span>`;
    if (eol.branchLatest && eol.branchLatest !== eol.globalLatest)
      em += `&nbsp;&nbsp;·&nbsp;&nbsp;Latest (this branch): <span class="hl-muted">${esc(eol.branchLatest)}</span>`;
  }
  if (eol.eolDate) em += `&nbsp;&nbsp;·&nbsp;&nbsp;EOL date: <span class="hl-warn">${esc(eol.eolDate)}</span>`;
  if (eol.lts)     em += `&nbsp;&nbsp;·&nbsp;&nbsp;<span class="badge-lts">LTS</span>`;
  $('eolLatest').innerHTML = em;

  // Source badges
  const sources = data.vulns?.sources || data.meta?.sources || ['OSV'];
  $('sourceBadges').innerHTML = sources.map(s =>
    `<span class="source-badge source-${s.toLowerCase()}">${esc(s)}</span>`
  ).join('');

  // CVE count
  const cveCount = $('cveCount');
  if ((data.vulns.list||[]).length > 0) {
    cveCount.textContent = data.vulns.total > data.vulns.list.length
      ? `${data.vulns.list.length} shown / ${data.vulns.total} total`
      : `${data.vulns.total} found`;
    cveCount.style.display = '';
  } else cveCount.style.display = 'none';

  $('cveFilters').style.display = (data.vulns.list||[]).length > 3 ? 'flex' : 'none';
  $('cveFilter').value = '';
  $('sevFilter').value = 'all';

  renderCVEList((data.vulns.list||[]).slice(0,100));
  $('btnExport').style.display = '';

  // Make results visible
  $('results').classList.add('visible');

  // BUG3 FIX: wait for display:block + fadeIn to paint, then re-enable transition and animate
  setTimeout(() => {
    bar.style.transition = '';   // re-enable the CSS transition
    bar.style.width      = score + '%';
  }, 100);

  renderTactical();

  setTimeout(() => $('results').scrollIntoView({ behavior: 'smooth', block: 'nearest' }), 50);
}

function setMetric(id, val, cls) { const el=$(id); el.textContent=val; el.className='metric-val '+cls; }

function renderRiskBreakdown(factors) {
  const box = $('riskBreakdown');
  if (!factors.length) { box.style.display='none'; return; }
  box.style.display='';
  box.innerHTML = factors.map(f =>
    `<div class="factor-row">
       <span class="factor-dot factor-${f.level}"></span>
       <span class="factor-label">${esc(f.label)}</span>
       <span class="factor-pts">+${f.points}</span>
     </div>`
  ).join('');
}

// =========================================
// AUXILIARY UI — version/dym/nontrackable
// =========================================

function renderNonTrackable(data) {
  $('nonTrackableBox').innerHTML =
    `<div class="nt-icon">ℹ</div>
     <div class="nt-body">
       <strong>${esc(data.target.tech)}</strong> is not trackable via CVE databases.
       <br>${esc(data.note)}
       <br><span class="nt-hint">Expected for SaaS services, CDN scripts, and cloud platforms. Check the provider's security bulletins directly.</span>
     </div>`;
  $('nonTrackableBox').style.display = 'flex';
}

function renderDidYouMean(data) {
  const box = $('didYouMeanBox');
  if (!data.suggestion) { box.style.display='none'; return; }
  const s = data.suggestion;
  // BUG1 FIX: was onclick= — now using data attributes + delegated listener (bound below)
  box.innerHTML =
    `<span class="dym-icon">💡</span>
     <div class="dym-body">
       Did you mean <strong>${esc(s.name)}</strong>?
       <button class="vw-btn" data-action="use-suggestion" data-name="${escAttr(s.name)}" data-eco="${escAttr(s.ecosystem||'')}">
         Use ${esc(s.name)}${s.ecosystem ? ' ('+esc(s.ecosystem)+')' : ''}
       </button>
     </div>`;
  box.style.display = 'flex';
}

function renderVersionWarning(data) {
  const vi  = data.versionInfo;
  const box = $('versionWarning');
  if (!vi || vi.exists === true) { box.style.display='none'; return; }

  // BUG1 FIX: data-action buttons instead of onclick=
  let html = `<span class="vw-icon">⚠</span>
    <div class="vw-body">
      <strong>Version not found in ${esc(data.target.ecosystem)} registry.</strong>`;
  if (vi.closest) {
    html += `<br>Closest: <button class="vw-btn" data-action="use-version" data-ver="${escAttr(vi.closest)}">${esc(vi.closest)}</button>`;
  }
  if (vi.recentVersions?.length) {
    html += `<br><span class="vw-label">Recent:</span> ` +
      vi.recentVersions.map(v =>
        `<button class="vw-btn" data-action="use-version" data-ver="${escAttr(v)}">${esc(v)}</button>`
      ).join(' ');
  }
  html += '</div>';
  box.innerHTML = html;
  box.style.display = 'flex';
}

// Event delegation for dynamic buttons (data-action pattern — CSP-safe)
document.addEventListener('click', e => {
  const btn = e.target.closest('[data-action]');
  if (!btn) return;

  const action = btn.dataset.action;

  if (action === 'use-version') {
    $('version').value = btn.dataset.ver;
    $('versionWarning').style.display = 'none';
    doScan();
  }

  if (action === 'use-suggestion') {
    $('tech').value = btn.dataset.name;
    if (btn.dataset.eco) $('ecosystem').value = btn.dataset.eco;
    $('didYouMeanBox').style.display = 'none';
    doScan();
  }
});

// =========================================
// CVE LIST
// =========================================

function renderCVEList(list) {
  const el = $('cveList');
  if (!list.length) {
    el.innerHTML = '<div class="no-cves">✓ No known vulnerabilities found for this version</div>';
    return;
  }
  el.innerHTML = list.map((v, i) => {
    const sc  = sevClass(v.severity), lbl = sevLabel(v.severity), id = v.displayId||v.id;
    const alt = (v.displayId && v.displayId !== v.id) ? `<span class="cve-alias">${esc(v.id)}</span>` : '';
    const sum = v.summary ? `<span class="cve-summary">${esc(v.summary.slice(0,110))}${v.summary.length>110?'…':''}</span>` : '';
    const lnk = v.link ? `<a class="cve-link" href="${escAttr(v.link)}" target="_blank" rel="noopener noreferrer">↗</a>` : '';
    const kev = v.kev  ? '<span class="kev-badge">⚑ KEV</span>' : '';
    const dt  = v.published ? `<span class="cve-date">${v.published.slice(0,10)}</span>` : '';
    const src = v.source && v.source !== 'OSV' ? `<span class="cve-src-badge">${esc(v.source)}</span>` : '';
    return `
      <div class="cve-item" style="animation-delay:${Math.min(i,20)*0.025}s"
           data-sev="${sc}" data-id="${escAttr(id)}">
        <div class="cve-main">
          <div class="cve-id-group">
            <span class="cve-id">${esc(id)}</span>${alt}${kev}
            <span class="sev-badge ${sc}">${lbl}</span>${src}${dt}
          </div>${sum}
        </div>${lnk}
      </div>`;
  }).join('');
}

function filterCVEs() {
  if (!_lastData) return;
  const text   = ($('cveFilter').value||'').toLowerCase();
  const sevSel = $('sevFilter').value;
  let list = (_lastData.vulns.list||[]).slice(0,100);
  if (sevSel !== 'all') list = list.filter(v => sevClass(v.severity) === 'sev-' + sevSel);
  if (text) list = list.filter(v =>
    (v.displayId||v.id).toLowerCase().includes(text) ||
    (v.summary||'').toLowerCase().includes(text) ||
    (v.allIds||[]).join(' ').toLowerCase().includes(text)
  );
  renderCVEList(list);
  $('cveCount').textContent = list.length < (_lastData.vulns.total||0)
    ? `${list.length} shown / ${_lastData.vulns.total} total`
    : `${_lastData.vulns.total} found`;
}

// =========================================
// EXPORT
// =========================================

function exportReport() {
  if (!_lastData) return;
  const s = _lastData.summary, r = _lastData.risk;
  const vulns   = (_lastData.vulns.list||[]).slice(0,100);
  const sources = (_lastData.vulns?.sources||['OSV']).join(', ');
  const tac     = _lastData.tactical;

  const L = (...a) => a; // shorthand
  const lines = [
    '='.repeat(60), '  SECURITY ASSESSMENT REPORT', '  EOL & CVE Checker  v8', '='.repeat(60), '',
    `Date:          ${s.date}`,
    `Target:        ${s.target}`,
    `Data Sources:  ${sources}`, '',
    '-'.repeat(60), 'EXECUTIVE SUMMARY', '-'.repeat(60), '',
    `Risk Level:    ${s.riskLevel}`,
    `Risk Score:    ${s.riskScore}/100`,
    `Max CVSS:      ${s.maxCvss||'N/A'}`, '',
    `Total CVEs:    ${s.totalVulns}`,
    `  Critical:    ${s.criticalVulns}`,
    `  High:        ${s.highVulns}`,
    `  KEV:         ${s.kevVulns}`, '',
    `EOL Status:    ${(s.eolStatus||'').toUpperCase()}`,
    s.eolDate       ? `EOL Date:      ${s.eolDate}`       : null,
    s.latestVersion ? `Latest Ver:    ${s.latestVersion}` : null, '',
    '-'.repeat(60), 'RISK FACTORS', '-'.repeat(60), '',
    ...(r.factors||[]).map(f => `  [${f.level.toUpperCase().padEnd(8)}] ${f.label} (+${f.points} pts)`), '',
    '-'.repeat(60), 'RECOMMENDATION', '-'.repeat(60), '',
    ...wordWrap(s.recommendation||'', 58).map(l => `  ${l}`), '',
    ...(tac ? [
      '-'.repeat(60), 'RED TEAM ANALYSIS', '-'.repeat(60), '',
      tac.red.replace(/#+\s/g,'').replace(/\*\*/g,'').replace(/<[^>]+>/g,''), '',
      '-'.repeat(60), 'BLUE TEAM ANALYSIS', '-'.repeat(60), '',
      tac.blue.replace(/#+\s/g,'').replace(/\*\*/g,'').replace(/<[^>]+>/g,''), ''
    ] : []),
    '-'.repeat(60), `VULNERABILITIES (${vulns.length} shown)`, '-'.repeat(60), '',
    ...vulns.map((v,i) => [
      `${String(i+1).padStart(3)}. ${v.displayId||v.id}  [${v.source||'OSV'}]`,
      `     Severity:  ${v.severity}${v.kev ? '  ⚑ ACTIVELY EXPLOITED (KEV)' : ''}`,
      v.published ? `     Published: ${v.published.slice(0,10)}` : null,
      v.summary   ? `     Summary:   ${v.summary.slice(0,100)}` : null,
      `     Reference: ${v.link||'N/A'}`, ''
    ].filter(Boolean)).flat(),
    '='.repeat(60),
    'Generated by EOL & CVE Checker v8 — https://theeolchecker.pages.dev',
    '='.repeat(60),
  ].filter(l => l !== null && l !== undefined).join('\n');

  const a = Object.assign(document.createElement('a'), {
    href:     URL.createObjectURL(new Blob([lines], {type:'text/plain;charset=utf-8'})),
    download: `security-report-${_lastData.target.tech}-${_lastData.target.version}-${s.date}.txt`
  });
  document.body.appendChild(a); a.click();
  document.body.removeChild(a); URL.revokeObjectURL(a.href);
  showBanner('Report downloaded ✓', 'info');
}

function wordWrap(t, w) {
  const words = (t||'').split(' '), lines = []; let c = '';
  for (const word of words) {
    if ((c+' '+word).trim().length > w) { lines.push(c); c = word; }
    else c = (c+' '+word).trim();
  }
  if (c) lines.push(c);
  return lines;
}

// =========================================
// HISTORY
// =========================================

function addToHistory(data) {
  const e = { tech:data.target.tech, version:data.target.version, eco:$('ecosystem').value, risk:data.risk.level, score:data.risk.score, total:data.vulns.total, ts:Date.now() };
  scanHistory = scanHistory.filter(h => !(h.tech===e.tech && h.version===e.version));
  scanHistory.unshift(e);
  if (scanHistory.length > 10) scanHistory = scanHistory.slice(0,10);
  saveHistory(scanHistory);
  renderHistory();
}

function renderHistory() {
  if (!scanHistory.length) { $('historySection').style.display='none'; return; }
  $('historySection').style.display = 'block';
  $('historyList').innerHTML = scanHistory.map(h => `
    <div class="history-item" tabindex="0"
      data-tech="${escAttr(h.tech)}" data-ver="${escAttr(h.version)}" data-eco="${escAttr(h.eco||'npm')}">
      <span class="history-tech">${esc(h.tech)}</span>
      <span class="history-ver">v${esc(h.version)}</span>
      <span class="history-eco">${esc(h.eco||'npm')}</span>
      <span class="history-count">${h.total!=null ? h.total+' CVEs' : ''}</span>
      <span class="history-risk risk-badge ${riskClass(h.risk)}">${esc(h.risk)}</span>
    </div>`).join('');

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

function loadHistory()  { try { return JSON.parse(localStorage.getItem('eolchecker_history')||'[]'); } catch { return []; } }
function saveHistory(h) { try { localStorage.setItem('eolchecker_history', JSON.stringify(h)); } catch {} }

// =========================================
// UTILITIES
// =========================================

function clearForm() {
  $('tech').value = ''; $('version').value = '';
  $('results').classList.remove('visible');
  hideBoxes();
  $('btnExport').style.display  = 'none';
  $('scanMs').style.display     = 'none';
  $('cacheHit').style.display   = 'none';
  $('tacticalPanel').style.display = 'none';
  _lastData = null;
}

function hideBoxes() {
  ['versionWarning','nonTrackableBox','didYouMeanBox'].forEach(id => $(id).style.display = 'none');
}

function showBanner(msg, type='error') {
  const b = $('banner');
  b.textContent = (type==='error' ? '⚠ ' : '✓ ') + msg;
  b.className   = 'banner banner-'+type+' visible';
  setTimeout(() => b.classList.remove('visible'), 5000);
}

function flashError(el) {
  el.style.borderColor = 'rgba(255,82,82,0.6)'; el.focus();
  setTimeout(() => { el.style.borderColor = ''; }, 1400);
}

function numSev(s)  { const n=parseFloat(s); return !isNaN(n)?n:(s==='CRITICAL'?9.5:s==='HIGH'?7.5:s==='MEDIUM'?5:0); }
function riskClass(l) { return {CRITICAL:'risk-critical',HIGH:'risk-high',MEDIUM:'risk-medium',LOW:'risk-low'}[l]||'risk-low'; }

function sevClass(s) {
  if (!s||s==='UNKNOWN') return 'sev-unknown';
  const n = parseFloat(s);
  if (!isNaN(n)) { if(n>=9) return 'sev-critical'; if(n>=7) return 'sev-high'; if(n>=4) return 'sev-medium'; return 'sev-low'; }
  const u = s.toUpperCase();
  if(u==='CRITICAL') return 'sev-critical'; if(u==='HIGH') return 'sev-high';
  if(u==='MEDIUM'||u==='MODERATE') return 'sev-medium'; if(u==='LOW') return 'sev-low';
  return 'sev-unknown';
}

function sevLabel(s) {
  if (!s||s==='UNKNOWN') return 'UNKNOWN';
  const n = parseFloat(s);
  if (!isNaN(n)) { if(n>=9) return `CRITICAL ${n.toFixed(1)}`; if(n>=7) return `HIGH ${n.toFixed(1)}`; if(n>=4) return `MEDIUM ${n.toFixed(1)}`; return `LOW ${n.toFixed(1)}`; }
  return s.toUpperCase();
}

function enc(s)      { return encodeURIComponent(s); }
function esc(s)      { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function escAttr(s)  { return String(s).replace(/"/g,'&quot;').replace(/'/g,'&#39;'); }
