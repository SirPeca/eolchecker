/* =========================================
   EOL & CVE Checker — app.js  v7
   ========================================= */

const $ = id => document.getElementById(id);

let _lastData    = null;
let _tacLang     = 'en';        // current language: 'en' | 'es'
let _tacTab      = 'red';       // current tab: 'red' | 'blue'
let scanHistory  = loadHistory();

renderHistory();
bindEvents();
loadVisitCounter();

// ---- Visit counter ----

async function loadVisitCounter() {
  try {
    const data = await (await fetch('/visits')).json();
    if (data.total != null) {
      const el = $('visitCounter');
      el.textContent = `${formatNumber(data.total)} scans`;
      el.style.display = '';
    }
  } catch {}
}

function formatNumber(n) {
  if (n >= 1000000) return (n/1000000).toFixed(1)+'M';
  if (n >= 1000)    return (n/1000).toFixed(1)+'K';
  return String(n);
}

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
  ['tech','version'].forEach(id => $(id).addEventListener('keydown', e => { if (e.key==='Enter') doScan(); }));
  $('cveFilter').addEventListener('input',  filterCVEs);
  $('sevFilter').addEventListener('change', filterCVEs);
}

// ---- Scan ----

async function doScan() {
  const tech      = $('tech').value.trim();
  const version   = $('version').value.trim();
  const ecosystem = $('ecosystem').value;
  if (!tech || !version) { flashError($('tech')); return; }

  $('results').classList.remove('visible');
  ['versionWarning','nonTrackableBox','didYouMeanBox'].forEach(id => $(id).style.display = 'none');
  $('loading').classList.add('visible');
  $('btn').disabled = true;

  const msgs = [
    'Validating version against registry...',
    ecosystem === 'auto' ? 'Auto-detecting ecosystem…' : `Querying OSV [${ecosystem}]…`,
    'Checking fallback sources (NVD, GitHub Advisories)...',
    'Checking CISA Known Exploited Vulnerabilities...',
    'Verifying end-of-life status...',
    'Computing risk score...',
    'Building tactical analysis...'
  ];
  let mi = 0;
  const ticker = setInterval(() => { $('loadingText').textContent = msgs[mi++ % msgs.length]; }, 850);
  const ctrl   = new AbortController();
  const tmout  = setTimeout(() => ctrl.abort(), 25000);

  try {
    const url  = `/check?tech=${encodeURIComponent(tech)}&version=${encodeURIComponent(version)}&ecosystem=${encodeURIComponent(ecosystem)}&lang=${_tacLang}`;
    const res  = await fetch(url, { signal: ctrl.signal });
    clearTimeout(tmout);
    const text = await res.text();
    clearInterval(ticker);
    $('loading').classList.remove('visible');
    $('btn').disabled = false;

    let data;
    try { data = JSON.parse(text); }
    catch { showBanner('Backend returned HTML instead of JSON. Is the Worker deployed?', 'error'); return; }

    if (!data.success) { showBanner(data.error || 'Unknown backend error.', 'error'); return; }

    if (data.visitTotal != null) {
      $('visitCounter').textContent = `${formatNumber(data.visitTotal)} scans`;
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

// ---- Tactical panel controls ----

window.switchTacTab = function(tab) {
  _tacTab = tab;
  $('tabRed').className  = 'tac-tab' + (tab==='red'  ? ' active-red'  : '');
  $('tabBlue').className = 'tac-tab' + (tab==='blue' ? ' active-blue' : '');
  renderTactical();
};

window.switchLang = function(lang) {
  _tacLang = lang;
  $('langEN').className = 'lang-btn' + (lang==='en' ? ' active' : '');
  $('langES').className = 'lang-btn' + (lang==='es' ? ' active' : '');
  // Re-fetch with new lang if we have data
  if (_lastData) {
    fetchTacticalForLang(lang);
  }
};

async function fetchTacticalForLang(lang) {
  if (!_lastData) return;
  const { tech, version, ecosystem } = _lastData.target;
  try {
    const url  = `/check?tech=${encodeURIComponent(tech)}&version=${encodeURIComponent(version)}&ecosystem=${encodeURIComponent(ecosystem)}&lang=${lang}`;
    const res  = await fetch(url);
    const data = await res.json();
    if (data.tactical) {
      _lastData.tactical = data.tactical;
      renderTactical();
    }
  } catch {}
}

function renderTactical() {
  if (!_lastData?.tactical) {
    $('tacticalPanel').style.display = 'none';
    return;
  }
  const content = _tacTab === 'red' ? _lastData.tactical.red : _lastData.tactical.blue;
  $('tacContent').className = `tac-content tac-panel-${_tacTab}`;
  $('tacContent').innerHTML = markdownToHtml(content);
  $('tacticalPanel').style.display = '';
}

window.copyTactical = function() {
  if (!_lastData?.tactical) return;
  const content = _tacTab === 'red' ? _lastData.tactical.red : _lastData.tactical.blue;
  navigator.clipboard.writeText(content).then(() => {
    const btn = $('tacCopyBtn');
    btn.textContent = '✓ Copied!';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = '⎘ Copy'; btn.classList.remove('copied'); }, 2000);
  }).catch(() => {
    // Fallback for non-secure context
    const ta = document.createElement('textarea');
    ta.value = content;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    showBanner('Copied to clipboard ✓', 'info');
  });
};

// Simple markdown → HTML renderer for tactical content
function markdownToHtml(md) {
  return md
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')   // escape first
    .replace(/^## (.+)$/gm, '<h2>$1</h2>')
    .replace(/^### (.+)$/gm, '<h3>$1</h3>')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/^- (.+)$/gm, '<li>$1</li>')
    .replace(/(<li>.*<\/li>(\n|$))+/g, m => `<ul>${m}</ul>`)
    .replace(/^\|(.+)\|$/gm, row => {
      const cells = row.split('|').filter(Boolean).map(c => c.trim());
      return '<tr>' + cells.map(c => `<td>${c}</td>`).join('') + '</tr>';
    })
    .replace(/(<tr>.*<\/tr>(\n|$))+/g, m => `<table>${m}</table>`)
    .replace(/\n{2,}/g, '</p><p>')
    .replace(/\n/g, '<br>')
    .replace(/^(?!<[hupbt])(.+)$/gm, m => m.startsWith('<') ? m : `<p>${m}</p>`)
    // Fix table headers (first row)
    .replace(/<tr><td>([^<]+)<\/td><td>([^<]+)<\/td><\/tr>/, '<tr><th>$1</th><th>$2</th></tr>');
}

// ---- Render Results ----

function renderResults(data) {
  let targetHtml = `${escHtml(data.target.tech)} ${escHtml(data.target.version)}`;
  if (data.target.ecosystem === 'auto') targetHtml += ' <span class="badge-auto">auto</span>';
  $('resTarget').innerHTML = targetHtml;

  $('cacheHit').style.display = data.cached ? '' : 'none';
  if (data.meta?.ms) { $('scanMs').textContent = `${data.meta.ms}ms`; $('scanMs').style.display=''; }

  const badge = $('resBadge');
  badge.textContent = data.risk.level;
  badge.className   = 'risk-badge ' + riskClass(data.risk.level);

  const kevCount  = data.vulns.list.filter(v => v.kev).length;
  const critCount = data.vulns.list.filter(v => numSev(v.severity) >= 9.0).length;
  setMetric('metCves', data.vulns.total, data.vulns.total>0 ? 'col-bad':'col-ok');
  setMetric('metCrit', critCount,         critCount>0        ? 'col-bad':'col-ok');
  setMetric('metKev',  kevCount,          kevCount>0         ? 'col-bad':'col-ok');

  // § BAR FIX — set class + reset to 0, make results visible, THEN animate
  const score = data.risk.score || 0;
  $('riskScore').textContent  = score;
  const bar = $('riskScoreBar');
  bar.className   = 'risk-bar-fill ' + riskClass(data.risk.level).replace('risk-','bar-');
  bar.style.width = '0%';   // always start from 0

  renderRiskBreakdown(data.risk.factors || []);

  // EOL
  const eol   = data.eol;
  const eolEl = $('eolStatus');
  eolEl.textContent = eol.status==='EOL' ? '✕ End of Life' : eol.status==='supported' ? '✓ Supported' : '? Unknown';
  eolEl.className   = 'eol-status '+(eol.status==='EOL'?'eol-eol':eol.status==='supported'?'eol-supported':'eol-unknown');

  let eolMeta = '';
  if (eol.globalLatest) {
    eolMeta += `Latest (global): <span class="hl">${escHtml(eol.globalLatest)}</span>`;
    if (eol.branchLatest && eol.branchLatest !== eol.globalLatest)
      eolMeta += `&nbsp;&nbsp;·&nbsp;&nbsp;Latest (this branch): <span class="hl-muted">${escHtml(eol.branchLatest)}</span>`;
  }
  if (eol.eolDate) eolMeta += `&nbsp;&nbsp;·&nbsp;&nbsp;EOL date: <span class="hl-warn">${escHtml(eol.eolDate)}</span>`;
  if (eol.lts)     eolMeta += `&nbsp;&nbsp;·&nbsp;&nbsp;<span class="badge-lts">LTS</span>`;
  $('eolLatest').innerHTML = eolMeta;

  // Source badges
  const sources = data.vulns?.sources || data.meta?.sources || ['OSV'];
  $('sourceBadges').innerHTML = sources.map(s =>
    `<span class="source-badge source-${s.toLowerCase()}">${escHtml(s)}</span>`
  ).join('');

  // CVE count
  const cveCount = $('cveCount');
  if (data.vulns.list.length > 0) {
    cveCount.textContent = data.vulns.total > data.vulns.list.length
      ? `${data.vulns.list.length} shown / ${data.vulns.total} total`
      : `${data.vulns.total} found`;
    cveCount.style.display = '';
  } else cveCount.style.display = 'none';

  $('cveFilters').style.display = data.vulns.list.length > 3 ? 'flex' : 'none';
  $('cveFilter').value = '';
  $('sevFilter').value = 'all';

  renderCVEList((data.vulns.list||[]).slice(0,100));
  $('btnExport').style.display = '';

  // Make results visible FIRST
  $('results').classList.add('visible');

  // § BAR ANIMATION — double rAF ensures the browser has painted the element
  // before we change width, so the CSS transition actually fires
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      bar.style.width = score + '%';
    });
  });

  // Render tactical panel
  renderTactical();

  setTimeout(() => $('results').scrollIntoView({ behavior:'smooth', block:'nearest' }), 50);
}

function setMetric(id, val, cls) { const el=$(id); el.textContent=val; el.className='metric-val '+cls; }

function renderRiskBreakdown(factors) {
  const box = $('riskBreakdown');
  if (!factors.length) { box.style.display='none'; return; }
  box.style.display='';
  box.innerHTML = factors.map(f => `
    <div class="factor-row">
      <span class="factor-dot factor-${f.level}"></span>
      <span class="factor-label">${escHtml(f.label)}</span>
      <span class="factor-pts">+${f.points}</span>
    </div>`).join('');
}

// ---- Auxiliary UI ----

function renderNonTrackable(data) {
  $('nonTrackableBox').innerHTML = `
    <div class="nt-icon">ℹ</div>
    <div class="nt-body">
      <strong>${escHtml(data.target.tech)}</strong> is not trackable via CVE databases.
      <br>${escHtml(data.note)}
      <br><span class="nt-hint">This is expected for SaaS services, CDN scripts, and cloud platforms.</span>
    </div>`;
  $('nonTrackableBox').style.display = 'flex';
}

function renderDidYouMean(data) {
  const box = $('didYouMeanBox');
  if (!data.suggestion) { box.style.display='none'; return; }
  const s = data.suggestion;
  box.innerHTML = `
    <span class="dym-icon">💡</span>
    <div class="dym-body">
      Did you mean <strong>${escHtml(s.name)}</strong>?
      <button class="vw-btn" onclick="useSuggestion('${escAttr(s.name)}','${escAttr(s.ecosystem||'')}')">
        Use ${escHtml(s.name)}${s.ecosystem?' ('+escHtml(s.ecosystem)+')':''}
      </button>
    </div>`;
  box.style.display = 'flex';
}

function renderVersionWarning(data) {
  const vi  = data.versionInfo;
  const box = $('versionWarning');
  if (!vi || vi.exists===true) { box.style.display='none'; return; }
  let html = `<span class="vw-icon">⚠</span>
    <div class="vw-body">
      <strong>Version not found in ${escHtml(data.target.ecosystem)} registry.</strong>`;
  if (vi.closest) html += `<br>Closest: <button class="vw-btn" onclick="useVersion('${escAttr(vi.closest)}')">${escHtml(vi.closest)}</button>`;
  if (vi.recentVersions?.length) html += `<br><span class="vw-label">Recent:</span> `+
    vi.recentVersions.map(v=>`<button class="vw-btn" onclick="useVersion('${escAttr(v)}')">${escHtml(v)}</button>`).join(' ');
  html += '</div>';
  box.innerHTML = html;
  box.style.display = 'flex';
}

window.useVersion    = v  => { $('version').value=v; $('versionWarning').style.display='none'; doScan(); };
window.useSuggestion = (n,e) => { $('tech').value=n; if(e) $('ecosystem').value=e; $('didYouMeanBox').style.display='none'; doScan(); };

// ---- CVE list ----

function renderCVEList(list) {
  const el = $('cveList');
  if (!list.length) { el.innerHTML='<div class="no-cves">✓ No known vulnerabilities found for this version</div>'; return; }
  el.innerHTML = list.map((v,i) => {
    const sc  = sevClass(v.severity), lbl = sevLabel(v.severity), id = v.displayId||v.id;
    const alt = (v.displayId&&v.displayId!==v.id) ? `<span class="cve-alias">${escHtml(v.id)}</span>` : '';
    const sum = v.summary ? `<span class="cve-summary">${escHtml(v.summary.slice(0,110))}${v.summary.length>110?'…':''}</span>` : '';
    const lnk = v.link    ? `<a class="cve-link" href="${escAttr(v.link)}" target="_blank" rel="noopener noreferrer">↗</a>` : '';
    const kev = v.kev     ? '<span class="kev-badge">⚑ KEV</span>' : '';
    const dt  = v.published ? `<span class="cve-date">${v.published.slice(0,10)}</span>` : '';
    const src = v.source&&v.source!=='OSV' ? `<span class="cve-src-badge">${escHtml(v.source)}</span>` : '';
    return `
      <div class="cve-item" style="animation-delay:${Math.min(i,20)*0.025}s"
           data-sev="${sc}" data-id="${escAttr(id)}" data-summary="${escAttr(v.summary||'')}">
        <div class="cve-main">
          <div class="cve-id-group">
            <span class="cve-id">${escHtml(id)}</span>${alt}${kev}
            <span class="sev-badge ${sc}">${lbl}</span>${src}${dt}
          </div>${sum}
        </div>${lnk}
      </div>`;
  }).join('');
}

function filterCVEs() {
  if (!_lastData) return;
  const text=($('cveFilter').value||'').toLowerCase(), sevSel=$('sevFilter').value;
  let list = (_lastData.vulns.list||[]).slice(0,100);
  if (sevSel!=='all') list=list.filter(v=>sevClass(v.severity)==='sev-'+sevSel);
  if (text) list=list.filter(v=>(v.displayId||v.id).toLowerCase().includes(text)||(v.summary||'').toLowerCase().includes(text)||(v.allIds||[]).join(' ').toLowerCase().includes(text));
  renderCVEList(list);
  $('cveCount').textContent = list.length<_lastData.vulns.total ? `${list.length} shown / ${_lastData.vulns.total} total` : `${_lastData.vulns.total} found`;
}

// ---- Export ----

function exportReport() {
  if (!_lastData) return;
  const s=_lastData.summary, r=_lastData.risk, vulns=(_lastData.vulns.list||[]).slice(0,100);
  const sources=(_lastData.vulns?.sources||['OSV']).join(', ');
  const tac=_lastData.tactical;
  const lines=[
    '='.repeat(60),'  SECURITY ASSESSMENT REPORT','  EOL & CVE Checker  v7','='.repeat(60),'',
    `Date:          ${s.date}`,`Target:        ${s.target}`,`Data Sources:  ${sources}`,'',
    '-'.repeat(60),'EXECUTIVE SUMMARY','-'.repeat(60),'',
    `Risk Level:    ${s.riskLevel}`,`Risk Score:    ${s.riskScore}/100`,`Max CVSS:      ${s.maxCvss||'N/A'}`,'',
    `Total CVEs:    ${s.totalVulns}`,`  Critical:    ${s.criticalVulns}`,`  High:        ${s.highVulns}`,`  KEV:         ${s.kevVulns}`,'',
    `EOL Status:    ${s.eolStatus?.toUpperCase()}`,
    s.eolDate?`EOL Date:      ${s.eolDate}`:'',s.latestVersion?`Latest Ver:    ${s.latestVersion}`:'','',
    '-'.repeat(60),'RISK FACTORS','-'.repeat(60),'',
    ...(r.factors||[]).map(f=>`  [${f.level.toUpperCase().padEnd(8)}] ${f.label} (+${f.points} pts)`),'',
    '-'.repeat(60),'RECOMMENDATION','-'.repeat(60),'',
    ...wordWrap(s.recommendation,58).map(l=>`  ${l}`),'',
    ...(tac?['-'.repeat(60),'RED TEAM ANALYSIS','-'.repeat(60),'',tac.red.replace(/<[^>]+>/g,''),'','-'.repeat(60),'BLUE TEAM ANALYSIS','-'.repeat(60),'',tac.blue.replace(/<[^>]+>/g,''),'']:[]),
    '-'.repeat(60),`VULNERABILITIES (${vulns.length} shown)`,'-'.repeat(60),'',
    ...vulns.map((v,i)=>[`${String(i+1).padStart(3)}. ${v.displayId||v.id}  [${v.source||'OSV'}]`,`     Severity:  ${v.severity}${v.kev?' ⚑ ACTIVELY EXPLOITED (KEV)':''}`,v.published?`     Published: ${v.published.slice(0,10)}`:'',v.summary?`     Summary:   ${v.summary.slice(0,100)}`:'',`     Reference: ${v.link||'N/A'}`,''].filter(Boolean)).flat(),
    '='.repeat(60),'Generated by EOL & CVE Checker v7 — https://theeolchecker.pages.dev','='.repeat(60),
  ].filter(l=>l!==undefined).join('\n');

  const a=Object.assign(document.createElement('a'),{
    href:URL.createObjectURL(new Blob([lines],{type:'text/plain;charset=utf-8'})),
    download:`security-report-${_lastData.target.tech}-${_lastData.target.version}-${s.date}.txt`
  });
  document.body.appendChild(a);a.click();document.body.removeChild(a);URL.revokeObjectURL(a.href);
  showBanner('Report downloaded ✓','info');
}

function wordWrap(t,w){const words=(t||'').split(' '),lines=[];let c='';for(const word of words){if((c+' '+word).trim().length>w){lines.push(c);c=word;}else c=(c+' '+word).trim();}if(c)lines.push(c);return lines;}

// ---- History ----

function addToHistory(data) {
  const e={tech:data.target.tech,version:data.target.version,eco:$('ecosystem').value,risk:data.risk.level,score:data.risk.score,total:data.vulns.total,ts:Date.now()};
  scanHistory=scanHistory.filter(h=>!(h.tech===e.tech&&h.version===e.version));
  scanHistory.unshift(e);
  if(scanHistory.length>10)scanHistory=scanHistory.slice(0,10);
  saveHistory(scanHistory);renderHistory();
}

function renderHistory() {
  if(!scanHistory.length){$('historySection').style.display='none';return;}
  $('historySection').style.display='block';
  $('historyList').innerHTML=scanHistory.map(h=>`
    <div class="history-item" tabindex="0"
      data-tech="${escAttr(h.tech)}" data-ver="${escAttr(h.version)}" data-eco="${escAttr(h.eco||'npm')}">
      <span class="history-tech">${escHtml(h.tech)}</span>
      <span class="history-ver">v${escHtml(h.version)}</span>
      <span class="history-eco">${escHtml(h.eco||'npm')}</span>
      <span class="history-count">${h.total!=null?h.total+' CVEs':''}</span>
      <span class="history-risk risk-badge ${riskClass(h.risk)}">${escHtml(h.risk)}</span>
    </div>`).join('');
  $('historyList').querySelectorAll('.history-item').forEach(el=>{
    const go=()=>{$('tech').value=el.dataset.tech;$('version').value=el.dataset.ver;$('ecosystem').value=el.dataset.eco;doScan();};
    el.addEventListener('click',go);
    el.addEventListener('keydown',e=>{if(e.key==='Enter')go();});
  });
}

function loadHistory(){try{return JSON.parse(localStorage.getItem('eolchecker_history')||'[]');}catch{return[];}}
function saveHistory(h){try{localStorage.setItem('eolchecker_history',JSON.stringify(h));}catch{}}

// ---- Misc ----

function clearForm() {
  $('tech').value='';$('version').value='';
  $('results').classList.remove('visible');
  ['versionWarning','nonTrackableBox','didYouMeanBox'].forEach(id=>$(id).style.display='none');
  $('btnExport').style.display='none';
  $('scanMs').style.display='none';
  $('cacheHit').style.display='none';
  $('tacticalPanel').style.display='none';
  _lastData=null;
}

function showBanner(msg,type='error'){
  const b=$('banner');
  b.textContent=(type==='error'?'⚠ ':'✓ ')+msg;
  b.className='banner banner-'+type+' visible';
  setTimeout(()=>b.classList.remove('visible'),5000);
}

function flashError(el){el.style.borderColor='rgba(255,82,82,0.6)';el.focus();setTimeout(()=>{el.style.borderColor='';},1400);}
function numSev(s){const n=parseFloat(s);return!isNaN(n)?n:(s==='CRITICAL'?9.5:s==='HIGH'?7.5:s==='MEDIUM'?5:0);}
function riskClass(l){return{CRITICAL:'risk-critical',HIGH:'risk-high',MEDIUM:'risk-medium',LOW:'risk-low'}[l]||'risk-low';}
function sevClass(s){
  if(!s||s==='UNKNOWN')return'sev-unknown';
  const n=parseFloat(s);
  if(!isNaN(n)){if(n>=9)return'sev-critical';if(n>=7)return'sev-high';if(n>=4)return'sev-medium';return'sev-low';}
  const u=s.toUpperCase();
  if(u==='CRITICAL')return'sev-critical';if(u==='HIGH')return'sev-high';
  if(u==='MEDIUM'||u==='MODERATE')return'sev-medium';if(u==='LOW')return'sev-low';
  return'sev-unknown';
}
function sevLabel(s){
  if(!s||s==='UNKNOWN')return'UNKNOWN';
  const n=parseFloat(s);
  if(!isNaN(n)){if(n>=9)return`CRITICAL ${n.toFixed(1)}`;if(n>=7)return`HIGH ${n.toFixed(1)}`;if(n>=4)return`MEDIUM ${n.toFixed(1)}`;return`LOW ${n.toFixed(1)}`;}
  return s.toUpperCase();
}
function escHtml(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function escAttr(s){return String(s).replace(/"/g,'&quot;').replace(/'/g,'&#39;');}
