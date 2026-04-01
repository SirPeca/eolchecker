// =========================================
// EOL & CVE Checker — functions/check.js  v6
//
// NEW in v6:
//  § SOURCES  Multi-source fallback: OSV → NVD API v2 → GitHub Advisories
//  § EOL FIX  globalLatest (latest of whole product) vs branchLatest
//  § KV CACHE Full response cache in KV (TTL 1h) — avoids redundant API calls
//  § COUNTER  Visit counter via KV (same namespace, key "visits:total")
//  § DYM      "Did you mean?" suggestions for common typos/aliases
//  All v5 features preserved (rate limit, strict validation, structured logs,
//  non-trackable detection, smart cascade, auto ecosystem, risk engine pro)
// =========================================

// =========================================
// CONSTANTS
// =========================================

const TECH_PATTERN    = /^[a-zA-Z0-9._\-/:@]{1,80}$/;
const VERSION_PATTERN = /^[a-zA-Z0-9._\-+:]{1,40}$/;

const VALID_ECOSYSTEMS = new Set([
  'npm','PyPI','Maven','Go','RubyGems','NuGet','Packagist',
  'crates.io','Hex','Pub','Linux','auto'
]);

// Name normalization
const NAME_NORMALIZE = {
  'node.js':'node','nodejs':'node','node-js':'node',
  'reactjs':'react','react.js':'react',
  'vuejs':'vue','vue.js':'vue',
  'angularjs':'angular','angular.js':'angular',
  'expressjs':'express','express.js':'express',
  'nextjs':'next','next.js':'next',
  'nuxtjs':'nuxt','nuxt.js':'nuxt',
  'postgresql':'postgres','mongodb':'mongo',
  'log4j2':'log4j','log4j-core':'log4j',
  'spring-boot':'spring-boot','springboot':'spring-boot',
  'ruby-on-rails':'rails','rubyonrails':'rails',
  'webpack.js':'webpack','babeljs':'babel','babel.js':'babel',
};

// Did-you-mean: common typos → correct name
// Key: typo (lowercase), value: [ correctedName, ecosystem ]
const DID_YOU_MEAN_MAP = {
  'corejs':     ['core-js',   'npm'],
  'core_js':    ['core-js',   'npm'],
  'reacts':     ['react',     'npm'],
  'recat':      ['react',     'npm'],
  'exress':     ['express',   'npm'],
  'expresss':   ['express',   'npm'],
  'lodahs':     ['lodash',    'npm'],
  'lodsah':     ['lodash',    'npm'],
  'jqurey':     ['jquery',    'npm'],
  'jqeury':     ['jquery',    'npm'],
  'djangoo':    ['django',    'PyPI'],
  'djagno':     ['django',    'PyPI'],
  'flasks':     ['flask',     'PyPI'],
  'springboot': ['spring-boot','Maven'],
  'opensll':    ['openssl',   'Linux'],
  'openss':     ['openssl',   'Linux'],
  'nginxx':     ['nginx',     'Linux'],
  'ngnix':      ['nginx',     'Linux'],
  'mysqll':     ['mysql',     'Linux'],
  'postgress':  ['postgres',  'Linux'],
  'mongodbb':   ['mongodb',   'Linux'],
};

// Non-trackable SaaS/CDN technologies
const NON_TRACKABLE = {
  'google analytics':'SaaS service — vulnerabilities patched by Google automatically',
  'ga4':'SaaS service (Google Analytics 4) — managed by Google',
  'google tag manager':'SaaS service — managed by Google',
  'gtm':'SaaS service (Google Tag Manager) — managed by Google',
  'cloudflare':'CDN/infrastructure service — not a software package',
  'firebase':'SaaS platform — vulnerabilities managed by Google',
  'aws':'Cloud platform — use AWS Security Bulletins for advisories',
  'azure':'Cloud platform — use Microsoft Security Response Center',
  'tiktok pixel':'Tracking script — no CVE tracking (third-party managed)',
  'facebook pixel':'Tracking script — no CVE tracking (third-party managed)',
  'meta pixel':'Tracking script — no CVE tracking (third-party managed)',
  'google ads':'Advertising service — no CVE tracking',
  'hubspot':'SaaS CRM — no CVE tracking for hosted service',
  'salesforce':'SaaS platform — no CVE tracking for hosted service',
  'stripe':'Payment API SaaS — no CVE tracking for hosted service',
  'twilio':'SaaS API — no CVE tracking for hosted service',
  'intercom':'SaaS service — no CVE tracking for hosted service',
  'hotjar':'Analytics SaaS — no CVE tracking for hosted service',
};

const RATE_LIMIT_REQUESTS = 30;
const RATE_LIMIT_WINDOW   = 60;
const CACHE_TTL_SECONDS   = 3600; // 1 hour KV cache

// =========================================
// HELPERS
// =========================================

function jsonResp(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type':'application/json',
      'Cache-Control':'no-store',
      'Access-Control-Allow-Origin':'*',
      'X-Content-Type-Options':'nosniff',
      'X-Frame-Options':'DENY',
      ...extra
    }
  });
}

async function safeFetch(url, opts = {}, timeoutMs = 8000) {
  try {
    const ctrl  = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    const res   = await fetch(url, {
      ...opts, signal: ctrl.signal,
      cf: { cacheTtl: 600, cacheEverything: true }
    });
    clearTimeout(timer);
    if (!res.ok) return null;
    return await res.json();
  } catch { return null; }
}

function normalize(t) { return t.toLowerCase().trim(); }

function sanitizeTech(s) {
  return String(s).toLowerCase().replace(/[^a-zA-Z0-9._\-/:@ ]/g,'').slice(0,80).trim();
}

function normalizeTech(raw) {
  const lower = raw.toLowerCase().trim();
  return NAME_NORMALIZE[lower] || lower;
}

function structuredLog(event, data) {
  console.log(JSON.stringify({ event, timestamp: Date.now(), ...data }));
}

// =========================================
// § DYM — Did You Mean?
// =========================================

function didYouMean(tech) {
  const lower = tech.toLowerCase().trim();
  const suggestion = DID_YOU_MEAN_MAP[lower];
  if (suggestion) return { name: suggestion[0], ecosystem: suggestion[1] };

  // Levenshtein distance check against known popular packages
  const KNOWN = ['react','express','lodash','jquery','webpack','babel','typescript',
    'angular','vue','next','nuxt','core-js','axios','moment','redux',
    'django','flask','fastapi','spring','rails','laravel',
    'openssl','nginx','mysql','postgres','mongodb','redis','apache'];

  let best = null, bestDist = 3; // max distance threshold
  for (const name of KNOWN) {
    const d = levenshtein(lower, name);
    if (d < bestDist) { bestDist = d; best = name; }
  }
  return best ? { name: best, ecosystem: null } : null;
}

function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m+1 }, (_, i) => Array.from({ length: n+1 }, (_, j) => i===0?j:j===0?i:0));
  for (let i=1;i<=m;i++) for (let j=1;j<=n;j++)
    dp[i][j] = a[i-1]===b[j-1] ? dp[i-1][j-1] : 1+Math.min(dp[i-1][j],dp[i][j-1],dp[i-1][j-1]);
  return dp[m][n];
}

// =========================================
// § KV — Rate limit, Cache, Visit counter
// =========================================

async function checkRateLimit(env, ip) {
  if (!env?.RATE_LIMIT) return { limited: false };
  const key = `rl:${ip}`;
  try {
    const raw   = await env.RATE_LIMIT.get(key);
    const count = raw ? parseInt(raw) : 0;
    if (count >= RATE_LIMIT_REQUESTS) return { limited: true, count };
    await env.RATE_LIMIT.put(key, String(count+1), { expirationTtl: RATE_LIMIT_WINDOW });
    return { limited: false, count: count+1 };
  } catch { return { limited: false }; }
}

async function getCached(env, key) {
  if (!env?.RATE_LIMIT) return null;
  try {
    const raw = await env.RATE_LIMIT.get(`cache:${key}`);
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
}

async function setCached(env, key, data) {
  if (!env?.RATE_LIMIT) return;
  try {
    await env.RATE_LIMIT.put(`cache:${key}`, JSON.stringify(data), { expirationTtl: CACHE_TTL_SECONDS });
  } catch {}
}

// § COUNTER — increments visit total and per-tech counters
async function incrementVisits(env, tech) {
  if (!env?.RATE_LIMIT) return null;
  try {
    // Total visits
    const totalRaw = await env.RATE_LIMIT.get('visits:total');
    const total    = (totalRaw ? parseInt(totalRaw) : 0) + 1;
    await env.RATE_LIMIT.put('visits:total', String(total));

    // Per-tech count (top packages leaderboard)
    const techKey = `visits:tech:${tech.slice(0,40)}`;
    const techRaw = await env.RATE_LIMIT.get(techKey);
    const techCnt = (techRaw ? parseInt(techRaw) : 0) + 1;
    await env.RATE_LIMIT.put(techKey, String(techCnt));

    return total;
  } catch { return null; }
}

// =========================================
// § NON-TRACKABLE
// =========================================

function checkNonTrackable(tech) {
  const lower = tech.toLowerCase();
  if (NON_TRACKABLE[lower]) return NON_TRACKABLE[lower];
  for (const [k, v] of Object.entries(NON_TRACKABLE)) {
    if (lower.includes(k) || k.includes(lower)) return v;
  }
  return null;
}

// =========================================
// § MULTI-SOURCE VULNERABILITY SEARCH
//
// Strategy:
//   1. OSV.dev (primary — best structured data)
//   2. NVD API v2 (fallback — catches CVEs missing from OSV)
//   3. GitHub Advisory Database API (fallback — GHSA ecosystem)
//
// Each source returns a normalized vuln object:
//   { id, displayId, allIds, summary, link, published, severity, source }
// =========================================

// ---- Source 1: OSV ----

async function osvQuery(packageObj, version, pageToken = null) {
  const body = { package: packageObj, version };
  if (pageToken) body.page_token = pageToken;
  try {
    const ctrl  = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 10000);
    const res   = await fetch('https://api.osv.dev/v1/query', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify(body), signal: ctrl.signal
    });
    clearTimeout(timer);
    if (!res.ok) return { vulns:[], next_page_token:null };
    const data = await res.json();
    return { vulns: data.vulns||[], next_page_token: data.next_page_token||null };
  } catch { return { vulns:[], next_page_token:null }; }
}

async function osvFetchAll(packageObj, version) {
  const all = []; let pt = null, pages = 0;
  do {
    const { vulns, next_page_token } = await osvQuery(packageObj, version, pt);
    all.push(...vulns); pt = next_page_token; pages++;
  } while (pt && pages < 5);
  return all;
}

async function getFromOSV(tech, version, ecosystem) {
  if (ecosystem === 'auto') {
    const ecos = ['npm','PyPI','Maven','RubyGems','Go','NuGet','crates.io'];
    const results = await Promise.all(ecos.map(eco => osvFetchAll({ name:tech, ecosystem:eco }, version)));
    const noEco   = await osvFetchAll({ name:tech }, version);
    return dedup([...results.flat(), ...noEco]);
  }

  const withEco = await osvFetchAll({ name:tech, ecosystem }, version);
  const sysEcos = new Set(['npm','PyPI','Maven','Go','RubyGems','NuGet','Packagist','crates.io','Hex','Pub']);
  const noEco   = sysEcos.has(ecosystem) ? await osvFetchAll({ name:tech }, version) : [];
  return dedup([...withEco, ...noEco]);
}

function normalizeOSV(raw, kevSet) {
  const aliases  = raw.aliases || [];
  const cveAlias = aliases.find(a => a.startsWith('CVE-'));
  const displayId = cveAlias || raw.id;
  const allIds    = [raw.id, ...aliases].filter(Boolean);
  const link      = buildLink(displayId, raw.id, aliases, raw.references||[]);
  return {
    id:         raw.id,
    displayId,
    allIds,
    summary:    raw.summary || raw.details?.split('\n')[0]?.slice(0,120) || '',
    link,
    published:  raw.published || null,
    severity:   parseSeverity(raw),
    kev:        kevSet.has(raw.id) || allIds.some(a => kevSet.has(a)),
    source:     'OSV'
  };
}

// ---- Source 2: NVD API v2 ----
// Searches by keyword (CPE/product name) + version
// NVD public API: 5 req/30s unauthenticated, no key needed for light use

async function getFromNVD(tech, version) {
  // NVD keyword search — finds CVEs mentioning the product
  const query = encodeURIComponent(tech);
  const url   = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${query}&resultsPerPage=50`;

  const data = await safeFetch(url, {
    headers: { 'Accept': 'application/json' }
  }, 12000);

  if (!data?.vulnerabilities) return [];

  const results = [];
  for (const item of data.vulnerabilities) {
    const cve = item.cve;
    if (!cve) continue;

    // Filter: only include if this version is plausibly affected
    // NVD doesn't filter by version in keyword search, so we do a loose check
    const desc = (cve.descriptions?.find(d => d.lang === 'en')?.value || '').toLowerCase();
    const versionMentioned = desc.includes(version.split('.')[0]) ||
      cve.configurations?.some(c =>
        c.nodes?.some(n => n.cpeMatch?.some(m =>
          m.vulnerable && (m.versionEndIncluding >= version || m.versionStartIncluding <= version)
        ))
      );

    if (!versionMentioned && data.vulnerabilities.length > 10) continue; // skip unrelated when many results

    const cvssV3  = cve.metrics?.cvssMetricV31?.[0]?.cvssData || cve.metrics?.cvssMetricV30?.[0]?.cvssData;
    const cvssV2  = cve.metrics?.cvssMetricV2?.[0]?.cvssData;
    const score   = cvssV3?.baseScore?.toFixed(1) || cvssV2?.baseScore?.toFixed(1) || 'UNKNOWN';
    const summary = cve.descriptions?.find(d => d.lang === 'en')?.value?.slice(0,120) || '';

    results.push({
      id:        cve.id,
      displayId: cve.id,
      allIds:    [cve.id],
      summary,
      link:      `https://nvd.nist.gov/vuln/detail/${cve.id}`,
      published: cve.published?.slice(0,10) || null,
      severity:  score,
      kev:       false, // KEV check done separately
      source:    'NVD'
    });
  }
  return results;
}

// ---- Source 3: GitHub Advisory Database ----
// Uses the public REST API (no auth needed, 60 req/h unauthenticated)

async function getFromGitHub(tech, version) {
  const query = encodeURIComponent(tech);
  const url   = `https://api.github.com/advisories?affects=${query}&per_page=30`;

  const data = await safeFetch(url, {
    headers: { 'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' }
  }, 10000);

  if (!Array.isArray(data)) return [];

  return data.map(adv => {
    const cveId = adv.cve_id;
    const ghsaId = adv.ghsa_id;
    const id     = cveId || ghsaId;
    const allIds = [ghsaId, cveId].filter(Boolean);
    const score  = adv.cvss?.score?.toFixed(1) || adv.severity?.toUpperCase() || 'UNKNOWN';
    return {
      id:        ghsaId,
      displayId: cveId || ghsaId,
      allIds,
      summary:   adv.summary?.slice(0,120) || adv.description?.split('\n')[0]?.slice(0,120) || '',
      link:      cveId ? `https://nvd.nist.gov/vuln/detail/${cveId}` : `https://github.com/advisories/${ghsaId}`,
      published: adv.published_at?.slice(0,10) || null,
      severity:  score,
      kev:       false,
      source:    'GitHub'
    };
  });
}

// ---- Merge all sources ----

async function getVulnsMultiSource(tech, version, ecosystem, kevSet) {
  // Step 1: OSV (always)
  const osvRaw  = await getFromOSV(tech, version, ecosystem);
  const osvNorm = osvRaw.map(v => normalizeOSV(v, kevSet));

  // Step 2: Only hit fallbacks if OSV found nothing
  let nvdResults = [], ghResults = [];

  if (osvNorm.length === 0) {
    structuredLog('fallback_triggered', { tech, version, reason: 'osv_empty' });
    // Run NVD and GitHub in parallel
    [nvdResults, ghResults] = await Promise.all([
      getFromNVD(tech, version),
      getFromGitHub(tech, version)
    ]);

    // Apply KEV to fallback results too
    for (const v of [...nvdResults, ...ghResults]) {
      v.kev = kevSet.has(v.id) || v.allIds.some(a => kevSet.has(a));
    }
  }

  // Merge all, deduplicate by displayId
  const all    = [...osvNorm, ...nvdResults, ...ghResults];
  const seen   = new Set();
  const merged = [];
  for (const v of all) {
    const key = v.displayId || v.id;
    if (!seen.has(key)) { seen.add(key); merged.push(v); }
  }

  return merged;
}

function dedup(arr) {
  const seen = new Set(); const out = [];
  for (const v of arr) { if (!seen.has(v.id)) { seen.add(v.id); out.push(v); } }
  return out;
}

// =========================================
// § EOL — globalLatest fix
// =========================================

async function getEOL(tech, version) {
  const slug = normalize(tech);
  const data = await safeFetch(`https://endoflife.date/api/${encodeURIComponent(slug)}.json`);
  if (!Array.isArray(data) || data.length === 0) return { status:'unknown', globalLatest:null, branchLatest:null, eolDate:null };

  // § FIX: globalLatest = latest version across ALL cycles (first entry = newest cycle)
  const globalLatest = data[0]?.latest || null;

  const parts  = version.split('.');
  const major  = parts[0];
  const minorV = parts.slice(0,2).join('.');

  const match =
    data.find(v => v.cycle === version) ||
    data.find(v => v.cycle === minorV) ||
    data.find(v => String(v.cycle).startsWith(major+'.')) ||
    data.find(v => String(v.cycle) === major);

  if (!match) return { status:'unknown', globalLatest, branchLatest:null, eolDate:null };

  const eolValue = match.eol;
  let status = 'unknown', eolDate = null;
  if (typeof eolValue === 'boolean') {
    status = eolValue ? 'EOL' : 'supported';
  } else if (typeof eolValue === 'string') {
    eolDate = eolValue;
    status  = new Date(eolValue) < new Date() ? 'EOL' : 'supported';
  }

  // branchLatest = latest in THIS specific cycle/branch
  const branchLatest = match.latest || null;

  return {
    status,
    globalLatest,          // newest version of the product overall
    branchLatest,          // newest version in the scanned branch
    latest:   globalLatest, // backwards compat alias
    eolDate,
    lts:      match.lts || false,
    support:  match.support || null
  };
}

// =========================================
// VERSION VALIDATION
// =========================================

function getValidator(ecosystem) {
  return { npm:validateNpm, PyPI:validatePyPI, RubyGems:validateRubyGems, 'crates.io':validateCratesIo }[ecosystem] || null;
}

async function validateVersion(tech, version, ecosystem) {
  const fn = getValidator(ecosystem);
  if (!fn) return { valid:true, exists:true, closest:null, allVersions:[] };
  try { return await fn(tech, version); }
  catch { return { valid:true, exists:true, closest:null, allVersions:[] }; }
}

async function validateNpm(name, version) {
  const data = await safeFetch(`https://registry.npmjs.org/${encodeURIComponent(name)}`);
  if (!data) return { valid:true, exists:true, closest:null, allVersions:[] };
  if (data.error === 'Not found') return { valid:false, exists:false, closest:null, allVersions:[] };
  const versions = Object.keys(data.versions||{});
  const exists   = versions.includes(version);
  return { valid:true, exists, closest: exists?null:findClosest(version,versions), allVersions: versions.slice(-10).reverse() };
}

async function validatePyPI(name, version) {
  const data = await safeFetch(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`);
  if (!data) return { valid:true, exists:true, closest:null, allVersions:[] };
  const versions = Object.keys(data.releases||{});
  const exists   = versions.includes(version);
  return { valid:true, exists, closest: exists?null:findClosest(version,versions), allVersions: versions.slice(-10).reverse() };
}

async function validateRubyGems(name, version) {
  const data = await safeFetch(`https://rubygems.org/api/v1/versions/${encodeURIComponent(name)}.json`);
  if (!Array.isArray(data)) return { valid:true, exists:true, closest:null, allVersions:[] };
  const versions = data.map(v => v.number);
  const exists   = versions.includes(version);
  return { valid:true, exists, closest: exists?null:findClosest(version,versions), allVersions: versions.slice(0,10) };
}

async function validateCratesIo(name, version) {
  const data = await safeFetch(`https://crates.io/api/v1/crates/${encodeURIComponent(name)}/versions`);
  if (!data?.versions) return { valid:true, exists:true, closest:null, allVersions:[] };
  const versions = data.versions.map(v => v.num);
  const exists   = versions.includes(version);
  return { valid:true, exists, closest: exists?null:findClosest(version,versions), allVersions: versions.slice(0,10) };
}

function findClosest(target, versions) {
  if (!versions.length) return null;
  const tP = target.split('.').map(p=>parseInt(p)||0);
  let best=null, best$=Infinity;
  for (const v of versions) {
    const vP = v.split('.').map(p=>parseInt(p)||0);
    const d  = Math.abs((tP[0]||0)-(vP[0]||0))*10000+Math.abs((tP[1]||0)-(vP[1]||0))*100+Math.abs((tP[2]||0)-(vP[2]||0));
    if (d<best$) { best$=d; best=v; }
  }
  return best;
}

// =========================================
// SEVERITY PARSING
// =========================================

function parseSeverity(osvVuln) {
  const sev = osvVuln.severity;
  if (sev?.length) {
    for (const s of sev) {
      if (!s.score) continue;
      const n = parseFloat(s.score);
      if (!isNaN(n)) return n.toFixed(1);
      if (typeof s.score === 'string' && s.score.startsWith('CVSS:')) {
        const x = extractCvss(s.score, osvVuln); if (x) return x;
      }
    }
  }
  const ds = osvVuln.database_specific;
  if (ds?.cvss) { const n=parseFloat(ds.cvss); if(!isNaN(n)) return n.toFixed(1); }
  if (ds?.severity) return ds.severity;
  for (const aff of (osvVuln.affected||[])) {
    const es = aff.ecosystem_specific;
    if (es?.severity) return es.severity;
    if (es?.cvss_score) { const n=parseFloat(es.cvss_score); if(!isNaN(n)) return n.toFixed(1); }
  }
  return 'UNKNOWN';
}

function extractCvss(vector, vuln) {
  const ds = vuln.database_specific;
  if (ds?.cvss_v3?.score) return parseFloat(ds.cvss_v3.score).toFixed(1);
  if (ds?.cvss_v2?.score) return parseFloat(ds.cvss_v2.score).toFixed(1);
  const net=vector.includes('/AV:N'), noAuth=vector.includes('/PR:N')||vector.includes('/Au:N'), noUI=vector.includes('/UI:N');
  if (net&&noAuth&&noUI) {
    if (vector.includes('/C:H/I:H/A:H')) return '9.8';
    if (vector.includes('/C:H')&&vector.includes('/I:H')) return '9.1';
    return '7.5';
  }
  if (vector.includes(':H/')||vector.endsWith(':H')) return '7.2';
  return '5.0';
}

function buildLink(displayId, osvId, aliases, references) {
  const cveId  = aliases.find(a=>a.startsWith('CVE-'))||(displayId.startsWith('CVE-')?displayId:null);
  if (cveId)  return `https://nvd.nist.gov/vuln/detail/${cveId}`;
  const ghsaId = aliases.find(a=>a.startsWith('GHSA-'))||(displayId.startsWith('GHSA-')?displayId:null);
  if (ghsaId) return `https://github.com/advisories/${ghsaId}`;
  if (osvId)  return `https://osv.dev/vulnerability/${osvId}`;
  const ref = references.find(r=>r.type==='WEB'||r.type==='ADVISORY');
  return ref?.url||`https://osv.dev/vulnerability/${osvId}`;
}

// =========================================
// CISA KEV
// =========================================

async function getKEV() {
  const data = await safeFetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
  if (!data?.vulnerabilities) return new Set();
  return new Set(data.vulnerabilities.map(v => v.cveID));
}

// =========================================
// RISK ENGINE PRO (preserved from v5)
// =========================================

function numScore(s) {
  const n=parseFloat(s); return !isNaN(n)?n:(s==='CRITICAL'?9.5:s==='HIGH'?7.5:s==='MEDIUM'?5:0);
}

function calcRiskPro(vulns, eol) {
  let score=0; const factors=[];
  const kev   = vulns.filter(v=>v.kev);
  const crit  = vulns.filter(v=>numScore(v.severity)>=9.0);
  const high  = vulns.filter(v=>{const n=numScore(v.severity);return n>=7&&n<9;});
  const med   = vulns.filter(v=>{const n=numScore(v.severity);return n>=4&&n<7;});
  const unk   = vulns.filter(v=>v.severity==='UNKNOWN');

  if (kev.length)  { const s=Math.min(40,kev.length*20);   score+=s; factors.push({key:'kev',          label:`${kev.length} actively exploited (KEV)`,               points:s,level:'critical'}); }
  if (crit.length) { const s=Math.min(30,crit.length*15);  score+=s; factors.push({key:'critical_cvss', label:`${crit.length} critical severity (CVSS ≥ 9.0)`,        points:s,level:'critical'}); }
  if (high.length) { const s=Math.min(20,high.length*5);   score+=s; factors.push({key:'high_cvss',     label:`${high.length} high severity (CVSS 7.0–8.9)`,          points:s,level:'high'}); }
  if (med.length)  { const s=Math.min(10,med.length*2);    score+=s; factors.push({key:'medium_cvss',   label:`${med.length} medium severity (CVSS 4.0–6.9)`,         points:s,level:'medium'}); }
  if (eol.status==='EOL') { score+=15; factors.push({key:'eol',label:'Version is End-of-Life (no security patches)',points:15,level:'high'}); }
  if (eol.status==='supported'&&eol.eolDate) {
    const days=Math.floor((new Date(eol.eolDate)-new Date())/86400000);
    if (days>=0&&days<=90) { score+=8; factors.push({key:'eol_soon',label:`EOL in ${days} days (${eol.eolDate})`,points:8,level:'medium'}); }
  }
  if (unk.length)  { const s=Math.min(5,unk.length); score+=s; factors.push({key:'unknown_sev',label:`${unk.length} vulnerabilities with unknown severity`,points:s,level:'low'}); }

  score = Math.min(100,Math.round(score));
  const level = score>=70?'CRITICAL':score>=45?'HIGH':score>=20?'MEDIUM':'LOW';
  const maxCvss = vulns.reduce((m,v)=>Math.max(m,numScore(v.severity)),0);
  return { level, score, factors, maxCvss: maxCvss>0?maxCvss.toFixed(1):null };
}

function buildSummary(tech, version, ecosystem, vulns, eol, risk) {
  const kev=vulns.filter(v=>v.kev).length, crit=vulns.filter(v=>numScore(v.severity)>=9).length;
  const high=vulns.filter(v=>{const n=numScore(v.severity);return n>=7&&n<9;}).length;
  const today=new Date().toISOString().split('T')[0];
  let rec='';
  if (risk.level==='CRITICAL') rec=`Immediate action required. ${kev>0?`${kev} vulnerabilit${kev>1?'ies are':'y is'} actively exploited in the wild. `:''}Upgrade to the latest version immediately.`;
  else if (risk.level==='HIGH') rec=`Urgent upgrade recommended. ${crit>0?`${crit} critical-severity vulnerabilit${crit>1?'ies':'y'} detected. `:''}Schedule upgrade within the next patch cycle.`;
  else if (risk.level==='MEDIUM') rec=eol.status==='EOL'?'Version is End-of-Life. Plan migration to a supported version.':`${vulns.length} vulnerabilit${vulns.length>1?'ies':'y'} detected. Review and upgrade in your next maintenance window.`;
  else rec=vulns.length===0?'No known vulnerabilities detected. Continue monitoring for new advisories.':'Low-risk vulnerabilities present. Review as part of standard maintenance.';
  return { date:today, target:`${tech} ${version} (${ecosystem})`, riskLevel:risk.level, riskScore:risk.score, totalVulns:vulns.length, criticalVulns:crit, highVulns:high, kevVulns:kev, maxCvss:risk.maxCvss, eolStatus:eol.status, eolDate:eol.eolDate, latestVersion:eol.globalLatest, recommendation:rec };
}

// =========================================
// MAIN HANDLER
// =========================================

export async function onRequest(context) {
  const t0  = Date.now();
  const req = context.request;
  const url = new URL(req.url);
  const env = context.env;
  const ip  = req.headers.get('CF-Connecting-IP') || req.headers.get('X-Forwarded-For') || 'unknown';

  const rawTech = url.searchParams.get('tech')      || '';
  const rawVer  = url.searchParams.get('version')   || '';
  const rawEco  = url.searchParams.get('ecosystem') || 'npm';

  const techRaw   = sanitizeTech(rawTech);
  const tech      = normalizeTech(techRaw);
  const version   = String(rawVer).replace(/[^a-zA-Z0-9._\-+:]/g,'').slice(0,40).trim();
  const ecosystem = VALID_ECOSYSTEMS.has(rawEco) ? rawEco : 'npm';

  // Input validation
  if (!tech || !version) return jsonResp({ success:false, error:'Missing parameters: tech and version are required.' }, 400);
  if (!TECH_PATTERN.test(tech) && !/^[a-z0-9 ._\-]{1,80}$/.test(tech)) return jsonResp({ success:false, error:'Invalid technology name format.' }, 400);
  if (!VERSION_PATTERN.test(version)) return jsonResp({ success:false, error:`Invalid version format: "${version}".` }, 400);
  if (!/\d/.test(version)) return jsonResp({ success:false, error:`"${version}" doesn't look like a valid version number.` }, 400);

  // Rate limit
  const rl = await checkRateLimit(env, ip);
  if (rl.limited) {
    structuredLog('rate_limited', { ip, tech, version });
    return jsonResp({ success:false, error:'Rate limit exceeded. Please wait before retrying.' }, 429, {
      'Retry-After':String(RATE_LIMIT_WINDOW), 'X-RateLimit-Limit':String(RATE_LIMIT_REQUESTS)
    });
  }

  // Non-trackable
  const ntReason = checkNonTrackable(tech);
  if (ntReason) {
    structuredLog('non_trackable', { ip, tech, version, reason:ntReason });
    await incrementVisits(env, tech);
    return jsonResp({ success:true, nonTrackable:true, note:ntReason, target:{tech,version,ecosystem},
      eol:{status:'unknown',globalLatest:null,branchLatest:null}, vulns:{total:0,list:[]},
      risk:{level:'LOW',score:0,factors:[],maxCvss:null},
      summary:{date:new Date().toISOString().split('T')[0],target:`${tech} ${version}`,riskLevel:'N/A',riskScore:0,totalVulns:0,recommendation:`${tech} is not trackable via CVE databases. Reason: ${ntReason}`}
    });
  }

  // § DYM check — did you mean?
  const suggestion = tech !== techRaw ? null : didYouMean(tech);

  structuredLog('scan_start', { ip, tech, version, ecosystem });

  // § KV CACHE — check before hitting APIs
  const cacheKey = `${tech}:${version}:${ecosystem}`;
  const cached   = await getCached(env, cacheKey);
  if (cached) {
    const visitTotal = await incrementVisits(env, tech);
    structuredLog('cache_hit', { ip, tech, version, ms: Date.now()-t0 });
    return jsonResp({ ...cached, cached:true, visitTotal }, 200, {
      'X-Cache':'HIT', 'X-Scan-Ms':String(Date.now()-t0)
    });
  }

  try {
    // Get KEV first (needed for all sources), OSV+EOL+version in parallel
    const [kevSet, eolData, versionInfo] = await Promise.all([
      getKEV(),
      getEOL(tech, version),
      validateVersion(tech, version, ecosystem)
    ]);

    // Multi-source vulnerability search
    const vulns = await getVulnsMultiSource(tech, version, ecosystem, kevSet);

    // Cap at 100, sort
    const sorted = vulns.slice(0,100).sort((a,b) => {
      if (a.kev!==b.kev) return b.kev-a.kev;
      const sa=numScore(a.severity), sb=numScore(b.severity);
      if (sa!==sb) return sb-sa;
      return a.displayId.localeCompare(b.displayId);
    });

    const risk    = calcRiskPro(sorted, eolData);
    const summary = buildSummary(tech, version, ecosystem, sorted, eolData, risk);
    const ms      = Date.now()-t0;

    // Count sources used
    const sources = [...new Set(sorted.map(v=>v.source))];

    const payload = {
      success:     true,
      target:      { tech, version, ecosystem },
      versionInfo: { exists:versionInfo.exists, closest:versionInfo.closest, recentVersions:versionInfo.allVersions.slice(0,6) },
      eol:         eolData,
      vulns:       { total:vulns.length, list:sorted.slice(0,50), sources },
      risk,
      summary,
      suggestion,  // did-you-mean (null if none)
      meta:        { ms, version:'6.0.0', sources }
    };

    // § KV CACHE — store result
    await setCached(env, cacheKey, payload);

    // § COUNTER — increment visits
    const visitTotal = await incrementVisits(env, tech);

    structuredLog('scan_complete', { ip, tech, version, ecosystem, vulns:sorted.length, risk:risk.level, score:risk.score, sources, ms });

    return jsonResp({ ...payload, visitTotal }, 200, {
      'X-Cache':'MISS', 'X-Scan-Ms':String(ms),
      'X-Risk-Level':risk.level, 'X-Vuln-Count':String(sorted.length), 'X-Sources':sources.join(',')
    });

  } catch (err) {
    structuredLog('scan_error', { ip, tech, version, error:err.message, ms:Date.now()-t0 });
    return jsonResp({ success:false, error:err.message }, 500);
  }
}
