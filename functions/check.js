// =========================================
// EOL & CVE Checker — functions/check.js  v5
//
// NEW in v5 (from technical assessment):
//  § 3.1  Strict input validation (regex whitelist, ecosystem whitelist)
//  § 3.2  Rate limiting via Cloudflare KV (IP-based, 30 req/min)
//  § 4.1  Smart cascade: only call KEV if OSV found results
//  § 4.2  Aggressive caching (CF edge + cache-key header)
//  § 5    Structured JSON logging (event, tech, version, ms, status)
//  § 2    Name normalization + alias map (node.js→node, etc.)
//  § 2    Smart fallback message when tech is SaaS/CDN/untrackable
//  § 2    "auto" ecosystem: tries all major ecosystems in sequence
//  § 6.2  Response size guard: cap vuln list at 100
//  § 6.3  rel="noopener noreferrer" enforced server-side via note
//  + v4   All v4 features preserved (version intelligence, risk engine, summary)
// =========================================

// =========================================
// CONSTANTS & MAPS
// =========================================

// Strict input validation patterns
const TECH_PATTERN    = /^[a-zA-Z0-9._\-/:@]{1,80}$/;
const VERSION_PATTERN = /^[a-zA-Z0-9._\-+:]{1,40}$/;

const VALID_ECOSYSTEMS = new Set([
  'npm','PyPI','Maven','Go','RubyGems','NuGet','Packagist',
  'crates.io','Hex','Pub','Linux','auto'
]);

// Name normalization: common aliases → canonical OSV name
const NAME_NORMALIZE = {
  'node.js':    'node',
  'nodejs':     'node',
  'node-js':    'node',
  'reactjs':    'react',
  'react.js':   'react',
  'vuejs':      'vue',
  'vue.js':     'vue',
  'angularjs':  'angular',
  'angular.js': 'angular',
  'expressjs':  'express',
  'express.js': 'express',
  'nextjs':     'next',
  'next.js':    'next',
  'nuxtjs':     'nuxt',
  'nuxt.js':    'nuxt',
  'postgresql': 'postgres',
  'mariadb':    'mariadb',
  'mongodb':    'mongo',
  'elasticsearch': 'elasticsearch',
  'log4j2':     'log4j',
  'log4j-core': 'log4j',
  'spring-boot': 'spring-boot',
  'springboot': 'spring-boot',
  'ruby-on-rails': 'rails',
  'rubyonrails': 'rails',
};

// Technologies that are NOT trackable via CVE databases
// (SaaS, CDN scripts, cloud services, tracking pixels, etc.)
// value: human-readable reason for UI
const NON_TRACKABLE = {
  'google analytics':  'SaaS service — vulnerabilities are patched by Google automatically',
  'ga4':               'SaaS service (Google Analytics 4) — managed by Google',
  'google tag manager':'SaaS service — managed by Google',
  'gtm':               'SaaS service (Google Tag Manager) — managed by Google',
  'cloudflare':        'CDN/infrastructure service — not a software package',
  'cloudflare workers':'CDN/infrastructure service — managed by Cloudflare',
  'firebase':          'SaaS platform — vulnerabilities managed by Google',
  'aws':               'Cloud platform — use AWS Security Bulletins for advisories',
  'aws lambda':        'Cloud service — use AWS Security Bulletins',
  'azure':             'Cloud platform — use Microsoft Security Response Center',
  'tiktok pixel':      'Tracking script — no CVE tracking (third-party managed)',
  'facebook pixel':    'Tracking script — no CVE tracking (third-party managed)',
  'meta pixel':        'Tracking script — no CVE tracking (third-party managed)',
  'google ads':        'Advertising service — no CVE tracking',
  'hubspot':           'SaaS CRM — no CVE tracking for hosted service',
  'salesforce':        'SaaS platform — no CVE tracking for hosted service',
  'stripe':            'Payment API SaaS — no CVE tracking for hosted service',
  'twilio':            'SaaS API — no CVE tracking for hosted service',
  'segment':           'Analytics SaaS — no CVE tracking for hosted service',
  'intercom':          'SaaS service — no CVE tracking for hosted service',
  'hotjar':            'Analytics SaaS — no CVE tracking for hosted service',
};

// Rate limit: 30 requests per minute per IP
const RATE_LIMIT_REQUESTS = 30;
const RATE_LIMIT_WINDOW   = 60; // seconds

// =========================================
// HELPERS
// =========================================

function jsonResp(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type':           'application/json',
      'Cache-Control':          'no-store',
      'Access-Control-Allow-Origin': '*',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options':        'DENY',
      ...extraHeaders
    }
  });
}

async function safeFetch(url, opts = {}, timeoutMs = 8000) {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const res = await fetch(url, {
      ...opts,
      signal: controller.signal,
      cf: { cacheTtl: 600, cacheEverything: true }  // § 4.2 extended cache
    });
    clearTimeout(timer);
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

function normalize(t) { return t.toLowerCase().trim(); }

function sanitizeTech(s) {
  // Allow spaces for multi-word names like "google analytics"
  return String(s).toLowerCase().replace(/[^a-zA-Z0-9._\-/:@ ]/g, '').slice(0, 80).trim();
}

// Normalize tech name: apply alias map
function normalizeTech(raw) {
  const lower = raw.toLowerCase().trim();
  return NAME_NORMALIZE[lower] || lower;
}

// =========================================
// § 3.2 RATE LIMITING (Cloudflare KV)
// Requires KV namespace "RATE_LIMIT" bound in wrangler.toml
// Falls back gracefully if KV is not configured
// =========================================

async function checkRateLimit(context, ip) {
  // If KV not bound, skip rate limiting gracefully
  if (!context.env?.RATE_LIMIT) return { limited: false };

  const key = `rl:${ip}`;
  try {
    const raw   = await context.env.RATE_LIMIT.get(key);
    const count = raw ? parseInt(raw) : 0;

    if (count >= RATE_LIMIT_REQUESTS) {
      return { limited: true, count };
    }

    // Increment counter with TTL
    await context.env.RATE_LIMIT.put(key, String(count + 1), {
      expirationTtl: RATE_LIMIT_WINDOW
    });

    return { limited: false, count: count + 1 };
  } catch {
    return { limited: false }; // Never block on KV errors
  }
}

// =========================================
// § 2 SMART FALLBACK — check if tech is non-trackable
// =========================================

function checkNonTrackable(tech) {
  const lower = tech.toLowerCase();
  // Exact match
  if (NON_TRACKABLE[lower]) return NON_TRACKABLE[lower];
  // Partial match for compound names
  for (const [key, reason] of Object.entries(NON_TRACKABLE)) {
    if (lower.includes(key) || key.includes(lower)) return reason;
  }
  return null;
}

// =========================================
// § 2 AUTO ECOSYSTEM
// When ecosystem='auto', try common ecosystems in priority order
// and return first with results, or merge all
// =========================================

const AUTO_ECOSYSTEM_ORDER = ['npm','PyPI','Maven','RubyGems','Go','NuGet','crates.io'];

async function getOSVAuto(tech, version) {
  // Run all common ecosystems in parallel for speed
  const results = await Promise.all(
    AUTO_ECOSYSTEM_ORDER.map(eco => osvFetchAll({ name: tech, ecosystem: eco }, version))
  );

  // Also run without ecosystem (system packages)
  const noEco = await osvFetchAll({ name: tech }, version);

  const seen = new Set();
  const merged = [];
  for (const list of [...results, noEco]) {
    for (const v of list) {
      if (!seen.has(v.id)) { seen.add(v.id); merged.push(v); }
    }
  }
  return merged;
}

// =========================================
// OSV QUERIES
// =========================================

async function osvQuery(packageObj, version, pageToken = null) {
  const body = { package: packageObj, version };
  if (pageToken) body.page_token = pageToken;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10000);
    const res = await fetch('https://api.osv.dev/v1/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: controller.signal
    });
    clearTimeout(timer);
    if (!res.ok) return { vulns: [], next_page_token: null };
    const data = await res.json();
    return { vulns: data.vulns || [], next_page_token: data.next_page_token || null };
  } catch {
    return { vulns: [], next_page_token: null };
  }
}

async function osvFetchAll(packageObj, version) {
  const allVulns = [];
  let pageToken = null;
  let pages = 0;
  const MAX_PAGES = 5;
  do {
    const { vulns, next_page_token } = await osvQuery(packageObj, version, pageToken);
    allVulns.push(...vulns);
    pageToken = next_page_token;
    pages++;
  } while (pageToken && pages < MAX_PAGES);
  return allVulns;
}

async function getOSV(tech, version, ecosystem) {
  if (ecosystem === 'auto') return getOSVAuto(tech, version);

  const withEco = await osvFetchAll({ name: tech, ecosystem }, version);

  const sysEcos = new Set(['npm','PyPI','Maven','Go','RubyGems','NuGet','Packagist','crates.io','Hex','Pub']);
  let withoutEco = [];
  if (sysEcos.has(ecosystem)) {
    withoutEco = await osvFetchAll({ name: tech }, version);
  }

  const seen = new Set();
  const merged = [];
  for (const v of [...withEco, ...withoutEco]) {
    if (!seen.has(v.id)) { seen.add(v.id); merged.push(v); }
  }
  return merged;
}

// =========================================
// § 4.1 SMART CASCADE — only call KEV if OSV found results
// =========================================

async function getOSVAndKEV(tech, version, ecosystem) {
  const osvRaw = await getOSV(tech, version, ecosystem);

  let kevSet = new Set();
  if (osvRaw.length > 0) {
    // Only fetch KEV (~600KB) when we actually have CVEs to check
    const kevData = await safeFetch(
      'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
    );
    if (kevData?.vulnerabilities) {
      kevSet = new Set(kevData.vulnerabilities.map(v => v.cveID));
    }
  }

  return { osvRaw, kevSet };
}

// =========================================
// EOL
// =========================================

async function getEOL(tech, version) {
  const slug = normalize(tech);
  const data = await safeFetch(`https://endoflife.date/api/${encodeURIComponent(slug)}.json`);
  if (!Array.isArray(data) || data.length === 0) return { status: 'unknown', latest: null, eolDate: null };

  const parts  = version.split('.');
  const major  = parts[0];
  const minorV = parts.slice(0, 2).join('.');

  const match =
    data.find(v => v.cycle === version) ||
    data.find(v => v.cycle === minorV) ||
    data.find(v => String(v.cycle).startsWith(major + '.')) ||
    data.find(v => String(v.cycle) === major);

  if (!match) return { status: 'unknown', latest: data[0]?.latest || null, eolDate: null };

  const eolValue = match.eol;
  let status = 'unknown', eolDate = null;
  if (typeof eolValue === 'boolean') {
    status = eolValue ? 'EOL' : 'supported';
  } else if (typeof eolValue === 'string') {
    eolDate = eolValue;
    status  = new Date(eolValue) < new Date() ? 'EOL' : 'supported';
  }
  return { status, latest: match.latest || null, eolDate, lts: match.lts || false, support: match.support || null };
}

// =========================================
// VERSION VALIDATION
// =========================================

function getValidator(ecosystem) {
  const map = {
    'npm':       validateNpm,
    'PyPI':      validatePyPI,
    'RubyGems':  validateRubyGems,
    'crates.io': validateCratesIo,
  };
  return map[ecosystem] || null;
}

async function validateVersion(tech, version, ecosystem) {
  const validator = getValidator(ecosystem);
  if (!validator) return { valid: true, exists: true, closest: null, allVersions: [] };
  try { return await validator(tech, version); }
  catch { return { valid: true, exists: true, closest: null, allVersions: [] }; }
}

async function validateNpm(name, version) {
  const data = await safeFetch(`https://registry.npmjs.org/${encodeURIComponent(name)}`);
  if (!data) return { valid: true, exists: true, closest: null, allVersions: [] };
  if (data.error === 'Not found') return { valid: false, exists: false, closest: null, allVersions: [] };
  const versions = Object.keys(data.versions || {});
  const exists   = versions.includes(version);
  return { valid: true, exists, closest: exists ? null : findClosestVersion(version, versions), allVersions: versions.slice(-10).reverse() };
}

async function validatePyPI(name, version) {
  const data = await safeFetch(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`);
  if (!data) return { valid: true, exists: true, closest: null, allVersions: [] };
  const versions = Object.keys(data.releases || {});
  const exists   = versions.includes(version);
  return { valid: true, exists, closest: exists ? null : findClosestVersion(version, versions), allVersions: versions.slice(-10).reverse() };
}

async function validateRubyGems(name, version) {
  const data = await safeFetch(`https://rubygems.org/api/v1/versions/${encodeURIComponent(name)}.json`);
  if (!Array.isArray(data)) return { valid: true, exists: true, closest: null, allVersions: [] };
  const versions = data.map(v => v.number);
  const exists   = versions.includes(version);
  return { valid: true, exists, closest: exists ? null : findClosestVersion(version, versions), allVersions: versions.slice(0, 10) };
}

async function validateCratesIo(name, version) {
  const data = await safeFetch(`https://crates.io/api/v1/crates/${encodeURIComponent(name)}/versions`);
  if (!data?.versions) return { valid: true, exists: true, closest: null, allVersions: [] };
  const versions = data.versions.map(v => v.num);
  const exists   = versions.includes(version);
  return { valid: true, exists, closest: exists ? null : findClosestVersion(version, versions), allVersions: versions.slice(0, 10) };
}

function findClosestVersion(target, versions) {
  if (!versions.length) return null;
  const tP = target.split('.').map(p => parseInt(p) || 0);
  let best = null, bestScore = Infinity;
  for (const v of versions) {
    const vP = v.split('.').map(p => parseInt(p) || 0);
    const score = Math.abs((tP[0]||0)-(vP[0]||0))*10000 + Math.abs((tP[1]||0)-(vP[1]||0))*100 + Math.abs((tP[2]||0)-(vP[2]||0));
    if (score < bestScore) { bestScore = score; best = v; }
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
        const x = extractCvssScore(s.score, osvVuln);
        if (x) return x;
      }
    }
  }
  const ds = osvVuln.database_specific;
  if (ds?.cvss) { const n = parseFloat(ds.cvss); if (!isNaN(n)) return n.toFixed(1); }
  if (ds?.severity) return ds.severity;
  for (const aff of (osvVuln.affected || [])) {
    const es = aff.ecosystem_specific;
    if (es?.severity) return es.severity;
    if (es?.cvss_score) { const n = parseFloat(es.cvss_score); if (!isNaN(n)) return n.toFixed(1); }
  }
  return 'UNKNOWN';
}

function extractCvssScore(vector, osvVuln) {
  const ds = osvVuln.database_specific;
  if (ds?.cvss_v3?.score) return parseFloat(ds.cvss_v3.score).toFixed(1);
  if (ds?.cvss_v2?.score) return parseFloat(ds.cvss_v2.score).toFixed(1);
  const net    = vector.includes('/AV:N');
  const noAuth = vector.includes('/PR:N') || vector.includes('/Au:N');
  const noUI   = vector.includes('/UI:N');
  if (net && noAuth && noUI) {
    if (vector.includes('/C:H/I:H/A:H')) return '9.8';
    if (vector.includes('/C:H') && vector.includes('/I:H')) return '9.1';
    return '7.5';
  }
  if (vector.includes(':H/') || vector.endsWith(':H')) return '7.2';
  return '5.0';
}

function extractVulnInfo(osvVuln) {
  const id      = osvVuln.id;
  const aliases = osvVuln.aliases || [];
  const cveAlias  = aliases.find(a => a.startsWith('CVE-'));
  const displayId = cveAlias || id;
  const allIds    = [id, ...aliases].filter(Boolean);
  const summary   = osvVuln.summary || osvVuln.details?.split('\n')[0]?.slice(0, 120) || '';
  const link      = buildLink(displayId, id, aliases, osvVuln.references || []);
  const published = osvVuln.published || null;
  return { id, displayId, allIds, summary, link, published };
}

function buildLink(displayId, osvId, aliases, references) {
  const cveId  = aliases.find(a => a.startsWith('CVE-')) || (displayId.startsWith('CVE-') ? displayId : null);
  if (cveId)  return `https://nvd.nist.gov/vuln/detail/${cveId}`;
  const ghsaId = aliases.find(a => a.startsWith('GHSA-')) || (displayId.startsWith('GHSA-') ? displayId : null);
  if (ghsaId) return `https://github.com/advisories/${ghsaId}`;
  if (osvId)  return `https://osv.dev/vulnerability/${osvId}`;
  const ref = references.find(r => r.type === 'WEB' || r.type === 'ADVISORY');
  return ref?.url || `https://osv.dev/vulnerability/${osvId}`;
}

// =========================================
// RISK ENGINE PRO (preserved from v4)
// =========================================

function numScore(s) {
  const n = parseFloat(s);
  return !isNaN(n) ? n : (s==='CRITICAL'?9.5:s==='HIGH'?7.5:s==='MEDIUM'?5.0:0);
}

function calcRiskPro(vulns, eol) {
  let score = 0;
  const factors = [];

  const kevVulns  = vulns.filter(v => v.kev);
  const critVulns = vulns.filter(v => numScore(v.severity) >= 9.0);
  const highVulns = vulns.filter(v => { const n = numScore(v.severity); return n >= 7.0 && n < 9.0; });
  const medVulns  = vulns.filter(v => { const n = numScore(v.severity); return n >= 4.0 && n < 7.0; });
  const unknownVulns = vulns.filter(v => v.severity === 'UNKNOWN');

  if (kevVulns.length > 0)  { const s = Math.min(40, kevVulns.length*20);  score += s; factors.push({ key:'kev',          label:`${kevVulns.length} actively exploited (KEV)`,                  points:s, level:'critical' }); }
  if (critVulns.length > 0) { const s = Math.min(30, critVulns.length*15); score += s; factors.push({ key:'critical_cvss', label:`${critVulns.length} critical severity (CVSS ≥ 9.0)`,          points:s, level:'critical' }); }
  if (highVulns.length > 0) { const s = Math.min(20, highVulns.length*5);  score += s; factors.push({ key:'high_cvss',     label:`${highVulns.length} high severity (CVSS 7.0–8.9)`,            points:s, level:'high'     }); }
  if (medVulns.length > 0)  { const s = Math.min(10, medVulns.length*2);   score += s; factors.push({ key:'medium_cvss',   label:`${medVulns.length} medium severity (CVSS 4.0–6.9)`,           points:s, level:'medium'   }); }
  if (eol.status === 'EOL') { score += 15; factors.push({ key:'eol', label:'Version is End-of-Life (no security patches)', points:15, level:'high' }); }

  if (eol.status === 'supported' && eol.eolDate) {
    const days = Math.floor((new Date(eol.eolDate) - new Date()) / 86400000);
    if (days >= 0 && days <= 90) { score += 8; factors.push({ key:'eol_soon', label:`EOL in ${days} days (${eol.eolDate})`, points:8, level:'medium' }); }
  }

  if (unknownVulns.length > 0) { const s = Math.min(5, unknownVulns.length); score += s; factors.push({ key:'unknown_sev', label:`${unknownVulns.length} vulnerabilities with unknown severity`, points:s, level:'low' }); }

  score = Math.min(100, Math.round(score));
  const level = score >= 70 ? 'CRITICAL' : score >= 45 ? 'HIGH' : score >= 20 ? 'MEDIUM' : 'LOW';
  const maxCvss = vulns.reduce((m,v) => Math.max(m, numScore(v.severity)), 0);
  return { level, score, factors, maxCvss: maxCvss > 0 ? maxCvss.toFixed(1) : null };
}

function buildSummary(tech, version, ecosystem, vulns, eol, risk) {
  const kevCount  = vulns.filter(v => v.kev).length;
  const critCount = vulns.filter(v => numScore(v.severity) >= 9.0).length;
  const highCount = vulns.filter(v => { const n = numScore(v.severity); return n >= 7.0 && n < 9.0; }).length;
  const today     = new Date().toISOString().split('T')[0];

  let recommendation = '';
  if (risk.level === 'CRITICAL') {
    recommendation = `Immediate action required. ${kevCount > 0 ? `${kevCount} vulnerabilit${kevCount>1?'ies are':'y is'} actively exploited in the wild. ` : ''}Upgrade to the latest version immediately and apply all available patches.`;
  } else if (risk.level === 'HIGH') {
    recommendation = `Urgent upgrade recommended. ${critCount > 0 ? `${critCount} critical-severity vulnerabilit${critCount>1?'ies':'y'} detected. ` : ''}Schedule upgrade within the next patch cycle.`;
  } else if (risk.level === 'MEDIUM') {
    recommendation = eol.status === 'EOL'
      ? 'Version is End-of-Life. Plan migration to a supported version. No new security patches will be issued.'
      : `${vulns.length} vulnerabilit${vulns.length>1?'ies':'y'} detected. Review and upgrade in your next maintenance window.`;
  } else {
    recommendation = vulns.length === 0
      ? 'No known vulnerabilities detected for this version. Continue monitoring for new advisories.'
      : 'Low-risk vulnerabilities present. Review and upgrade as part of standard maintenance.';
  }

  return { date: today, target: `${tech} ${version} (${ecosystem})`, riskLevel: risk.level, riskScore: risk.score, totalVulns: vulns.length, criticalVulns: critCount, highVulns: highCount, kevVulns: kevCount, maxCvss: risk.maxCvss, eolStatus: eol.status, eolDate: eol.eolDate, latestVersion: eol.latest, recommendation };
}

// =========================================
// § 5 STRUCTURED LOGGING
// =========================================

function structuredLog(event, data) {
  console.log(JSON.stringify({ event, timestamp: Date.now(), ...data }));
}

// =========================================
// MAIN HANDLER
// =========================================

export async function onRequest(context) {
  const t0  = Date.now();
  const req = context.request;
  const url = new URL(req.url);

  // § 3.2 Get client IP
  const ip = req.headers.get('CF-Connecting-IP') || req.headers.get('X-Forwarded-For') || 'unknown';

  // Raw inputs
  const rawTech = url.searchParams.get('tech')      || '';
  const rawVer  = url.searchParams.get('version')   || '';
  const rawEco  = url.searchParams.get('ecosystem') || 'npm';

  // § 3.1 Strict input validation
  const techRaw = sanitizeTech(rawTech);
  const tech    = normalizeTech(techRaw);   // apply alias map
  const version = String(rawVer).replace(/[^a-zA-Z0-9._\-+:]/g, '').slice(0, 40).trim();
  const ecosystem = VALID_ECOSYSTEMS.has(rawEco) ? rawEco : 'npm';

  if (!tech || !version) {
    return jsonResp({ success: false, error: 'Missing parameters: tech and version are required.' }, 400);
  }

  if (!TECH_PATTERN.test(tech) && !/^[a-z0-9 ._\-]{1,80}$/.test(tech)) {
    return jsonResp({ success: false, error: `Invalid technology name format.` }, 400);
  }

  if (!VERSION_PATTERN.test(version)) {
    return jsonResp({ success: false, error: `Invalid version format: "${version}".` }, 400);
  }

  if (!/\d/.test(version)) {
    return jsonResp({ success: false, error: `"${version}" doesn't look like a valid version number.` }, 400);
  }

  // § 3.2 Rate limiting
  const rl = await checkRateLimit(context, ip);
  if (rl.limited) {
    structuredLog('rate_limited', { ip, tech, version });
    return jsonResp({ success: false, error: 'Rate limit exceeded. Please wait before retrying.' }, 429, {
      'Retry-After': String(RATE_LIMIT_WINDOW),
      'X-RateLimit-Limit': String(RATE_LIMIT_REQUESTS),
    });
  }

  // § 2 Non-trackable technology detection
  const nonTrackableReason = checkNonTrackable(tech);
  if (nonTrackableReason) {
    structuredLog('non_trackable', { ip, tech, version, reason: nonTrackableReason });
    return jsonResp({
      success: true,
      nonTrackable: true,
      note: nonTrackableReason,
      target: { tech, version, ecosystem },
      eol: { status: 'unknown', latest: null },
      vulns: { total: 0, list: [] },
      risk: { level: 'LOW', score: 0, factors: [], maxCvss: null },
      summary: {
        date: new Date().toISOString().split('T')[0],
        target: `${tech} ${version} (${ecosystem})`,
        riskLevel: 'N/A',
        riskScore: 0,
        totalVulns: 0,
        recommendation: `This technology (${tech}) is not trackable via CVE databases. Reason: ${nonTrackableReason}`
      }
    });
  }

  structuredLog('scan_start', { ip, tech, version, ecosystem });

  try {
    // § 4.1 Smart cascade: OSV first, then KEV only if needed, EOL always in parallel with OSV
    const [{ osvRaw, kevSet }, eol, versionInfo] = await Promise.all([
      getOSVAndKEV(tech, version, ecosystem),
      getEOL(tech, version),
      validateVersion(tech, version, ecosystem)
    ]);

    // § 6.2 Response size guard
    const vulnsRaw = osvRaw.slice(0, 100).map(v => {
      const info = extractVulnInfo(v);
      return {
        id:        info.id,
        displayId: info.displayId,
        allIds:    info.allIds,
        summary:   info.summary,
        link:      info.link,
        published: info.published,
        severity:  parseSeverity(v),
        kev:       kevSet.has(info.id) || info.allIds.some(a => kevSet.has(a))
      };
    });

    vulnsRaw.sort((a, b) => {
      if (a.kev !== b.kev) return b.kev - a.kev;
      const sa = numScore(a.severity), sb = numScore(b.severity);
      if (sa !== sb) return sb - sa;
      return a.displayId.localeCompare(b.displayId);
    });

    const risk    = calcRiskPro(vulnsRaw, eol);
    const summary = buildSummary(tech, version, ecosystem, vulnsRaw, eol, risk);
    const ms      = Date.now() - t0;

    structuredLog('scan_complete', {
      ip, tech, version, ecosystem,
      vulns: vulnsRaw.length, risk: risk.level, score: risk.score, ms
    });

    return jsonResp({
      success: true,
      target:  { tech, version, ecosystem },
      versionInfo: {
        exists:         versionInfo.exists,
        closest:        versionInfo.closest,
        recentVersions: versionInfo.allVersions.slice(0, 6)
      },
      eol,
      vulns:   { total: osvRaw.length, list: vulnsRaw.slice(0, 50) },
      risk,
      summary,
      meta:    { ms, version: '5.0.0' }
    }, 200, {
      'X-Scan-Ms':      String(ms),
      'X-Risk-Level':   risk.level,
      'X-Vuln-Count':   String(vulnsRaw.length)
    });

  } catch (err) {
    structuredLog('scan_error', { ip, tech, version, error: err.message, ms: Date.now()-t0 });
    return jsonResp({ success: false, error: err.message }, 500);
  }
}
