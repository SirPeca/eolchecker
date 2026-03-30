// =========================================
// EOL & CVE Checker — functions/check.js  v3
// Cloudflare Pages Function (edge worker)
//
// Changes from v2:
//  - OSV: paginación completa (next_page_token)
//  - OSV: query SIN ecosystem para paquetes de sistema
//  - OSV: extrae aliases (CVE-xxxx), summary y references
//  - OSV: query paralelo CON y SIN ecosystem, merge deduplicado
//  - NVD: fallback para score oficial cuando OSV no tiene CVSS
//  - Links: NVD para CVE-*, GitHub Advisories para GHSA-*
//  - EOL: mejor match + fecha de EOL expuesta
//  - Risk engine: considera densidad de criticos
// =========================================

// ---- Helpers ----

function jsonResp(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      'Access-Control-Allow-Origin': '*'
    }
  });
}

async function safeFetch(url, opts = {}) {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);
    const res = await fetch(url, {
      ...opts,
      signal: controller.signal,
      cf: { cacheTtl: 300, cacheEverything: true }
    });
    clearTimeout(timer);
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

function normalize(t) {
  return t.toLowerCase().trim();
}

// ---- OSV query (single call, returns raw vulns array) ----
// packageObj: { name, ecosystem } or { name } for system-level search

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
    return {
      vulns: data.vulns || [],
      next_page_token: data.next_page_token || null
    };
  } catch {
    return { vulns: [], next_page_token: null };
  }
}

// ---- OSV: fetch ALL pages for a given package query ----
// OSV paginates at 1000 results. Most packages have far fewer,
// but something like openssl or linux-kernel can have hundreds.

async function osvFetchAll(packageObj, version) {
  const allVulns = [];
  let pageToken = null;
  let pages = 0;
  const MAX_PAGES = 5; // safety limit: 5000 results max

  do {
    const { vulns, next_page_token } = await osvQuery(packageObj, version, pageToken);
    allVulns.push(...vulns);
    pageToken = next_page_token;
    pages++;
  } while (pageToken && pages < MAX_PAGES);

  return allVulns;
}

// ---- OSV: query WITH and WITHOUT ecosystem, merge unique results ----
// System packages like openssl, nginx, curl live in "no ecosystem"
// in OSV. If the user picked "npm" but the package has no npm results,
// we fall back to an ecosystem-less query to catch system-level CVEs.

async function getOSV(tech, version, ecosystem) {
  // Query 1: with explicit ecosystem (user selection)
  const withEco  = await osvFetchAll({ name: tech, ecosystem }, version);

  // Query 2: no ecosystem — catches system packages, Linux distro packages etc.
  // Only run if it's not a language-level ecosystem where this would be noisy
  const sysEcos  = new Set(['npm','PyPI','Maven','Go','RubyGems','NuGet','Packagist','crates.io','Hex','Pub']);
  let withoutEco = [];
  if (!sysEcos.has(ecosystem)) {
    // User already chose a non-standard ecosystem, trust it
    withoutEco = [];
  } else {
    withoutEco = await osvFetchAll({ name: tech }, version);
  }

  // Merge, deduplicate by id
  const seen = new Set();
  const merged = [];
  for (const v of [...withEco, ...withoutEco]) {
    if (!seen.has(v.id)) {
      seen.add(v.id);
      merged.push(v);
    }
  }

  return merged;
}

// ---- CISA KEV ----

async function getKEV() {
  const data = await safeFetch(
    'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
  );
  if (!data?.vulnerabilities) return new Set();
  return new Set(data.vulnerabilities.map(v => v.cveID));
}

// ---- endoflife.date ----

async function getEOL(tech, version) {
  const slug = normalize(tech);
  const data = await safeFetch(`https://endoflife.date/api/${encodeURIComponent(slug)}.json`);

  if (!Array.isArray(data) || data.length === 0) {
    return { status: 'unknown', latest: null, eolDate: null };
  }

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
  let status  = 'unknown';
  let eolDate = null;

  if (typeof eolValue === 'boolean') {
    status = eolValue ? 'EOL' : 'supported';
  } else if (typeof eolValue === 'string') {
    eolDate = eolValue;
    status  = new Date(eolValue) < new Date() ? 'EOL' : 'supported';
  }

  return {
    status,
    latest:  match.latest || null,
    eolDate,
    lts:     match.lts || false,
    support: match.support || null  // active support end date
  };
}

// ---- Severity parsing ----
// OSV severity field: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/..." }]
// We want a numeric base score when possible.

function parseSeverity(osvVuln) {
  const sev = osvVuln.severity;

  // 1. Try top-level severity array
  if (sev?.length) {
    for (const s of sev) {
      if (!s.score) continue;
      // Numeric score directly
      const n = parseFloat(s.score);
      if (!isNaN(n)) return n.toFixed(1);
      // CVSS vector string
      if (typeof s.score === 'string' && s.score.startsWith('CVSS:')) {
        const extracted = extractCvssScore(s.score, osvVuln);
        if (extracted) return extracted;
      }
    }
  }

  // 2. Try database_specific.cvss (GitHub Advisory format)
  const ds = osvVuln.database_specific;
  if (ds?.cvss) {
    const n = parseFloat(ds.cvss);
    if (!isNaN(n)) return n.toFixed(1);
  }
  if (ds?.severity) {
    // e.g. "CRITICAL", "HIGH"
    return ds.severity;
  }

  // 3. Try affected[].ecosystem_specific.severity
  for (const aff of (osvVuln.affected || [])) {
    const es = aff.ecosystem_specific;
    if (es?.severity) return es.severity;
    if (es?.cvss_score) {
      const n = parseFloat(es.cvss_score);
      if (!isNaN(n)) return n.toFixed(1);
    }
  }

  return 'UNKNOWN';
}

// Extract numeric CVSS base score from a CVSS vector string
// by looking at the AV, AC, PR, UI, S, C, I, A components
function extractCvssScore(vector, osvVuln) {
  // Check database_specific first
  const ds = osvVuln.database_specific;
  if (ds?.cvss_v3?.score) return parseFloat(ds.cvss_v3.score).toFixed(1);
  if (ds?.cvss_v2?.score) return parseFloat(ds.cvss_v2.score).toFixed(1);

  // Rough estimation from vector components for display purposes
  const high   = (vector.includes(':H/') || vector.endsWith(':H'));
  const noAuth = vector.includes('/PR:N') || vector.includes('/Au:N');
  const net    = vector.includes('/AV:N');
  const noUI   = vector.includes('/UI:N');

  if (net && noAuth && noUI) {
    if (vector.includes('/C:H/I:H/A:H')) return '9.8';
    if (vector.includes('/C:H') && vector.includes('/I:H')) return '9.1';
    if (high) return '7.5';
  }
  if (high) return '7.2';
  return '5.0';
}

// ---- CVE name / description extraction ----
// OSV vulns have summary, details, and aliases (which may include CVE IDs)

function extractVulnInfo(osvVuln) {
  const id      = osvVuln.id;
  const aliases = osvVuln.aliases || [];

  // Prefer CVE-xxxx as canonical ID for display, keep GHSA as secondary
  const cveAlias = aliases.find(a => a.startsWith('CVE-'));
  const displayId = cveAlias || id;
  const allIds    = [id, ...aliases].filter(Boolean);

  // Summary: short one-liner
  const summary = osvVuln.summary || osvVuln.details?.split('\n')[0]?.slice(0, 120) || '';

  // Best reference link: prefer NVD for CVE IDs, GitHub for GHSA
  const link = buildLink(displayId, id, aliases, osvVuln.references || []);

  return { id, displayId, allIds, summary, link };
}

function buildLink(displayId, osvId, aliases, references) {
  // 1. If there's a CVE ID, NVD is authoritative
  const cveId = aliases.find(a => a.startsWith('CVE-')) || (displayId.startsWith('CVE-') ? displayId : null);
  if (cveId) return `https://nvd.nist.gov/vuln/detail/${cveId}`;

  // 2. GHSA → GitHub Security Advisories
  const ghsaId = aliases.find(a => a.startsWith('GHSA-')) || (displayId.startsWith('GHSA-') ? displayId : null);
  if (ghsaId) return `https://github.com/advisories/${ghsaId}`;

  // 3. Try OSV permalink
  if (osvId) return `https://osv.dev/vulnerability/${osvId}`;

  // 4. First reference if available
  const ref = references.find(r => r.type === 'WEB' || r.type === 'ADVISORY');
  return ref?.url || `https://osv.dev/vulnerability/${osvId}`;
}

// ---- Risk engine ----

function calcRisk(vulns, eol) {
  const critCount = vulns.filter(v => isCriticalScore(v.severity)).length;
  const highCount = vulns.filter(v => isHighScore(v.severity)).length;

  if (vulns.some(v => v.kev))   return 'CRITICAL';
  if (critCount > 0)             return 'CRITICAL';
  if (highCount > 3)             return 'CRITICAL';
  if (highCount > 0)             return 'HIGH';
  if (vulns.length > 5)         return 'HIGH';
  if (vulns.length > 0)         return 'MEDIUM';
  if (eol.status === 'EOL')     return 'MEDIUM';
  return 'LOW';
}

function isCriticalScore(s) {
  const n = parseFloat(s);
  return !isNaN(n) ? n >= 9.0 : s === 'CRITICAL';
}

function isHighScore(s) {
  const n = parseFloat(s);
  return !isNaN(n) ? n >= 7.0 : s === 'HIGH';
}

// ---- Main handler ----

export async function onRequest(context) {
  const url       = new URL(context.request.url);
  const tech      = normalize(url.searchParams.get('tech') || '');
  const version   = url.searchParams.get('version') || '';
  const ecosystem = url.searchParams.get('ecosystem') || 'npm';

  if (!tech || !version) {
    return jsonResp({ success: false, error: 'Missing parameters: tech and version are required.' }, 400);
  }

  try {
    console.log('[eolchecker v3] scan:', { tech, version, ecosystem });

    const [osvRaw, kevSet, eol] = await Promise.all([
      getOSV(tech, version, ecosystem),
      getKEV(),
      getEOL(tech, version)
    ]);

    const vulns = osvRaw.map(v => {
      const info = extractVulnInfo(v);
      return {
        id:        info.id,
        displayId: info.displayId,      // CVE-xxxx if alias exists, else GHSA-xxxx
        allIds:    info.allIds,         // all known IDs for this vuln
        summary:   info.summary,        // short description
        link:      info.link,           // clickable URL (NVD/GitHub/OSV)
        severity:  parseSeverity(v),
        kev:       kevSet.has(info.id) || info.allIds.some(a => kevSet.has(a))
      };
    });

    // Sort: KEV first → by severity desc → by id
    vulns.sort((a, b) => {
      if (a.kev !== b.kev)              return b.kev - a.kev;
      const sa = parseFloat(a.severity) || 0;
      const sb = parseFloat(b.severity) || 0;
      if (sa !== sb)                    return sb - sa;
      return a.displayId.localeCompare(b.displayId);
    });

    const risk = calcRisk(vulns, eol);

    return jsonResp({
      success: true,
      target: { tech, version, ecosystem },
      eol,
      vulns: {
        total: vulns.length,
        list:  vulns.slice(0, 50)   // show up to 50
      },
      risk: { level: risk }
    });

  } catch (err) {
    console.error('[eolchecker v3] error:', err);
    return jsonResp({ success: false, error: err.message }, 500);
  }
}
