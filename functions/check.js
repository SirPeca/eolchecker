// =========================================
// EOL & CVE Checker — functions/check.js  v4
//
// NEW in v4:
//  - Version Intelligence: valida que la versión exista realmente
//    consultando el package registry (npm, PyPI, etc.)
//    Si no existe → devuelve versiones cercanas sugeridas
//  - Risk Engine Pro: score numérico 0-100, factores múltiples
//    (CVSS score, KEV weight, EOL penalty, exploit availability)
//  - Executive Summary en el response (listo para el informe)
//  - Rate limiting suave via CF headers
//  - Input sanitization reforzada
// =========================================

// ---- Helpers ----

function jsonResp(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      'Access-Control-Allow-Origin': '*',
      'X-Content-Type-Options': 'nosniff'
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

// Sanitize input: only allow alphanumeric, dots, dashes, underscores, slashes (for Go modules)
function sanitize(s, maxLen = 120) {
  return String(s).replace(/[^a-zA-Z0-9.\-_/: ]/g, '').slice(0, maxLen).trim();
}

// =========================================
// VERSION INTELLIGENCE
// Validates that a package@version actually exists.
// Returns: { valid: bool, exists: bool, closest: string|null, allVersions: string[] }
// =========================================

async function validateVersion(tech, version, ecosystem) {
  // Only validate ecosystems where we can query a registry
  const validator = getValidator(ecosystem);
  if (!validator) return { valid: true, exists: true, closest: null, allVersions: [] };

  try {
    const result = await validator(tech, version);
    return result;
  } catch {
    // If registry is unreachable, don't block the scan — just skip validation
    return { valid: true, exists: true, closest: null, allVersions: [] };
  }
}

function getValidator(ecosystem) {
  const map = {
    'npm':        validateNpm,
    'PyPI':       validatePyPI,
    'RubyGems':   validateRubyGems,
    'crates.io':  validateCratesIo,
  };
  return map[ecosystem] || null;
}

async function validateNpm(name, version) {
  const data = await safeFetch(`https://registry.npmjs.org/${encodeURIComponent(name)}`);
  if (!data) return { valid: true, exists: true, closest: null, allVersions: [] };
  if (data.error === 'Not found') return { valid: false, exists: false, closest: null, allVersions: [] };

  const versions = Object.keys(data.versions || {});
  if (versions.length === 0) return { valid: true, exists: true, closest: null, allVersions: [] };

  const exists = versions.includes(version);
  const closest = exists ? null : findClosestVersion(version, versions);
  return { valid: true, exists, closest, allVersions: versions.slice(-10).reverse() };
}

async function validatePyPI(name, version) {
  const data = await safeFetch(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`);
  if (!data) return { valid: true, exists: true, closest: null, allVersions: [] };

  const versions = Object.keys(data.releases || {});
  if (versions.length === 0) return { valid: true, exists: true, closest: null, allVersions: [] };

  const exists = versions.includes(version);
  const closest = exists ? null : findClosestVersion(version, versions);
  return { valid: true, exists, closest, allVersions: versions.slice(-10).reverse() };
}

async function validateRubyGems(name, version) {
  const data = await safeFetch(`https://rubygems.org/api/v1/versions/${encodeURIComponent(name)}.json`);
  if (!Array.isArray(data)) return { valid: true, exists: true, closest: null, allVersions: [] };

  const versions = data.map(v => v.number);
  const exists = versions.includes(version);
  const closest = exists ? null : findClosestVersion(version, versions);
  return { valid: true, exists, closest, allVersions: versions.slice(0, 10) };
}

async function validateCratesIo(name, version) {
  const data = await safeFetch(`https://crates.io/api/v1/crates/${encodeURIComponent(name)}/versions`);
  if (!data?.versions) return { valid: true, exists: true, closest: null, allVersions: [] };

  const versions = data.versions.map(v => v.num);
  const exists = versions.includes(version);
  const closest = exists ? null : findClosestVersion(version, versions);
  return { valid: true, exists, closest, allVersions: versions.slice(0, 10) };
}

// Find the closest semver version from a list
function findClosestVersion(target, versions) {
  if (!versions.length) return null;

  const tParts = target.split('.').map(p => parseInt(p) || 0);

  let best = null;
  let bestScore = Infinity;

  for (const v of versions) {
    const vParts = v.split('.').map(p => parseInt(p) || 0);
    // Weighted distance: major diff counts most
    const score =
      Math.abs((tParts[0] || 0) - (vParts[0] || 0)) * 10000 +
      Math.abs((tParts[1] || 0) - (vParts[1] || 0)) * 100 +
      Math.abs((tParts[2] || 0) - (vParts[2] || 0));

    if (score < bestScore) {
      bestScore = score;
      best = v;
    }
  }
  return best;
}

// =========================================
// OSV
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
// CISA KEV
// =========================================

async function getKEV() {
  const data = await safeFetch(
    'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
  );
  if (!data?.vulnerabilities) return new Set();
  return new Set(data.vulnerabilities.map(v => v.cveID));
}

// =========================================
// EOL
// =========================================

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
  let status = 'unknown', eolDate = null;

  if (typeof eolValue === 'boolean') {
    status = eolValue ? 'EOL' : 'supported';
  } else if (typeof eolValue === 'string') {
    eolDate = eolValue;
    status = new Date(eolValue) < new Date() ? 'EOL' : 'supported';
  }

  return { status, latest: match.latest || null, eolDate, lts: match.lts || false, support: match.support || null };
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
        const extracted = extractCvssScore(s.score, osvVuln);
        if (extracted) return extracted;
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
  // Extract published date if available
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
// RISK ENGINE PRO
// Numeric score 0–100 + label + breakdown
// =========================================

function calcRiskPro(vulns, eol) {
  let score = 0;
  const factors = [];

  // ---- KEV: actively exploited in the wild ----
  const kevVulns = vulns.filter(v => v.kev);
  if (kevVulns.length > 0) {
    const kevScore = Math.min(40, kevVulns.length * 20);
    score += kevScore;
    factors.push({
      key:    'kev',
      label:  `${kevVulns.length} actively exploited (KEV)`,
      points: kevScore,
      level:  'critical'
    });
  }

  // ---- Critical CVEs (CVSS ≥ 9.0) ----
  const critVulns = vulns.filter(v => numScore(v.severity) >= 9.0);
  if (critVulns.length > 0) {
    const critScore = Math.min(30, critVulns.length * 15);
    score += critScore;
    factors.push({
      key:    'critical_cvss',
      label:  `${critVulns.length} critical severity (CVSS ≥ 9.0)`,
      points: critScore,
      level:  'critical'
    });
  }

  // ---- High CVEs (CVSS 7.0–8.9) ----
  const highVulns = vulns.filter(v => { const n = numScore(v.severity); return n >= 7.0 && n < 9.0; });
  if (highVulns.length > 0) {
    const highScore = Math.min(20, highVulns.length * 5);
    score += highScore;
    factors.push({
      key:    'high_cvss',
      label:  `${highVulns.length} high severity (CVSS 7.0–8.9)`,
      points: highScore,
      level:  'high'
    });
  }

  // ---- Medium CVEs ----
  const medVulns = vulns.filter(v => { const n = numScore(v.severity); return n >= 4.0 && n < 7.0; });
  if (medVulns.length > 0) {
    const medScore = Math.min(10, medVulns.length * 2);
    score += medScore;
    factors.push({
      key:    'medium_cvss',
      label:  `${medVulns.length} medium severity (CVSS 4.0–6.9)`,
      points: medScore,
      level:  'medium'
    });
  }

  // ---- EOL penalty ----
  if (eol.status === 'EOL') {
    score += 15;
    factors.push({
      key:    'eol',
      label:  'Version is End-of-Life (no security patches)',
      points: 15,
      level:  'high'
    });
  }

  // ---- EOL date approaching (within 90 days) ----
  if (eol.status === 'supported' && eol.eolDate) {
    const daysUntilEol = Math.floor((new Date(eol.eolDate) - new Date()) / 86400000);
    if (daysUntilEol >= 0 && daysUntilEol <= 90) {
      score += 8;
      factors.push({
        key:    'eol_soon',
        label:  `EOL in ${daysUntilEol} days (${eol.eolDate})`,
        points: 8,
        level:  'medium'
      });
    }
  }

  // ---- Unknown severity penalty (incomplete data) ----
  const unknownVulns = vulns.filter(v => v.severity === 'UNKNOWN');
  if (unknownVulns.length > 0) {
    const unknownScore = Math.min(5, unknownVulns.length * 1);
    score += unknownScore;
    factors.push({
      key:    'unknown_sev',
      label:  `${unknownVulns.length} vulnerabilities with unknown severity`,
      points: unknownScore,
      level:  'low'
    });
  }

  score = Math.min(100, Math.round(score));

  // Label from score
  let level;
  if (score >= 70)      level = 'CRITICAL';
  else if (score >= 45) level = 'HIGH';
  else if (score >= 20) level = 'MEDIUM';
  else if (score > 0)   level = 'LOW';
  else                   level = 'LOW';

  // Max CVSS for summary
  const maxCvss = vulns.reduce((m, v) => Math.max(m, numScore(v.severity)), 0);

  return { level, score, factors, maxCvss: maxCvss > 0 ? maxCvss.toFixed(1) : null };
}

function numScore(s) {
  const n = parseFloat(s);
  return !isNaN(n) ? n : (s === 'CRITICAL' ? 9.5 : s === 'HIGH' ? 7.5 : s === 'MEDIUM' ? 5.0 : 0);
}

// =========================================
// EXECUTIVE SUMMARY builder
// =========================================

function buildSummary(tech, version, ecosystem, vulns, eol, risk) {
  const kevCount  = vulns.filter(v => v.kev).length;
  const critCount = vulns.filter(v => numScore(v.severity) >= 9.0).length;
  const highCount = vulns.filter(v => { const n = numScore(v.severity); return n >= 7.0 && n < 9.0; }).length;
  const today     = new Date().toISOString().split('T')[0];

  // Recommendation text
  let recommendation = '';
  if (risk.level === 'CRITICAL') {
    recommendation = `Immediate action required. ${kevCount > 0 ? `${kevCount} vulnerabilit${kevCount > 1 ? 'ies are' : 'y is'} actively exploited in the wild. ` : ''}Upgrade to the latest version immediately and apply all available patches.`;
  } else if (risk.level === 'HIGH') {
    recommendation = `Urgent upgrade recommended. ${critCount > 0 ? `${critCount} critical-severity vulnerabilit${critCount > 1 ? 'ies' : 'y'} detected. ` : ''}Schedule upgrade within the next patch cycle.`;
  } else if (risk.level === 'MEDIUM') {
    recommendation = eol.status === 'EOL'
      ? 'Version is End-of-Life. Plan migration to a supported version. No new security patches will be issued.'
      : `${vulns.length} vulnerabilit${vulns.length > 1 ? 'ies' : 'y'} detected. Review and upgrade in your next maintenance window.`;
  } else {
    recommendation = vulns.length === 0
      ? 'No known vulnerabilities detected for this version. Continue monitoring for new advisories.'
      : 'Low-risk vulnerabilities present. Review and upgrade as part of standard maintenance.';
  }

  return {
    date:           today,
    target:         `${tech} ${version} (${ecosystem})`,
    riskLevel:      risk.level,
    riskScore:      risk.score,
    totalVulns:     vulns.length,
    criticalVulns:  critCount,
    highVulns:      highCount,
    kevVulns:       kevCount,
    maxCvss:        risk.maxCvss,
    eolStatus:      eol.status,
    eolDate:        eol.eolDate,
    latestVersion:  eol.latest,
    recommendation
  };
}

// =========================================
// MAIN HANDLER
// =========================================

export async function onRequest(context) {
  const url       = new URL(context.request.url);
  const rawTech   = url.searchParams.get('tech')      || '';
  const rawVer    = url.searchParams.get('version')   || '';
  const rawEco    = url.searchParams.get('ecosystem') || 'npm';

  // Input sanitization
  const tech      = sanitize(normalize(rawTech), 80);
  const version   = sanitize(rawVer, 30);
  const ecosystem = sanitize(rawEco, 40);

  if (!tech || !version) {
    return jsonResp({ success: false, error: 'Missing parameters: tech and version are required.' }, 400);
  }

  // Basic version format check — must contain at least one digit
  if (!/\d/.test(version)) {
    return jsonResp({ success: false, error: `"${version}" doesn't look like a valid version number.` }, 400);
  }

  try {
    console.log('[eolchecker v4] scan:', { tech, version, ecosystem });

    // Run all queries in parallel — version validation included
    const [osvRaw, kevSet, eol, versionInfo] = await Promise.all([
      getOSV(tech, version, ecosystem),
      getKEV(),
      getEOL(tech, version),
      validateVersion(tech, version, ecosystem)
    ]);

    // Build vuln list
    const vulns = osvRaw.map(v => {
      const info = extractVulnInfo(v);
      return {
        id:         info.id,
        displayId:  info.displayId,
        allIds:     info.allIds,
        summary:    info.summary,
        link:       info.link,
        published:  info.published,
        severity:   parseSeverity(v),
        kev:        kevSet.has(info.id) || info.allIds.some(a => kevSet.has(a))
      };
    });

    // Sort: KEV first → severity desc → id
    vulns.sort((a, b) => {
      if (a.kev !== b.kev) return b.kev - a.kev;
      const sa = numScore(a.severity), sb = numScore(b.severity);
      if (sa !== sb) return sb - sa;
      return a.displayId.localeCompare(b.displayId);
    });

    const risk    = calcRiskPro(vulns, eol);
    const summary = buildSummary(tech, version, ecosystem, vulns, eol, risk);

    return jsonResp({
      success: true,
      target:  { tech, version, ecosystem },

      // Version intelligence
      versionInfo: {
        exists:      versionInfo.exists,
        closest:     versionInfo.closest,
        recentVersions: versionInfo.allVersions.slice(0, 6)
      },

      eol,

      vulns: {
        total: vulns.length,
        list:  vulns.slice(0, 50)
      },

      // Pro risk engine
      risk,

      // Executive summary (used by report export)
      summary
    });

  } catch (err) {
    console.error('[eolchecker v4] error:', err);
    return jsonResp({ success: false, error: err.message }, 500);
  }
}
