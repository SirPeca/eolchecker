// =========================================
// EOL & CVE Checker — functions/check.js
// Cloudflare Pages Function (edge worker)
// =========================================

// ---- Response helpers ----

function json(data, status = 200) {
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
    const res = await fetch(url, { ...opts, cf: { cacheTtl: 300, cacheEverything: true } });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

function normalize(t) {
  return t.toLowerCase().trim();
}

// ---- OSV (Open Source Vulnerabilities) ----
// Supports all major ecosystems: npm, PyPI, Maven, Go, RubyGems,
// NuGet, Packagist, crates.io, Hex, Pub, Swift URL, etc.

async function getOSV(tech, version, ecosystem) {
  try {
    const res = await fetch('https://api.osv.dev/v1/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        package: { name: tech, ecosystem },
        version
      })
    });
    if (!res.ok) return [];
    const data = await res.json();
    return data.vulns || [];
  } catch {
    return [];
  }
}

// ---- CISA KEV (Known Exploited Vulnerabilities) ----
// Cached at edge — this file is ~600KB but changes slowly.

async function getKEV() {
  const data = await safeFetch(
    'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
  );
  if (!data?.vulnerabilities) return new Set();
  return new Set(data.vulnerabilities.map(v => v.cveID));
}

// ---- endoflife.date ----
// Tries exact cycle match, then major match.

async function getEOL(tech, version) {
  const slug = normalize(tech);
  const data = await safeFetch(`https://endoflife.date/api/${encodeURIComponent(slug)}.json`);

  if (!Array.isArray(data) || data.length === 0) {
    return { status: 'unknown', latest: null };
  }

  const parts  = version.split('.');
  const major  = parts[0];
  const minorV = parts.slice(0, 2).join('.');

  // Try most specific match first (major.minor), then major
  const match =
    data.find(v => v.cycle === version) ||
    data.find(v => v.cycle === minorV) ||
    data.find(v => String(v.cycle).startsWith(major + '.')) ||
    data.find(v => String(v.cycle) === major);

  if (!match) return { status: 'unknown', latest: data[0]?.latest || null };

  const eolValue = match.eol;
  let status = 'unknown';

  if (typeof eolValue === 'boolean') {
    status = eolValue ? 'EOL' : 'supported';
  } else if (typeof eolValue === 'string') {
    // eolValue is a date string like "2024-01-01"
    const eolDate = new Date(eolValue);
    status = eolDate < new Date() ? 'EOL' : 'supported';
  }

  return {
    status,
    latest:  match.latest || null,
    eolDate: typeof eolValue === 'string' ? eolValue : null
  };
}

// ---- Severity parser ----
// OSV returns CVSS scores as numbers, strings, or CVSS vectors.
// This normalises to a float or label.

function parseSeverity(osvVuln) {
  // OSV severity field: [{ type: "CVSS_V3", score: "CVSS:3.1/..." }]
  const sev = osvVuln.severity;
  if (!sev || sev.length === 0) return 'UNKNOWN';

  for (const s of sev) {
    if (!s.score) continue;
    const score = s.score;
    // CVSS vector string — extract base score from database_specific if available
    if (typeof score === 'string' && score.startsWith('CVSS:')) {
      // Try database_specific for numeric score
      const ds = osvVuln.database_specific;
      if (ds?.cvss) {
        const n = parseFloat(ds.cvss);
        if (!isNaN(n)) return n.toFixed(1);
      }
      // Try affected[].ecosystem_specific
      for (const aff of (osvVuln.affected || [])) {
        const es = aff.ecosystem_specific;
        if (es?.severity) return es.severity;
      }
      return labelFromVector(score);
    }
    const n = parseFloat(score);
    if (!isNaN(n)) return n.toFixed(1);
    return score;
  }
  return 'UNKNOWN';
}

function labelFromVector(vector) {
  // CVSS:3.x/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → rough estimate
  if (vector.includes('/C:H/I:H/A:H')) return '9.8';
  if (vector.includes('/C:H') || vector.includes('/I:H')) return '7.5';
  if (vector.includes('/C:M') || vector.includes('/I:M')) return '5.3';
  return 'UNKNOWN';
}

// ---- Risk Engine ----

function calcRisk(vulns, eol) {
  if (vulns.some(v => v.kev))    return 'CRITICAL';
  if (vulns.some(v => isCriticalScore(v.severity))) return 'CRITICAL';
  if (vulns.some(v => isHighScore(v.severity)))     return 'HIGH';
  if (vulns.length > 5)          return 'HIGH';
  if (vulns.length > 0)          return 'MEDIUM';
  if (eol.status === 'EOL')      return 'MEDIUM';
  return 'LOW';
}

function isCriticalScore(s) {
  const n = parseFloat(s);
  return !isNaN(n) && n >= 9.0;
}

function isHighScore(s) {
  const n = parseFloat(s);
  return !isNaN(n) && n >= 7.0;
}

// ---- Main handler ----

export async function onRequest(context) {
  const url       = new URL(context.request.url);
  const tech      = normalize(url.searchParams.get('tech') || '');
  const version   = url.searchParams.get('version') || '';
  const ecosystem = url.searchParams.get('ecosystem') || 'npm';

  if (!tech || !version) {
    return json({ success: false, error: 'Missing parameters: tech and version are required.' }, 400);
  }

  try {
    console.log('[eolchecker] scan:', { tech, version, ecosystem });

    // Parallel requests — KEV is cached at edge so it's fast after first hit
    const [osvVulns, kevSet, eol] = await Promise.all([
      getOSV(tech, version, ecosystem),
      getKEV(),
      getEOL(tech, version)
    ]);

    const vulns = osvVulns.map(v => ({
      id:       v.id,
      severity: parseSeverity(v),
      kev:      kevSet.has(v.id),
      aliases:  v.aliases || []
    }));

    // Sort: KEV first, then by severity descending
    vulns.sort((a, b) => {
      if (a.kev !== b.kev) return b.kev - a.kev;
      const sa = parseFloat(a.severity) || 0;
      const sb = parseFloat(b.severity) || 0;
      return sb - sa;
    });

    const risk = calcRisk(vulns, eol);

    return json({
      success: true,
      target: { tech, version, ecosystem },
      eol,
      vulns: {
        total: vulns.length,
        list:  vulns.slice(0, 25)  // cap display at 25
      },
      risk: { level: risk }
    });

  } catch (err) {
    console.error('[eolchecker] error:', err);
    return json({ success: false, error: err.message }, 500);
  }
}
