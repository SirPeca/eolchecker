// =========================================
// EOL & CVE Checker — functions/check.js  v3 HARDENED
// =========================================

// ---- Security Config ----
const ALLOWED_ORIGIN = 'https://theeolchecker.pages.dev';
const RATE_LIMIT = new Map();
const MAX_REQ = 20;
const WINDOW_MS = 60000;

// ---- Helpers ----

function jsonResp(data, status = 200, origin = '') {
  const allowed = origin === ALLOWED_ORIGIN ? origin : ALLOWED_ORIGIN;

  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      'Access-Control-Allow-Origin': allowed,
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'no-referrer',
      'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none';"
    }
  });
}

function isValidInput(str) {
  return /^[a-zA-Z0-9._-]{1,50}$/.test(str);
}

function normalize(t) {
  return t.toLowerCase().trim();
}

async function safeFetch(url, opts = {}) {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);

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

// ---- OSV ----

async function osvQuery(packageObj, version, pageToken = null) {
  const body = { package: packageObj, version };
  if (pageToken) body.page_token = pageToken;

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);

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
    if (!seen.has(v.id)) {
      seen.add(v.id);
      merged.push(v);
    }
  }

  return merged;
}

// ---- KEV ----

async function getKEV() {
  const data = await safeFetch(
    'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
  );

  if (!data?.vulnerabilities) return new Set();
  return new Set(data.vulnerabilities.map(v => v.cveID));
}

// ---- EOL ----

async function getEOL(tech, version) {
  const slug = normalize(tech);
  const data = await safeFetch(`https://endoflife.date/api/${encodeURIComponent(slug)}.json`);

  if (!Array.isArray(data) || data.length === 0) {
    return { status: 'unknown', latest: null, eolDate: null };
  }

  const parts = version.split('.');
  const major = parts[0];
  const minorV = parts.slice(0, 2).join('.');

  const match =
    data.find(v => v.cycle === version) ||
    data.find(v => v.cycle === minorV) ||
    data.find(v => String(v.cycle).startsWith(major + '.')) ||
    data.find(v => String(v.cycle) === major);

  if (!match) return { status: 'unknown', latest: data[0]?.latest || null, eolDate: null };

  const eolValue = match.eol;
  let status = 'unknown';
  let eolDate = null;

  if (typeof eolValue === 'boolean') {
    status = eolValue ? 'EOL' : 'supported';
  } else if (typeof eolValue === 'string') {
    eolDate = eolValue;
    status = new Date(eolValue) < new Date() ? 'EOL' : 'supported';
  }

  return {
    status,
    latest: match.latest || null,
    eolDate,
    lts: match.lts || false,
    support: match.support || null
  };
}

// ---- Severity ----

function parseSeverity(v) {
  const sev = v.severity;

  if (sev?.length) {
    for (const s of sev) {
      const n = parseFloat(s.score);
      if (!isNaN(n)) return n.toFixed(1);
    }
  }

  return 'UNKNOWN';
}

// ---- Risk ----

function calcRisk(vulns, eol) {
  if (vulns.some(v => v.kev)) return 'CRITICAL';
  if (vulns.length > 10) return 'HIGH';
  if (vulns.length > 0) return 'MEDIUM';
  if (eol.status === 'EOL') return 'MEDIUM';
  return 'LOW';
}

// ---- MAIN ----

export async function onRequest(context) {
  const origin = context.request.headers.get('Origin') || '';
  const ip = context.request.headers.get('CF-Connecting-IP') || 'unknown';

  const now = Date.now();

  if (!RATE_LIMIT.has(ip)) RATE_LIMIT.set(ip, []);

  const timestamps = RATE_LIMIT.get(ip).filter(t => now - t < WINDOW_MS);
  timestamps.push(now);
  RATE_LIMIT.set(ip, timestamps);

  if (timestamps.length > MAX_REQ) {
    return jsonResp({ success: false, error: 'Rate limit exceeded' }, 429, origin);
  }

  const url = new URL(context.request.url);
  const tech = normalize(url.searchParams.get('tech') || '');
  const version = url.searchParams.get('version') || '';
  const ecosystem = url.searchParams.get('ecosystem') || 'npm';

  if (!tech || !version) {
    return jsonResp({ success: false, error: 'Missing parameters' }, 400, origin);
  }

  if (!isValidInput(tech) || !isValidInput(version)) {
    return jsonResp({ success: false, error: 'Invalid input format' }, 400, origin);
  }

  try {
    console.log('[SCAN]', { ip, tech, version, ecosystem });

    const [osvRaw, kevSet, eol] = await Promise.all([
      getOSV(tech, version, ecosystem),
      getKEV(),
      getEOL(tech, version)
    ]);

    const vulns = osvRaw.map(v => ({
      id: v.id,
      severity: parseSeverity(v),
      kev: kevSet.has(v.id)
    }));

    const risk = calcRisk(vulns, eol);

    return jsonResp({
      success: true,
      target: { tech, version, ecosystem },
      eol,
      vulns: {
        total: vulns.length,
        list: vulns.slice(0, 50)
      },
      risk: { level: risk }
    }, 200, origin);

  } catch (err) {
    console.error('[ERROR]', err);
    return jsonResp({ success: false, error: 'Internal server error' }, 500, origin);
  }
}
