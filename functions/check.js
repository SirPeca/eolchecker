// ================================
// HELPERS
// ================================
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}

async function safeFetch(url) {
  try {
    const res = await fetch(url);
    if (!res.ok) throw new Error(res.statusText);
    return await res.json();
  } catch {
    return null;
  }
}

function normalize(t) {
  return t.toLowerCase().trim();
}

// ================================
// OSV (rápido)
// ================================
async function getOSV(tech, version, ecosystem) {
  try {
    const res = await fetch("https://api.osv.dev/v1/query", {
      method: "POST",
      body: JSON.stringify({
        package: { name: tech, ecosystem },
        version
      })
    });

    const data = await res.json();
    return data.vulns || [];
  } catch {
    return [];
  }
}

// ================================
// NVD (PRO REAL)
// ================================
async function getNVD(tech) {
  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${tech}`;

  const data = await safeFetch(url);

  if (!data?.vulnerabilities) return [];

  return data.vulnerabilities.slice(0, 50).map(v => {
    const cve = v.cve;

    return {
      id: cve.id,
      severity: cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore ||
                cve.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore ||
                "UNKNOWN"
    };
  });
}

// ================================
// KEV
// ================================
async function getKEV() {
  const data = await safeFetch(
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
  );

  if (!data) return [];

  return data.vulnerabilities.map(v => v.cveID);
}

// ================================
// EOL
// ================================
async function getEOL(tech, version) {
  const data = await safeFetch(`https://endoflife.date/api/${tech}.json`);

  if (!data) return { status: "unknown" };

  const major = version.split(".")[0];

  const match = data.find(v => v.cycle.startsWith(major));

  if (!match) return { status: "unknown" };

  return {
    status: match.eol ? "EOL" : "supported",
    latest: match.latest
  };
}

// ================================
// RISK ENGINE PRO
// ================================
function calcRisk(vulns, eol) {
  if (vulns.some(v => v.kev)) return "CRITICAL";

  const scores = vulns
    .map(v => parseFloat(v.severity))
    .filter(v => !isNaN(v));

  const max = Math.max(...scores, 0);

  if (eol.status === "EOL" && max >= 7) return "CRITICAL";
  if (max >= 9) return "CRITICAL";
  if (max >= 7) return "HIGH";
  if (max >= 4) return "MEDIUM";
  if (vulns.length > 0) return "LOW";

  return "LOW";
}

// ================================
// MAIN
// ================================
export async function onRequest(context) {
  const url = new URL(context.request.url);

  const tech = normalize(url.searchParams.get("tech") || "");
  const version = url.searchParams.get("version");
  const ecosystem = url.searchParams.get("ecosystem") || "npm";

  if (!tech || !version) {
    return json({ success: false, error: "Missing parameters" }, 400);
  }

  try {
    const [osv, nvd, kevList, eol] = await Promise.all([
      getOSV(tech, version, ecosystem),
      getNVD(tech),
      getKEV(),
      getEOL(tech, version)
    ]);

    const combined = [...osv, ...nvd];

    const vulns = combined.map(v => ({
      id: v.id,
      severity: v.severity || "UNKNOWN",
      kev: kevList.includes(v.id)
    }));

    const unique = Object.values(
      vulns.reduce((acc, v) => {
        acc[v.id] = v;
        return acc;
      }, {})
    );

    const risk = calcRisk(unique, eol);

    return json({
      success: true,
      target: { tech, version },
      eol,
      vulns: {
        total: unique.length,
        list: unique.slice(0, 20)
      },
      risk: { level: risk }
    });

  } catch (err) {
    return json({
      success: false,
      error: err.message
    }, 500);
  }
}
