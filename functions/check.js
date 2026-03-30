// ================================
// UTILS
// ================================
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}

async function safeFetchJson(url) {
  try {
    const res = await fetch(url);
    if (!res.ok) throw new Error(res.statusText);
    return await res.json();
  } catch (e) {
    return null;
  }
}

function normalizeTech(t) {
  return t.toLowerCase().trim();
}

// ================================
// OSV (CVEs)
// ================================
async function fetchOSV(tech, version, ecosystem) {
  const body = {
    package: { name: tech, ecosystem },
    version
  };

  try {
    const res = await fetch("https://api.osv.dev/v1/query", {
      method: "POST",
      body: JSON.stringify(body)
    });

    const data = await res.json();

    return data.vulns || [];
  } catch {
    return [];
  }
}

// ================================
// KEV (Exploited)
// ================================
async function fetchKEV() {
  const data = await safeFetchJson(
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
  );

  if (!data) return [];

  return data.vulnerabilities.map(v => v.cveID);
}

// ================================
// EOL
// ================================
async function fetchEOL(tech, version) {
  const data = await safeFetchJson(`https://endoflife.date/api/${tech}.json`);

  if (!data) {
    return { status: "unknown" };
  }

  const major = version.split(".")[0];

  const match = data.find(d => d.cycle.startsWith(major));

  if (!match) return { status: "unknown" };

  return {
    status: match.eol ? "EOL" : "supported",
    latest: match.latest
  };
}

// ================================
// RISK ENGINE
// ================================
function calculateRisk(vulns) {
  if (vulns.some(v => v.kev)) return "CRITICAL";
  if (vulns.length > 10) return "HIGH";
  if (vulns.length > 0) return "MEDIUM";
  return "LOW";
}

// ================================
// MAIN HANDLER
// ================================
export async function onRequest(context) {
  const url = new URL(context.request.url);

  const tech = normalizeTech(url.searchParams.get("tech") || "");
  const version = url.searchParams.get("version");
  const ecosystem = url.searchParams.get("ecosystem") || "npm";

  if (!tech || !version) {
    return json({ success: false, error: "Missing parameters" }, 400);
  }

  try {
    console.log("Request:", { tech, version, ecosystem });

    const [osv, kevList, eol] = await Promise.all([
      fetchOSV(tech, version, ecosystem),
      fetchKEV(),
      fetchEOL(tech, version)
    ]);

    const vulns = osv.map(v => ({
      id: v.id,
      severity: v.severity?.[0]?.score || "UNKNOWN",
      kev: kevList.includes(v.id)
    }));

    const risk = calculateRisk(vulns);

    return json({
      success: true,
      target: { tech, version },
      eol,
      vulns: {
        total: vulns.length,
        list: vulns.slice(0, 20) // limit
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
