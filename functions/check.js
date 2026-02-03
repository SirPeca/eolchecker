const NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0";

const TECH_CATALOG = {
  openssl: { vendor: "openssl", product: "openssl", eol: "openssl" },
  jquery: { vendor: "jquery", product: "jquery", eol: "jquery" },
  bootstrap: { vendor: "twbs", product: "bootstrap", eol: "bootstrap" },
  vue: { vendor: "vuejs", product: "vue.js", eol: "vue" }
};

const SEV_ORDER = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };

function getSeverity(cve) {
  return (
    cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity ||
    cve.metrics?.cvssMetricV30?.[0]?.cvssData?.baseSeverity ||
    cve.metrics?.cvssMetricV2?.[0]?.baseSeverity ||
    "UNKNOWN"
  );
}

export async function onRequest({ request, env }) {
  const url = new URL(request.url);
  const techRaw = url.searchParams.get("tech")?.toLowerCase().trim();
  const version = url.searchParams.get("version")?.trim();

  if (!techRaw || !version) {
    return Response.json({ error: "Missing parameters" }, { status: 400 });
  }

  const tech = TECH_CATALOG[techRaw];
  if (!tech) {
    return Response.json({
      technology: techRaw,
      version,
      error: "Tecnología no soportada aún",
      cves: []
    });
  }

  // ---------- EOL ----------
  let cycles = [];
  let latest = null;
  let supported = null;

  try {
    const eolRes = await fetch(`https://endoflife.date/api/${tech.eol}.json`);
    cycles = await eolRes.json();
    latest = cycles[0]?.latest || null;
    supported = cycles.find(c => !c.eol || new Date(c.eol) > new Date())?.latest || null;
  } catch {}

  // ---------- CVEs ----------
  const cpe = `cpe:2.3:a:${tech.vendor}:${tech.product}:${version}:*:*:*:*:*:*:*`;
  let cves = [];

  try {
    const res = await fetch(
      `${NVD_API}?cpeName=${encodeURIComponent(cpe)}&resultsPerPage=100`,
      { headers: env.API_KEY ? { apiKey: env.API_KEY } : {} }
    );

    const data = await res.json();

    cves = (data.vulnerabilities || []).map(v => {
      const cve = v.cve;
      return {
        id: cve.id,
        severity: getSeverity(cve),
        description: cve.descriptions?.[0]?.value || "",
        url: `https://nvd.nist.gov/vuln/detail/${cve.id}`
      };
    });
  } catch {}

  cves.sort((a, b) => (SEV_ORDER[b.severity] || 0) - (SEV_ORDER[a.severity] || 0));

  const summary = {
    total: cves.length,
    CRITICAL: cves.filter(c => c.severity === "CRITICAL").length,
    HIGH: cves.filter(c => c.severity === "HIGH").length
  };

  return Response.json(
    {
      technology: techRaw,
      version,
      latest_version: latest,
      latest_supported_version: supported,
      summary,
      cves,
      fuentes: [
        "https://endoflife.date",
        "https://nvd.nist.gov"
      ]
    },
    {
      headers: {
        "Cache-Control": "no-store"
      }
    }
  );
}
