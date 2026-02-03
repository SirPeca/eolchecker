const NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0";

/**
 * Catálogo curado (extensible)
 * Agregar aquí NO rompe nada
 */
const TECH_CATALOG = {
  openssl: { vendor: "openssl", product: "openssl", eol: "openssl" },
  jquery: { vendor: "jquery", product: "jquery", eol: "jquery" },
  bootstrap: { vendor: "twbs", product: "bootstrap", eol: "bootstrap" },
  vue: { vendor: "vuejs", product: "vue.js", eol: "vue" },
  react: { vendor: "facebook", product: "react", eol: "react" },
  angular: { vendor: "google", product: "angular", eol: "angular" },
  php: { vendor: "php", product: "php", eol: "php" },
  nginx: { vendor: "nginx", product: "nginx", eol: "nginx" }
};

const SEV_SCORE = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };

function extractSeverity(cve) {
  return (
    cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity ||
    cve.metrics?.cvssMetricV30?.[0]?.cvssData?.baseSeverity ||
    cve.metrics?.cvssMetricV2?.[0]?.baseSeverity ||
    "UNKNOWN"
  );
}

function computeVerdict({ eolDate, latestSupported, inputVersion, cves }) {
  const now = new Date();
  const hasCritical = cves.some(c => c.severity === "CRITICAL");
  const hasHigh = cves.some(c => c.severity === "HIGH");

  if (eolDate && new Date(eolDate) < now) {
    if (hasCritical || hasHigh) {
      return { status: "OBSOLETA", risk: "ALTO" };
    }
    return { status: "FUERA DE SOPORTE", risk: "MEDIO" };
  }

  if (latestSupported && latestSupported !== inputVersion) {
    return { status: "DESACTUALIZADA", risk: hasCritical ? "ALTO" : "MEDIO" };
  }

  return { status: "SOPORTADA", risk: hasCritical ? "MEDIO" : "BAJO" };
}

export async function onRequest({ request, env }) {
  const url = new URL(request.url);
  const techRaw = url.searchParams.get("tech")?.toLowerCase().trim();
  const version = url.searchParams.get("version")?.trim();

  if (!techRaw || !version) {
    return Response.json({ error: "Missing parameters" }, { status: 400 });
  }

  const tech = TECH_CATALOG[techRaw];
  let cycles = [];
  let latest = null;
  let latestSupported = null;
  let eolDate = null;

  // ---------- EOL ----------
  if (tech?.eol) {
    try {
      const eolRes = await fetch(`https://endoflife.date/api/${tech.eol}.json`);
      cycles = await eolRes.json();
      latest = cycles[0]?.latest || null;

      const active = cycles.find(c => !c.eol || new Date(c.eol) > new Date());
      latestSupported = active?.latest || null;

      const matched = cycles.find(c => String(version).startsWith(String(c.cycle)));
      eolDate = matched?.eol || null;
    } catch {}
  }

  // ---------- CVEs ----------
  let cves = [];
  let coverage = "exact";

  try {
    let apiUrl;

    if (tech) {
      const cpe = `cpe:2.3:a:${tech.vendor}:${tech.product}:${version}:*:*:*:*:*:*:*`;
      apiUrl = `${NVD_API}?cpeName=${encodeURIComponent(cpe)}&resultsPerPage=100`;
    } else {
      // Fallback heurístico controlado
      coverage = "heuristic";
      apiUrl = `${NVD_API}?keywordSearch=${encodeURIComponent(`${techRaw} ${version}`)}&resultsPerPage=50`;
    }

    const res = await fetch(apiUrl, {
      headers: env.API_KEY ? { apiKey: env.API_KEY } : {}
    });

    const data = await res.json();

    cves = (data.vulnerabilities || []).map(v => {
      const cve = v.cve;
      return {
        id: cve.id,
        severity: extractSeverity(cve),
        description: cve.descriptions?.[0]?.value || "",
        url: `https://nvd.nist.gov/vuln/detail/${cve.id}`
      };
    });

  } catch {}

  cves.sort((a, b) => (SEV_SCORE[b.severity] || 0) - (SEV_SCORE[a.severity] || 0));

  const summary = {
    total: cves.length,
    CRITICAL: cves.filter(c => c.severity === "CRITICAL").length,
    HIGH: cves.filter(c => c.severity === "HIGH").length
  };

  const verdict = computeVerdict({
    eolDate,
    latestSupported,
    inputVersion: version,
    cves
  });

  return Response.json(
    {
      technology: techRaw,
      version,
      status: verdict.status,
      risk: verdict.risk,
      latest_version: latest,
      latest_supported_version: latestSupported,
      coverage,
      summary,
      cves,
      fuentes: [
        "https://endoflife.date",
        "https://nvd.nist.gov"
      ]
    },
    { headers: { "Cache-Control": "no-store" } }
  );
}
