// ======================= CATALOGO DE TECNOLOGIAS =======================
const CATALOG_UPDATE_DATE = "2026-02-03";

const CATALOG = {
  "jquery": true,
  "jquery ui": true,
  "jquery blockui": true,
  "bootstrap": true,
  "angular": true,
  "react": true,
  "vue": true,
  "openssl": true,
  "php": true,
  "node.js": true
  // el resto lo podés seguir agregando
};

// ======================= WORKER =======================
export async function onRequest({ request }) {
  try {
    const url = new URL(request.url);
    const techRaw = url.searchParams.get("tec");
    const versionRaw = url.searchParams.get("ver");

    if (!techRaw || !versionRaw) {
      return json({ error: "Parámetros requeridos: tec, ver" }, 400);
    }

    const tech = techRaw.trim().toLowerCase();
    const version = versionRaw.trim();

    let status = "DESCONOCIDO";
    let latest = "-";
    let latestSupported = "-";
    let cycle = null;

    // ======================= END OF LIFE =======================
    try {
      const eolRes = await fetch(`https://endoflife.date/api/${encodeURIComponent(tech)}.json`);
      if (eolRes.ok) {
        const eolData = await eolRes.json();

        if (Array.isArray(eolData)) {
          cycle = eolData.find(c => c.cycle && version.startsWith(String(c.cycle)));

          const supported = eolData.find(c => !c.eol || new Date(c.eol) > new Date());
          const latestEntry = eolData.find(c => c.latest);

          latest = latestEntry?.latest || "-";
          latestSupported = supported?.latest || "-";

          if (cycle?.eol) {
            status = new Date(cycle.eol) < new Date()
              ? "FUERA DE SOPORTE"
              : "CON SOPORTE";
          }

          if (status === "CON SOPORTE" && latestSupported !== "-" && version !== latestSupported) {
            status = "DESACTUALIZADO";
          }
        }
      }
    } catch {}

    // ======================= CVEs =======================
    let cves = [];
    try {
      const cveRes = await fetch(
        `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(tech)}&resultsPerPage=200`
      );
      if (cveRes.ok) {
        const cveJson = await cveRes.json();
        cves = (cveJson.vulnerabilities || [])
          .map(v => {
            const cve = v.cve;
            const metrics = cve.metrics || {};
            const score =
              metrics.cvssMetricV31?.[0]?.cvssData ||
              metrics.cvssMetricV30?.[0]?.cvssData ||
              metrics.cvssMetricV2?.[0]?.cvssData;

            return {
              id: cve.id,
              severity: score?.baseSeverity || "UNKNOWN",
              score: score?.baseScore || null,
              published: cve.published,
              url: `https://nvd.nist.gov/vuln/detail/${cve.id}`
            };
          });
      }
    } catch {}

    return json({
      tecnologia: techRaw,
      version,
      estado: status,
      latestVersion: latest,
      latestSupportedVersion: latestSupported,
      ciclo: cycle,
      cves,
      catalogUpdate: CATALOG_UPDATE_DATE
    });

  } catch (e) {
    return json({ error: "Error interno", detail: e.message }, 500);
  }
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}
