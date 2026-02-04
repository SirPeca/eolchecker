// ============================================================
// EOL & CVE Checker — API
// Evaluación profesional de soporte y vulnerabilidades
// ============================================================

// --- Catálogo de normalización (solo identificación) ---
const CATALOG_UPDATE_DATE = "2026-02-03";

const CATALOG = {
  "jquery": ["jquery"],
  "jquery ui": ["jquery ui"],
  "bootstrap": ["bootstrap"],
  "openssl": ["openssl"],
  "vue": ["vue", "vue.js"],
  "react": ["react"],
  "angular": ["angular"],
  "moment.js": ["moment", "moment.js"],
  "toastr": ["toastr"],
  "select2": ["select2"],
  "core-js": ["core-js"]
};

// --- Utilidades ---
function normalizeTechnology(input) {
  const value = input.toLowerCase().trim();
  for (const key in CATALOG) {
    if (CATALOG[key].includes(value)) {
      return key;
    }
  }
  return value;
}

function now() {
  return new Date();
}

// --- Handler principal ---
export async function onRequest({ request }) {
  try {
    const url = new URL(request.url);
    const techRaw = url.searchParams.get("tec");
    const version = url.searchParams.get("ver");

    if (!techRaw || !version) {
      return response(
        { error: "Parámetros requeridos: tec, ver" },
        400
      );
    }

    const tech = normalizeTechnology(techRaw);

    let status = "DESCONOCIDO";
    let latestVersion = "-";
    let latestSupportedVersion = "-";
    let cycleInfo = null;

    // ================= END OF LIFE =================
    try {
      const eolResponse = await fetch(
        `https://endoflife.date/api/${encodeURIComponent(tech)}.json`,
        { cf: { cacheTtl: 86400 } }
      );

      if (eolResponse.ok) {
        const data = await eolResponse.json();

        if (Array.isArray(data)) {
          cycleInfo = data.find(
            c => c.cycle && version.startsWith(String(c.cycle))
          );

          const supportedCycle = data.find(
            c => !c.eol || new Date(c.eol) > now()
          );

          const latestEntry = data.find(c => c.latest);

          latestVersion = latestEntry?.latest || "-";
          latestSupportedVersion = supportedCycle?.latest || "-";

          if (cycleInfo?.eol) {
            status =
              new Date(cycleInfo.eol) < now()
                ? "FUERA DE SOPORTE"
                : "CON SOPORTE";
          }

          if (
            status === "CON SOPORTE" &&
            latestSupportedVersion !== "-" &&
            version !== latestSupportedVersion
          ) {
            status = "DESACTUALIZADO";
          }
        }
      }
    } catch {
      // Se mantiene estado DESCONOCIDO
    }

    // ================= CVEs =================
    let cves = [];

    try {
      const cveResponse = await fetch(
        `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(
          tech
        )}&resultsPerPage=200`
      );

      if (cveResponse.ok) {
        const json = await cveResponse.json();

        cves = (json.vulnerabilities || []).map(v => {
          const cve = v.cve;
          const metrics = cve.metrics || {};
          const cvss =
            metrics.cvssMetricV31?.[0]?.cvssData ||
            metrics.cvssMetricV30?.[0]?.cvssData ||
            metrics.cvssMetricV2?.[0]?.cvssData;

          return {
            id: cve.id,
            severity: cvss?.baseSeverity || "UNKNOWN",
            score: cvss?.baseScore || null,
            published: cve.published,
            url: `https://nvd.nist.gov/vuln/detail/${cve.id}`
          };
        });
      }
    } catch {}

    // ================= Orden y resumen =================
    const severityOrder = {
      CRITICAL: 1,
      HIGH: 2,
      MEDIUM: 3,
      LOW: 4,
      UNKNOWN: 5
    };

    cves.sort(
      (a, b) => severityOrder[a.severity] - severityOrder[b.severity]
    );

    const summary = {
      total: cves.length,
      critical: cves.filter(c => c.severity === "CRITICAL").length,
      high: cves.filter(c => c.severity === "HIGH").length
    };

    // ================= Respuesta =================
    return response({
      tecnologia: techRaw,
      version,
      estado: status,
      latestVersion,
      latestSupportedVersion,
      ciclo: cycleInfo,
      cves,
      resumen: summary,
      fuentes: ["endoflife.date", "nvd.nist.gov"],
      catalogUpdate: CATALOG_UPDATE_DATE
    });

  } catch (err) {
    return response(
      { error: "Error interno del servicio" },
      500
    );
  }
}

// --- Helper response ---
function response(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}
