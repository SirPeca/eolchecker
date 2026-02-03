// ======================= CATALOGO (IDENTIFICACION בלבד) =======================
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

// ======================= UTILS =======================
function normalizeTech(input) {
  const t = input.toLowerCase().trim();
  for (const key in CATALOG) {
    if (CATALOG[key].includes(t)) return key;
  }
  return t; // fallback libre
}

function today() {
  return new Date();
}

// ======================= WORKER =======================
export async function onRequest({ request }) {
  try {
    const url = new URL(request.url);
    const techRaw = url.searchParams.get("tec");
    const version = url.searchParams.get("ver");

    if (!techRaw || !version) {
      return json({ error: "Parámetros requeridos: tec, ver" }, 400);
    }

    const techNormalized = normalizeTech(techRaw);

    // ======================= ESTADO =======================
    let status = "DESCONOCIDO";
    let latest = "-";
    let latestSupported = "-";
    let cycle = null;

    // ======================= END OF LIFE =======================
    try {
      const eolRes = await fetch(
        `https://endoflife.date/api/${encodeURIComponent(techNormalized)}.json`,
        { cf: { cacheTtl: 86400 } }
      );

      if (eolRes.ok) {
        const data = await eolRes.json();

        if (Array.isArray(data)) {
          cycle = data.find(c => c.cycle && version.startsWith(String(c.cycle)));

          const supported = data.find(
            c => !c.eol || new Date(c.eol) > today()
          );

          const latestEntry = data.find(c => c.latest);

          latest = latestEntry?.latest || "-";
          latestSupported = supported?.latest || "-";

          if (cycle?.eol) {
            status =
              new Date(cycle.eol) < today()
                ? "FUERA DE SOPORTE"
                : "CON SOPORTE";
          }

          if (
            status === "CON SOPORTE" &&
            latestSupported !== "-" &&
            version !== latestSupported
          ) {
            status = "DESACTUALIZADO";
          }
        }
      }
    } catch {
      // silencioso a propósito
    }

    // ======================= CVEs =======================
    let cves = [];
    try {
      const cveRes = await fetch(
        `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(
          techNormalized
        )}&resultsPerPage=200`
      );

      if (cveRes.ok) {
        const jsonCve = await cveRes.json();

        cves = (jsonCve.vulnerabilities || []).map(v => {
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

    // ======================= ORDEN Y RESUMEN =======================
    const order = { CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 4, UNKNOWN: 5 };
    cves.sort((a, b) => order[a.severity] - order[b.severity]);

    const summary = {
      total: cves.length,
      critical: cves.filter(c => c.severity === "CRITICAL").length,
      high: cves.filter(c => c.severity === "HIGH").length
    };

    // ======================= RESPONSE =======================
    return json({
      tecnologia: techRaw,
      version,
      estado: status,
      latestVersion: latest,
      latestSupportedVersion: latestSupported,
      ciclo: cycle,
      cves,
      resumen: summary,
      fuentes: ["endoflife.date", "nvd.nist.gov"],
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
