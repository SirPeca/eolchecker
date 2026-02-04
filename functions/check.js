const CATALOG_UPDATE_DATE = "2026-02-03";

const CATALOG = {
  "jquery": ["jquery"],
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

function normalizeTechnology(input) {
  const value = input.toLowerCase().trim();
  for (const key in CATALOG) {
    if (CATALOG[key].includes(value)) return key;
  }
  return value;
}

function now() {
  return new Date();
}

export async function onRequest({ request }) {
  const url = new URL(request.url);
  const techRaw = url.searchParams.get("tec");
  const version = url.searchParams.get("ver");

  if (!techRaw || !version) {
    return json({ error: "Parámetros requeridos: tec, ver" }, 400);
  }

  const tech = normalizeTechnology(techRaw);

  let estado = "SOPORTE NO CONFIRMADO";
  let supportMessage =
    "No se encontró información oficial de soporte para esta tecnología en endoflife.date. " +
    "El estado de mantenimiento no puede confirmarse.";

  let latestSupportedVersion = "-";
  let cycleInfo = null;

  try {
    const eolRes = await fetch(
      `https://endoflife.date/api/${encodeURIComponent(tech)}.json`,
      { cf: { cacheTtl: 86400 } }
    );

    if (eolRes.ok) {
      const data = await eolRes.json();

      cycleInfo = data.find(c =>
        c.cycle && version.startsWith(String(c.cycle))
      );

      const supported = data.find(
        c => !c.eol || new Date(c.eol) > now()
      );

      latestSupportedVersion = supported?.latest || "-";

      if (cycleInfo?.eol) {
        if (new Date(cycleInfo.eol) < now()) {
          estado = "FUERA DE SOPORTE";
          supportMessage =
            `El soporte oficial finalizó el ${cycleInfo.eol}. Se recomienda actualizar.`;
        } else if (
          latestSupportedVersion !== "-" &&
          version !== latestSupportedVersion
        ) {
          estado = "DESACTUALIZADO";
          supportMessage =
            "La versión analizada tiene soporte, pero no es la última versión mantenida.";
        } else {
          estado = "CON SOPORTE";
          supportMessage =
            "La versión analizada se encuentra dentro del período de soporte.";
        }
      }
    }
  } catch {}

  // ================= CVEs (SIEMPRE) =================
  let cves = [];

  try {
    const res = await fetch(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(tech)}&resultsPerPage=200`
    );

    if (res.ok) {
      const json = await res.json();

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

  const summary = {
    total: cves.length,
    critical: cves.filter(c => c.severity === "CRITICAL").length,
    high: cves.filter(c => c.severity === "HIGH").length
  };

  return json({
    tecnologia: techRaw,
    version,
    estado,
    supportMessage,
    latestSupportedVersion,
    ciclo: cycleInfo,
    cves,
    resumen: summary,
    catalogUpdate: CATALOG_UPDATE_DATE
  });
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}
