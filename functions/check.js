// ============================================================
// EOL & CVE Checker — API (Cloudflare Pages Functions)
// ============================================================

const CATALOG_UPDATE_DATE = "2026-02-03";

const CATALOG = {
  jquery: ["jquery"],
  toastr: ["toastr"],
  angular: ["angular"],
  react: ["react"],
  vue: ["vue", "vue.js"],
  bootstrap: ["bootstrap"],
  openssl: ["openssl"],
  "moment.js": ["moment", "moment.js"]
};

function normalizeTechnology(input) {
  const value = input.toLowerCase().trim();
  for (const key in CATALOG) {
    if (CATALOG[key].includes(value)) return key;
  }
  return value;
}

const now = () => new Date();

export async function onRequest({ request }) {
  try {
    const url = new URL(request.url);
    const techRaw = url.searchParams.get("tec");
    const version = url.searchParams.get("ver");

    if (!techRaw || !version) {
      return json({ error: "Parámetros requeridos: tec, ver" }, 400);
    }

    const tech = normalizeTechnology(techRaw);

    let estado = "SOPORTE NO CONFIRMADO";
    let latestVersion = "-";
    let latestSupportedVersion = "-";
    let ciclo = null;

    // ================= END OF LIFE =================
    try {
      const eolRes = await fetch(
        `https://endoflife.date/api/${encodeURIComponent(tech)}.json`,
        { cf: { cacheTtl: 86400 } }
      );

      if (eolRes.ok) {
        const data = await eolRes.json();

        if (Array.isArray(data)) {
          // Ciclo exacto (misma rama)
          ciclo = data.find(c =>
            c.cycle && version.startsWith(String(c.cycle))
          );

          // Última versión global
          const latestGlobal = data.find(c => c.latest);
          latestVersion = latestGlobal?.latest || "-";

          if (ciclo) {
            latestSupportedVersion = ciclo.latest || "-";

            if (ciclo.eol && new Date(ciclo.eol) < now()) {
              estado = "FUERA DE SOPORTE";
            } else {
              estado =
                version === latestSupportedVersion
                  ? "CON SOPORTE"
                  : "DESACTUALIZADO";
            }
          }
        }
      }
    } catch {
      // Estado queda en SOPORTE NO CONFIRMADO
    }

    // ================= CVEs =================
    let cves = [];

    try {
      const cveRes = await fetch(
        `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(
          tech
        )}&resultsPerPage=200`
      );

      if (cveRes.ok) {
        const json = await cveRes.json();

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

    const order = { CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 4, UNKNOWN: 5 };
    cves.sort((a, b) => order[a.severity] - order[b.severity]);

    const resumen = {
      total: cves.length,
      critical: cves.filter(c => c.severity === "CRITICAL").length,
      high: cves.filter(c => c.severity === "HIGH").length
    };

    return json({
      tecnologia: techRaw,
      version,
      estado,
      latestVersion,
      latestSupportedVersion,
      ciclo,
      cves,
      resumen,
      fuentes: ["endoflife.date", "nvd.nist.gov"],
      catalogUpdate: CATALOG_UPDATE_DATE
    });

  } catch {
    return json({ error: "Error interno del servicio" }, 500);
  }
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}
