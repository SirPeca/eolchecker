import semver from "semver";

const CATALOG_UPDATE_DATE = "2026-02-03";

const CATALOG = {
  jquery: ["jquery"],
  toastr: ["toastr"],
  bootstrap: ["bootstrap"],
  angular: ["angular"],
  react: ["react"],
  vue: ["vue", "vue.js"],
  openssl: ["openssl"]
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

function response(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}

/**
 * Determina si un CVE aplica a la versión
 * true  -> aplica
 * false -> no aplica
 * null  -> rango no especificado (riesgo potencial)
 */
function cveApplies(cpe, version) {
  if (!cpe.vulnerable) return false;

  const hasRange =
    cpe.versionStartIncluding ||
    cpe.versionStartExcluding ||
    cpe.versionEndIncluding ||
    cpe.versionEndExcluding;

  if (!hasRange) return null;

  let min = "0.0.0";
  let max = "9999.9999.9999";

  if (cpe.versionStartIncluding)
    min = cpe.versionStartIncluding;

  if (cpe.versionStartExcluding)
    min = semver.inc(cpe.versionStartExcluding, "patch");

  if (cpe.versionEndIncluding)
    max = cpe.versionEndIncluding;

  if (cpe.versionEndExcluding)
    max = semver.dec(cpe.versionEndExcluding);

  return semver.gte(version, min) && semver.lte(version, max);
}

// ================= HANDLER =================
export async function onRequest({ request }) {
  try {
    const url = new URL(request.url);
    const techRaw = url.searchParams.get("tec");
    const version = url.searchParams.get("ver");

    if (!techRaw || !version) {
      return response({ error: "Parámetros requeridos: tec, ver" }, 400);
    }

    const tech = normalizeTechnology(techRaw);

    // ---------- EOL ----------
    let estado = "SOPORTE NO CONFIRMADO";
    let latestSupportedVersion = "-";
    let ciclo = null;

    try {
      const eolRes = await fetch(
        `https://endoflife.date/api/${encodeURIComponent(tech)}.json`,
        { cf: { cacheTtl: 86400 } }
      );

      if (eolRes.ok) {
        const data = await eolRes.json();
        if (Array.isArray(data)) {
          ciclo = data.find(c => version.startsWith(String(c.cycle)));
          const supported = data.find(c => !c.eol || new Date(c.eol) > now());
          latestSupportedVersion = supported?.latest || "-";

          if (ciclo?.eol) {
            estado =
              new Date(ciclo.eol) < now()
                ? "FUERA DE SOPORTE"
                : "CON SOPORTE";
          }
        }
      }
    } catch {}

    // ---------- CVEs ----------
    let applicable = [];
    let potential = [];

    try {
      const cveRes = await fetch(
        `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(
          tech
        )}&resultsPerPage=200`
      );

      if (cveRes.ok) {
        const json = await cveRes.json();

        for (const v of json.vulnerabilities || []) {
          const cve = v.cve;
          const metrics = cve.metrics || {};
          const cvss =
            metrics.cvssMetricV31?.[0]?.cvssData ||
            metrics.cvssMetricV30?.[0]?.cvssData ||
            metrics.cvssMetricV2?.[0]?.cvssData;

          let applies = false;
          let unknown = false;

          for (const node of cve.configurations?.nodes || []) {
            for (const match of node.cpeMatch || []) {
              const res = cveApplies(match, version);
              if (res === true) applies = true;
              if (res === null) unknown = true;
            }
          }

          const item = {
            id: cve.id,
            severity: cvss?.baseSeverity || "UNKNOWN",
            score: cvss?.baseScore || null,
            url: `https://nvd.nist.gov/vuln/detail/${cve.id}`
          };

          if (applies) applicable.push(item);
          else if (unknown) potential.push(item);
        }
      }
    } catch {}

    // ---------- RESPUESTA ----------
    return response({
      tecnologia: techRaw,
      version,
      estado,
      ciclo,
      latestSupportedVersion,
      cves: {
        aplicables: applicable,
        riesgoPotencial: potential
      },
      resumen: {
        aplicables: applicable.length,
        riesgoPotencial: potential.length
      },
      fuentes: ["endoflife.date", "nvd.nist.gov"],
      catalogUpdate: CATALOG_UPDATE_DATE
    });

  } catch {
    return response({ error: "Error interno del servicio" }, 500);
  }
}
