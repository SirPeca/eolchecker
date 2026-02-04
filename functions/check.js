// ============================================================
// EOL & CVE Checker — Cloudflare Pages compatible
// ============================================================

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

// ---------- Version utils (sin librerías) ----------
function normalizeVersion(v) {
  return v.split(".").map(n => parseInt(n, 10) || 0);
}

function compareVersions(a, b) {
  const va = normalizeVersion(a);
  const vb = normalizeVersion(b);
  const len = Math.max(va.length, vb.length);

  for (let i = 0; i < len; i++) {
    const diff = (va[i] || 0) - (vb[i] || 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

function isBetween(version, min, max) {
  if (min && compareVersions(version, min) < 0) return false;
  if (max && compareVersions(version, max) > 0) return false;
  return true;
}

/**
 * true  -> CVE aplica
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

  let min = null;
  let max = null;

  if (cpe.versionStartIncluding) min = cpe.versionStartIncluding;
  if (cpe.versionStartExcluding) min = cpe.versionStartExcluding;
  if (cpe.versionEndIncluding) max = cpe.versionEndIncluding;
  if (cpe.versionEndExcluding) max = cpe.versionEndExcluding;

  return isBetween(version, min, max);
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
    let aplicables = [];
    let potenciales = [];

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

          if (applies) aplicables.push(item);
          else if (unknown) potenciales.push(item);
        }
      }
    } catch {}

    return response({
      tecnologia: techRaw,
      version,
      estado,
      ciclo,
      latestSupportedVersion,
      cves: {
        aplicables,
        riesgoPotencial: potenciales
      },
      resumen: {
        aplicables: aplicables.length,
        riesgoPotencial: potenciales.length
      },
      fuentes: ["endoflife.date", "nvd.nist.gov"],
      catalogUpdate: CATALOG_UPDATE_DATE
    });

  } catch {
    return response({ error: "Error interno del servicio" }, 500);
  }
}
