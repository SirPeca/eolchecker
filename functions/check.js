// check.js  (Cloudflare Pages Function style)
// Ruta sugerida en Pages: /functions/check.js => /api/check
// Si tu plataforma usa /api/* automáticamente, mantenelo así.

const EOL_BASE = "https://endoflife.date/api"; // /api/{product}.json  [7](https://deepwiki.com/endoflife-date/endoflife.date/6-api-and-data-access)
const NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"; // [4](https://nvd.nist.gov/developers/vulnerabilities)
const OSV_QUERY = "https://api.osv.dev/v1/query"; // [9](https://google.github.io/osv.dev/post-v1-query/)
const KEV_JSON = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"; // [11](https://github.com/cisagov/kev-data)

const SLUG_MAP = {
  "node": "nodejs",
  "node.js": "nodejs",
  ".net": "dotnet",
  "dotnet": "dotnet",
};

const OSV_ECOSYSTEM_HINTS = {
  // para tu caso (libs web típicas) es razonable arrancar con npm
  // si después querés, lo ampliamos a PyPI/Maven/NuGet por heurística.
  "jquery": "npm",
  "bootstrap": "npm",
  "datatables": "npm",
  "core-js": "npm",
  "lodash": "npm",
  "moment": "npm",
  "toastr": "npm",
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET,OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    },
  });
}

function pickBestCvss(metrics = {}) {
  const m31 = metrics.cvssMetricV31?.[0]?.cvssData;
  const m30 = metrics.cvssMetricV30?.[0]?.cvssData;
  const m2  = metrics.cvssMetricV2?.[0]?.cvssData;
  return m31 || m30 || m2 || null;
}

function normalizeVersion(v) {
  return String(v || "").trim();
}

async function safeFetchJson(url, init) {
  const r = await fetch(url, init);
  if (!r.ok) throw new Error(`${r.status} ${r.statusText} - ${url}`);
  return await r.json();
}

function chooseCycle(cycles, version) {
  const maj = String(version).split(".")[0];
  return cycles.find(c => String(c.cycle).startsWith(maj));
}

function classify({ supportedKnown, inSupport, isEol, hasCve }) {
  // Estados según tu spec (y el prompt de tu amigo)
  if (supportedKnown && isEol && hasCve) return "obsolete with known vulnerabilities";
  if (supportedKnown && isEol && !hasCve) return "obsolete without known vulnerabilities";
  if (supportedKnown && inSupport && hasCve) return "outdated with known vulnerabilities";
  if (supportedKnown && inSupport && !hasCve) return "outdated without known vulnerabilities";
  if (supportedKnown && inSupport && !hasCve) return "uptodate";
  return "unknown";
}

function buildPerspectives(state, kevHits) {
  // Sin inventar pasos ofensivos: lo dejamos a nivel conceptual, alineado a MITRE.
  const red = [
    "Posibles técnicas MITRE ATT&CK dependen del CVE y del tipo de componente (p.ej., ejecución remota, XSS, deserialización).",
    "Si existe KEV, priorizar escenarios donde haya explotación en el mundo real."
  ];

  const blue = [
    "Medidas defensivas típicas incluyen hardening, WAF/IDS, monitoreo de logs, y detección de patrones de explotación asociados al CVE.",
    "Si existe KEV, elevar prioridad de detección y contención (alerting + playbooks)."
  ];

  if (kevHits?.length) {
    red.push(`KEV presente: ${kevHits.join(", ")}`);
    blue.push(`KEV presente: ${kevHits.join(", ")}`);
  }
  return { red, blue };
}

export async function onRequest(context) {
  const req = context.request;

  if (req.method === "OPTIONS") return json({ ok: true });
  if (req.method !== "GET") return json({ error: "Method not allowed" }, 405);

  const url = new URL(req.url);
  const productRaw = (url.searchParams.get("product") || "").trim();
  const versionRaw = (url.searchParams.get("version") || "").trim();

  if (!productRaw || !versionRaw) {
    return json({ error: "Parámetros requeridos: product, version" }, 400);
  }

  const product = productRaw.toLowerCase();
  const version = normalizeVersion(versionRaw);

  const nvdKey = context.env?.NVD_API_KEY || ""; // NO en front
  const slug = SLUG_MAP[product] || product;

  // 1) Soporte/EOL (best-effort via endoflife.date)
  let eol = null, supportUntil = null, latest = null, supportedKnown = false, inSupport = false, isEol = false;
  let eolEvidenceUrl = `${EOL_BASE}/${encodeURIComponent(slug)}.json`;

  try {
    const cycles = await safeFetchJson(eolEvidenceUrl);
    supportedKnown = true;
    const cycle = chooseCycle(cycles, version);
    if (cycle) {
      latest = cycle.latest || null;
      // endoflife.date puede tener eol boolean o string
      if (cycle.eol === true) {
        isEol = true;
      } else if (typeof cycle.eol === "string") {
        eol = cycle.eol;
        isEol = new Date(cycle.eol) < new Date();
      }
      // support/security/lts: tomamos el primero disponible como “hasta cuándo”
      supportUntil = cycle.support || cycle.security || (typeof cycle.lts === "string" ? cycle.lts : null);
      if (supportUntil) inSupport = new Date(supportUntil) > new Date();
      else if (!isEol) inSupport = true; // best-effort
    }
  } catch (_) {
    supportedKnown = false; // no existe slug o fallo
  }

  // 2) CVEs: OSV (si podemos inferir ecosistema)
  let osvVulns = [];
  let cveIds = new Set();

  try {
    const eco = OSV_ECOSYSTEM_HINTS[product]; // por ahora npm para libs típicas
    if (eco) {
      const payload = {
        package: { name: product, ecosystem: eco },
        version
      };
      const osv = await safeFetchJson(OSV_QUERY, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      osvVulns = osv.vulns || [];
      for (const v of osvVulns) {
        const aliases = v.aliases || [];
        for (const a of aliases) if (String(a).startsWith("CVE-")) cveIds.add(a);
      }
    }
  } catch (_) {}

  // 3) CVEs: NVD (complemento) - keywordSearch (best-effort)
  let nvdCves = [];
  try {
    const params = new URLSearchParams({
      keywordSearch: `${product} ${version}`,
      noRejected: "true",
      resultsPerPage: "25",
    });

    const headers = {};
    if (nvdKey) headers["apiKey"] = nvdKey; // NVD soporta apiKey header [4](https://nvd.nist.gov/developers/vulnerabilities)

    const nvd = await safeFetchJson(`${NVD_BASE}?${params.toString()}`, { headers });
    const vulns = nvd.vulnerabilities || [];
    nvdCves = vulns.map(v => {
      const cve = v.cve || {};
      const cvss = pickBestCvss(cve.metrics || {});
      const desc = (cve.descriptions || []).find(d => d.lang === "en")?.value
                || (cve.descriptions || [])[0]?.value
                || "";
      return {
        id: cve.id,
        cvss: cvss?.baseScore ?? null,
        severity: cvss?.baseSeverity ?? null,
        summary: desc,
        url: cve.id ? `https://nvd.nist.gov/vuln/detail/${cve.id}` : null
      };
    }).filter(x => x.id);

    for (const c of nvdCves) cveIds.add(c.id);
  } catch (_) {}

  const cveList = Array.from(cveIds);

  // 4) KEV cross-check
  let kevHits = [];
  try {
    if (cveList.length) {
      const kev = await safeFetchJson(KEV_JSON);
      const kevItems = kev.vulnerabilities || kev; // según formato
      const kevSet = new Set((kevItems || []).map(x => x.cveID || x.cveId || x.cve));
      kevHits = cveList.filter(id => kevSet.has(id));
    }
  } catch (_) {}

  // 5) Clasificación final
  const hasCve = cveList.length > 0;
  const state = classify({ supportedKnown, inSupport, isEol, hasCve });
  const title = `${productRaw}, ${versionRaw}, ${state}`;

  // 6) Salida en tu formato
  const evidence = {
    support: supportedKnown ? [eolEvidenceUrl] : [],
    cve_sources: [
      "https://nvd.nist.gov/developers/vulnerabilities",
      "https://osv.dev",
      "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
    ],
    kev_data: [KEV_JSON]
  };

  const { red, blue } = buildPerspectives(state, kevHits);

  const recommendation = (
    state.includes("obsolete") || state.includes("outdated")
      ? "Actualizar a una versión soportada por el proveedor (o la última estable disponible) y validar compatibilidad."
      : "Mantener la versión y monitorear nuevas vulnerabilidades y cambios de soporte."
  );

  const impact = (
    hasCve
      ? "La versión presenta vulnerabilidades públicas que podrían ser explotables dependiendo del contexto (exposición, configuraciones, controles compensatorios)."
      : "No se encontraron CVEs públicos asociados (esto no garantiza ausencia de riesgo; puede haber fallas no publicadas)."
  );

  return json({
    Title: title, // *no mostrar “Title:” en UI si no querés, pero acá va el dato
    Description: {
      state,
      support: {
        known: supportedKnown,
        eol,
        supportUntil,
        latest
      },
      notes: supportedKnown ? "Estado obtenido de endoflife.date (best-effort por ciclo)." : "No se pudo determinar soporte/EOL con endoflife.date para esta tecnología."
    },
    "Evidence support": evidence,
    "CVE code list": cveList,
    "Known exploited (KEV)": kevHits,
    Impact: impact,
    Recomendation: recommendation,
    "Red team perspective": red,
    "Blue team perspective": blue,
    Disclaimer: "Remember the information generated may be incorrect, manually check each reference or link to ensure the truthfulness of the answer"
  });
}
