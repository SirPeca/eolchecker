// app.js (frontend) — GitHub Pages only (sin backend)

const OSV_QUERY = "https://api.osv.dev/v1/query"; // docs: POST /v1/query [4](https://google.github.io/osv.dev/post-v1-query/)
const KEV_JSON  = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"; // repo KEV [5](https://github.com/cisagov/kev-data)
const NVD_BASE  = "https://services.nvd.nist.gov/rest/json/cves/2.0"; // apiKey por header en 2.0 [6](https://nvd.nist.gov/General/News/api-20-announcements)

// Cache local (en tu repo). Si existe, se usa para EOL/Support sin CORS.
const LOCAL_EOL_CACHE_PREFIX = "./eol-cache/";

// Alias / normalización de slugs (endoflife-date style)
const SLUG_MAP = {
  "node": "nodejs",
  "node.js": "nodejs",
  ".net": "dotnet",
  "dotnet": "dotnet",
  "asp.net": "dotnet",
};

// Heurística simple de ecosistema para OSV
const OSV_ECOSYSTEM_HINTS = {
  // JS libs típicas
  "jquery": "npm",
  "bootstrap": "npm",
  "lodash": "npm",
  "moment": "npm",
  "react": "npm",
  "angular": "npm",
  "vue": "npm",
  // runtimes
  "nodejs": "npm", // ojo: nodejs como runtime no es package npm; se usa best-effort
};

function $(id){ return document.getElementById(id); }

function esc(s){
  return String(s ?? "").replace(/[&<>"']/g, c => ({
    "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;"
  }[c]));
}

function stateBadgeClass(state){
  const s = (state || "").toLowerCase();
  if (s.includes("obsolete")) return "bad";
  if (s.includes("outdated")) return "warn";
  if (s.includes("uptodate")) return "ok";
  return "warn";
}

function classifyState({ supportKnown, isEol, inSupport, hasCve }){
  // Estados según el prompt que pegaste (best-effort)
  if (supportKnown && isEol && hasCve) return "obsolete with known vulnerabilities";
  if (supportKnown && isEol && !hasCve) return "obsolete without known vulnerabilities";
  if (supportKnown && inSupport && hasCve) return "outdated with known vulnerabilities";
  if (supportKnown && inSupport && !hasCve) return "outdated without known vulnerabilities";
  // “uptodate” requiere supported + sin CVE, pero como es best-effort lo dejamos como caso aparte
  if (supportKnown && inSupport && !hasCve) return "uptodate";
  return "unknown";
}

// ---- EOL (desde cache local) ----
async function fetchLocalEol(productSlug){
  const url = `${LOCAL_EOL_CACHE_PREFIX}${encodeURIComponent(productSlug)}.json`;
  const r = await fetch(url, { cache: "no-store" });
  if (!r.ok) return null;
  return await r.json();
}

function chooseCycleFromEolApi(cycles, version){
  // endoflife.date expone ciclos por “cycle” (ej: "3.6", "16", etc.)
  // Heurística: matchear por major o major.minor
  const v = String(version).trim();
  const parts = v.split(".");
  const major = parts[0] || v;
  const majorMinor = parts.length >= 2 ? `${parts[0]}.${parts[1]}` : major;

  // Prioriza major.minor exacto, luego major
  return (cycles || []).find(c => String(c.cycle) === majorMinor)
      || (cycles || []).find(c => String(c.cycle) === major)
      || null;
}

function computeSupportFromCycle(cycle){
  // Campos típicos en endoflife.date: eol (string o boolean), support (string/bool), security (string/bool), latest
  // (No inventamos: si no existe, queda null)
  let eol = null, supportUntil = null, latest = null;
  let isEol = false, inSupport = false;

  if (!cycle) return { eol, supportUntil, latest, isEol, inSupport };

  latest = cycle.latest ?? null;

  // eol puede ser true/false o string fecha
  if (cycle.eol === true) {
    isEol = true;
  } else if (typeof cycle.eol === "string") {
    eol = cycle.eol;
    isEol = (new Date(cycle.eol) < new Date());
  }

  // support/security podrían ser fechas (string)
  // tomamos el primero que tenga pinta de fecha
  const candidate = (typeof cycle.support === "string" ? cycle.support : null)
                 || (typeof cycle.security === "string" ? cycle.security : null);

  supportUntil = candidate;

  if (supportUntil) {
    inSupport = (new Date(supportUntil) > new Date());
  } else {
    // best-effort: si no está EOL, asumimos “en soporte” desconocido → true suave
    inSupport = !isEol;
  }

  return { eol, supportUntil, latest, isEol, inSupport };
}

// ---- CVE: OSV ----
async function queryOSV(productName, version){
  // OSV requiere ecosystem + name (o purl). Docs de POST /v1/query [4](https://google.github.io/osv.dev/post-v1-query/)
  const eco = OSV_ECOSYSTEM_HINTS[productName] || null;
  if (!eco) return { vulns: [], cves: [] };

  const payload = {
    package: { name: productName, ecosystem: eco },
    version: String(version).trim()
  };

  const r = await fetch(OSV_QUERY, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });

  if (!r.ok) return { vulns: [], cves: [] };

  const data = await r.json();
  const vulns = data.vulns || [];
  const cveSet = new Set();

  for (const v of vulns){
    for (const a of (v.aliases || [])){
      if (String(a).startsWith("CVE-")) cveSet.add(a);
    }
  }
  return { vulns, cves: [...cveSet] };
}

// ---- KEV cross-check ----
async function fetchKEV(){
  const r = await fetch(KEV_JSON, { cache: "no-store" });
  if (!r.ok) return null;
  return await r.json();
}

function kevHitsFromList(kevJson, cveList){
  if (!kevJson || !Array.isArray(cveList) || !cveList.length) return [];
  const items = kevJson.vulnerabilities || kevJson;
  const set = new Set((items || []).map(x => x.cveID || x.cveId || x.cve).filter(Boolean));
  return cveList.filter(id => set.has(id));
}

// ---- NVD (best-effort) ----
async function queryNVDKeyword(productName, version){
  // apiKey 2.0 va en header "apiKey" (si tuvieras una) [6](https://nvd.nist.gov/General/News/api-20-announcements)
  // Sin apiKey: best-effort (puede rate-limit o CORS del lado del navegador).
  const params = new URLSearchParams({
    keywordSearch: `${productName} ${version}`,
    noRejected: "true",
    resultsPerPage: "20"
  });

  const url = `${NVD_BASE}?${params.toString()}`;
  const r = await fetch(url, { cache: "no-store" });
  if (!r.ok) return [];

  const data = await r.json();
  const vulns = data.vulnerabilities || [];
  const out = [];

  for (const v of vulns){
    const cve = v.cve || {};
    if (cve.id) out.push({
      id: cve.id,
      url: `https://nvd.nist.gov/vuln/detail/${cve.id}`
    });
  }
  return out;
}

// ---- Perspectivas (alto nivel, sin “cómo explotar”) ----
function buildPerspectives(state, kevList){
  const red = [];
  const blue = [];

  red.push("Las técnicas MITRE ATT&CK aplicables dependen del tipo de CVE (p.ej., ejecución de código, inyección, XSS) y del contexto de exposición.");
  blue.push("Aplicar controles compensatorios: hardening, WAF/IDS, logging, detecciones y monitoreo de comportamiento asociado al tipo de vulnerabilidad.");

  if (kevList && kevList.length){
    red.push(`Priorizar escenarios por evidencia de explotación en el mundo real (KEV): ${kevList.join(", ")}`);
    blue.push(`Elevar prioridad SOC/IR para indicadores asociados (KEV): ${kevList.join(", ")}`);
  }
  return { red, blue };
}

// ---- Render ----
function renderReport(outEl, report){
  const badge = stateBadgeClass(report.Description?.state);
  const title = report.Title || "(sin título)";
  const state = report.Description?.state || "unknown";

  const support = report.Description?.support || {};
  const evidence = report["Evidence support"] || {};
  const cves = report["CVE code list"] || [];
  const kev = report["Known exploited (KEV)"] || [];

  outEl.innerHTML = `
    <div>
      <div style="font-size:1.15rem;font-weight:800;">
        ${esc(title)}
        <span class="badge ${badge}">${esc(state)}</span>
      </div>
    </div>

    <div class="section">
      <h3>Description</h3>
      <pre>${esc(
`State: ${state}
Support known: ${support.known}
EOL: ${support.eol ?? "N/A"}
Support until: ${support.supportUntil ?? "N/A"}
Latest: ${support.latest ?? "N/A"}
Notes: ${report.Description?.notes ?? ""}`
      )}</pre>
    </div>

    <div class="section">
      <h3>Evidence support</h3>
      <pre>${esc(JSON.stringify(evidence, null, 2))}</pre>
    </div>

    <div class="section">
      <h3>CVE code list</h3>
      ${cves.length ? `<ul>${cves.map(id => `<li>${esc(id)}${kev.includes(id) ? ` <span class="badge bad">KEV</span>` : ""}</li>`).join("")}</ul>`
      : `<pre>Sin CVEs detectados (best-effort).</pre>`}
    </div>

    <div class="section">
      <h3>Impact</h3>
      <pre>${esc(report.Impact || "")}</pre>
    </div>

    <div class="section">
      <h3>Recomendation</h3>
      <pre>${esc(report.Recomendation || "")}</pre>
    </div>

    <div class="section">
      <h3>Red team perspective</h3>
      <ul>${(report["Red team perspective"] || []).map(x => `<li>${esc(x)}</li>`).join("")}</ul>
    </div>

    <div class="section">
      <h3>Blue team perspective</h3>
      <ul>${(report["Blue team perspective"] || []).map(x => `<li>${esc(x)}</li>`).join("")}</ul>
    </div>

    <div class="section">
      <h3>Disclaimer</h3>
      <pre>${esc(report.Disclaimer || "")}</pre>
    </div>
  `;
}

function buildEvidence({ productSlug, usedLocalEolCache, nvdTried }){
  const evidence = {
    support: [],
    cve_sources: [
      "https://osv.dev",
      "https://api.osv.dev/v1/query",
      "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
      "https://services.nvd.nist.gov/rest/json/cves/2.0"
    ],
    kev_data: [KEV_JSON]
  };

  if (usedLocalEolCache){
    evidence.support.push(`${LOCAL_EOL_CACHE_PREFIX}${productSlug}.json (cache local del repo)`);
  } else {
    evidence.support.push("Support/EOL: no disponible en cache local (best-effort).");
  }

  evidence.nvd_attempted = Boolean(nvdTried);
  return evidence;
}

async function analyze(){
  const techRaw = $("tech").value.trim();
  const verRaw  = $("version").value.trim();
  const out = $("output");
  const btn = $("btn");

  out.innerHTML = "";
  if (!techRaw || !verRaw){
    out.innerHTML = `<pre>Faltan datos. Ingresá tecnología y versión.</pre>`;
    return;
  }

  btn.disabled = true;
  out.innerHTML = `<pre>Consultando… (best-effort)</pre>`;

  const productKey = techRaw.toLowerCase();
  const productSlug = (SLUG_MAP[productKey] || productKey);

  // 1) Support/EOL desde cache local (si existe)
  let supportKnown = false;
  let cycle = null;
  let eolCycles = null;
  let usedLocalEolCache = false;

  try {
    eolCycles = await fetchLocalEol(productSlug);
    if (Array.isArray(eolCycles)) {
      usedLocalEolCache = true;
      supportKnown = true;
      cycle = chooseCycleFromEolApi(eolCycles, verRaw);
    }
  } catch(_) {}

  const supportComputed = computeSupportFromCycle(cycle);

  // 2) OSV
  let osv = { vulns: [], cves: [] };
  try {
    osv = await queryOSV(productKey, verRaw);
  } catch(_) {}

  // 3) KEV
  let kevHits = [];
  try {
    const kevJson = await fetchKEV();
    kevHits = kevHitsFromList(kevJson, osv.cves);
  } catch(_) {}

  // 4) NVD best-effort
  let nvdLinks = [];
  let nvdTried = false;
  try {
    nvdTried = true;
    nvdLinks = await queryNVDKeyword(productKey, verRaw);
  } catch(_) {
    nvdLinks = [];
  }

  // Consolidación CVEs (OSV primero; NVD aporta links si trae ids)
  const cveSet = new Set(osv.cves);
  for (const x of nvdLinks) if (x?.id) cveSet.add(x.id);
  const cveList = [...cveSet];

  const hasCve = cveList.length > 0;
  const state = classifyState({
    supportKnown,
    isEol: supportComputed.isEol,
    inSupport: supportComputed.inSupport,
    hasCve
  });

  const title = `${techRaw}, ${verRaw}, ${state}`;

  const impact = hasCve
    ? "La versión presenta vulnerabilidades públicas que podrían ser explotables dependiendo del contexto (exposición, configuraciones, controles compensatorios)."
    : "No se encontraron CVEs públicos asociados (esto no garantiza ausencia de riesgo; pueden existir fallas no publicadas o no correlacionadas por versión).";

  const recomendation = (state.includes("obsolete") || state.includes("outdated"))
    ? "Actualizar a una versión soportada por el proveedor (o la última estable disponible) y validar compatibilidad. Priorizar si hay KEV."
    : "Mantener la versión, monitorear nuevas vulnerabilidades/cambios de soporte y aplicar controles compensatorios según exposición.";

  const { red, blue } = buildPerspectives(state, kevHits);

  const report = {
    Title: title,
    Description: {
      state,
      support: {
        known: supportKnown,
        eol: supportComputed.eol,
        supportUntil: supportComputed.supportUntil,
        latest: supportComputed.latest
      },
      notes: supportKnown
        ? "Soporte/EOL obtenido desde cache local del repo (best-effort por ciclo)."
        : "No se encontró cache local para soporte/EOL (best-effort)."
    },
    "Evidence support": {
      ...buildEvidence({ productSlug, usedLocalEolCache, nvdTried }),
      nvd_results: nvdLinks.slice(0, 10),
      osv_summary: {
        ecosystem_used: OSV_ECOSYSTEM_HINTS[productKey] || null,
        vulns_found: (osv.vulns || []).length
      }
    },
    "CVE code list": cveList,
    "Known exploited (KEV)": kevHits,
    Impact: impact,
    Recomendation: recomendation,
    "Red team perspective": red,
    "Blue team perspective": blue,
    Disclaimer: "Remember the information generated may be incorrect, manually check each reference or link to ensure the truthfulness of the answer"
  };

  renderReport(out, report);
  btn.disabled = false;
}

window.addEventListener("DOMContentLoaded", () => {
  $("btn").addEventListener("click", analyze);
  $("version").addEventListener("keydown", (e) => {
    if (e.key === "Enter") analyze();
  });
  $("tech").addEventListener("keydown", (e) => {
    if (e.key === "Enter") analyze();
  });
});
