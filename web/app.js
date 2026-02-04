/* EOL & CVE Checker — v2 (determinista)
 * Sin dependencias. Cumple reglas de CPE/CVE y EOL (incluye política latest-only).
 * Fuentes públicas:
 *  - endoflife.date (API v1 por producto) → https://endoflife.date/jquery  [1](https://endoflife.date/jquery)
 *  - Política jQuery (solo última de ciclo soportada) → https://jquery.com/support/  [2](https://jquery.com/support/)
 */

// ------------------------------ Utilitarios ------------------------------
const $ = (sel) => document.querySelector(sel);
const todayISO = () => new Date().toISOString().slice(0,10);

function semverParse(v){
  // Acepta "x.y.z" (ignora sufijos -rc, -beta, etc.)
  const clean = String(v).trim().replace(/^v/i,'').split('-')[0];
  const [maj, min, pat] = clean.split('.').map(n => parseInt(n,10) || 0);
  return {maj, min, pat, raw: v};
}
function semverCmp(a,b){
  const A = semverParse(a), B = semverParse(b);
  if (A.maj!==B.maj) return A.maj-B.maj;
  if (A.min!==B.min) return A.min-B.min;
  return A.pat-B.pat;
}
function inRange(version, startIncl, startExcl, endIncl, endExcl){
  // Solo una de startIncl/startExcl y una de endIncl/endExcl debería venir seteada según NVD.
  const cmpStart = (s, incl) => s ? (incl ? semverCmp(version,s) >= 0 : semverCmp(version,s) > 0) : true;
  const cmpEnd   = (e, incl) => e ? (incl ? semverCmp(version,e) <= 0 : semverCmp(version,e) < 0) : true;
  return cmpStart(startIncl, true) && cmpStart(startExcl, false)
      && cmpEnd(endIncl, true) && cmpEnd(endExcl, false);
}
function isoDateLE(aISO, bISO){ return new Date(aISO) <= new Date(bISO); }
function isoDateGT(aISO, bISO){ return new Date(aISO) >  new Date(bISO); }

// ------------------------------ Política latest-only ------------------------------
// Lista blanca de productos cuyo soporte público declara "solo la última del ciclo".
// Clave: slug endoflife.date o product CPE (minúsculas).
const LATEST_ONLY = new Set(["jquery"]);

// ------------------------------ endoflife.date ------------------------------
async function fetchEOL(slug){
  // Devuelve { releases:[{version, eol?}], ok }
  const res = await fetch(`https://endoflife.date/api/v1/products/${encodeURIComponent(slug)}/`, {mode:"cors"});
  if (!res.ok) return {ok:false, releases:[]};
  const data = await res.json();
  // API v1 entrega {releases:[{cycle?, latest?, eol?}], ...} dependiendo del producto.
  const releases = Array.isArray(data.releases) ? data.releases : (Array.isArray(data) ? data : []);
  // Normalizamos: version = release.cycle o release.latest o release.release? según producto.
  const norm = releases.map(r => {
    const version = r.version || r.cycle || r.latest || r.release || r.lts || r.codename || "";
    return { version: String(version || "").trim(), eol: r.eol ?? null };
  }).filter(r => r.version);
  return {ok:true, releases: norm};
}

function resolveSupportByPolicy(version, releases, slug){
  // 1) Intentar encontrar exactamente la versión en releases con eol explícito.
  const exact = releases.find(r => r.version === version);
  if (exact && (typeof exact.eol === "string")) {
    return isoDateGT(exact.eol, todayISO()) ? "supported" : "eol";
  }
  if (exact && (exact.eol === true)) return "eol";
  if (exact && (exact.eol === null || exact.eol === undefined)) return "supported"; // "inexistente" según regla

  // 2) Si no hay entrada por versión menor y el producto es latest-only, aplicar herencia de ciclo.
  const productKey = (slug || "").toLowerCase();
  if (LATEST_ONLY.has(productKey)) {
    const target = semverParse(version);
    // Candidatos del mismo major:
    const sameMajor = releases
      .map(r => r.version)
      .filter(v => semverParse(v).maj === target.maj)
      .sort((a,b)=> semverCmp(a,b));
    if (sameMajor.length === 0) return "unknown";
    const latestOfMajor = sameMajor[sameMajor.length-1];
    if (semverCmp(version, latestOfMajor) === 0) {
      // Es la última del major → soportada, salvo que exista un release con eol=true/fecha<=hoy que lo contradiga
      const rec = releases.find(r => r.version === latestOfMajor);
      if (rec && rec.eol) {
        if (rec.eol === true) return "eol";
        if (typeof rec.eol === "string" && isoDateLE(rec.eol, todayISO())) return "eol";
      }
      return "supported";
    } else {
      return "eol";
    }
  }

  // 3) Sin política aplicable y sin entrada explícita -> desconocido
  return "unknown";
}

// ------------------------------ NVD (CPE → CVEs) ------------------------------
async function fetchCVEsByCPE(vendor, product, apiKey){
  // NVD v2: https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=...
  // Filtramos después por rangos STRICTOS y por coincidencia EXACTA de cpe:2.3:a:vendor:product
  const baseCPE = `cpe:2.3:a:${vendor}:${product}`;
  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=${encodeURIComponent(baseCPE)}&noRejected`;
  const headers = apiKey ? { "apiKey": apiKey } : undefined;

  let data;
  try{
    const res = await fetch(url, { headers, mode:"cors" });
    if (!res.ok) throw new Error(`NVD ${res.status}`);
    data = await res.json();
  }catch(e){
    // Fallo NVD (CORS, rate, red) → sin CVEs (preferir omitir antes que errar)
    return {baseCPE, cves:[], degraded:true};
  }

  const items = Array.isArray(data.vulnerabilities) ? data.vulnerabilities : [];
  return { baseCPE, cves: items, degraded:false };
}

function cvesApplicableStrict(cves, vendor, product, version){
  const v = version;
  const baseCPE = `cpe:2.3:a:${vendor}:${product}`;
  const out = [];

  for (const item of cves){
    const cve = item.cve;
    const configs = cve.configurations || [];
    let applies = false;

    // Inspeccionar nodos de configuración (árbol lógico AND/OR).
    const checkNode = (node) => {
      // Revisar cpeMatch (si existe)
      if (Array.isArray(node.cpeMatch)) {
        for (const m of node.cpeMatch){
          const name = (m.criteria || m.cpeName || "").toLowerCase();
          if (!name.startsWith(baseCPE)) continue; // CPE debe coincidir exactamente en vendor/product
          // Extraer límites de versión si existen
          const sI = m.versionStartIncluding, sE = m.versionStartExcluding;
          const eI = m.versionEndIncluding,   eE = m.versionEndExcluding;
          if (!sI && !sE && !eI && !eE) {
            applies = true; // sin rangos => aplica a todas
          } else if (inRange(v, sI, sE, eI, eE)) {
            applies = true;
          }
        }
      }
      // Recursión en children
      if (Array.isArray(node.nodes)) {
        for (const ch of node.nodes) checkNode(ch);
      }
    };

    for (const cfg of configs) checkNode(cfg);

    if (applies){
      // Preparar salida mínima (solo si categoría D lo requiere)
      const id = cve.id;
      const metrics = cve.metrics || {};
      const v31 = Array.isArray(metrics.cvssMetricV31) ? metrics.cvssMetricV31[0] : null;
      const cvss = v31 ? v31.cvssData.baseScore : null;
      const descArr = (cve.descriptions || []).filter(d => d.lang === "en" || d.lang === "es");
      const desc = descArr.length ? descArr[0].value : "Sin descripción disponible.";
      out.push({ id, cvss, desc });
    }
  }
  return out;
}

// ------------------------------ Clasificación ------------------------------
function classify(supportState, hasNewer, cves){
  const hasCVEs = cves.length > 0;
  if (supportState === "supported") {
    return {cat:"A", msg:"La versión se encuentra bajo soporte de seguridad", tone:"ok"};
  }
  if (supportState === "eol" && !hasCVEs && hasNewer) {
    return {cat:"B", msg:"La versión está desactualizada, pero no presenta vulnerabilidades conocidas", tone:"warn"};
  }
  if (supportState === "eol" && !hasCVEs) {
    return {cat:"C", msg:"La versión está fuera de soporte, aunque no se registran vulnerabilidades conocidas", tone:"no"};
  }
  if (supportState === "eol" && hasCVEs) {
    return {cat:"D", msg:"La versión está fuera de soporte y presenta vulnerabilidades conocidas", tone:"no"};
  }
  return {cat:"?", msg:"No se pudo determinar el estado exacto de esta versión con la información pública disponible.", tone:"warn"};
}

// ------------------------------ UI Lógica ------------------------------
$("#checker-form").addEventListener("input", () => {
  const vendor = $("#vendor").value.trim();
  const product= $("#product").value.trim();
  $("#cpePreview").textContent = `cpe:2.3:a:${vendor || "<vendor>"}:${product || "<product>"}`;
});

$("#btnTest").addEventListener("click", async (e)=>{
  e.preventDefault();
  $("#vendor").value  = "jquery";
  $("#product").value = "jquery";
  $("#version").value = "3.6.0";
  $("#eolSlug").value = "jquery";
  $("#checker-form").dispatchEvent(new Event("submit"));
});

$("#checker-form").addEventListener("submit", async (e)=>{
  e.preventDefault();
  $("#result").classList.add("hidden");
  $("#cveList").classList.add("hidden");
  $("#cveItems").innerHTML = "";

  const vendor = $("#vendor").value.trim().toLowerCase();
  const product= $("#product").value.trim().toLowerCase();
  const version= $("#version").value.trim();
  const slug   = ($("#eolSlug").value.trim() || product).toLowerCase();
  const nvdKey = $("#nvdKey").value.trim() || null;

  // 1) endoflife.date
  const eol = await fetchEOL(slug);
  let supportState = "unknown", hasNewer = false;

  if (eol.ok){
    supportState = resolveSupportByPolicy(version, eol.releases, slug);

    // Determinar si existe versión más nueva (para decidir B vs C)
    const allVers = eol.releases.map(r => r.version).filter(Boolean);
    if (allVers.length){
      const sorted = allVers.slice().sort((a,b)=> semverCmp(a,b));
      hasNewer = semverCmp(version, sorted[sorted.length-1]) < 0;
    }
  }

  // 2) NVD (CPE exacto) → CVEs aplicables estrictos
  let cves = [];
  const nvd = await fetchCVEsByCPE(vendor, product, nvdKey);
  if (!nvd.degraded){
    cves = cvesApplicableStrict(nvd.cves, vendor, product, version);
  } // si degraded → preferimos no listar CVEs

  // 3) Clasificación
  const cls = classify(supportState, hasNewer, cves);

  // 4) Render
  const result = $("#result"); result.classList.remove("hidden");
  const classBox = $("#classification");
  classBox.className = `classification ${cls.tone}`;
  classBox.textContent = `(${cls.cat}) ${cls.msg}`;

  const expl = $("#explanation");
  const reasons = [];
  // Explicación minimal, sin CVEs salvo D
  if (supportState === "supported") reasons.push("endoflife.date indica soporte vigente o sin fecha de EOL para esta versión/ciclo.");
  if (supportState === "eol") reasons.push("endoflife.date indica fuera de soporte (o política latest‑only aplicada).");
  if (supportState === "unknown") reasons.push("No se halló entrada específica en endoflife.date para esta versión.");
  if (hasNewer) reasons.push("Existe una versión más nueva del mismo producto/ciclo.");
  if (nvd.degraded) reasons.push("No se consultaron CVEs por limitación de la API/CORS; se prioriza exactitud > cobertura.");
  if (!nvd.degraded && cves.length === 0) reasons.push("No se confirmaron CVEs aplicables bajo CPE y rangos estrictos.");
  expl.textContent = reasons.join(" ");

  if (cls.cat === "D"){
    $("#cveList").classList.remove("hidden");
    const ul = $("#cveItems");
    for (const x of cves){
      const li = document.createElement("li");
      li.innerHTML = `<code>${x.id}</code>${x.cvss ? ` — CVSS ${x.cvss}` : ""} — ${x.desc}`;
      ul.appendChild(li);
    }
  }
});
