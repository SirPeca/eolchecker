/* =========================================================
 * EOL & CVE Checker — v2 determinista (estático)
 * - UI minimal: software + versión
 * - CPE por defecto: cpe:2.3:a:<software>:<software> (minúsculas, espacios→guiones)
 * - Advanced (opcional) para override de CPE y slug
 * - endoflife.date + política latest-only SOLO para jQuery
 * - Comparador smart (1.0.1k, 1.1.1t, rc, etc.)
 * - NVD v2 con paginación + AbortController
 * - Usa SOLO window.NVD_API_KEY; si falta, omite CVEs (auditable)
 * =======================================================*/

// ---------- Helpers de DOM y estado ----------
const $ = (sel) => document.querySelector(sel);
let currentAbort = null; // para cancelar consultas en curso

const todayISO = () => new Date().toISOString().slice(0,10);

// ---------- Normalización de “software” a CPE/slug por defecto ----------
function normalizeName(s) {
  // minúsculas, recorta y reemplaza espacios consecutivos por '-'
  return String(s || "").trim().toLowerCase().replace(/\s+/g, '-');
}

// ---------- Parser/Comparador de versiones (smart) ----------
function parseSmart(versionRaw) {
  const raw = String(versionRaw || "").trim().replace(/^v/i,'');
  const preCut = raw.split('-')[0]; // remove -rc/-beta for comparison
  const parts = preCut.split('.');
  const out = [];
  for (let p of parts) {
    const m = /^(\d+)([a-z]+)?$/i.exec(p);
    if (m) {
      out.push({num: parseInt(m[1],10), suf: (m[2] || "").toLowerCase()});
    } else if (/^[a-z]+$/i.test(p)) {
      out.push({num: 0, suf: p.toLowerCase()});
    } else {
      out.push({num: isNaN(+p) ? 0 : +p, suf: ""});
    }
  }
  return out;
}
function cmpSmart(aRaw, bRaw) {
  const A = parseSmart(aRaw), B = parseSmart(bRaw);
  const n = Math.max(A.length, B.length);
  for (let i=0; i<n; i++){
    const a = A[i] || {num:0, suf:""}, b = B[i] || {num:0, suf:""};
    if (a.num !== b.num) return a.num - b.num;
    if (a.suf !== b.suf) {
      if (!a.suf) return 1;   // 1.0.1 > 1.0.1a
      if (!b.suf) return -1;
      if (a.suf < b.suf) return -1;
      if (a.suf > b.suf) return 1;
    }
  }
  return 0;
}
function inRangeSmart(version, startIncl, startExcl, endIncl, endExcl){
  const ge = (a,b) => cmpSmart(a,b) >= 0;
  const gt = (a,b) => cmpSmart(a,b) >  0;
  const le = (a,b) => cmpSmart(a,b) <= 0;
  const lt = (a,b) => cmpSmart(a,b) <  0;
  const okStart = (startIncl ? ge(version, startIncl) : true) && (startExcl ? gt(version, startExcl) : true);
  const okEnd   = (endIncl   ? le(version, endIncl)   : true) && (endExcl   ? lt(version, endExcl)   : true);
  return okStart && okEnd;
}

// ---------- Productos con política “latest-only” documentada ----------
const LATEST_ONLY = new Set(["jquery"]);

// ---------- endoflife.date ----------
async function fetchEOL(slug, signal){
  const url = `https://endoflife.date/api/v1/products/${encodeURIComponent(slug)}/`;
  const res = await fetch(url, {mode:"cors", signal});
  if (!res.ok) return {ok:false, releases:[]};
  const data = await res.json();
  const releases = Array.isArray(data.releases) ? data.releases : (Array.isArray(data) ? data : []);
  const norm = releases.map(r => {
    const version = r.version || r.cycle || r.latest || r.release || r.lts || r.codename || "";
    return { version: String(version || "").trim(), eol: r.eol ?? null };
  }).filter(r => r.version);
  return {ok:true, releases: norm};
}

function isoDateLE(aISO, bISO){ return new Date(aISO) <= new Date(bISO); }
function isoDateGT(aISO, bISO){ return new Date(aISO) >  new Date(bISO); }

function resolveSupportByPolicy(version, releases, slug){
  // 1) Entrada exacta
  const exact = releases.find(r => r.version === version);
  if (exact && typeof exact.eol === "string") {
    return isoDateGT(exact.eol, todayISO()) ? "supported" : "eol";
  }
  if (exact && exact.eol === true) return "eol";
  if (exact && (exact.eol === null || exact.eol === undefined)) return "supported";

  // 2) Herencia por ciclo si aplica (solo latest-only, p.ej. jQuery)
  const key = (slug || "").toLowerCase();
  if (LATEST_ONLY.has(key)) {
    const targetMajor = (String(version).split('.')[0] || "").trim();
    const sameMajor = releases
      .map(r => r.version)
      .filter(v => (v.split('.')[0] || "") === targetMajor)
      .sort((a,b)=> cmpSmart(a,b));
    if (!sameMajor.length) return "unknown";
    const latestOfMajor = sameMajor[sameMajor.length-1];
    if (cmpSmart(version, latestOfMajor) === 0) {
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
  return "unknown";
}

// ---------- NVD v2 (CPE exacto) con paginación ----------
function hasNVDKey(){
  return typeof window !== "undefined" && typeof window.NVD_API_KEY === "string" && window.NVD_API_KEY.trim().length > 0;
}

async function fetchAllCVEsByCPE(vendor, product, signal){
  if (!hasNVDKey()){
    // Sin API key → no consultamos CVEs (auditable)
    return { baseCPE: `cpe:2.3:a:${vendor}:${product}`, cves: [], degraded: true };
  }
  const apiKey = window.NVD_API_KEY.trim();
  const baseCPE = `cpe:2.3:a:${vendor}:${product}`;
  const headers = { "apiKey": apiKey };
  const pageSize = 2000;

  let startIndex = 0;
  let total = null;
  const all = [];

  while (true) {
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=${encodeURIComponent(baseCPE)}&noRejected&startIndex=${startIndex}&resultsPerPage=${pageSize}`;
    const res = await fetch(url, { headers, mode:"cors", signal });
    if (!res.ok) throw new Error(`NVD ${res.status}`);
    const data = await res.json();
    const chunk = Array.isArray(data.vulnerabilities) ? data.vulnerabilities : [];
    all.push(...chunk);
    if (total === null) total = data.totalResults ?? chunk.length;
    startIndex += chunk.length;
    if (startIndex >= total || chunk.length === 0) break;
  }

  return { baseCPE, cves: all, degraded: false };
}

function cvesApplicableStrict(cves, vendor, product, version){
  const baseCPE = `cpe:2.3:a:${vendor}:${product}`.toLowerCase();
  const out = [];
  for (const item of cves){
    const cve = item.cve;
    const configs = cve.configurations || [];
    let applies = false;

    const walk = (node) => {
      if (Array.isArray(node.cpeMatch)) {
        for (const m of node.cpeMatch){
          const name = (m.criteria || m.cpeName || "").toLowerCase();
          if (!name.startsWith(baseCPE)) continue; // vendor/product exacto
          const sI = m.versionStartIncluding, sE = m.versionStartExcluding;
          const eI = m.versionEndIncluding,   eE = m.versionEndExcluding;
          if (!sI && !sE && !eI && !eE) { applies = true; }
          else if (inRangeSmart(version, sI, sE, eI, eE)) { applies = true; }
        }
      }
      if (Array.isArray(node.nodes)) node.nodes.forEach(walk);
    };
    configs.forEach(walk);

    if (applies){
      const id = cve.id;
      const metrics = cve.metrics || {};
      const v31 = Array.isArray(metrics.cvssMetricV31) ? metrics.cvssMetricV31[0] : null;
      const cvss = v31 ? v31.cvssData.baseScore : null;
      const descArr = (cve.descriptions || []).filter(d => d.lang === "es" || d.lang === "en");
      const desc = descArr.length ? descArr[0].value : "Sin descripción disponible.";
      out.push({ id, cvss, desc });
    }
  }
  return out;
}

// ---------- Clasificación ----------
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

// ---------- UI helpers ----------
function resetUI() {
  $("#result").classList.add("hidden");
  $("#cveList").classList.add("hidden");
  $("#cveItems").innerHTML = "";
  const classBox = $("#classification");
  if (classBox) { classBox.className = "classification"; classBox.textContent = ""; }
  const expl = $("#explanation"); if (expl) expl.textContent = "";
}

function updateCPEPreview() {
  const software = normalizeName($("#software").value);
  const vendor = normalizeName($("#cpeVendor").value) || software;
  const product= normalizeName($("#cpeProduct").value) || software;
  $("#cpePreview").textContent = `cpe:2.3:a:${vendor || "-"}:${product || "-"}`;
}

// Reactividad (sin autocompletar ni ejemplos)
$("#checker-form").addEventListener("input", updateCPEPreview);

// Submit principal
$("#checker-form").addEventListener("submit", async (e)=>{
  e.preventDefault();

  // cancelar consulta previa
  if (currentAbort) currentAbort.abort();
  currentAbort = new AbortController();
  const { signal } = currentAbort;

  resetUI();

  // Normalización de entradas
  const softwareName = $("#software").value;
  const version = $("#version").value.trim();
  const sw = normalizeName(softwareName);
  const vendor = normalizeName($("#cpeVendor").value) || sw;
  const product= normalizeName($("#cpeProduct").value) || sw;
  const slug   = normalizeName($("#eolSlug").value) || sw;

  // 1) endoflife.date
  let supportState = "unknown", hasNewer = false;
  const eol = await fetchEOL(slug, signal).catch(()=>({ok:false,releases:[]}));
  if (eol.ok){
    supportState = resolveSupportByPolicy(version, eol.releases, slug);
    const allVers = eol.releases.map(r => r.version).filter(Boolean);
    if (allVers.length){
      const sorted = allVers.slice().sort((a,b)=> cmpSmart(a,b));
      hasNewer = cmpSmart(version, sorted[sorted.length-1]) < 0;
    }
  }

  // 2) NVD (CPE exacto) — con paginación (solo si hay API key inyectada)
  let cves = [];
  let degraded = false;
  try{
    const nvd = await fetchAllCVEsByCPE(vendor, product, signal);
    degraded = nvd.degraded;
    if (!degraded) cves = cvesApplicableStrict(nvd.cves, vendor, product, version);
  }catch(err){
    degraded = true; // preferimos omitir CVEs antes que errar
  }

  // 3) Clasificación
  const cls = classify(supportState, hasNewer, cves);

  // 4) Render
  const result = $("#result"); result.classList.remove("hidden");
  const classBox = $("#classification");
  classBox.className = `classification ${cls.tone}`;
  classBox.textContent = `(${cls.cat}) ${cls.msg}`;

  const expl = $("#explanation");
  const reasons = [];
  if (supportState === "supported") reasons.push("endoflife.date indica soporte vigente o sin fecha de EOL para esta versión/ciclo.");
  if (supportState === "eol") reasons.push("endoflife.date indica fuera de soporte (o política latest‑only aplicada donde corresponde).");
  if (supportState === "unknown") reasons.push("No se halló entrada específica en endoflife.date para esta versión.");
  if (hasNewer) reasons.push("Existe una versión más nueva del mismo producto/ciclo.");
  if (degraded) reasons.push("No se consultaron CVEs por ausencia de NVD API Key inyectada; se prioriza exactitud > cobertura.");
  if (!degraded && cves.length === 0) reasons.push("No se confirmaron CVEs aplicables bajo CPE y rangos estrictos.");
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

// Inicializar preview en blanco
updateCPEPreview();
``
