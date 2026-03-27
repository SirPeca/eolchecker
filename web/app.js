// app.js (GitHub Pages - frontend only)
//
// Objetivo: EOL + CVEs/KEV "best-effort" sin backend (GitHub Pages es estático).
// - OSV (solo si aplica a ecosistema de paquetes)
// - KEV (dataset público)
// - Soporte/EOL (best-effort) desde metadata pública (repo endoflife-date) + links
//
// Importante: GitHub Pages no ejecuta /functions ni server-side.
// Este app.js NO usa /api/check.

// ========================
// Configuración / Fuentes
// ========================
const OSV_QUERY = "https://api.osv.dev/v1/query";
const KEV_JSON  = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json";
const EOL_PRODUCTS_RAW = "https://raw.githubusercontent.com/endoflife-date/endoflife.date/master/products/";

// Slugs/alias comunes
const SLUG_MAP = {
  "node": "nodejs",
  "node.js": "nodejs",
  ".net": "dotnet",
  "dotnet": "dotnet",
};

// Heurística: si el usuario pone "Auto" y es un paquete típico, inferimos ecosistema para OSV
const OSV_HINTS = {
  "jquery": "npm",
  "bootstrap": "npm",
  "datatables": "npm",
  "lodash": "npm",
  "moment": "npm",
  "react": "npm",
  "angular": "npm",
  "angularjs": "npm",
  "vue": "npm",
};

// Productos para los cuales OSV NO aplica (vendor/system, no package manager)
const NON_OSV_PRODUCTS = new Set([
  "openssl",
  "nginx",
  "apache",
  "httpd",
  "windows",
  "linux",
  "kernel",
  "ubuntu",
  "debian",
  "rhel",
  "centos",
  "oracle",
  "mysql",
  "postgresql",
  "postgres",
  "iis",
  "tomcat",
  "kubernetes",
  "docker"
]);

// ========================
// Helpers de UI
// ========================
const btn = document.getElementById("btn");
const btnExample = document.getElementById("btnExample");
btn.addEventListener("click", analyze);
btnExample.addEventListener("click", () => {
  document.getElementById("tech").value = "jquery";
  document.getElementById("version").value = "3.6.1";
  document.getElementById("ecosystem").value = "npm";
  analyze();
});
window.analyze = analyze;

function esc(s){
  return String(s ?? "")
    .replaceAll("&","&amp;")
    .replaceAll("<","&lt;")
    .replaceAll(">","&gt;")
    .replaceAll('"',"&quot;")
    .replaceAll("'","&#039;");
}

function badgeClass(state){
  const v = (state || "").toLowerCase();
  if (v.includes("obsolete")) return "bad";
  if (v.includes("outdated")) return "warn";
  if (v.includes("uptodate")) return "ok";
  return "unk";
}

function isoToday(){
  const d = new Date();
  return new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
}

function parseDateSafe(s){
  if (!s) return null;
  const d = new Date(s);
  return isNaN(d.getTime()) ? null : d;
}

// ========================
// Fetch helpers (robustos)
// ========================
async function fetchJson(url, init = {}, timeoutMs = 15000){
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);

  try{
    const res = await fetch(url, { ...init, signal: ctrl.signal });
    const ct = (res.headers.get("content-type") || "").toLowerCase();
    const text = await res.text();

    // Si no es JSON, devolvemos una estructura informativa (NO tiramos exception acá)
    if (!ct.includes("application/json")){
      return {
        ok: false,
        nonJson: true,
        status: res.status,
        statusText: res.statusText,
        url,
        bodyPreview: text.slice(0, 400)
      };
    }

    let data = null;
    try { data = JSON.parse(text); }
    catch {
      return { ok:false, nonJson:true, status: res.status, statusText: "Invalid JSON", url, bodyPreview: text.slice(0, 400) };
    }

    return { ok: res.ok, status: res.status, data };
  } catch (e){
    // Fallo duro: CORS / red / abort
    return { ok:false, fetchError:true, url, error: String(e) };
  } finally {
    clearTimeout(t);
  }
}

async function fetchText(url, timeoutMs = 15000){
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);

  try{
    const res = await fetch(url, { signal: ctrl.signal });
    const text = await res.text();
    return { ok: res.ok, status: res.status, text };
  } catch (e){
    return { ok:false, fetchError:true, url, error: String(e) };
  } finally {
    clearTimeout(t);
  }
}

// ========================
// YAML frontmatter (minimal)
// ========================
function extractFrontMatter(md){
  const lines = md.split(/\r?\n/);
  if (lines[0]?.trim() !== "---") return null;
  let end = -1;
  for (let i=1;i<lines.length;i++){
    if (lines[i].trim() === "---"){ end = i; break; }
  }
  if (end === -1) return null;
  return lines.slice(1, end).join("\n");
}

function stripYamlValue(v){
  let s = String(v ?? "").trim();
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))){
    s = s.slice(1,-1);
  }
  if (s === "true") return true;
  if (s === "false") return false;
  return s;
}

function parseSimpleYaml(yaml){
  const obj = {};
  const lines = yaml.split(/\r?\n/);

  let currentKey = null;
  let currentList = null;
  let currentObj = null;

  const commitObj = () => {
    if (currentKey && currentObj){
      currentList.push(currentObj);
      currentObj = null;
    }
  };

  for (let raw of lines){
    const line = raw.replace(/\t/g,"  ");
    if (!line.trim() || line.trim().startsWith("#")) continue;

    const mList = line.match(/^\s*-\s*(.*)\s*$/);
    if (mList && currentKey){
      const rest = mList[1];
      if (!Array.isArray(obj[currentKey])) obj[currentKey] = [];
      currentList = obj[currentKey];

      const mInline = rest.match(/^([A-Za-z0-9_\-]+)\s*:\s*(.*)$/);
      if (mInline){
        commitObj();
        currentObj = {};
        currentObj[mInline[1]] = stripYamlValue(mInline[2]);
      } else {
        commitObj();
        currentList.push(stripYamlValue(rest));
      }
      continue;
    }

    const mKV = line.match(/^\s*([A-Za-z0-9_\-]+)\s*:\s*(.*)\s*$/);
    if (mKV){
      commitObj();
      currentKey = mKV[1];
      const v = mKV[2];
      if (v === ""){
        obj[currentKey] = obj[currentKey] ?? [];
        currentList = Array.isArray(obj[currentKey]) ? obj[currentKey] : null;
      } else {
        obj[currentKey] = stripYamlValue(v);
        currentList = null;
      }
      continue;
    }

    if (currentObj && currentKey && line.startsWith("  ")){
      const m = line.trim().match(/^([A-Za-z0-9_\-]+)\s*:\s*(.*)$/);
      if (m){
        currentObj[m[1]] = stripYamlValue(m[2]);
      }
    }
  }

  commitObj();
  return obj;
}

// ========================
// Soporte/EOL best-effort
// ========================
async function getSupportBestEffort(productInput, versionInput){
  const product = (productInput || "").toLowerCase().trim();
  const slug = SLUG_MAP[product] || product;
  const major = String(versionInput || "").split(".")[0];

  const evidence = {
    support_links: [],
    notes: []
  };

  const rawUrl = `${EOL_PRODUCTS_RAW}${encodeURIComponent(slug)}.md`;
  evidence.support_links.push(rawUrl);

  const r = await fetchText(rawUrl, 12000);

  if (!r.ok){
    if (r.fetchError){
      evidence.notes.push(`No se pudo obtener metadata de soporte/EOL (fetch error): ${r.error}`);
    } else {
      evidence.notes.push(`No se pudo obtener metadata de soporte/EOL desde el repo (HTTP ${r.status}).`);
    }
    evidence.notes.push("Best-effort: validar soporte/EOL en fuentes oficiales del proveedor si aplica.");
    return {
      known: false,
      eol: null,
      supportUntil: null,
      latest: null,
      cycleFound: null,
      evidence
    };
  }

  const fm = extractFrontMatter(r.text);
  if (!fm){
    evidence.notes.push("No se detectó frontmatter YAML en el archivo del producto (best-effort).");
    return { known:false, eol:null, supportUntil:null, latest:null, cycleFound:null, evidence };
  }

  const meta = parseSimpleYaml(fm);
  const releases = Array.isArray(meta.releases) ? meta.releases : [];
  let chosen = null;

  for (const item of releases){
    const cycle = String(item.cycle ?? item.releaseCycle ?? item.version ?? "").trim();
    if (!cycle) continue;
    if (cycle === major || cycle.startsWith(major + ".") || cycle.startsWith(major + " ")){
      chosen = item; break;
    }
  }

  if (!chosen && releases.length){
    for (const item of releases){
      const cycle = String(item.cycle ?? item.releaseCycle ?? item.version ?? "").trim();
      if (cycle && String(versionInput).startsWith(cycle)) { chosen = item; break; }
    }
  }

  if (!chosen){
    evidence.notes.push("No se encontró un ciclo compatible para esa versión en la metadata (best-effort).");
    return { known:true, eol:null, supportUntil:null, latest:null, cycleFound:null, evidence };
  }

  const eol = chosen.eol ?? null;
  const supportUntil = chosen.support ?? chosen.security ?? (typeof chosen.lts === "string" ? chosen.lts : null) ?? null;
  const latest = chosen.latest ?? null;

  return {
    known: true,
    eol,
    supportUntil,
    latest,
    cycleFound: String(chosen.cycle ?? chosen.releaseCycle ?? "").trim() || null,
    evidence
  };
}

// ========================
// OSV CVEs (con guard NO-OSV)
// ========================
async function getOsvVulns(productInput, versionInput, ecosystemOverride){
  const product = (productInput || "").trim();
  const productLower = product.toLowerCase();

  // ✅ GUARD: NO OSV para productos vendor/sistema (como openssl)
  if (NON_OSV_PRODUCTS.has(productLower)){
    return {
      used: false,
      ecosystem: null,
      vulns: [],
      cveIds: [],
      evidence: {
        osv: [],
        notes: ["OSV no aplica para este producto (librería/servicio de sistema / vendor)."]
      }
    };
  }

  const eco = ecosystemOverride || OSV_HINTS[productLower] || "";

  // Si no sabemos ecosistema, no llamamos OSV (evita Failed to fetch y deja trazabilidad)
  if (!eco){
    return {
      used: false,
      ecosystem: null,
      vulns: [],
      cveIds: [],
      evidence: {
        osv: [],
        notes: [
          "No se pudo inferir ecosistema para OSV. Elegí uno en el selector (npm/PyPI/Maven/NuGet/etc)."
        ]
      }
    };
  }

  const payload = {
    package: { name: product, ecosystem: eco },
    version: String(versionInput || "").trim()
  };

  const resp = await fetchJson(OSV_QUERY, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  }, 20000);

  if (!resp.ok){
    const note = resp.fetchError
      ? `OSV fetch error (posible CORS/red): ${resp.error}`
      : resp.nonJson
        ? `OSV respondió no-JSON (HTTP ${resp.status}).`
        : `OSV HTTP ${resp.status}.`;
    return {
      used: true,
      ecosystem: eco,
      vulns: [],
      cveIds: [],
      evidence: { osv: [OSV_QUERY], notes: [note] }
    };
  }

  const vulns = resp.data?.vulns || [];
  const cveSet = new Set();
  for (const v of vulns){
    const aliases = v.aliases || [];
    for (const a of aliases){
      if (String(a).startsWith("CVE-")) cveSet.add(String(a));
    }
  }

  return {
    used: true,
    ecosystem: eco,
    vulns,
    cveIds: Array.from(cveSet),
    evidence: { osv: [OSV_QUERY], notes: [] }
  };
}

// ========================
// KEV cross-check
// ========================
async function getKevHits(cveIds){
  const evidence = [KEV_JSON];
  if (!cveIds?.length){
    return { kevHits: [], evidence, notes: ["Sin CVEs para cruzar con KEV."] };
  }

  const resp = await fetchJson(KEV_JSON, {}, 20000);
  if (!resp.ok){
    const note = resp.fetchError
      ? `KEV fetch error (posible CORS/red): ${resp.error}`
      : resp.nonJson
        ? `KEV respondió no-JSON (HTTP ${resp.status}).`
        : `KEV HTTP ${resp.status}.`;
    return { kevHits: [], evidence, notes: [note] };
  }

  const list = resp.data?.vulnerabilities || resp.data || [];
  const kevSet = new Set((list || []).map(x => x.cveID || x.cveId || x.cve).filter(Boolean));
  const hits = cveIds.filter(id => kevSet.has(id));
  return { kevHits: hits, evidence, notes: [] };
}

// ========================
// Clasificación estilo Rodrigo
// ========================
function classifyState({ supportKnown, isEol, inSupport, hasCve }){
  if (supportKnown && isEol && hasCve) return "obsolete with known vulnerabilities";
  if (supportKnown && isEol && !hasCve) return "obsolete without known vulnerabtilies";
  if (supportKnown && inSupport && hasCve) return "outdated with known vulnerabilities";
  if (supportKnown && inSupport && !hasCve) return "outdated without known vulnerabtilies";
  if (supportKnown && inSupport && !hasCve) return "uptodate";
  return "unknown";
}

function buildImpact(state, cveCount, kevHits){
  const kevNote = kevHits?.length ? ` Además, ${kevHits.length} CVE(s) figuran como KEV (explotadas activamente).` : "";
  if (state.includes("obsolete")){
    return `Riesgo elevado: la versión se considera fuera de soporte (EOL) y su exposición a vulnerabilidades públicas aumenta el riesgo operativo.${kevNote}`;
  }
  if (state.includes("outdated")){
    return `Riesgo moderado: la tecnología aún podría tener soporte, pero la versión puede estar desactualizada y con vulnerabilidades conocidas (${cveCount}).${kevNote}`;
  }
  if (state.includes("uptodate")){
    return `Riesgo bajo por “CVE públicas” (best-effort): no se detectaron CVEs asociadas a la combinación producto/versión consultada. Esto no garantiza ausencia de riesgo.${kevNote}`;
  }
  return `Impacto no determinable con certeza (best-effort). Revisar manualmente evidencia y referencias.${kevNote}`;
}

function buildRecommendation(state, support){
  if (state.includes("obsolete") || state.includes("outdated")){
    const latest = support?.latest ? ` Sugerencia: evaluar actualización hacia ${support.latest} (o última estable soportada).` : "";
    return `Actualizar a una versión soportada por el proveedor y validar compatibilidad/regresión.${latest}`.trim();
  }
  if (state.includes("uptodate")){
    return `Mantener versión, monitorear nuevas vulnerabilidades y cambios de soporte.`;
  }
  return `Recomendación best-effort: confirmar soporte/EOL en fuentes oficiales del proveedor y luego definir upgrade path.`;
}

// Red/Blue: conceptual (sin instrucciones ofensivas)
function buildPerspectives(state, kevHits){
  const red = [];
  const blue = [];

  red.push("Según el tipo de CVE (si aplica), podrían involucrarse técnicas MITRE ATT&CK relacionadas a explotación de aplicaciones/servicios y ejecución de código (mapeo depende del CVE específico).");
  if (kevHits?.length){
    red.push("Al estar en KEV, asumir explotación real y priorizar escenarios de abuso según exposición/superficie/controles.");
  }

  blue.push("Aplicar hardening y controles compensatorios: segmentación, mínimos privilegios, WAF/IDS/IPS cuando corresponda, y monitoreo/alertas en logs.");
  blue.push("Definir detecciones en SOC para patrones asociados a explotación del componente (requests anómalas, errores, indicadores del proveedor).");
  if (kevHits?.length){
    blue.push("KEV presente: elevar prioridad de monitoreo y playbooks de contención/erradicación para esos CVEs.");
  }
  if (state.includes("uptodate")){
    blue.push("Aunque no haya CVEs detectadas, mantener inventario, SBOM y scanning recurrente.");
  }

  return { red, blue };
}

// ========================
// Render
// ========================
function renderReport(report){
  const state = report?.Description?.state || "unknown";
  const b = badgeClass(state);

  const eSupport = report?.["Evidence support"] || {};
  const cves = report?.["CVE code list"] || [];
  const kev = report?.["Known exploited (KEV)"] || [];

  const red = report?.["Red team perspective"] || [];
  const blue = report?.["Blue team perspective"] || [];

  return `
    <div class="box">
      <h2>${esc(report.Title)} <span class="badge ${b}">${esc(state)}</span></h2>

      <h3>Description</h3>
      <pre>${esc(JSON.stringify(report.Description, null, 2))}</pre>

      <h3>Evidence support (references)</h3>
      <pre>${esc(JSON.stringify(eSupport, null, 2))}</pre>

      <h3>CVE code list</h3>
      <div>${cves.length ? esc(cves.join(", ")) : "Sin CVEs detectados (best-effort)."}</div>

      <h3>Known exploited (KEV)</h3>
      <pre>${esc(kev.length ? kev.join(", ") : "Sin coincidencias con KEV (best-effort).")}</pre>

      <h3>Impact</h3>
      <pre>${esc(report.Impact || "")}</pre>

      <h3>Recomendation</h3>
      <pre>${esc(report.Recomendation || "")}</pre>

      <h3>Red team perspective</h3>
      <pre>${esc(red.map(x => "- " + x).join("\n"))}</pre>

      <h3>Blue team perspective</h3>
      <pre>${esc(blue.map(x => "- " + x).join("\n"))}</pre>

      <h3>Disclaimer</h3>
      <pre>${esc(report.Disclaimer || "")}</pre>
    </div>
  `;
}

// ========================
// MAIN
// ========================
async function analyze(){
  const tech = document.getElementById("tech").value.trim();
  const version = document.getElementById("version").value.trim();
  const ecoSel = document.getElementById("ecosystem").value.trim();
  const out = document.getElementById("output");

  out.innerHTML = "";

  if (!tech || !version){
    out.innerHTML = `<div class="box"><h2>Faltan datos</h2><div class="muted">Ingresá tecnología/producto y versión.</div></div>`;
    return;
  }

  out.innerHTML = `<div class="box"><h2>Consultando…</h2><div class="muted">Buscando soporte/EOL y vulnerabilidades (best-effort).</div></div>`;

  // 1) soporte/eol best-effort
  const support = await getSupportBestEffort(tech, version);

  // 2) OSV (con guard)
  const osv = await getOsvVulns(tech, version, ecoSel);

  // 3) KEV (solo si hay CVEs)
  const kev = await getKevHits(osv.cveIds);

  // 4) state calc
  const today = isoToday();
  const eolDate = parseDateSafe(support.eol);
  const supportUntilDate = parseDateSafe(support.supportUntil);

  const isEol = eolDate ? (eolDate < today) : false;
  const inSupport = supportUntilDate ? (supportUntilDate > today) : (support.known ? !isEol : false);

  const hasCve = (osv.cveIds || []).length > 0;
  const state = classifyState({ supportKnown: support.known, isEol, inSupport, hasCve });

  const title = `${tech}, ${version}, ${state}`;

  const evidence = {
    support: support.evidence?.support_links || [],
    support_notes: support.evidence?.notes || [],
    osv: osv.evidence?.osv || [],
    osv_notes: osv.evidence?.notes || [],
    kev: kev.evidence || [],
    kev_notes: kev.notes || []
  };

  const impact = buildImpact(state, (osv.cveIds || []).length, kev.kevHits || []);
  const recommendation = buildRecommendation(state, support);
  const { red, blue } = buildPerspectives(state, kev.kevHits || []);

  const report = {
    Title: title,
    Description: {
      state,
      support: {
        known: support.known,
        eol: support.eol || null,
        supportUntil: support.supportUntil || null,
        latest: support.latest || null,
        cycle: support.cycleFound || null
      },
      notes: support.known
        ? "Soporte/EOL obtenido best-effort desde metadata pública (puede requerir verificación manual)."
        : "No se pudo determinar soporte/EOL automáticamente (best-effort)."
    },
    "Evidence support": evidence,
    "CVE code list": osv.cveIds || [],
    "Known exploited (KEV)": kev.kevHits || [],
    Impact: impact,
    Recomendation: recommendation,
    "Red team perspective": red,
    "Blue team perspective": blue,
    Disclaimer: "Remember the information generated may be incorrect, manually check each reference or link to ensure the truthfulness of the answer"
  };

  out.innerHTML = renderReport(report);
}
