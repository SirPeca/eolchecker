/* =========================
   CATALOGO DE TECNOLOGIAS
   ~50 librerías/frameworks comunes
========================= */
const CATALOG = {
  "jquery": { name: "jQuery", key: "jquery" },
  "jquery ui": { name: "jQuery UI", key: "jquery ui" },
  "jquery blockui": { name: "jQuery BlockUI", key: "jquery blockui" },
  "bootstrap": { name: "Bootstrap", key: "bootstrap" },
  "angular": { name: "Angular", key: "angular" },
  "react": { name: "React", key: "react" },
  "vue": { name: "Vue.js", key: "vue" },
  "vuex": { name: "Vuex", key: "vuex" },
  "nuxt": { name: "Nuxt.js", key: "nuxt" },
  "moment.js": { name: "Moment.js", key: "moment" },
  "moment-timezone": { name: "Moment Timezone", key: "moment-timezone" },
  "toastr": { name: "Toastr", key: "toastr" },
  "select2": { name: "Select2", key: "select2" },
  "highcharts": { name: "Highcharts", key: "highcharts" },
  "chart.js": { name: "Chart.js", key: "chart.js" },
  "d3": { name: "D3.js", key: "d3" },
  "axios": { name: "Axios", key: "axios" },
  "socket.io": { name: "Socket.IO", key: "socket.io" },
  "lodash": { name: "Lodash", key: "lodash" },
  "underscore": { name: "Underscore.js", key: "underscore" },
  "tailwindcss": { name: "Tailwind CSS", key: "tailwindcss" },
  "material-ui": { name: "Material-UI", key: "material-ui" },
  "ant-design": { name: "Ant Design", key: "ant-design" },
  "webpack": { name: "Webpack", key: "webpack" },
  "babel": { name: "Babel", key: "babel" },
  "typescript": { name: "TypeScript", key: "typescript" },
  "sass": { name: "Sass", key: "sass" },
  "less": { name: "Less", key: "less" },
  "three.js": { name: "Three.js", key: "three.js" },
  "animejs": { name: "Anime.js", key: "animejs" },
  "gsap": { name: "GSAP", key: "gsap" },
  "backbone": { name: "Backbone.js", key: "backbone" },
  "ember": { name: "Ember.js", key: "ember" },
  "p5": { name: "p5.js", key: "p5" },
  "turbolinks": { name: "Turbolinks", key: "turbolinks" },
  "crypto-js": { name: "CryptoJS", key: "crypto-js" },
  "openssl": { name: "OpenSSL", key: "openssl" },
  "node.js": { name: "Node.js", key: "node.js" },
  "php": { name: "PHP", key: "php" },
  "django": { name: "Django", key: "django" },
  "laravel": { name: "Laravel", key: "laravel" },
  "spring": { name: "Spring Framework", key: "spring" },
  "ruby on rails": { name: "Ruby on Rails", key: "rails" },
  "express": { name: "Express", key: "express" },
  "flask": { name: "Flask", key: "flask" },
  "matomo": { name: "Matomo Analytics", key: "matomo" },
  "font awesome": { name: "Font Awesome", key: "fontawesome" },
  "microsoft asp.net": { name: "ASP.NET", key: "asp.net" },
  "hsts": { name: "HSTS", key: "hsts" }
};

/* =========================
   FUNCION PRINCIPAL
========================= */
export async function onRequest({ request }) {
  try {
    const url = new URL(request.url);
    const techRaw = url.searchParams.get("tec");
    const versionRaw = url.searchParams.get("ver");

    if (!techRaw || !versionRaw) return json({ error: "Parámetros requeridos: tec, ver" }, 400);

    let techKey = techRaw.trim().toLowerCase();
    const version = versionRaw.trim();

    if (CATALOG[techKey]) techKey = CATALOG[techKey].key;

    /* ========== END OF LIFE ========== */
    let eolData = null;
    try {
      const eolRes = await fetch(`https://endoflife.date/api/${techKey}.json`, { cf: { cacheTtl: 3600 } });
      if (eolRes.ok) eolData = await eolRes.json();
    } catch {}

    let cycle = null, latest = null, latestSupported = null, status = "DESCONOCIDO";

    if (Array.isArray(eolData)) {
      latest = eolData.find(c => c.latest)?.latest || null;
      latestSupported = eolData.find(c => !c.eol || new Date(c.eol) > new Date())?.latest || null;
      cycle = eolData.find(c => c.cycle && version.startsWith(String(c.cycle)));
      if (cycle?.eol) status = new Date(cycle.eol) < new Date() ? "FUERA DE SOPORTE" : "CON SOPORTE";
      if (latest && latestSupported && version !== latestSupported && status === "CON SOPORTE") status = "DESACTUALIZADO";
    }

    /* ========== NVD CVES ========== */
    let cves = [];
    try {
      const cveRes = await fetch(
        `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(techKey)}&resultsPerPage=200`
      );
      if (cveRes.ok) {
        const cveJson = await cveRes.json();
        cves = (cveJson.vulnerabilities || []).map(v => {
          const cve = v.cve;
          const metrics = cve.metrics || {};
          const score = metrics.cvssMetricV31?.[0]?.cvssData || metrics.cvssMetricV30?.[0]?.cvssData || metrics.cvssMetricV2?.[0]?.cvssData;
          return {
            id: cve.id,
            severity: score?.baseSeverity || "UNKNOWN",
            score: score?.baseScore || null,
            published: cve.published,
            description: cve.descriptions?.[0]?.value || "",
            url: `https://nvd.nist.gov/vuln/detail/${cve.id}`
          };
        }).filter(c => c.description.toLowerCase().includes(techKey) && c.description.includes(version));
      }
    } catch {}

    /* ========== ORDER & SUMMARY ========== */
    const order = { CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 4, UNKNOWN: 5 };
    cves.sort((a,b) => order[a.severity]-order[b.severity]);
    const summary = { total: cves.length, critical: cves.filter(c=>c.severity==="CRITICAL").length, high: cves.filter(c=>c.severity==="HIGH").length };

    return json({
      tecnologia: techRaw,
      version,
      estado: status,
      latestVersion: latest,
      latestSupportedVersion: latestSupported,
      ciclo: cycle || null,
      cves,
      resumen: summary,
      fuentes: ["https://endoflife.date","https://nvd.nist.gov"]
    });

  } catch(e){
    return json({ error: "Error interno", detail: e.message }, 500);
  }
}

function json(data, status=200) {
  return new Response(JSON.stringify(data), { status, headers: {"Content-Type":"application/json"} });
}
