// ======================= CATALOG: Top 100 Librerías & Frameworks =======================
const JS_LIBS = {
  "jquery": { latestVersion: "4.0.0", latestSupportedVersion: "4.0.0", status: "CON SOPORTE" },
  "jquery ui": { latestVersion: "1.13.2", latestSupportedVersion: "1.13.2", status: "CON SOPORTE" },
  "jquery blockui": { latestVersion: "2.70", latestSupportedVersion: "2.70", status: "CON SOPORTE" },
  "bootstrap": { latestVersion: "5.3.8", latestSupportedVersion: "5.3.8", status: "CON SOPORTE" },
  "angular": { latestVersion: "16.2.2", latestSupportedVersion: "16.2.2", status: "CON SOPORTE" },
  "react": { latestVersion: "18.2.0", latestSupportedVersion: "18.2.0", status: "CON SOPORTE" },
  "vue": { latestVersion: "3.3.4", latestSupportedVersion: "3.3.4", status: "CON SOPORTE" },
  "vuex": { latestVersion: "4.1.0", latestSupportedVersion: "4.1.0", status: "CON SOPORTE" },
  "nuxt": { latestVersion: "3.7.1", latestSupportedVersion: "3.7.1", status: "CON SOPORTE" },
  "svelte": { latestVersion: "4.2.0", latestSupportedVersion: "4.2.0", status: "CON SOPORTE" },
  "moment.js": { latestVersion: "2.29.4", latestSupportedVersion: "2.29.4", status: "CON SOPORTE" },
  "moment-timezone": { latestVersion: "0.5.42", latestSupportedVersion: "0.5.42", status: "CON SOPORTE" },
  "toastr": { latestVersion: "2.1.4", latestSupportedVersion: "2.1.4", status: "CON SOPORTE" },
  "select2": { latestVersion: "4.1.0-rc.0", latestSupportedVersion: "4.1.0-rc.0", status: "CON SOPORTE" },
  "highcharts": { latestVersion: "11.2.0", latestSupportedVersion: "11.2.0", status: "CON SOPORTE" },
  "chart.js": { latestVersion: "4.3.0", latestSupportedVersion: "4.3.0", status: "CON SOPORTE" },
  "d3": { latestVersion: "7.10.0", latestSupportedVersion: "7.10.0", status: "CON SOPORTE" },
  "axios": { latestVersion: "1.4.0", latestSupportedVersion: "1.4.0", status: "CON SOPORTE" },
  "socket.io": { latestVersion: "4.8.1", latestSupportedVersion: "4.8.1", status: "CON SOPORTE" },
  "lodash": { latestVersion: "4.17.21", latestSupportedVersion: "4.17.21", status: "CON SOPORTE" },
  "underscore": { latestVersion: "1.13.6", latestSupportedVersion: "1.13.6", status: "CON SOPORTE" },
  "core-js": { latestVersion: "3.31.1", latestSupportedVersion: "3.31.1", status: "CON SOPORTE" },
  "tailwindcss": { latestVersion: "3.3.3", latestSupportedVersion: "3.3.3", status: "CON SOPORTE" },
  "material-ui": { latestVersion: "5.14.10", latestSupportedVersion: "5.14.10", status: "CON SOPORTE" },
  "ant-design": { latestVersion: "5.10.1", latestSupportedVersion: "5.10.1", status: "CON SOPORTE" },
  "webpack": { latestVersion: "5.88.2", latestSupportedVersion: "5.88.2", status: "CON SOPORTE" },
  "babel": { latestVersion: "7.23.0", latestSupportedVersion: "7.23.0", status: "CON SOPORTE" },
  "typescript": { latestVersion: "5.3.1", latestSupportedVersion: "5.3.1", status: "CON SOPORTE" },
  "sass": { latestVersion: "1.70.2", latestSupportedVersion: "1.70.2", status: "CON SOPORTE" },
  "less": { latestVersion: "4.1.3", latestSupportedVersion: "4.1.3", status: "CON SOPORTE" },
  "three.js": { latestVersion: "0.166.0", latestSupportedVersion: "0.166.0", status: "CON SOPORTE" },
  "animejs": { latestVersion: "3.2.1", latestSupportedVersion: "3.2.1", status: "CON SOPORTE" },
  "gsap": { latestVersion: "3.13.3", latestSupportedVersion: "3.13.3", status: "CON SOPORTE" },
  "backbone": { latestVersion: "1.4.1", latestSupportedVersion: "1.4.1", status: "CON SOPORTE" },
  "ember": { latestVersion: "4.12.0", latestSupportedVersion: "4.12.0", status: "CON SOPORTE" },
  "p5": { latestVersion: "1.6.0", latestSupportedVersion: "1.6.0", status: "CON SOPORTE" },
  "turbolinks": { latestVersion: "5.2.0", latestSupportedVersion: "5.2.0", status: "CON SOPORTE" },
  "crypto-js": { latestVersion: "4.1.1", latestSupportedVersion: "4.1.1", status: "CON SOPORTE" },
  "openssl": { latestVersion: "3.6.1", latestSupportedVersion: "3.6.1", status: "CON SOPORTE" },
  "node.js": { latestVersion: "20.6.0", latestSupportedVersion: "20.6.0", status: "CON SOPORTE" },
  "php": { latestVersion: "8.3.11", latestSupportedVersion: "8.3.11", status: "CON SOPORTE" },
  "django": { latestVersion: "5.2.0", latestSupportedVersion: "5.2.0", status: "CON SOPORTE" },
  "laravel": { latestVersion: "10.10.0", latestSupportedVersion: "10.10.0", status: "CON SOPORTE" },
  "spring": { latestVersion: "6.3.6", latestSupportedVersion: "6.3.6", status: "CON SOPORTE" },
  "ruby on rails": { latestVersion: "7.2.2", latestSupportedVersion: "7.2.2", status: "CON SOPORTE" },
  "express": { latestVersion: "4.18.2", latestSupportedVersion: "4.18.2", status: "CON SOPORTE" },
  "flask": { latestVersion: "2.3.5", latestSupportedVersion: "2.3.5", status: "CON SOPORTE" },
  "matomo": { latestVersion: "4.21.1", latestSupportedVersion: "4.21.1", status: "CON SOPORTE" },
  "font awesome": { latestVersion: "6.5.2", latestSupportedVersion: "6.5.2", status: "CON SOPORTE" },
  "microsoft asp.net": { latestVersion: "8.0", latestSupportedVersion: "8.0", status: "CON SOPORTE" },
  "hsts": { latestVersion: "strict", latestSupportedVersion: "strict", status: "CON SOPORTE" },
  "rxjs": { latestVersion: "7.9.1", latestSupportedVersion: "7.9.1", status: "CON SOPORTE" },
  "immer": { latestVersion: "9.0.22", latestSupportedVersion: "9.0.22", status: "CON SOPORTE" },
  "recoil": { latestVersion: "0.7.7", latestSupportedVersion: "0.7.7", status: "CON SOPORTE" },
  "zustand": { latestVersion: "4.3.8", latestSupportedVersion: "4.3.8", status: "CON SOPORTE" },
  "formik": { latestVersion: "2.4.2", latestSupportedVersion: "2.4.2", status: "CON SOPORTE" },
  "yup": { latestVersion: "1.2.0", latestSupportedVersion: "1.2.0", status: "CON SOPORTE" },
  "joi": { latestVersion: "17.9.2", latestSupportedVersion: "17.9.2", status: "CON SOPORTE" },
  "react-query": { latestVersion: "5.4.1", latestSupportedVersion: "5.4.1", status: "CON SOPORTE" },
  "react-router": { latestVersion: "6.14.2", latestSupportedVersion: "6.14.2", status: "CON SOPORTE" },
  "next.js": { latestVersion: "14.2.0", latestSupportedVersion: "14.2.0", status: "CON SOPORTE" },
  "gatsby": { latestVersion: "5.20.3", latestSupportedVersion: "5.20.3", status: "CON SOPORTE" },
  "vite": { latestVersion: "5.2.0", latestSupportedVersion: "5.2.0", status: "CON SOPORTE" },
  "parcel": { latestVersion: "2.9.4", latestSupportedVersion: "2.9.4", status: "CON SOPORTE" },
  "rollup": { latestVersion: "3.30.0", latestSupportedVersion: "3.30.0", status: "CON SOPORTE" },
  "eslint": { latestVersion: "8.47.0", latestSupportedVersion: "8.47.0", status: "CON SOPORTE" },
  "prettier": { latestVersion: "3.9.0", latestSupportedVersion: "3.9.0", status: "CON SOPORTE" },
  "stylelint": { latestVersion: "15.13.0", latestSupportedVersion: "15.13.0", status: "CON SOPORTE" },
  "jest": { latestVersion: "29.7.0", latestSupportedVersion: "29.7.0", status: "CON SOPORTE" },
  "mocha": { latestVersion: "10.2.0", latestSupportedVersion: "10.2.0", status: "CON SOPORTE" },
  "chai": { latestVersion: "4.4.0", latestSupportedVersion: "4.4.0", status: "CON SOPORTE" },
  "cypress": { latestVersion: "12.18.0", latestSupportedVersion: "12.18.0", status: "CON SOPORTE" },
  "playwright": { latestVersion: "1.44.0", latestSupportedVersion: "1.44.0", status: "CON SOPORTE" },
  "puppeteer": { latestVersion: "21.3.8", latestSupportedVersion: "21.3.8", status: "CON SOPORTE" },
  "karma": { latestVersion: "6.4.2", latestSupportedVersion: "6.4.2", status: "CON SOPORTE" },
  "protractor": { latestVersion: "7.0.0", latestSupportedVersion: "7.0.0", status: "CON SOPORTE" },
  "nightwatch": { latestVersion: "2.5.1", latestSupportedVersion: "2.5.1", status: "CON SOPORTE" },
  "webdriverio": { latestVersion: "8.25.0", latestSupportedVersion: "8.25.0", status: "CON SOPORTE" },
  "capybara": { latestVersion: "3.42.0", latestSupportedVersion: "3.42.0", status: "CON SOPORTE" },
  "selenium": { latestVersion: "4.14.0", latestSupportedVersion: "4.14.0", status: "CON SOPORTE" },
  "cucumber": { latestVersion: "9.1.3", latestSupportedVersion: "9.1.3", status: "CON SOPORTE" },
  "chai-http": { latestVersion: "4.3.0", latestSupportedVersion: "4.3.0", status: "CON SOPORTE" },
  "supertest": { latestVersion: "6.3.3", latestSupportedVersion: "6.3.3", status: "CON SOPORTE" },
  "nvd": { latestVersion: "2.0", latestSupportedVersion: "2.0", status: "CON SOPORTE" },
  "endoflife.date": { latestVersion: "1.0", latestSupportedVersion: "1.0", status: "CON SOPORTE" }
};

// ======================= CHECK FUNCTION =======================
export async function onRequest({ request }) {
  try {
    const url = new URL(request.url);
    const techRaw = url.searchParams.get("tec");
    const version = url.searchParams.get("ver");

    if (!techRaw || !version) return json({ error: "Parámetros requeridos: tec, ver" }, 400);

    const tech = techRaw.trim().toLowerCase();
    let latest = null;
    let latestSupported = null;
    let status = "DESCONOCIDO";

    // ======================= 1️⃣ EOL / CATALOG CHECK =======================
    if (JS_LIBS[tech]) {
      latest = JS_LIBS[tech].latestVersion;
      latestSupported = JS_LIBS[tech].latestSupportedVersion;
      status = JS_LIBS[tech].status;

      if (version !== latestSupported && status === "CON SOPORTE") status = "DESACTUALIZADO";
    } else {
      // EndOfLife.date fallback
      try {
        const eolRes = await fetch(`https://endoflife.date/api/${tech}.json`, { cf: { cacheTtl: 3600 } });
        if (eolRes.ok) {
          const eolData = await eolRes.json();
          const cycle = eolData.find(c => version.startsWith(String(c.cycle))) || null;
          latest = eolData.find(c => c.latest)?.latest || null;
          latestSupported = eolData.find(c => !c.eol || new Date(c.eol) > new Date())?.latest || null;

          if (cycle?.eol) {
            status = new Date(cycle.eol) < new Date() ? "FUERA DE SOPORTE" : "CON SOPORTE";
          }
          if (latest && latestSupported && version !== latestSupported && status === "CON SOPORTE") {
            status = "DESACTUALIZADO";
          }
        }
      } catch {}
    }

    // ======================= 2️⃣ NVD CVE SEARCH =======================
    let cves = [];
    try {
      const cveRes = await fetch(
        `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(
          tech
        )}&resultsPerPage=200`
      );
      if (cveRes.ok) {
        const data = await cveRes.json();
        cves = (data.vulnerabilities || [])
          .map(v => {
            const cve = v.cve;
            const metrics = cve.metrics || {};
            const score =
              metrics.cvssMetricV31?.[0]?.cvssData ||
              metrics.cvssMetricV30?.[0]?.cvssData ||
              metrics.cvssMetricV2?.[0]?.cvssData;

            return {
              id: cve.id,
              severity: score?.baseSeverity || "UNKNOWN",
              score: score?.baseScore || null,
              published: cve.published,
              description: cve.descriptions?.[0]?.value || "",
              url: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
            };
          })
          .filter(c => c.description.toLowerCase().includes(tech) && c.description.includes(version));
      }
    } catch {}

    // ======================= 3️⃣ ORDER & SUMMARY =======================
    const order = { CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 4, UNKNOWN: 5 };
    cves.sort((a, b) => order[a.severity] - order[b.severity]);

    const summary = {
      total: cves.length,
      critical: cves.filter(c => c.severity === "CRITICAL").length,
      high: cves.filter(c => c.severity === "HIGH").length,
    };

    return json({
      tecnologia: techRaw,
      version,
      estado: status,
      latestVersion: latest,
      latestSupportedVersion: latestSupported,
      cves,
      resumen: summary,
      fuentes: ["https://endoflife.date", "https://nvd.nist.gov"],
    });
  } catch (e) {
    return json({ error: "Error interno", detail: e.message }, 500);
  }
}

// ======================= RESPONSE HELP =======================
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
