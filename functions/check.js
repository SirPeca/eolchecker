export async function onRequest({ request }) {
  try {
    const url = new URL(request.url);
    const techRaw = url.searchParams.get("tec");
    const versionRaw = url.searchParams.get("ver");

    if (!techRaw || !versionRaw) {
      return json({ error: "Parámetros requeridos: tec, ver" }, 400);
    }

    const tech = techRaw.trim().toLowerCase();
    const version = versionRaw.trim();

    /* =======================
       1️⃣ END OF LIFE CHECK
    ======================= */
    let eolData = null;
    try {
      const eolRes = await fetch(`https://endoflife.date/api/${tech}.json`, { cf: { cacheTtl: 3600 } });
      if (eolRes.ok) {
        eolData = await eolRes.json();
      }
    } catch {}

    let cycle = null;
    let latest = null;
    let latestSupported = null;
    let status = "DESCONOCIDO";

    if (Array.isArray(eolData)) {
      latest = eolData.find(c => c.latest)?.latest || null;
      latestSupported = eolData.find(c => !c.eol || new Date(c.eol) > new Date())?.latest || null;

      cycle = eolData.find(c =>
        c.cycle && version.startsWith(String(c.cycle))
      );

      if (cycle?.eol) {
        status = new Date(cycle.eol) < new Date() ? "FUERA DE SOPORTE" : "CON SOPORTE";
      }
    }

    if (latest && latestSupported && version !== latestSupported) {
      status = status === "CON SOPORTE" ? "DESACTUALIZADO" : status;
    }

    /* =======================
       2️⃣ NVD CVE SEARCH
    ======================= */
    const cveRes = await fetch(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(
        tech
      )}&resultsPerPage=200`
    );

    let cves = [];
    if (cveRes.ok) {
      const cveJson = await cveRes.json();

      cves = (cveJson.vulnerabilities || [])
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
            url: `https://nvd.nist.gov/vuln/detail/${cve.id}`
          };
        })
        .filter(c =>
          c.description.toLowerCase().includes(tech) &&
          c.description.includes(version)
        );
    }

    /* =======================
       3️⃣ ORDER & SUMMARY
    ======================= */
    const order = { CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 4, UNKNOWN: 5 };
    cves.sort((a, b) => order[a.severity] - order[b.severity]);

    const summary = {
      total: cves.length,
      critical: cves.filter(c => c.severity === "CRITICAL").length,
      high: cves.filter(c => c.severity === "HIGH").length
    };

    return json({
      tecnologia: techRaw,
      version,
      estado: status,
      latestVersion: latest,
      latestSupportedVersion: latestSupported,
      ciclo: cycle || null,
      cves,
      resumen: summary,
      fuentes: ["https://endoflife.date", "https://nvd.nist.gov"]
    });

  } catch (e) {
    return json({ error: "Error interno", detail: e.message }, 500);
  }
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}
