/**
 * EOL & CVE Checker – Final Professional Version
 * Fuentes:
 *  - End of Life: endoflife.date
 *  - CVEs: NVD (CPE amplio + filtrado propio)
 */

const SEVERITY_ORDER = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  NA: 0
};

export async function onRequest({ request }) {
  try {
    const { searchParams } = new URL(request.url);
    const tec = searchParams.get("tec")?.trim();
    const ver = searchParams.get("ver")?.trim();

    if (!tec || !ver) {
      return json({ error: "Parámetros requeridos: tec, ver" }, 400);
    }

    /* =========================
       1️⃣ END OF LIFE
       ========================= */
    let ciclo = null;
    let veredicto = "CON SOPORTE";
    let ultimaVersionConSoporte = null;
    let ultimaVersionPublicada = null;

    try {
      const eolRes = await fetch(
        `https://endoflife.date/api/${encodeURIComponent(tec.toLowerCase())}.json`
      );

      if (eolRes.ok) {
        const cycles = await eolRes.json();
        const major = ver.split(".")[0];

        ciclo = cycles.find(c => String(c.cycle).startsWith(major)) || null;

        // Última versión publicada (global)
        ultimaVersionPublicada =
          cycles.map(c => c.latest).filter(Boolean).sort().at(-1) || null;

        // Última versión con soporte vigente
        const soportados = cycles.filter(
          c => c.support && new Date(c.support) > new Date()
        );

        ultimaVersionConSoporte =
          soportados.map(c => c.latest).filter(Boolean).sort().at(-1) || null;

        if (ciclo?.eol && new Date(ciclo.eol) < new Date()) {
          veredicto = "OBSOLETA";
        }
      }
    } catch (e) {
      console.log("EOL error:", e.message);
    }

    /* =========================
       2️⃣ CVEs – NVD
       ========================= */
    const product = tec.toLowerCase().replace(/\s+/g, "_");
    const cpePrefix = `cpe:2.3:a:${product}:${product}`;

    const nvdUrl =
      `https://services.nvd.nist.gov/rest/json/cves/2.0` +
      `?resultsPerPage=200&cpeName=${encodeURIComponent(`${cpePrefix}:*`)}`;

    let cves = [];

    try {
      const nvdRes = await fetch(nvdUrl);
      if (nvdRes.ok) {
        const data = await nvdRes.json();

        cves = (data.vulnerabilities || [])
          .map(v => {
            const metrics =
              v.cve.metrics?.cvssMetricV31?.[0] ||
              v.cve.metrics?.cvssMetricV30?.[0] ||
              v.cve.metrics?.cvssMetricV2?.[0];

            return {
              id: v.cve.id,
              url: `https://nvd.nist.gov/vuln/detail/${v.cve.id}`,
              severity: metrics?.cvssData?.baseSeverity || "NA",
              score: metrics?.cvssData?.baseScore || "-",
              published: v.cve.published,
              description: v.cve.descriptions?.[0]?.value || ""
            };
          })
          // Filtro por versión mencionada (clave para legacy)
          .filter(c =>
            c.description.toLowerCase().includes(ver.toLowerCase())
          );
      }
    } catch (e) {
      console.log("NVD error:", e.message);
    }

    /* =========================
       3️⃣ SORT & SUMMARY
       ========================= */
    cves.sort(
      (a, b) =>
        (SEVERITY_ORDER[b.severity] ?? 0) -
        (SEVERITY_ORDER[a.severity] ?? 0)
    );

    const summary = {
      total: cves.length,
      CRITICAL: cves.filter(c => c.severity === "CRITICAL").length,
      HIGH: cves.filter(c => c.severity === "HIGH").length,
      MEDIUM: cves.filter(c => c.severity === "MEDIUM").length,
      LOW: cves.filter(c => c.severity === "LOW").length
    };

    /* =========================
       4️⃣ RESPONSE
       ========================= */
    return json({
      tecnologia: tec,
      version: ver,
      veredicto,
      ciclo,
      ultima_version_con_soporte: ultimaVersionConSoporte,
      ultima_version_publicada: ultimaVersionPublicada,
      summary,
      cves,
      fuentes: [
        "https://endoflife.date",
        "https://nvd.nist.gov"
      ]
    });

  } catch (err) {
    return json(
      { error: "Error interno", detail: err.message },
      500
    );
  }
}

/* =========================
   Helper
   ========================= */
function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}
