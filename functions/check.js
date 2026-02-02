/**
 * Checker de soporte y CVEs
 * - End-of-Life desde endoflife.date
 * - CVEs reales desde NVD JSON feeds (public feed, no API key)
 * - Devuelve todos los CVEs encontrados para la versión solicitada
 */

export async function onRequest({ request }) {
  try {
    const url = new URL(request.url);
    const tec = url.searchParams.get("tec")?.trim();
    const ver = url.searchParams.get("ver")?.trim();

    if (!tec || !ver) {
      return new Response(
        JSON.stringify({ error: "Parámetros requeridos: tec, ver" }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    }

    // --- 1. End-of-Life ---
    let cycle = null;
    let verdict = "CON SOPORTE";
    try {
      const eolRes = await fetch(`https://endoflife.date/api/${encodeURIComponent(tec.toLowerCase())}.json`);
      if (eolRes.ok) {
        const cycles = await eolRes.json();
        const majorVer = ver.split(".")[0];
        cycle = cycles.find(c => String(c.cycle).startsWith(majorVer));
        const eolDate = cycle?.eol ? new Date(cycle.eol) : null;
        if (eolDate && eolDate < new Date()) verdict = "OBSOLETA";
      }
    } catch (e) {
      console.log("EOL fetch error:", e.message);
    }

    // --- 2. CVEs desde NVD JSON feed ---
    let cves = [];
    try {
      // Construimos la query simple: keyword=tec+ver
      const nvdUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0?keyword=${encodeURIComponent(tec)}+${encodeURIComponent(ver)}`;
      const nvdRes = await fetch(nvdUrl);
      if (nvdRes.ok) {
        const data = await nvdRes.json();
        if (data.vulnerabilities && Array.isArray(data.vulnerabilities)) {
          cves = data.vulnerabilities.map(v => ({
            id: v.cve.id,
            url: `https://nvd.nist.gov/vuln/detail/${v.cve.id}`,
            severity: v.cve.metrics?.cvssMetricV3?.[0]?.cvssData?.baseSeverity || 'NA',
            score: v.cve.metrics?.cvssMetricV3?.[0]?.cvssData?.baseScore || '-',
            published: v.cve.published
          }));
        }
      }
    } catch (e) {
      console.log("NVD fetch error:", e.message);
    }

    // --- 3. Response final ---
    return new Response(JSON.stringify({
      tecnologia: tec,
      version: ver,
      veredicto: verdict,
      ciclo: cycle || null,
      fuentes: ["https://endoflife.date", "https://nvd.nist.gov"],
      cves
    }), { headers: { "Content-Type": "application/json" } });

  } catch (err) {
    return new Response(JSON.stringify({
      error: "Error interno",
      detail: err.message
    }), { status: 500, headers: { "Content-Type": "application/json" } });
  }
}
