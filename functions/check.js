/**
 * Check EOL + CVEs
 * Sources: endoflife.date (EOL), MITRE CVE public feed (scraping ligero)
 */

export async function onRequest({ request }) {
  try {
    const url = new URL(request.url);
    const tec = url.searchParams.get("tec")?.trim();
    const ver = url.searchParams.get("ver")?.trim();
    const sevFilter = url.searchParams.get("sev")?.toUpperCase();

    if (!tec || !ver) {
      return new Response(
        JSON.stringify({ error: "Parámetros requeridos: tec, ver" }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    }

    // --- 1. End-of-Life check ---
    const eolRes = await fetch(`https://endoflife.date/api/${encodeURIComponent(tec.toLowerCase())}.json`);
    if (!eolRes.ok) {
      return new Response(
        JSON.stringify({ error: "Tecnología no encontrada en endoflife.date" }),
        { status: 404, headers: { "Content-Type": "application/json" } }
      );
    }
    const cycles = await eolRes.json();
    const majorVer = ver.split(".")[0];
    const cycle = cycles.find(c => String(c.cycle).startsWith(majorVer));
    const now = new Date();
    const eolDate = cycle?.eol ? new Date(cycle.eol) : null;
    const verdict = eolDate && eolDate < now ? "OBSOLETA" : "CON SOPORTE";

    // --- 2. CVEs reales desde MITRE ---
    let cves = [];
    try {
      // MITRE CVE search query: https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=<tec>+<ver>
      const searchUrl = `https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=${encodeURIComponent(tec)}+${encodeURIComponent(ver)}`;
      const html = await fetch(searchUrl).then(r => r.text());

      // Regex ligero para capturar los CVE IDs y links
      const regex = /<a href="(\/cgi-bin\/CVEkey\.cgi\?keyword=CVE-\d+-\d+)">((CVE-\d+-\d+))<\/a>/g;
      let match;
      while ((match = regex.exec(html)) !== null) {
        cves.push({
          id: match[3],
          url: `https://cve.mitre.org${match[1]}`,
          severity: 'NA',   // MITRE no da score directo
          score: '-',       // se puede integrar CVSS de NVD si se quiere
          published: '-'
        });
      }

      // Filtrar severidad si se indica HIGH/CRITICAL (solo placeholder, MITRE no tiene score en la página)
      if (sevFilter) {
        // En este ejemplo no filtramos porque no hay severidad en MITRE HTML
        // Puedes integrar CVSS de NVD para filtrar si quieres
      }

    } catch(e) {
      console.log("Error fetching CVEs MITRE:", e.message);
    }

    // --- 3. Response final ---
    return new Response(JSON.stringify({
      tecnologia: tec,
      version: ver,
      veredicto: verdict,
      ciclo: cycle || null,
      fuentes: ["https://endoflife.date", "https://cve.mitre.org"],
      cves
    }), { headers: { "Content-Type": "application/json" } });

  } catch (err) {
    return new Response(JSON.stringify({
      error: "Error interno",
      detail: err.message
    }), { status: 500, headers: { "Content-Type": "application/json" } });
  }
}
