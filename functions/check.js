export async function onRequest(context) {
  const url = new URL(context.request.url);
  const tech = url.searchParams.get("tec");
  const version = url.searchParams.get("ver");

  if (!tech || !version) {
    return new Response(
      JSON.stringify({ error: "Faltan parámetros" }),
      { status: 400 }
    );
  }

  // ===============================
  // 1. END OF LIFE
  // ===============================
  let support = {
    estado: "SOPORTE NO CONFIRMADO",
    latest: "-",
    eol: null
  };

  try {
    const eolRes = await fetch(`https://endoflife.date/api/${tech}.json`);
    if (eolRes.ok) {
      const data = await eolRes.json();
      const latest = data.find(d => d.latest)?.latest;
      const match = data.find(d => d.cycle === version.split(".")[0]);

      support.latest = latest || "-";

      if (match?.eol && new Date(match.eol) < new Date()) {
        support.estado = "FUERA DE SOPORTE";
        support.eol = match.eol;
      } else {
        support.estado = "CON SOPORTE";
      }
    }
  } catch (_) {}

  // ===============================
  // 2. CVE – SOLO APLICABLES
  // ===============================
  const cveAplicables = [];

  try {
    const nvdRes = await fetch(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${tech}`
    );
    const nvd = await nvdRes.json();

    for (const item of nvd.vulnerabilities || []) {
      const cve = item.cve;
      const configs = cve.configurations || [];

      for (const conf of configs) {
        for (const node of conf.nodes || []) {
          for (const match of node.cpeMatch || []) {
            if (!match.versionStartIncluding && !match.versionEndExcluding) continue;

            const start = match.versionStartIncluding || "0";
            const end = match.versionEndExcluding || "9999";

            if (version >= start && version < end) {
              cveAplicables.push({
                id: cve.id,
                score: cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore || "N/A",
                severity: cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity || "UNKNOWN"
              });
            }
          }
        }
      }
    }
  } catch (_) {}

  // Deduplicar
  const unique = Object.values(
    Object.fromEntries(cveAplicables.map(c => [c.id, c]))
  );

  return new Response(
    JSON.stringify({
      tecnologia: tech,
      version,
      soporte: support,
      cves: unique
    }),
    { headers: { "Content-Type": "application/json" } }
  );
}
