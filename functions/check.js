export async function onRequest({ request }) {
  const url = new URL(request.url);
  const tech = url.searchParams.get("tec");
  const version = url.searchParams.get("ver");

  if (!tech || !version) {
    return json({ error: "Faltan parámetros" }, 400);
  }

  // =========================
  // SOPORTE (endoflife.date)
  // =========================
  let soporte = {
    estado: "SOPORTE NO CONFIRMADO",
    latest: "-"
  };

  try {
    const eolRes = await fetch(`https://endoflife.date/api/${tech}.json`);
    if (eolRes.ok) {
      const data = await eolRes.json();
      const latest = data.find(d => d.latest)?.latest;
      soporte.latest = latest || "-";
      soporte.estado = "CON SOPORTE";
    }
  } catch {}

  // =========================
  // CVE – SOLO CPE EXACTO
  // =========================
  const cves = [];

  try {
    const nvdRes = await fetch(
      "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=2000"
    );
    const nvd = await nvdRes.json();

    for (const v of nvd.vulnerabilities || []) {
      const cve = v.cve;

      for (const conf of cve.configurations || []) {
        for (const node of conf.nodes || []) {
          for (const match of node.cpeMatch || []) {

            if (
              match.vulnerable === true &&
              match.criteria.includes(`:${tech}:`) &&
              match.criteria.endsWith(`:${version}`)
            ) {
              const cvss =
                cve.metrics?.cvssMetricV31?.[0]?.cvssData ||
                cve.metrics?.cvssMetricV30?.[0]?.cvssData ||
                null;

              cves.push({
                id: cve.id,
                severity: cvss?.baseSeverity || "UNKNOWN",
                score: cvss?.baseScore || "N/A"
              });
            }
          }
        }
      }
    }
  } catch {}

  return json({
    tecnologia: tech,
    version,
    soporte,
    cves
  });
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}
