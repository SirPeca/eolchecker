export async function onRequest({ request }) {
  const url = new URL(request.url);
  const tech = url.searchParams.get("tec");
  const version = url.searchParams.get("ver");

  if (!tech || !version) {
    return json({ error: "Parámetros incompletos" }, 400);
  }

  // ================= SOPORTE =================
  let soporte = {
    estado: "SOPORTE NO CONFIRMADO",
    latest: "-"
  };

  try {
    const eol = await fetch(`https://endoflife.date/api/${tech}.json`);
    if (eol.ok) {
      const data = await eol.json();
      soporte.estado = "CON SOPORTE";
      soporte.latest = data.find(d => d.latest)?.latest || "-";
    }
  } catch {}

  // ================= CVE =================
  const cves = [];

  try {
    const res = await fetch(
      "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=2000"
    );
    const jsonNvd = await res.json();

    for (const v of jsonNvd.vulnerabilities || []) {
      const cve = v.cve;

      for (const conf of cve.configurations || []) {
        for (const node of conf.nodes || []) {
          for (const match of node.cpeMatch || []) {

            if (!match.vulnerable) continue;
            if (!match.criteria.includes(`:${tech}:`)) continue;

            // ---- RANGOS ----
            if (
              match.versionStartIncluding ||
              match.versionEndIncluding ||
              match.versionEndExcluding
            ) {
              if (
                (!match.versionStartIncluding || version >= match.versionStartIncluding) &&
                (!match.versionEndIncluding || version <= match.versionEndIncluding) &&
                (!match.versionEndExcluding || version < match.versionEndExcluding)
              ) {
                pushCVE(cves, cve);
              }
            }
            // ---- SIN RANGO ----
            else if (match.criteria.includes(`:${version}`)) {
              pushCVE(cves, cve);
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
    totalCVE: cves.length,
    cves
  });
}

function pushCVE(arr, cve) {
  const cvss =
    cve.metrics?.cvssMetricV31?.[0]?.cvssData ||
    cve.metrics?.cvssMetricV30?.[0]?.cvssData ||
    null;

  arr.push({
    id: cve.id,
    severity: cvss?.baseSeverity || "UNKNOWN",
    score: cvss?.baseScore || "N/A"
  });
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}
