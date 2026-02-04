export async function onRequest({ request }) {
  const url = new URL(request.url);
  const tech = url.searchParams.get("tec")?.toLowerCase();
  const version = url.searchParams.get("ver");

  if (!tech || !version) {
    return json({ error: "Parámetros requeridos" }, 400);
  }

  let estado = "DESCONOCIDO";
  let estadoColor = "gray";
  let mensajeSoporte = "No se dispone de información oficial de ciclo de vida para esta tecnología.";

  // ---------- END OF LIFE ----------
  try {
    const eol = await fetch(`https://endoflife.date/api/${tech}.json`);
    if (eol.ok) {
      const data = await eol.json();
      const cycle = data.find(c => c.cycle && version.startsWith(c.cycle));

      if (cycle?.eol) {
        if (new Date(cycle.eol) < new Date()) {
          estado = "FUERA DE SOPORTE";
          estadoColor = "red";
          mensajeSoporte = `El soporte finalizó el ${cycle.eol}.`;
        } else {
          estado = "CON SOPORTE";
          estadoColor = "green";
          mensajeSoporte = `La versión se encuentra dentro del período de soporte.`;
        }
      }
    }
  } catch {}

  // ---------- CVEs ----------
  let cves = [];
  let mensajeCVE =
    "Las vulnerabilidades listadas corresponden al producto según NVD. NVD no permite garantizar asociación exacta por versión.";

  try {
    const res = await fetch(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${tech}&resultsPerPage=50`
    );

    if (res.ok) {
      const json = await res.json();
      cves = (json.vulnerabilities || []).map(v => {
        const cve = v.cve;
        const cvss =
          cve.metrics?.cvssMetricV31?.[0]?.cvssData ||
          cve.metrics?.cvssMetricV30?.[0]?.cvssData;

        return {
          id: cve.id,
          severity: cvss?.baseSeverity || "UNKNOWN",
          url: `https://nvd.nist.gov/vuln/detail/${cve.id}`
        };
      });
    }
  } catch {}

  return json({
    tecnologia: tech,
    version,
    estado,
    estadoColor,
    mensajeSoporte,
    mensajeCVE,
    cves
  });
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}
