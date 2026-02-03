const NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0";

const SEVERITY_ORDER = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1
};

function normalizeSeverity(cve) {
  return (
    cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity ||
    cve.metrics?.cvssMetricV30?.[0]?.cvssData?.baseSeverity ||
    cve.metrics?.cvssMetricV2?.[0]?.baseSeverity ||
    "UNKNOWN"
  );
}

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);

  const tech = url.searchParams.get("tech")?.toLowerCase().trim();
  const version = url.searchParams.get("version")?.trim();

  if (!tech || !version) {
    return new Response(
      JSON.stringify({ error: "Missing parameters" }),
      { status: 400, headers: { "Cache-Control": "no-store" } }
    );
  }

  const cpe = `cpe:2.3:a:${tech}:${tech}:${version}:*:*:*:*:*:*:*`;
  const apiUrl = `${NVD_API}?cpeName=${encodeURIComponent(cpe)}&resultsPerPage=50`;

  let cves = [];

  try {
    const res = await fetch(apiUrl, {
      headers: env.API_KEY ? { apiKey: env.API_KEY } : {}
    });

    const data = await res.json();

    cves = (data.vulnerabilities || []).map(v => {
      const cve = v.cve;
      const severity = normalizeSeverity(cve);

      return {
        id: cve.id,
        severity,
        description: cve.descriptions?.[0]?.value || "No description",
        score:
          cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore ||
          cve.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore ||
          null,
        url: `https://nvd.nist.gov/vuln/detail/${cve.id}`
      };
    });

  } catch (err) {
    return new Response(
      JSON.stringify({
        technology: tech,
        version,
        cves: [],
        error: "NVD unavailable"
      }),
      { headers: { "Cache-Control": "no-store" } }
    );
  }

  cves.sort(
    (a, b) =>
      (SEVERITY_ORDER[b.severity] || 0) -
      (SEVERITY_ORDER[a.severity] || 0)
  );

  const summary = {
    total: cves.length,
    CRITICAL: cves.filter(c => c.severity === "CRITICAL").length,
    HIGH: cves.filter(c => c.severity === "HIGH").length,
    MEDIUM: cves.filter(c => c.severity === "MEDIUM").length,
    LOW: cves.filter(c => c.severity === "LOW").length
  };

  return new Response(
    JSON.stringify({
      technology: tech,
      version,
      latest_version: tech === "jquery" ? "3.7.1" : "1.1.1w",
      latest_supported_version: tech === "jquery" ? "3.7.1" : "1.1.1w",
      summary,
      cves
    }),
    {
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"
      }
    }
  );
}
