async function analyze() {
  const tech = document.getElementById("tech").value.toLowerCase();
  const version = document.getElementById("version").value;
  const result = document.getElementById("result");

  result.innerHTML = "Analizando…";

  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${tech}`;
  const res = await fetch(url);
  const data = await res.json();

  const applicable = [];

  for (const item of data.vulnerabilities || []) {
    const cve = item.cve;

    for (const conf of cve.configurations || []) {
      for (const node of conf.nodes || []) {
        for (const match of node.cpeMatch || []) {

          if (!match.criteria.toLowerCase().includes(tech)) continue;

          const start = match.versionStartIncluding || match.versionStartExcluding;
          const end = match.versionEndIncluding || match.versionEndExcluding;

          if (isVersionAffected(version, start, end)) {
            applicable.push({
              id: cve.id,
              score: cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore || "N/A"
            });
          }
        }
      }
    }
  }

  render(version, applicable);
}

function isVersionAffected(target, start, end) {
  const t = normalize(target);
  if (start && t < normalize(start)) return false;
  if (end && t > normalize(end)) return false;
  return true;
}

function normalize(v) {
  return v.split(".").map(n => n.padStart(3, "0")).join("");
}

function render(version, cves) {
  let html = `<h3>Versión analizada: ${version}</h3>`;
  html += `<p>Total CVE aplicables: <b>${cves.length}</b></p>`;

  if (cves.length === 0) {
    html += `<span style="color:green;font-weight:bold">Sin CVE aplicables</span>`;
  } else {
    html += `<ul>`;
    for (const c of cves.slice(0, 10)) {
      html += `<li>${c.id} – Score ${c.score}</li>`;
    }
    html += `</ul>`;
  }

  document.getElementById("result").innerHTML = html;
}
