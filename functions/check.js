const CATALOG = {
  openssl: {
    cpe: "cpe:2.3:a:openssl:openssl",
    latest: "3.6.1",
    supported: "3.6.1",
    eolBelow: "1.1.1",
  },
  bootstrap: {
    cpe: "cpe:2.3:a:twbs:bootstrap",
    latest: "5.3.8",
    supported: "5.3.8",
    eolBelow: "4.0.0",
  },
  jquery: {
    cpe: "cpe:2.3:a:jquery:jquery",
    latest: "3.7.1",
    supported: "3.7.1",
    eolBelow: "3.0.0",
  },
  vue: {
    cpe: "cpe:2.3:a:vuejs:vue",
    latest: "3.4.27",
    supported: "3.4.27",
    eolBelow: "2.7.0",
  }
  // 👉 aquí se agregan las top 100 sin tocar la lógica
};

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

document.getElementById("checkBtn").addEventListener("click", runCheck);

async function runCheck() {
  const tech = document.getElementById("technology").value.trim().toLowerCase();
  const version = document.getElementById("version").value.trim();
  const severityFilter = document.getElementById("severity").value;
  const result = document.getElementById("result");

  result.innerHTML = "<div class='alert alert-info'>Consultando…</div>";

  if (!tech || !version) {
    result.innerHTML = "<div class='alert alert-warning'>Complete tecnología y versión.</div>";
    return;
  }

  const catalog = CATALOG[tech];
  let statusText = "Estado desconocido";
  let statusClass = "";

  if (catalog) {
    if (compare(version, catalog.eolBelow) < 0) {
      statusText = "❌ Software fuera de soporte (EOL)";
      statusClass = "status-eol";
    } else if (version !== catalog.latest) {
      statusText = "⚠️ Software desactualizado";
      statusClass = "status-outdated";
    } else {
      statusText = "✅ Software soportado";
      statusClass = "status-supported";
    }
  }

  let cves = [];
  if (catalog) {
    cves = await fetchCVEs(catalog.cpe, version);
  }

  if (severityFilter !== "ALL") {
    cves = cves.filter(c => c.severity === severityFilter);
  }

  cves.sort((a, b) =>
    SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );

  const summary = {
    total: cves.length,
    CRITICAL: cves.filter(c => c.severity === "CRITICAL").length,
    HIGH: cves.filter(c => c.severity === "HIGH").length,
  };

  let html = `
  <div class="card p-4">
    <p><strong>Última versión publicada:</strong> ${catalog?.latest ?? "No disponible"}</p>
    <p><strong>Última versión con soporte:</strong> ${catalog?.supported ?? "No disponible"}</p>
    <p class="${statusClass}">${statusText}</p>
    <hr>
    <p><strong>Total CVEs:</strong> ${summary.total} |
       CRITICAL: ${summary.CRITICAL} |
       HIGH: ${summary.HIGH}</p>
  `;

  if (cves.length === 0) {
    html += `<div class="alert alert-success">No se encontraron CVEs relevantes.</div>`;
  } else {
    cves.forEach(cve => {
      html += `
      <div class="mb-3">
        <span class="badge badge-${cve.severity.toLowerCase()}">${cve.severity}</span>
        <strong>${cve.id}</strong><br>
        ${cve.desc}<br>
        <a href="https://nvd.nist.gov/vuln/detail/${cve.id}" target="_blank">Ver en NVD</a>
      </div>`;
    });
  }

  html += "</div>";
  result.innerHTML = html;
}

async function fetchCVEs(cpe, version) {
  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=${cpe}:${version}`;
  try {
    const res = await fetch(url);
    const data = await res.json();
    if (!data.vulnerabilities) return [];

    return data.vulnerabilities.map(v => ({
      id: v.cve.id,
      severity: v.cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity || "LOW",
      desc: v.cve.descriptions[0].value
    }));
  } catch {
    return [];
  }
}

function compare(a, b) {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const diff = (pa[i] || 0) - (pb[i] || 0);
    if (diff !== 0) return diff;
  }
  return 0;
}
