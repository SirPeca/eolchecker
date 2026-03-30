const btn = document.getElementById("btn");
const btnExample = document.getElementById("btnExample");
const output = document.getElementById("output");

btn.addEventListener("click", async () => {
  const tech = document.getElementById("tech").value.trim();
  const version = document.getElementById("version").value.trim();
  const ecosystem = document.getElementById("ecosystem").value;

  if (!tech || !version) {
    output.textContent = "⚠️ Complete tech and version";
    return;
  }

  output.textContent = "Consulting...";

  try {
    const res = await fetch(`/api/check?tech=${tech}&version=${version}&ecosystem=${ecosystem}`);
    const data = await res.json();

    output.textContent = formatReport(data);

  } catch (err) {
    output.textContent = "Error: " + err.message;
  }
});

btnExample.addEventListener("click", () => {
  document.getElementById("tech").value = "jquery";
  document.getElementById("version").value = "3.3.1";
});

function formatReport(data) {
  if (!data.success) return JSON.stringify(data, null, 2);

  return `
===============================
EOL & CVE SECURITY REPORT
===============================

Target:
  Technology: ${data.target.tech}
  Version:    ${data.target.version}

--------------------------------
EOL STATUS
--------------------------------
  Status: ${data.eol.status}
  Latest: ${data.eol.latest || "N/A"}

--------------------------------
VULNERABILITIES
--------------------------------
  Total CVEs: ${data.vulns.total}

${data.vulns.list.map(v => `
  - ${v.id}
    Severity: ${v.severity}
    KEV: ${v.kev ? "YES (Exploited)" : "NO"}
`).join("")}

--------------------------------
RISK ASSESSMENT
--------------------------------
  Risk Level: ${data.risk.level}

===============================
`;
}
