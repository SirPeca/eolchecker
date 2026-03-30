function getColor(level) {
  return {
    CRITICAL: "#ff4d4d",
    HIGH: "#ff944d",
    MEDIUM: "#ffd24d",
    LOW: "#4dff88"
  }[level] || "#ccc";
}

function formatReport(data) {
  if (!data.success) return JSON.stringify(data, null, 2);

  const riskColor = getColor(data.risk.level);

  return `
TARGET
------
${data.target.tech} ${data.target.version}

EOL
---
Status: ${data.eol.status}
Latest: ${data.eol.latest || "N/A"}

RISK
----
Level: ${data.risk.level}

VULNERABILITIES (${data.vulns.total})
------------------------------------

${data.vulns.list.map(v => `
${v.id}
  Severity: ${v.severity}
  KEV: ${v.kev ? "🔥 YES" : "NO"}
`).join("")}
`;
}
