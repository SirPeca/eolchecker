const btn = document.getElementById("btn");
const btnExample = document.getElementById("btnExample");
const output = document.getElementById("output");

// ============================
// CLICK PRINCIPAL
// ============================
btn.addEventListener("click", async () => {
  const tech = document.getElementById("tech").value.trim();
  const version = document.getElementById("version").value.trim();
  const ecosystem = document.getElementById("ecosystem").value;

  if (!tech || !version) {
    output.textContent = "⚠️ Complete tech and version";
    return;
  }

  output.textContent = "Scanning...";

  try {
    const res = await fetch(`/check?tech=${tech}&version=${version}&ecosystem=${ecosystem}`);

    const text = await res.text();

    let data;
    try {
      data = JSON.parse(text);
    } catch {
      output.textContent = "❌ Backend error:\n\n" + text;
      return;
    }

    output.innerHTML = formatReport(data);

  } catch (err) {
    output.textContent = "❌ Network error: " + err.message;
  }
});

// ============================
// BOTÓN EJEMPLO
// ============================
btnExample.addEventListener("click", () => {
  document.getElementById("tech").value = "jquery";
  document.getElementById("version").value = "3.3.1";
});

// ============================
// COLOR RIESGO
// ============================
function getColor(level) {
  return {
    CRITICAL: "#ff4d4d",
    HIGH: "#ff944d",
    MEDIUM: "#ffd24d",
    LOW: "#4dff88"
  }[level] || "#ccc";
}

// ============================
// FORMATO PRO
// ============================
function formatReport(data) {
  if (!data.success) return `<pre>${JSON.stringify(data, null, 2)}</pre>`;

  const riskColor = getColor(data.risk.level);

  return `
  <div style="border-left:5px solid ${riskColor}; padding-left:10px">

    <h3>🎯 Target</h3>
    <p>${data.target.tech} ${data.target.version}</p>

    <h3>📦 EOL</h3>
    <p>Status: <b>${data.eol.status}</b><br>
    Latest: ${data.eol.latest || "N/A"}</p>

    <h3 style="color:${riskColor}">🔥 Risk: ${data.risk.level}</h3>

    <h3>🧨 Vulnerabilities (${data.vulns.total})</h3>

    ${data.vulns.list.map(v => `
      <div style="border:1px solid #30363d; padding:8px; margin-bottom:5px">
        <b>${v.id}</b><br>
        Severity: ${v.severity}<br>
        KEV: ${v.kev ? "🔥 YES" : "NO"}
      </div>
    `).join("")}

  </div>
  `;
}
