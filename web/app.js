// app.js (frontend)
async function analyze() {
  const tech = document.getElementById("tech").value.trim();
  const version = document.getElementById("version").value.trim();
  const out = document.getElementById("output");
  out.innerHTML = "";

  if (!tech || !version) {
    out.innerHTML = `<div class="result warn"><strong>Faltan datos</strong><p>Ingresá tecnología y versión.</p></div>`;
    return;
  }

  out.innerHTML = `<div class="result info"><strong>Consultando…</strong><p>Buscando soporte y CVEs.</p></div>`;

  try {
    const url = `/api/check?product=${encodeURIComponent(tech)}&version=${encodeURIComponent(version)}`;
    const res = await fetch(url);
    const data = await res.json();

    if (!res.ok) {
      out.innerHTML = `<div class="result bad"><strong>Error</strong><pre>${escapeHtml(JSON.stringify(data, null, 2))}</pre></div>`;
      return;
    }

    const state = data?.Description?.state || "unknown";
    const css = state.includes("obsolete") ? "bad" : (state.includes("outdated") ? "warn" : "ok");

    out.innerHTML = `
      <div class="result ${css}">
        <h3 style="margin-top:0">${escapeHtml(data.Title || `${tech}, ${version}, ${state}`)}</h3>

        <h4>Description</h4>
        <p><strong>State:</strong> ${escapeHtml(state)}</p>
        <p><strong>EOL:</strong> ${escapeHtml(String(data?.Description?.support?.eol ?? "N/A"))}</p>
        <p><strong>Support until:</strong> ${escapeHtml(String(data?.Description?.support?.supportUntil ?? "N/A"))}</p>
        <p><strong>Latest:</strong> ${escapeHtml(String(data?.Description?.support?.latest ?? "N/A"))}</p>

        <h4>Evidence support</h4>
        <pre>${escapeHtml(JSON.stringify(data["Evidence support"] || {}, null, 2))}</pre>

        <h4>CVE code list</h4>
        <p>${(data["CVE code list"] || []).length ? (data["CVE code list"] || []).map(escapeHtml).join(", ") : "Sin CVEs detectados (best-effort)."}</p>

        <h4>Impact</h4>
        <p>${escapeHtml(data.Impact || "")}</p>

        <h4>Recomendation</h4>
        <p>${escapeHtml(data.Recomendation || "")}</p>

        <h4>Red team perspective</h4>
        <ul>${(data["Red team perspective"] || []).map(x => `<li>${escapeHtml(x)}</li>`).join("")}</ul>

        <h4>Blue team perspective</h4>
        <ul>${(data["Blue team perspective"] || []).map(x => `<li>${escapeHtml(x)}</li>`).join("")}</ul>

        <hr/>
        <p><strong>Disclaimer:</strong> ${escapeHtml(data.Disclaimer || "")}</p>
      </div>
    `;
  } catch (e) {
    out.innerHTML = `<div class="result bad"><strong>Error de red</strong><p>${escapeHtml(String(e))}</p></div>`;
  }
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
  }[c]));
}

// botón
window.analyze = analyze;
