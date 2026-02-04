async function analyze() {
  const product = document.getElementById("product").value.trim();
  const version = document.getElementById("version").value.trim();
  const output = document.getElementById("output");

  output.innerHTML = "";

  if (!product || !version) {
    toastr.error("Completá tecnología y versión");
    return;
  }

  toastr.info("Buscando CVEs…");

  try {
    const url = `https://cve.circl.lu/api/search/${encodeURIComponent(product)}/${encodeURIComponent(version)}`;
    const res = await fetch(url);

    if (!res.ok) {
      throw new Error("Error consultando CIRCL");
    }

    const data = await res.json();
    const cves = data.data || [];

    let html = `
      <h3>Resultado</h3>
      <p><b>Tecnología:</b> ${product}</p>
      <p><b>Versión:</b> ${version}</p>
      <p><b>Estado de soporte:</b> <i>Unknown (best-effort)</i></p>
      <p><b>Total CVE:</b> ${cves.length}</p>
    `;

    if (cves.length === 0) {
      html += `<p>No se encontraron CVEs conocidas.</p>`;
    } else {
      cves.slice(0, 20).forEach(cve => {
        html += `
          <div class="cve">
            <b>${cve.id}</b><br/>
            Score: ${cve.cvss || "N/A"}<br/>
            ${cve.summary || ""}
          </div>
        `;
      });
    }

    output.innerHTML = html;
    toastr.success("Análisis completo");

  } catch (err) {
    console.error(err);
    toastr.error("No se pudieron obtener CVEs");
  }
}
