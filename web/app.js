const productInput = document.getElementById("product");
const versionInput = document.getElementById("version");
const checkBtn = document.getElementById("checkBtn");
const formMessage = document.getElementById("formMessage");
const resultsPanel = document.getElementById("results");
const cveList = document.getElementById("cveList");
const supportBadge = document.getElementById("supportBadge");

checkBtn.addEventListener("click", async () => {
  const product = productInput.value.trim().toLowerCase();
  const version = versionInput.value.trim();

  formMessage.textContent = "";
  cveList.innerHTML = "";
  resultsPanel.style.display = "none";

  if (!product || !version) {
    formMessage.textContent = "Debe ingresar producto y versión.";
    return;
  }

  checkBtn.disabled = true;
  formMessage.textContent = "Consultando CVEs...";
  formMessage.className = "message loading";

  supportBadge.textContent = "Support: Unknown";
  supportBadge.className = "badge unknown";

  try {
    const response = await fetch(
      `https://cve.circl.lu/api/search/${encodeURIComponent(product)}/${encodeURIComponent(product)}`
    );

    if (!response.ok) {
      throw new Error("Respuesta inválida");
    }

    const data = await response.json();
    const versionLower = version.toLowerCase();

    const matchedCVEs = (data.data || []).filter(cve => {
      const text = JSON.stringify(cve).toLowerCase();
      return text.includes(versionLower);
    });

    resultsPanel.style.display = "block";
    formMessage.textContent = "";

    if (matchedCVEs.length === 0) {
      cveList.innerHTML =
        '<div class="message">No se encontraron CVEs para esta versión.</div>';
      return;
    }

    matchedCVEs.forEach(cve => {
      const div = document.createElement("div");
      div.className = "cve";

      const cvss =
        cve.cvss ||
        (cve.cvss3 && cve.cvss3.baseScore) ||
        "N/A";

      div.innerHTML = `
        <div class="cve-header">
          <div class="cve-id">${cve.id}</div>
          <div class="cvss">CVSS: ${cvss}</div>
        </div>
        <div class="cve-desc">${cve.summary || "Sin descripción disponible."}</div>
      `;

      cveList.appendChild(div);
    });
  } catch (err) {
    formMessage.textContent =
      "No se pudo consultar la fuente de CVEs.";
    formMessage.className = "message error";
  } finally {
    checkBtn.disabled = false;
  }
});
