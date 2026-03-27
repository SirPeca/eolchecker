EOL & CVE Checker
Soporte/EOL (best-effort) + CVEs/KEV usando fuentes públicas (OSV/NVD/KEV/endoflife-date repo)

Tecnología / Producto
jquery
Versión
3.3.1
Ecosistema (para OSV)

Auto
Consultar
Ejemplo
jquery, 3.3.1, unknown unknown
Description
{
  "state": "unknown",
  "support": {
    "known": false,
    "eol": null,
    "supportUntil": null,
    "latest": null,
    "cycle": null
  },
  "notes": "No se pudo determinar soporte/EOL automáticamente (best-effort)."
}
Evidence support (references)
{
  "support": [
    "https://raw.githubusercontent.com/endoflife-date/endoflife.date/master/products/jquery.md"
  ],
  "support_notes": [
    "No se pudo obtener metadata de soporte/EOL (fetch error): TypeError: Failed to fetch",
    "Best-effort: validar soporte/EOL en fuentes oficiales del proveedor si aplica."
  ],
  "osv": [
    "https://api.osv.dev/v1/query"
  ],
  "osv_notes": [],
  "kev": [
    "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"
  ],
  "kev_notes": [
    "KEV fetch error (posible CORS/red): TypeError: Failed to fetch"
  ]
}
CVE code list
CVE-2019-11358, CVE-2020-11022, CVE-2020-11023
Known exploited (KEV)
Sin coincidencias con KEV (best-effort).
Impact
Impacto no determinable con certeza (best-effort). Revisar manualmente evidencia y referencias.
Recomendation
Recomendación best-effort: confirmar soporte/EOL en fuentes oficiales del proveedor y luego definir upgrade path.
Red team perspective
- Según el tipo de CVE (si aplica), podrían involucrarse técnicas MITRE ATT&CK relacionadas a explotación de aplicaciones/servicios y ejecución de código (mapeo depende del CVE específico).
Blue team perspective
- Aplicar hardening y controles compensatorios: segmentación, mínimos privilegios, WAF/IDS/IPS cuando corresponda, y monitoreo/alertas en logs.
- Definir detecciones en SOC para patrones asociados a explotación del componente (requests anómalas, errores, indicadores del proveedor).
Disclaimer
Remember the information generated may be incorrect, manually check each reference or link to ensure the truthfulness of the answer
