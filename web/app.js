// app.js (frontend) — GitHub Pages only (sin backend)

const OSV_QUERY = "https://api.osv.dev/v1/query"; // docs: POST /v1/query [4](https://google.github.io/osv.dev/post-v1-query/)
const KEV_JSON  = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"; // repo KEV [5](https://github.com/cisagov/kev-data)
const NVD_BASE  = "https://services.nvd.nist.gov/rest/json/cves/2.0"; // apiKey por header en 2.0 [6](https://nvd.nist.gov/General/News/api-20-announcements)

// Cache local (en tu repo). Si existe, se usa para EOL/Support sin CORS.
const LOCAL_EOL_CACHE_PREFIX = "./eol-cache/";

// Alias / normalización de slugs (endoflife-date style)
const SLUG_MAP = {
  "node": "nodejs",
  "node.js": "nodejs",
  ".net": "dotnet",
