/**
 * Diagnostic endpoint — GET /diag
 * Verifies the Workers runtime is alive and returns build info.
 */
export async function onRequest() {
  return new Response(JSON.stringify({
    status:    'OK',
    runtime:   'Cloudflare Workers',
    timestamp: new Date().toISOString(),
    version:   '2.0.0'
  }), {
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store'
    }
  });
}
