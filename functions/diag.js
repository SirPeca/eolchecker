/**
 * Diagnostic endpoint
 * Checks if Functions runtime is alive
 */

export async function onRequest() {
  return new Response(JSON.stringify({
    status: "OK",
    runtime: "Cloudflare Workers",
    timestamp: new Date().toISOString()
  }), {
    headers: { "Content-Type": "application/json" }
  });
}
