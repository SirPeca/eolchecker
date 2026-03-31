export async function onRequest() {
  return new Response(JSON.stringify({
    status: 'OK', runtime: 'Cloudflare Workers',
    version: '4.0.0', timestamp: new Date().toISOString()
  }), { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
}
