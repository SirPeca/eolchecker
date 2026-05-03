export async function onRequest() {
  return new Response(JSON.stringify({
    status: 'OK', runtime: 'Cloudflare Workers',
    version: '9.0.0'
  }), { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
}
