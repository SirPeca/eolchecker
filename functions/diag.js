export async function onRequest() {
  return new Response(
    JSON.stringify({
      status: "OK",
      runtime: "Cloudflare Workers",
      timestamp: new Date().toISOString()
    }),
    { headers: { "Content-Type": "application/json" } }
  );
}
