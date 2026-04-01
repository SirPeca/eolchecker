// =========================================
// EOL & CVE Checker — functions/visits.js
// GET /visits  → returns total scan count
// Used by the frontend to display the counter
// =========================================

export async function onRequest(context) {
  const env = context.env;

  if (!env?.RATE_LIMIT) {
    return new Response(JSON.stringify({ total: null, note: 'KV not configured' }), {
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
    });
  }

  try {
    const total = await env.RATE_LIMIT.get('visits:total');
    return new Response(JSON.stringify({ total: total ? parseInt(total) : 0 }), {
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Cache-Control': 'no-store'
      }
    });
  } catch {
    return new Response(JSON.stringify({ total: 0 }), {
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
    });
  }
}
