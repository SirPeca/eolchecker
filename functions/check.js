export async function onRequest({ request, env }) {
  try {
    const url = new URL(request.url);
    const tec = url.searchParams.get("tec");
    const ver = url.searchParams.get("ver");

    if (!tec || !ver) {
      return new Response(
        JSON.stringify({ error: "Parámetros requeridos: tec, ver" }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    }

    const eolRes = await fetch(`https://endoflife.date/api/${encodeURIComponent(tec.toLowerCase())}.json`);
    if (!eolRes.ok) {
      return new Response(
        JSON.stringify({ error: "Tecnología no encontrada en endoflife.date" }),
        { status: 404, headers: { "Content-Type": "application/json" } }
      );
    }

    const cycles = await eolRes.json();
    const cycle = cycles.find(c => String(c.cycle).startsWith(ver.split(".")[0]));

    const now = new Date();
    const eol = cycle?.eol ? new Date(cycle.eol) : null;

    const verdict = eol && eol < now
      ? "OBSOLETA"
      : "CON SOPORTE";

    return new Response(
      JSON.stringify({
        tecnologia: tec,
        version: ver,
        veredicto: verdict,
        ciclo: cycle || null,
        fuente: "https://endoflife.date"
      }),
      { headers: { "Content-Type": "application/json" } }
    );

  } catch (err) {
    return new Response(
      JSON.stringify({ error: "Error interno", detail: err.message }),
      { status: 500, headers: { "Content-Type": "application/json" } }
    );
  }
}
