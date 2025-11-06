export default async (req) => {
  const headers = Object.fromEntries(req.headers);
  const body = await req.text();
  const out = {
    marker: "echo@eml-to-text-bot",
    method: req.method,
    headers,
    body
  };
  console.log("ECHO_HIT", out);
  return new Response(JSON.stringify(out, null, 2), {
    headers: { "content-type": "application/json" }
  });
};
