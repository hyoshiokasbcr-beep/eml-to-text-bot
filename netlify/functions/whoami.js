export default async (req) => {
  const info = {
    marker: "whoami@eml-to-text-bot", // ← この文字が見えたら“このサイトのFunctions”に当たっています
    now: new Date().toISOString(),
    url: req.url,
    method: req.method,
    env: {
      hasToken: !!process.env.SLACK_BOT_TOKEN,
      hasSecret: !!process.env.SLACK_SIGNING_SECRET,
      blobStore: process.env.BLOB_STORE_NAME || "(default)",
      node: process.version
    }
  };
  return new Response(JSON.stringify(info, null, 2), {
    headers: { "content-type": "application/json" }
  });
};
