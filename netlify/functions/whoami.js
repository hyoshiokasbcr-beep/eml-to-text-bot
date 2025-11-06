// netlify/functions/whoami.js  --- ESM
import { getStore } from "@netlify/blobs";

export default async function handler() {
  const hasToken = !!process.env.SLACK_BOT_TOKEN;
  const hasSecret = !!process.env.SLACK_SIGNING_SECRET;

  // ストア名は固定 "logs"
  const blobStore = "logs";
  // 存在チェックだけ（エラーは握りつぶす）
  try {
    const store = getStore({ name: blobStore });
    await store.set(
      `diag/whoami-${Date.now()}`,
      JSON.stringify({ ping: new Date().toISOString() }),
      { contentType: "application/json" }
    );
  } catch {
    // noop
  }

  const payload = {
    marker: "whoami@eml-to-text-bot",
    now: new Date().toISOString(),
    url: ".netlify/functions/whoami",
    method: "GET",
    env: {
      hasToken,
      hasSecret,
      blobStore,
      node: process.version,
    },
  };

  return new Response(JSON.stringify(payload, null, 2), {
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}
