import crypto from "node:crypto";
import { getStore } from "@netlify/blobs";

const store = getStore({ name: "logs" });
const BOT_TOKEN = process.env.SLACK_BOT_TOKEN;
const SIGNING_SECRET = process.env.SLACK_SIGNING_SECRET;

function verifySlackSignature({ bodyText, timestamp, slackSig }) {
  const base = `v0:${timestamp}:${bodyText}`;
  const hmac = crypto.createHmac("sha256", SIGNING_SECRET.trim());
  hmac.update(base);
  const hex = hmac.digest("hex");
  const expected = `v0=${hex}`;
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(slackSig));
}

async function chatPostMessage({ channel, text, thread_ts }) {
  const res = await fetch("https://slack.com/api/chat.postMessage", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${BOT_TOKEN}`,
      "Content-Type": "application/json; charset=utf-8",
    },
    body: JSON.stringify({ channel, text, thread_ts }),
  });
  return res.json();
}

export default async function handler(req) {
  const raw = await req.text();
  const ts = req.headers.get("x-slack-request-timestamp");
  const sig = req.headers.get("x-slack-signature");

  if (!verifySlackSignature({ bodyText: raw, timestamp: ts, slackSig: sig })) {
    await store.set(`errors/sign/${Date.now()}`, JSON.stringify({ invalid: true }));
    return new Response("invalid signature", { status: 401 });
  }

  let payload = {};
  try {
    payload = JSON.parse(raw);
  } catch {
    return new Response("bad request", { status: 400 });
  }

  if (payload.type === "url_verification") {
    return new Response(payload.challenge, {
      headers: { "Content-Type": "text/plain" },
    });
  }

  if (payload.type === "event_callback") {
    const ev = payload.event;
    if (ev.type === "app_mention" && ev.text?.toLowerCase().includes("diag")) {
      await chatPostMessage({
        channel: ev.channel,
        text: "diag: ok ✅",
        thread_ts: ev.ts,
      });
      return new Response("", { status: 200 });
    }

    if (ev.type === "file_shared") {
      await chatPostMessage({
        channel: ev.channel,
        thread_ts: ev.event_ts,
        text: "📎 `.eml` ファイルを検知。解析中…",
      });
      return new Response("", { status: 200 });
    }
  }

  return new Response("", { status: 200 });
}
