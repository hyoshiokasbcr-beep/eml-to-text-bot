// netlify/functions/slack-events.js
import crypto from "node:crypto";
import { simpleParser } from "mailparser";
import { getStore } from "@netlify/blobs";
import { htmlToText } from "html-to-text";
// ❌ ここでの静的 import はやめる
// import MsgReader from "msgreader";

const BOT_TOKEN = process.env.SLACK_BOT_TOKEN ?? "";
const SIGNING_SECRET = (process.env.SLACK_SIGNING_SECRET ?? "").trim();
const MAX_PREVIEW = parseInt(process.env.MAX_PREVIEW_CHARS ?? "3000", 10);
const LOG_TO_BLOBS = (process.env.LOG_TO_BLOBS ?? "false").toLowerCase() === "true";
const BLOB_STORE_NAME = process.env.BLOB_STORE_NAME || "logs";
const store = LOG_TO_BLOBS ? getStore({ name: BLOB_STORE_NAME }) : null;

function timingSafeEq(a, b) {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

function verifySlackSignature({ rawBody, timestamp, slackSig }) {
  if (!SIGNING_SECRET || !slackSig || !timestamp) return false;
  const base = `v0:${timestamp}:${rawBody}`;
  const hmac = crypto.createHmac("sha256", SIGNING_SECRET);
  hmac.update(base);
  const expected = `v0=${hmac.digest("hex")}`;
  return timingSafeEq(expected, slackSig);
}

async function postMessage({ channel, text, thread_ts }) {
  const r = await fetch("https://slack.com/api/chat.postMessage", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${BOT_TOKEN}`,
      "Content-Type": "application/json; charset=utf-8",
    },
    body: JSON.stringify({ channel, text, thread_ts }),
  });
  return r.json();
}

async function filesInfo(fileId) {
  const r = await fetch(`https://slack.com/api/files.info?file=${encodeURIComponent(fileId)}`, {
    headers: { Authorization: `Bearer ${BOT_TOKEN}` },
  });
  return r.json();
}

async function downloadPrivate(url) {
  const r = await fetch(url, { headers: { Authorization: `Bearer ${BOT_TOKEN}` } });
  if (!r.ok) throw new Error(`download failed: ${r.status}`);
  const ab = await r.arrayBuffer();
  return Buffer.from(ab);
}

function normalizeText(txt) {
  const clean = (txt ?? "").replace(/\r\n/g, "\n").replace(/\t/g, "  ").trim();
  if (clean.length <= MAX_PREVIEW) return clean;
  return clean.slice(0, MAX_PREVIEW) + "\n…(truncated)";
}

async function parseEML(buf) {
  const mail = await simpleParser(buf);
  let body = "";
  if (mail.html) body = htmlToText(mail.html, { wordwrap: false });
  else if (mail.text) body = mail.text;

  const headerLines = [
    `From: ${mail.from?.text ?? ""}`,
    `To: ${mail.to?.text ?? ""}`,
    mail.cc ? `Cc: ${mail.cc.text}` : null,
    `Date: ${mail.date ?? ""}`,
    `Subject: ${mail.subject ?? ""}`,
  ].filter(Boolean);

  return `# ${mail.subject ?? ""}\n${headerLines.join("\n")}\n\n${body ?? ""}`;
}

async function parseMSG(buf) {
  // 💡必要な時だけロード（.eml では読み込まないのでエラーを回避できる）
  const { default: MsgReader } = await import("@kenjiuno/msgreader");
  const reader = new MsgReader(buf);
  const info = reader.getFileData();

  const html = info.bodyHTML ?? info.messageComps?.htmlBody ?? null;
  const rtf  = info.bodyRTF  ?? info.messageComps?.rtfBody  ?? null;
  const text = info.body     ?? info.messageComps?.plainText ?? null;

  let body = "";
  if (html) body = htmlToText(html, { wordwrap: false });
  else if (text) body = text;
  else if (rtf) body = rtf.replace(/\\[a-z]+\d* ?|[{}]/gi, " ").replace(/\s+/g, " ").trim();

  const headerLines = [
    `From: ${info.senderName || info.senderEmail || ""}`,
    `To: ${Array.isArray(info.recipients) ? info.recipients.map(r => r.name || r.email).join(", ") : ""}`,
    info.cc ? `Cc: ${info.cc}` : null,
    `Date: ${info.messageDeliveryTime || info.creationTime || ""}`,
    `Subject: ${info.subject || ""}`,
  ].filter(Boolean);

  return `# ${info.subject || ""}\n${headerLines.join("\n")}\n\n${body || ""}`;
}

async function parseOFT(buf) {
  return parseMSG(buf);
}

function isSupportedName(name = "") {
  const low = name.toLowerCase();
  return low.endsWith(".eml") || low.endsWith(".msg") || low.endsWith(".oft");
}

async function logBlob(path, data) {
  if (!LOG_TO_BLOBS || !store) return;
  try { await store.set(path, typeof data === "string" ? data : JSON.stringify(data)); } catch {}
}

async function handleFileShared(ev) {
  const channel = ev.channel_id || ev.channel;
  const thread_ts = ev.ts || ev.event_ts;

  if (channel) {
    await postMessage({ channel, thread_ts, text: "📎 `.eml/.msg` を検知。解析中…" });
  }

  const fileId =
    ev.file_id ||
    ev.file?.id ||
    (Array.isArray(ev.files) && ev.files[0]?.id) ||
    null;

  if (!fileId) throw new Error("no file_id");

  const finfo = await filesInfo(fileId);
  if (!finfo.ok) throw new Error(`files.info failed: ${JSON.stringify(finfo)}`);
  const f = finfo.file;

  if (!isSupportedName(f.name)) {
    if (channel) await postMessage({ channel, thread_ts, text: `⚠️ 未対応拡張子: \`${f.name}\`` });
    return;
  }

  const url = f.url_private_download || f.url_private;
  if (!url) throw new Error("no url_private_download");

  const buf = await downloadPrivate(url);

  let parsed = "";
  const low = f.name.toLowerCase();
  if (low.endsWith(".eml")) parsed = await parseEML(buf);
  else if (low.endsWith(".msg")) parsed = await parseMSG(buf);
  else if (low.endsWith(".oft")) parsed = await parseOFT(buf);

  const body = normalizeText(parsed);
  const code = "```text\n" + body + "\n```";

  if (channel) {
    await postMessage({ channel, thread_ts, text: `🧾 解析結果（${f.name}）\n${code}` });
  }
}

export default async function handler(req) {
  const raw = await req.text();
  const ts = req.headers.get("x-slack-request-timestamp");
  const sig = req.headers.get("x-slack-signature");

  if (!verifySlackSignature({ rawBody: raw, timestamp: ts, slackSig: sig })) {
    await logBlob(`errors/sign/${Date.now()}`, { reason: "invalid-signature", ts });
    return new Response("invalid signature", { status: 401 });
  }

  let payload;
  try { payload = JSON.parse(raw); }
  catch (e) {
    await logBlob(`errors/parse/${Date.now()}`, { e: e?.message });
    return new Response("bad request", { status: 400 });
  }

  if (payload.type === "url_verification") {
    return new Response(payload.challenge, { headers: { "Content-Type": "text/plain" } });
  }

  if (payload.type === "event_callback") {
    const ev = payload.event;

    if (ev.type === "app_mention" && /diag/i.test(ev.text ?? "")) {
      const text =
        "diag: ok ✅\n" +
        `node: ${process.version}\n` +
        `hasToken:${Boolean(BOT_TOKEN)} hasSecret:${Boolean(SIGNING_SECRET)}\n` +
        `blobs:${LOG_TO_BLOBS ? "on" : "off"} store:${BLOB_STORE_NAME}`;
      if (ev.channel) await postMessage({ channel: ev.channel, thread_ts: ev.ts, text });
      return new Response("", { status: 200 });
    }

    if (ev.type === "file_shared" || ev.subtype === "file_share") {
      try {
        await handleFileShared(ev);
      } catch (e) {
        await logBlob(`errors/handler/${Date.now()}`, { message: e?.message ?? String(e), ev });
        const ch = ev.channel_id || ev.channel;
        const th = ev.ts || ev.event_ts;
        if (ch) await postMessage({ channel: ch, thread_ts: th, text: `❌ 解析失敗: ${e?.message ?? e}` });
      }
      return new Response("", { status: 200 });
    }
  }

  return new Response("", { status: 200 });
}
