// netlify/functions/slack-events.js
// ──────────────────────────────────────────────────────────────
// 目的：eml/msg を確実に拾い、モーダル全文表示。二重投稿防止。
// 追加：イベント受信の診断ログ（type/subtype/最低限のID）を Blobs に保存。
// 修正：MSGReader のクラス名（大文字）に対応 + ESM/CJS両対応 + ArrayBuffer/Uint8Array兼用。
//       file_shared と message.file_share の両方を処理（重複はロック&doneで1回に抑制）。
// UI：スレッドに1行プレビュー + 「全文を見る（モーダル）」、モーダルに「📋自分に送る」。
// ──────────────────────────────────────────────────────────────

import crypto from "node:crypto";
import { simpleParser } from "mailparser";
import { getStore } from "@netlify/blobs";
import { htmlToText } from "html-to-text";

const BOT_TOKEN = process.env.SLACK_BOT_TOKEN ?? "";
const SIGNING_SECRET = (process.env.SLACK_SIGNING_SECRET ?? "").trim();
const MAX_PREVIEW_CHARS = parseInt(process.env.MAX_PREVIEW_CHARS ?? "3000", 10);

// ログ保存（任意）
const LOG_TO_BLOBS = (process.env.LOG_TO_BLOBS ?? "false").toLowerCase() === "true";
const LOG_STORE = LOG_TO_BLOBS ? getStore({ name: process.env.BLOB_STORE_NAME || "logs" }) : null;

// 本文/フラグ保存
const STORE = getStore({ name: process.env.PREVIEW_STORE_NAME || "previews" });

/* ── Utils ───────────────────────────────────────────── */
function timingSafeEq(a, b) {
  const ab = Buffer.from(a), bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}
function verifySlackSignature({ rawBody, timestamp, slackSig }) {
  if (!SIGNING_SECRET || !slackSig || !timestamp) return false;
  const base = `v0:${timestamp}:${rawBody}`;
  const hmac = crypto.createHmac("sha256", SIGNING_SECRET);
  hmac.update(base);
  return timingSafeEq(`v0=${hmac.digest("hex")}`, slackSig);
}
async function slackApi(path, payload) {
  const r = await fetch(`https://slack.com/api/${path}`, {
    method: "POST",
    headers: { Authorization: `Bearer ${BOT_TOKEN}`, "Content-Type": "application/json; charset=utf-8" },
    body: JSON.stringify(payload),
  });
  return r.json();
}
async function postMessage({ channel, text, thread_ts, blocks }) {
  return slackApi("chat.postMessage", { channel, text, thread_ts, blocks });
}
async function viewsOpen({ trigger_id, view }) {
  return slackApi("views.open", { trigger_id, view });
}
async function conversationsOpen(userId) {
  return slackApi("conversations.open", { users: userId }); // im:write
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
async function blobLog(kind, data) {
  if (!LOG_TO_BLOBS || !LOG_STORE) return;
  try {
    await LOG_STORE.set(`${kind}/${Date.now()}`, typeof data === "string" ? data : JSON.stringify(data));
  } catch {}
}

/* ── Parse helpers ───────────────────────────────────── */
function normalizeText(txt) {
  const clean = (txt ?? "").replace(/\r\n/g, "\n").replace(/\t/g, "  ").trim();
  if (clean.length <= MAX_PREVIEW_CHARS) return clean;
  return clean.slice(0, MAX_PREVIEW_CHARS) + "\n…(truncated)";
}
function firstLine(text) {
  const line = (text ?? "").split("\n").find(s => s.trim().length > 0) ?? "";
  return line.length > 120 ? (line.slice(0, 120) + " …") : (line || "(no content)");
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

// Buffer/Uint8Array/ArrayBuffer 互換
function toUint8Array(buf) {
  if (buf instanceof Uint8Array && !(buf instanceof Buffer)) return buf;
  return new Uint8Array(buf.buffer, buf.byteOffset ?? 0, buf.byteLength);
}
function sliceToArrayBuffer(u8) {
  return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength);
}

// MSGReader 取得（大文字クラス名・default/named 両対応）
async function getMSGReaderCtor() {
  const mod = await import("@kenjiuno/msgreader");
  const candidates = [mod.MSGReader, mod.default, mod.MsgReader]; // ← 大文字優先（公式は MSGReader）
  const Ctor = candidates.find(v => typeof v === "function");
  if (!Ctor) throw new Error("MSGReader constructor not found");
  return Ctor;
}
async function parseMSGorOFT(buf) {
  const MSGReader = await getMSGReaderCtor();
  const u8 = toUint8Array(buf);

  let info;
  try {
    // 公式は ArrayBuffer を推奨
    info = new MSGReader(sliceToArrayBuffer(u8)).getFileData();
  } catch (e1) {
    try {
      // 一部環境では Uint8Array でも動く
      info = new MSGReader(u8).getFileData();
    } catch (e2) {
      await blobLog("errors/msgreader", { e1: String(e1), e2: String(e2) });
      throw new Error("failed to construct MSGReader");
    }
  }

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

function isSupportedName(name = "") {
  const low = name.toLowerCase();
  return low.endsWith(".eml") || low.endsWith(".msg") || low.endsWith(".oft");
}
function resolveFromShares(file) {
  const shares = file?.shares || {};
  for (const area of ["private", "public"]) {
    const m = shares[area];
    if (!m) continue;
    for (const [cid, posts] of Object.entries(m)) {
      if (Array.isArray(posts) && posts.length) {
        const p = posts[0];
        const ts = p.thread_ts || p.ts;
        if (cid && ts) return { channel: cid, thread_ts: ts };
      }
    }
  }
  return { channel: null, thread_ts: null };
}

/* ── UI ─────────────────────────────────────────────── */
function blocksPreview(filename, preview, payloadVal) {
  return [
    { type: "section",
      text: { type: "mrkdwn", text: `🧾 解析結果（${filename}）\n\`\`\`\n${preview}\n\`\`\`` } },
    { type: "actions", elements: [
      { type: "button", text: { type: "plain_text", text: "全文を見る（モーダル）" }, action_id: "open_modal", value: payloadVal }
    ]}
  ];
}
function chunkText(s, n) { const out=[]; for (let i=0;i<s.length;i+=n) out.push(s.slice(i,i+n)); return out; }
function buildModalView(filename, body, meta) {
  const title = (filename || "解析結果").slice(0, 24);
  const chunks = chunkText(body, 2900);
  const blocks = chunks.length ? chunks.map(c => ({ type:"section", text:{ type:"mrkdwn", text:"```\n"+c+"\n```" } })) :
    [{ type:"section", text:{ type:"mrkdwn", text:"（内容なし）" } }];
  blocks.push({
    type: "actions",
    elements: [
      { type: "button", action_id: "send_copy_dm", text: { type: "plain_text", text: "📋 自分に送る（コピー用）" } }
    ]
  });
  return { type:"modal", title:{ type:"plain_text", text:title }, close:{ type:"plain_text", text:"閉じる" }, private_metadata: JSON.stringify(meta||{}), blocks };
}

/* ── Core（重複防止つきファイル処理） ─────────────── */
async function processFileById({ fileId, channelHint, threadHint }) {
  // 受信イベントを記録（診断用）
  await blobLog("events/seen", { fileId, channelHint, threadHint });

  const lockKey = `lock:${fileId}`;
  if (await STORE.get(lockKey)) return;         // 進行中/済
  await STORE.set(lockKey, String(Date.now()));

  try {
    if (await STORE.get(`done:${fileId}`)) return;

    const finfo = await filesInfo(fileId);
    if (!finfo.ok) throw new Error(`files.info failed: ${JSON.stringify(finfo)}`);
    const f = finfo.file;

    const sharesRef = resolveFromShares(f);
    const channel = channelHint || sharesRef.channel;
    const thread_ts = threadHint || sharesRef.thread_ts;
    if (!channel || !thread_ts) throw new Error("cannot resolve thread");

    if (!isSupportedName(f.name)) {
      await postMessage({ channel, thread_ts, text: `⚠️ 未対応の拡張子です: \`${f.name}\`（.eml/.msg/.oft）` });
      await STORE.set(`done:${fileId}`, "1");
      return;
    }

    const url = f.url_private_download || f.url_private;
    if (!url) throw new Error("no url_private_download");
    const buf = await downloadPrivate(url);

    let parsed = "";
    const low = f.name.toLowerCase();
    try {
      parsed = low.endsWith(".eml") ? await parseEML(buf) : await parseMSGorOFT(buf);
    } catch (e) {
      await blobLog("errors/parse", { file: f.name, e: String(e) });
      throw new Error("parse failed");
    }

    const body = normalizeText(parsed);
    const key = `p:${Date.now()}:${fileId}`;
    await STORE.set(key, body);

    const preview = firstLine(body);
    await postMessage({
      channel,
      thread_ts,
      text: "解析結果（プレビュー）",
      blocks: blocksPreview(f.name, preview, JSON.stringify({ key, filename: f.name })),
    });

    await STORE.set(`done:${fileId}`, "1");
  } finally {
    await STORE.set(lockKey, "done");
  }
}

/* ── Interactivity ─────────────────────────────────── */
async function handleBlockActions(payload) {
  const action = payload?.actions?.[0];
  if (!action) return new Response("", { status: 200 });

  if (action.action_id === "open_modal") {
    const trigger_id = payload.trigger_id;
    const val = action.value ? JSON.parse(action.value) : null;
    const key = val?.key, filename = val?.filename || "解析結果";
    if (!trigger_id || !key) return new Response("", { status: 200 });
    const body = (await STORE.get(key)) ?? "(content expired)";
    await viewsOpen({ trigger_id, view: buildModalView(filename, body, { key, filename }) });
    return new Response("", { status: 200 });
  }

  if (action.action_id === "send_copy_dm") {
    const userId = payload.user?.id;
    const meta = payload.view?.private_metadata ? JSON.parse(payload.view.private_metadata) : {};
    const key = meta.key, filename = meta.filename || "解析結果";
    if (!userId || !key) return new Response("", { status: 200 });
    const content = (await STORE.get(key)) ?? "(content expired)";
    const opened = await conversationsOpen(userId); // im:write
    if (opened?.ok && opened?.channel?.id) {
      await postMessage({ channel: opened.channel.id, text: `🧾 解析結果（${filename}）\n\`\`\`\n${content}\n\`\`\`` });
    } else {
      await blobLog("errors/open-dm-failed", opened || {});
    }
    return new Response("", { status: 200 });
  }

  return new Response("", { status: 200 });
}

/* ── Entry ─────────────────────────────────────────── */
export default async function handler(req) {
  const raw = await req.text();
  const ts = req.headers.get("x-slack-request-timestamp");
  const sig = req.headers.get("x-slack-signature");
  const contentType = req.headers.get("content-type") || "";

  if (req.headers.get("x-slack-retry-num")) {
    return new Response("", { status: 200, headers: { "X-Slack-No-Retry": "1" } });
  }
  if (!verifySlackSignature({ rawBody: raw, timestamp: ts, slackSig: sig })) {
    await blobLog("errors/sign", { ts, note: "invalid-signature" });
    return new Response("invalid signature", { status: 401 });
  }

  // Interactivity
  if (contentType.includes("application/x-www-form-urlencoded")) {
    const m = /^payload=(.*)$/.exec(raw);
    if (!m) return new Response("", { status: 200 });
    const payload = JSON.parse(decodeURIComponent(m[1]));
    return handleBlockActions(payload);
  }

  // Events API
  let payload;
  try { payload = JSON.parse(raw); }
  catch {
    await blobLog("errors/json-parse", raw.slice(0, 800));
    return new Response("bad request", { status: 400 });
  }

  // 受信イベントの種類を記録（診断）
  await blobLog("events/heads", {
    type: payload.type,
    etype: payload.event?.type,
    subtype: payload.event?.subtype,
    file_id: payload.event?.file_id || payload.event?.files?.[0]?.id || null
  });

  if (payload.type === "url_verification") {
    return new Response(payload.challenge, { headers: { "Content-Type": "text/plain" } });
  }

  if (payload.type === "event_callback") {
    const ev = payload.event;

    // diag
    if (ev.type === "app_mention" && /diag/i.test(ev.text ?? "")) {
      if (ev.channel) await postMessage({ channel: ev.channel, thread_ts: ev.ts, text: "diag: ok ✅" });
      return new Response("", { status: 200 });
    }

    // 両方対応：message.file_share / file_shared
    if (ev.type === "message" && ev.subtype === "file_share") {
      const fileId = ev.files?.[0]?.id;
      if (fileId) await processFileById({ fileId, channelHint: ev.channel, threadHint: ev.ts });
      return new Response("", { status: 200 });
    }
    if (ev.type === "file_shared") {
      const fileId = ev.file_id;
      if (fileId) await processFileById({ fileId });
      return new Response("", { status: 200 });
    }
  }

  return new Response("", { status: 200 });
}
