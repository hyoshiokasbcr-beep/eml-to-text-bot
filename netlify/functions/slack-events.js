// netlify/functions/slack-events.js
// 最小堅牢版：プレビュー＋モーダル全文のみ / .msg互換強化 / 二重投稿撲滅（message.file_shareのみ処理）

import crypto from "node:crypto";
import { simpleParser } from "mailparser";
import { getStore } from "@netlify/blobs";
import { htmlToText } from "html-to-text";

const BOT_TOKEN = process.env.SLACK_BOT_TOKEN ?? "";
const SIGNING_SECRET = (process.env.SLACK_SIGNING_SECRET ?? "").trim();
const MAX_PREVIEW_CHARS = parseInt(process.env.MAX_PREVIEW_CHARS ?? "3000", 10);

// 軽量ログ（任意）
const LOG_TO_BLOBS = (process.env.LOG_TO_BLOBS ?? "false").toLowerCase() === "true";
const LOG_STORE = LOG_TO_BLOBS ? getStore({ name: process.env.BLOB_STORE_NAME || "logs" }) : null;

// 本文一時保存＆ロック/フラグ管理
const PREVIEW_STORE = getStore({ name: process.env.PREVIEW_STORE_NAME || "previews" });

/* ========= 共通 ========= */
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
async function logBlob(path, data) {
  if (!LOG_TO_BLOBS || !LOG_STORE) return;
  try { await LOG_STORE.set(path, typeof data === "string" ? data : JSON.stringify(data)); } catch {}
}

/* ========= 解析 ========= */
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

// Buffer/Uint8Array/ArrayBuffer の互換対応
function toUint8Array(buf) {
  if (buf instanceof Uint8Array && !(buf instanceof Buffer)) return buf;
  return new Uint8Array(buf.buffer, buf.byteOffset ?? 0, buf.byteLength);
}
// ちょうどの ArrayBuffer を安全に作る（byteOffset考慮）
function safeSliceArrayBuffer(u8) {
  const ab = new ArrayBuffer(u8.byteLength);
  new Uint8Array(ab).set(u8);
  return ab;
}

async function parseMSGorOFT(buf) {
  const mod = await import("@kenjiuno/msgreader"); // robust import
  const MsgReaderCtor = mod.MsgReader || mod.default;
  if (typeof MsgReaderCtor !== "function") throw new Error("msgreader module not available");

  const u8 = toUint8Array(buf);

  let info;
  try {
    // 1) Uint8Array そのまま（多くの環境でOK）
    const reader = new MsgReaderCtor(u8);
    info = reader.getFileData();
  } catch (e1) {
    try {
      // 2) ちょうどの ArrayBuffer を渡す（環境差吸収）
      const reader2 = new MsgReaderCtor(safeSliceArrayBuffer(u8));
      info = reader2.getFileData();
    } catch (e2) {
      await logBlob(`errors/handler/${Date.now()}`, { kind: "msgreader-ctor", e1: String(e1), e2: String(e2) });
      throw new Error("failed to construct MsgReader");
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
        const ts = p.thread_ts || p.ts; // 親メッセージ ts
        if (cid && ts) return { channel: cid, thread_ts: ts };
      }
    }
  }
  return { channel: null, thread_ts: null };
}

/* ========= Slack UI ========= */
// プレビュー（1行）+ モーダルボタンのみ
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
function buildModalView(filename, body) {
  const title = (filename || "解析結果").slice(0, 24);
  const chunks = chunkText(body, 2900);
  const blocks = chunks.length ? chunks.map(c => ({ type:"section", text:{ type:"mrkdwn", text:"```\n"+c+"\n```" } })) :
    [{ type:"section", text:{ type:"mrkdwn", text:"（内容なし）" } }];
  return { type:"modal", title:{ type:"plain_text", text:title }, close:{ type:"plain_text", text:"閉じる" }, blocks };
}

/* ========= メイン処理 ========= */
async function handleFileSharedMessage(ev) {
  // file_share（メッセージのサブタイプ）からだけ処理する
  const fileId = ev.files?.[0]?.id || ev.file?.id || ev.file_id || null;
  if (!fileId) throw new Error("no file_id");

  // ロックで同時実行を抑止（粗いが実効性高）
  const lockKey = `lock:${fileId}`;
  if (await PREVIEW_STORE.get(lockKey)) return; // 既に処理中/済
  await PREVIEW_STORE.set(lockKey, String(Date.now()));

  try {
    const finfo = await filesInfo(fileId);
    if (!finfo.ok) throw new Error(`files.info failed: ${JSON.stringify(finfo)}`);
    const f = finfo.file;

    const sharesRef = resolveFromShares(f);
    const channel = ev.channel || ev.channel_id || sharesRef.channel;
    const thread_ts = ev.ts || sharesRef.thread_ts || ev.event_ts;
    if (!channel || !thread_ts) throw new Error("cannot resolve thread");

    if (!isSupportedName(f.name)) {
      await postMessage({ channel, thread_ts, text: `⚠️ 未対応の拡張子です: \`${f.name}\`（.eml/.msg/.oft）` });
      return;
    }

    const url = f.url_private_download || f.url_private;
    if (!url) throw new Error("no url_private_download");
    const buf = await downloadPrivate(url);

    let parsed = "";
    const low = f.name.toLowerCase();
    try {
      if (low.endsWith(".eml")) parsed = await parseEML(buf);
      else parsed = await parseMSGorOFT(buf);
    } catch (e) {
      await logBlob(`errors/handler/${Date.now()}`, { kind: "parse-failed", name: f.name, e: String(e) });
      throw new Error("parse failed");
    }

    const body = normalizeText(parsed);

    // 本文保存（モーダル用）
    const key = `p:${Date.now()}:${fileId}`;
    await PREVIEW_STORE.set(key, body);

    // プレビュー投下（本文には出さず、スレッドのみ）
    const preview = firstLine(body);
    await postMessage({
      channel,
      thread_ts,
      text: "解析結果（プレビュー）",
      blocks: blocksPreview(f.name, preview, JSON.stringify({ key, filename: f.name })),
    });
  } finally {
    // ロック解除（短命でもOK。厳密なTTLは不要）
    await PREVIEW_STORE.set(lockKey, "done");
  }
}

/* ========= インタラクション ========= */
async function handleBlockActions(payload) {
  const action = payload?.actions?.[0];
  if (!action) return new Response("", { status: 200 });

  if (action.action_id === "open_modal") {
    const trigger_id = payload.trigger_id;
    const val = action.value ? JSON.parse(action.value) : null;
    const key = val?.key, filename = val?.filename || "解析結果";
    if (!trigger_id || !key) return new Response("", { status: 200 });
    const body = (await PREVIEW_STORE.get(key)) ?? "(content expired)";
    await viewsOpen({ trigger_id, view: buildModalView(filename, body) });
    return new Response("", { status: 200 });
  }

  return new Response("", { status: 200 });
}

/* ========= エントリーポイント ========= */
export default async function handler(req) {
  const raw = await req.text();
  const ts = req.headers.get("x-slack-request-timestamp");
  const sig = req.headers.get("x-slack-signature");
  const contentType = req.headers.get("content-type") || "";

  // Slackのリトライは即 200 で打ち止め
  if (req.headers.get("x-slack-retry-num")) {
    return new Response("", { status: 200, headers: { "X-Slack-No-Retry": "1" } });
  }

  if (!verifySlackSignature({ rawBody: raw, timestamp: ts, slackSig: sig })) {
    await logBlob(`errors/sign/${Date.now()}`, { reason: "invalid-signature", ts });
    return new Response("invalid signature", { status: 401 });
  }

  // Interactivity: x-www-form-urlencoded
  if (contentType.includes("application/x-www-form-urlencoded")) {
    const m = /^payload=(.*)$/.exec(raw);
    if (!m) return new Response("", { status: 200 });
    const payload = JSON.parse(decodeURIComponent(m[1]));
    if (payload?.type === "block_actions") return handleBlockActions(payload);
    return new Response("", { status: 200 });
  }

  // Events API
  let payload;
  try { payload = JSON.parse(raw); }
  catch {
    await logBlob(`errors/parse/${Date.now()}`, { raw: raw.slice(0, 200) + "..." });
    return new Response("bad request", { status: 400 });
  }

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

    // ✅ ここが重要：message.subtype=file_share だけ処理する（重複防止）
    if (ev.type === "message" && ev.subtype === "file_share") {
      try {
        await handleFileSharedMessage(ev);
      } catch (e) {
        await logBlob(`errors/handler/${Date.now()}`, { message: e?.message ?? String(e), evType: "message.file_share" });
        const ch = ev.channel;
        const th = ev.ts;
        if (ch && th) await postMessage({ channel: ch, thread_ts: th, text: `❌ 解析失敗: ${e?.message ?? e}` });
      }
      return new Response("", { status: 200 });
    }

    // ❌ file_shared は完全スキップ（200返却のみ）
    if (ev.type === "file_shared") {
      return new Response("", { status: 200 });
    }
  }

  return new Response("", { status: 200 });
}
