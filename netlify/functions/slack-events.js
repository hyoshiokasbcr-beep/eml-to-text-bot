// netlify/functions/slack-events.js
// ハイブリッド版：
//  - スレッドに「1行プレビュー」+ ボタン2つ
//      1) 「全文を見る」→ モーダルで開閉（開く=1API/閉じる=0）※省クレジット＆モバイル配慮
//      2) 「スレッドに全文を投稿」→ そのスレッドに1回だけ全文を恒久投稿（検索しやすい）
//  - 二重投稿防止（Slack再送 & 同一ファイルイベント）
//  - .msg/.oft対応（MsgReaderのexport差とUint8Array化に対応）
//  - コードブロックの言語ラベルは空（``` の後に言語名を書かない）

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

// 本文一時保存＆フラグ管理
const PREVIEW_STORE = getStore({ name: process.env.PREVIEW_STORE_NAME || "previews" });

/* ============ 共通 ============ */
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
async function updateMessage({ channel, ts, text, blocks }) {
  return slackApi("chat.update", { channel, ts, text, blocks });
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

/* ============ 解析 ============ */
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

function toUint8Array(buf) {
  if (buf instanceof Uint8Array && !(buf instanceof Buffer)) return buf;
  return new Uint8Array(buf.buffer, buf.byteOffset ?? 0, buf.byteLength);
}
async function parseMSGorOFT(buf) {
  const mod = await import("@kenjiuno/msgreader"); // robust: default/named両対応
  const MsgReaderCtor = mod.MsgReader || mod.default;
  if (typeof MsgReaderCtor !== "function") throw new Error("msgreader module not available");
  const reader = new MsgReaderCtor(toUint8Array(buf));
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

/* ============ Slack UI ============ */
// プレビュー（1行）+ 2ボタン
function blocksPreview(filename, preview, payloadVal) {
  return [
    { type: "section",
      text: { type: "mrkdwn", text: `🧾 解析結果（${filename}）\n\`\`\`\n${preview}\n\`\`\`` } },
    { type: "actions", elements: [
      { type: "button", text: { type: "plain_text", text: "全文を見る（モーダル）" }, action_id: "open_modal", value: payloadVal },
      { type: "button", text: { type: "plain_text", text: "スレッドに全文を投稿" }, action_id: "post_full_once", value: payloadVal, style: "primary" }
    ]}
  ];
}
// モーダル（全文）
function chunkText(s, n) { const out=[]; for (let i=0;i<s.length;i+=n) out.push(s.slice(i,i+n)); return out; }
function buildModalView(filename, body) {
  const title = (filename || "解析結果").slice(0, 24);
  const chunks = chunkText(body, 2900);
  const blocks = chunks.length ? chunks.map(c => ({ type:"section", text:{ type:"mrkdwn", text:"```\n"+c+"\n```" } })) :
    [{ type:"section", text:{ type:"mrkdwn", text:"（内容なし）" } }];
  return { type:"modal", title:{ type:"plain_text", text:title }, close:{ type:"plain_text", text:"閉じる" }, blocks };
}

/* ============ メイン処理 ============ */
async function handleFileShared(ev) {
  const fileId = ev.file_id || ev.file?.id || (Array.isArray(ev.files) && ev.files[0]?.id) || null;
  if (!fileId) throw new Error("no file_id");

  // 同一ファイル二重イベント防止
  const doneKey = `done:${fileId}`;
  if (await PREVIEW_STORE.get(doneKey)) return;

  const finfo = await filesInfo(fileId);
  if (!finfo.ok) throw new Error(`files.info failed: ${JSON.stringify(finfo)}`);
  const f = finfo.file;

  const sharesRef = resolveFromShares(f);
  const channel = ev.channel_id || ev.channel || sharesRef.channel;
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
  if (low.endsWith(".eml")) parsed = await parseEML(buf);
  else parsed = await parseMSGorOFT(buf);

  const body = normalizeText(parsed);

  // 保存 & フラグ
  const key = `p:${Date.now()}:${fileId}`;
  await PREVIEW_STORE.set(key, body);
  await PREVIEW_STORE.set(doneKey, "1");

  // プレビュー投下（本文は出さず、スレッドのみ）
  const preview = firstLine(body);
  await postMessage({
    channel,
    thread_ts,
    text: "解析結果（プレビュー）",
    blocks: blocksPreview(f.name, preview, JSON.stringify({ key, filename: f.name, channel, thread_ts })),
  });
}

/* ============ インタラクション ============ */
async function handleBlockActions(payload) {
  const action = payload?.actions?.[0];
  if (!action) return new Response("", { status: 200 });

  // payload 共通
  const trigger_id = payload.trigger_id;
  const actionVal = action.value ? JSON.parse(action.value) : {};
  const key = actionVal.key;
  const filename = actionVal.filename || "解析結果";
  const originChannel = actionVal.channel;
  const originThreadTs = actionVal.thread_ts;

  if (action.action_id === "open_modal") {
    if (!trigger_id || !key) return new Response("", { status: 200 });
    const body = (await PREVIEW_STORE.get(key)) ?? "(content expired)";
    const view = buildModalView(filename, body);
    await viewsOpen({ trigger_id, view });
    return new Response("", { status: 200 });
  }

  if (action.action_id === "post_full_once") {
    // 1スレッド1回だけ恒久投稿（検索向け）。二重防止フラグで制御。
    if (!originChannel || !originThreadTs || !key) return new Response("", { status: 200 });
    const postFlagKey = `posted:${originChannel}:${originThreadTs}`;
    if (await PREVIEW_STORE.get(postFlagKey)) {
      // すでに投稿済みなら、ボタンだけ無効化（任意）
      const ts = payload.message?.ts;
      if (ts) {
        // ボタンをグレーアウトに差し替え
        const preview = firstLine((await PREVIEW_STORE.get(key)) ?? "");
        const blocks = [
          { type:"section", text:{ type:"mrkdwn", text:`🧾 解析結果（${filename}）\n\`\`\`\n${preview}\n\`\`\`` } },
          { type:"context", elements:[ { type:"mrkdwn", text:"✅ このスレッドにはすでに全文を投稿済みです" } ] }
        ];
        await updateMessage({ channel: originChannel, ts, text:"解析結果（プレビュー）", blocks });
      }
      return new Response("", { status: 200 });
    }

    const body = (await PREVIEW_STORE.get(key)) ?? "(content expired)";
    const code = "```\n" + body + "\n```";
    await postMessage({
      channel: originChannel,
      thread_ts: originThreadTs, // スレッドに恒久投稿
      text: `🧾 解析結果（全文） — ${filename}\n${code}`
    });
    await PREVIEW_STORE.set(postFlagKey, "1");

    // 押した元メッセージのボタンを「投稿済み」表示に更新（任意）
    const ts = payload.message?.ts;
    if (ts) {
      const preview = firstLine(body);
      const blocks = [
        { type:"section", text:{ type:"mrkdwn", text:`🧾 解析結果（${filename}）\n\`\`\`\n${preview}\n\`\`\`` } },
        { type:"context", elements:[ { type:"mrkdwn", text:"✅ このスレッドに全文を投稿しました（1回だけ）" } ] }
      ];
      await updateMessage({ channel: originChannel, ts, text:"解析結果（プレビュー）", blocks });
    }
    return new Response("", { status: 200 });
  }

  return new Response("", { status: 200 });
}

/* ============ エントリーポイント ============ */
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

  // Interactivity: x-www-form-urlencoded（payload=...）
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

    if (ev.type === "app_mention" && /diag/i.test(ev.text ?? "")) {
      if (ev.channel) await postMessage({ channel: ev.channel, thread_ts: ev.ts, text: "diag: ok ✅" });
      return new Response("", { status: 200 });
    }

    if (ev.type === "file_shared" || ev.subtype === "file_share") {
      try {
        await handleFileShared(ev);
      } catch (e) {
        await logBlob(`errors/handler/${Date.now()}`, { message: e?.message ?? String(e) });
        const ch = ev.channel_id || ev.channel;
        const th = ev.ts || ev.event_ts;
        if (ch && th) await postMessage({ channel: ch, thread_ts: th, text: `❌ 解析失敗: ${e?.message ?? e}` });
      }
      return new Response("", { status: 200 });
    }
  }

  return new Response("", { status: 200 });
}
