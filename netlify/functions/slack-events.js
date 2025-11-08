// netlify/functions/slack-events.js
// プレビュー↔全文トグル対応 / 二重投稿防止 / スレッドのみ返信 / 言語ラベル(text)削除版

import crypto from "node:crypto";
import { simpleParser } from "mailparser";
import { getStore } from "@netlify/blobs";
import { htmlToText } from "html-to-text";

const BOT_TOKEN = process.env.SLACK_BOT_TOKEN ?? "";
const SIGNING_SECRET = (process.env.SLACK_SIGNING_SECRET ?? "").trim();
const MAX_PREVIEW_CHARS = parseInt(process.env.MAX_PREVIEW_CHARS ?? "3000", 10);

// 任意の軽量ログ
const LOG_TO_BLOBS = (process.env.LOG_TO_BLOBS ?? "false").toLowerCase() === "true";
const LOG_STORE = LOG_TO_BLOBS ? getStore({ name: process.env.BLOB_STORE_NAME || "logs" }) : null;

// プレビュー/全文の一時保存用（省コスト）
const PREVIEW_STORE = getStore({ name: process.env.PREVIEW_STORE_NAME || "previews" });

/* -------------------- 共通ユーティリティ -------------------- */
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

async function postMessage({ channel, text, thread_ts, blocks }) {
  const r = await fetch("https://slack.com/api/chat.postMessage", {
    method: "POST",
    headers: { Authorization: `Bearer ${BOT_TOKEN}`, "Content-Type": "application/json; charset=utf-8" },
    body: JSON.stringify({ channel, text, thread_ts, blocks }),
  });
  return r.json();
}
async function updateMessage({ channel, ts, text, blocks }) {
  const r = await fetch("https://slack.com/api/chat.update", {
    method: "POST",
    headers: { Authorization: `Bearer ${BOT_TOKEN}`, "Content-Type": "application/json; charset=utf-8" },
    body: JSON.stringify({ channel, ts, text, blocks }),
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
async function logBlob(path, data) {
  if (!LOG_TO_BLOBS || !LOG_STORE) return;
  try { await LOG_STORE.set(path, typeof data === "string" ? data : JSON.stringify(data)); } catch {}
}

/* -------------------- 解析系 -------------------- */
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
async function parseMSGorOFT(buf) {
  const { default: MsgReader } = await import("@kenjiuno/msgreader"); // 動的 import（.eml 時は未読込）
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
        const ts = p.thread_ts || p.ts; // 親メッセージの ts
        if (cid && ts) return { channel: cid, thread_ts: ts };
      }
    }
  }
  return { channel: null, thread_ts: null };
}

/* -------------------- Slack UI Blocks -------------------- */
// 言語ラベル(text)を外すため、``` の後は空にする
function blocksPreview(filename, preview, key) {
  return [
    { type: "section",
      text: { type: "mrkdwn", text: `🧾 解析結果（${filename}）\n\`\`\`\n${preview}\n\`\`\`` } },
    { type: "actions", elements: [
      { type: "button", text: { type: "plain_text", text: "全文を見る" }, action_id: "show_full", value: key }
    ]}
  ];
}
function blocksFull(body) {
  return [
    { type: "section", text: { type: "mrkdwn", text: "```\n" + body + "\n```" } },
    { type: "actions", elements: [
      { type: "button", text: { type: "plain_text", text: "プレビューに戻す" }, action_id: "show_preview" }
    ]}
  ];
}

/* -------------------- メイン処理 -------------------- */
async function handleFileShared(ev) {
  // 二重実行の早期リターン（Slackのリトライ or 同一ファイル二重イベント）
  const fileId = ev.file_id || ev.file?.id || (Array.isArray(ev.files) && ev.files[0]?.id) || null;
  if (!fileId) throw new Error("no file_id");

  const doneKey = `done:${fileId}`;
  if (await PREVIEW_STORE.get(doneKey)) return; // 既に投稿済みなら何もしない

  const finfo = await filesInfo(fileId);
  if (!finfo.ok) throw new Error(`files.info failed: ${JSON.stringify(finfo)}`);
  const f = finfo.file;

  // スレッド先を厳密決定
  const sharesRef = resolveFromShares(f);
  const channel = ev.channel_id || ev.channel || sharesRef.channel;
  const thread_ts = ev.ts || sharesRef.thread_ts || ev.event_ts;
  if (!channel || !thread_ts) throw new Error("cannot resolve thread");

  // 拡張子判定
  if (!isSupportedName(f.name)) {
    await postMessage({ channel, thread_ts, text: `⚠️ 未対応の拡張子です: \`${f.name}\`（.eml/.msg/.oft）` });
    return;
  }

  // ダウンロード→解析
  const url = f.url_private_download || f.url_private;
  if (!url) throw new Error("no url_private_download");
  const buf = await downloadPrivate(url);

  let parsed = "";
  const low = f.name.toLowerCase();
  if (low.endsWith(".eml")) parsed = await parseEML(buf);
  else parsed = await parseMSGorOFT(buf);

  const body = normalizeText(parsed);

  // プレビュー保存 / 二重投稿防止フラグ
  const dataKey = `p:${Date.now()}:${fileId}`;
  await PREVIEW_STORE.set(dataKey, body);
  await PREVIEW_STORE.set(doneKey, "1");

  // 1行プレビュー＋トグルボタン（スレッドのみ）
  const preview = firstLine(body);
  await postMessage({
    channel,
    thread_ts,
    text: "解析結果（プレビュー）",
    blocks: blocksPreview(f.name, preview, dataKey),
  });
}

/* --------- ボタン押下（全文↔プレビューのトグル） --------- */
async function handleBlockActions(payload) {
  const action = payload?.actions?.[0];
  const channel = payload.channel?.id;
  const ts = payload.message?.ts;
  if (!channel || !ts) return new Response("", { status: 200 });

  if (action?.action_id === "show_full") {
    const key = action.value;
    const body = (await PREVIEW_STORE.get(key)) ?? "(content expired)";
    await updateMessage({ channel, ts, text: "解析結果（全文）", blocks: blocksFull(body) });
    return new Response("", { status: 200 });
  }
  if (action?.action_id === "show_preview") {
    // 直前の全文テキストから1行プレビュー再生成（タイトル行の text ラベルなし）
    const fullBlock = payload.message?.blocks?.find(b => b.type === "section");
    const code = fullBlock?.text?.text || "";
    const body = code.replace(/^```\n?|\n?```$/g, ""); // ``` で挟まれた部分を抽出
    const preview = firstLine(body);
    await updateMessage({
      channel,
      ts,
      text: "解析結果（プレビュー）",
      blocks: blocksPreview("メール本文", preview, "reopen-not-needed")
    });
    return new Response("", { status: 200 });
  }

  return new Response("", { status: 200 });
}

/* -------------------- エントリーポイント -------------------- */
export default async function handler(req) {
  const raw = await req.text();
  const ts = req.headers.get("x-slack-request-timestamp");
  const sig = req.headers.get("x-slack-signature");
  const contentType = req.headers.get("content-type") || "";

  // Slackのリトライは即 200 で打ち止め
  const retryNum = req.headers.get("x-slack-retry-num");
  if (retryNum) {
    return new Response("", { status: 200, headers: { "X-Slack-No-Retry": "1" } });
    }

  // 署名検証（Interactivity も Events も raw でOK）
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

    // diag
    if (ev.type === "app_mention" && /diag/i.test(ev.text ?? "")) {
      const text = "diag: ok ✅";
      if (ev.channel) await postMessage({ channel: ev.channel, thread_ts: ev.ts, text });
      return new Response("", { status: 200 });
    }

    // ファイル共有（file_shared / message.subtype=file_share 両対応）
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
