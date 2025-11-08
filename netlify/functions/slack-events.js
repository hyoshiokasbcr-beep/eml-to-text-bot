// netlify/functions/slack-events.js
// ✅改訂版：プレビュー↔全文を何度でもトグル可（content expired を解消）
// - ボタンの value に一貫して “key” を持たせ、毎回その key で本文を取得
// - PREVIEW_STORE には { body, filename } を JSON で保存
// - .eml/.msg/.oft 以外は完全スルー（返信なし）→ クレジット最小化
// - file_shared のみ処理（message.subtype=file_share は無視）
// - 重複防止: done:<fileId>:<channel>:<thread_ts>
// - スレッドのみ返信、言語ラベル（text）非表示、msgreader は動的 import

import crypto from "node:crypto";
import { simpleParser } from "mailparser";
import { getStore } from "@netlify/blobs";
import { htmlToText } from "html-to-text";

const BOT_TOKEN = process.env.SLACK_BOT_TOKEN ?? "";
const SIGNING_SECRET = (process.env.SLACK_SIGNING_SECRET ?? "").trim();
const MAX_PREVIEW_CHARS = parseInt(process.env.MAX_PREVIEW_CHARS ?? "3000", 10);

// 省エネ：ログは既定OFF
const LOG_TO_BLOBS = (process.env.LOG_TO_BLOBS ?? "false").toLowerCase() === "true";
const LOG_STORE = LOG_TO_BLOBS ? getStore({ name: process.env.BLOB_STORE_NAME || "logs" }) : null;

// プレビュー/全文データ保存（低コスト）
const PREVIEW_STORE = getStore({ name: process.env.PREVIEW_STORE_NAME || "previews" });

/* -------------------- utils -------------------- */
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
async function logBlob(path, data) {
  if (!LOG_TO_BLOBS || !LOG_STORE) return;
  try { await LOG_STORE.set(path, typeof data === "string" ? data : JSON.stringify(data)); } catch {}
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

/* -------------------- parsing -------------------- */
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
  // .msg/.oft のみ読込（.eml の時は未読込）→ コスト削減
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

/* -------------------- Slack UI Blocks -------------------- */
// 言語ラベルを出さないため ``` の後は空
function blocksPreview(filename, preview, key) {
  return [
    {
      type: "section",
      text: { type: "mrkdwn", text: `🧾 解析結果（${filename}）\n\`\`\`\n${preview}\n\`\`\`` }
    },
    {
      type: "actions",
      elements: [
        { type: "button", text: { type: "plain_text", text: "全文を見る" }, action_id: "show_full", value: key }
      ]
    }
  ];
}
function blocksFull(filename, body, key) {
  return [
    { type: "section", text: { type: "mrkdwn", text: `🧾 解析結果（${filename}）\n\`\`\`\n${body}\n\`\`\`` } },
    { type: "actions", elements: [
      { type: "button", text: { type: "plain_text", text: "プレビューに戻す" }, action_id: "show_preview", value: key }
    ] }
  ];
}

/* -------------------- メイン処理 -------------------- */
async function handleFileShared(ev) {
  // file_shared のみ処理（subtype=file_share は無視）
  const fileId = ev.file_id || ev.file?.id || (Array.isArray(ev.files) && ev.files[0]?.id) || null;
  if (!fileId) return;

  // まずファイル情報だけ見て対応拡張子か確認（非対応は完全スルー）
  const finfo = await filesInfo(fileId);
  if (!finfo.ok) return;
  const f = finfo.file;
  if (!isSupportedName(f.name)) return;

  // スレッド先（channel, thread_ts）確定
  const sharesRef = resolveFromShares(f);
  const channel = ev.channel_id || ev.channel || sharesRef.channel;
  const thread_ts = ev.ts || sharesRef.thread_ts || ev.event_ts;
  if (!channel || !thread_ts) return;

  // 重複防止（fileId + channel + thread_ts）
  const doneKey = `done:${fileId}:${channel}:${thread_ts}`;
  if (await PREVIEW_STORE.get(doneKey)) return;

  // ここから初めてダウンロード（対応拡張子のみ）→ 節約
  const url = f.url_private_download || f.url_private;
  if (!url) return;
  const buf = await downloadPrivate(url);

  // 解析
  let parsed = "";
  const low = f.name.toLowerCase();
  if (low.endsWith(".eml")) parsed = await parseEML(buf);
  else parsed = await parseMSGorOFT(buf);

  const body = normalizeText(parsed);

  // データ保存：本文とファイル名を JSON で保持（何度でも開閉OK）
  const dataKey = `p:${Date.now()}:${fileId}`;
  const data = { body, filename: f.name };
  await PREVIEW_STORE.set(dataKey, JSON.stringify(data));
  await PREVIEW_STORE.set(doneKey, "1"); // 重複防止フラグ

  // 1行プレビューだけをスレッドに投稿（ボタン value に key を常に付与）
  const preview = firstLine(body);
  await postMessage({
    channel,
    thread_ts,
    text: "解析結果（プレビュー）",
    blocks: blocksPreview(f.name, preview, dataKey),
  });
}

/* --------- ボタン押下（全文↔プレビューのトグル：何度でもOK） --------- */
async function handleBlockActions(payload) {
  const action = payload?.actions?.[0];
  const channel = payload.channel?.id;
  const ts = payload.message?.ts;
  if (!channel || !ts || !action) return new Response("", { status: 200 });

  // どちらのボタンも value に key を持たせている
  const key = action.value;
  let raw = await PREVIEW_STORE.get(key);
  if (!raw) {
    // キーが無ければ終了（保存期間切れ時など）
    return new Response("", { status: 200 });
  }
  // 文字列 or JSON 互換
  let body = "";
  let filename = "メール本文";
  try {
    const obj = JSON.parse(raw);
    body = obj.body ?? "";
    filename = obj.filename ?? filename;
  } catch {
    body = String(raw);
  }

  if (action.action_id === "show_full") {
    await updateMessage({ channel, ts, text: "解析結果（全文）", blocks: blocksFull(filename, body, key) });
    return new Response("", { status: 200 });
  }
  if (action.action_id === "show_preview") {
    const preview = firstLine(body);
    await updateMessage({ channel, ts, text: "解析結果（プレビュー）", blocks: blocksPreview(filename, preview, key) });
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

  // Slack のリトライは即 200（処理を重ねない）
  if (req.headers.get("x-slack-retry-num")) {
    return new Response("", { status: 200, headers: { "X-Slack-No-Retry": "1" } });
  }

  // 署名検証（Events も Interactivity も raw でOK）
  if (!verifySlackSignature({ rawBody: raw, timestamp: ts, slackSig: sig })) {
    await logBlob(`errors/sign/${Date.now()}`, { reason: "invalid-signature", ts });
    return new Response("invalid signature", { status: 401 });
  }

  // Interactivity（ボタン）
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

    // diag（任意・省エネのため最小限）
    if (ev.type === "app_mention" && /diag/i.test(ev.text ?? "")) {
      if (ev.channel) await postMessage({ channel: ev.channel, thread_ts: ev.ts, text: "diag: ok ✅" });
      return new Response("", { status: 200 });
    }

    // ★ file_shared のみ処理（subtype=file_share は無視）
    if (ev.type === "file_shared") {
      try {
        await handleFileShared(ev);
      } catch (e) {
        await logBlob(`errors/handler/${Date.now()}`, { message: e?.message ?? String(e) });
        // 省クレ運用: ユーザーへのエラー返信はしない
      }
      return new Response("", { status: 200 });
    }
  }

  return new Response("", { status: 200 });
}
