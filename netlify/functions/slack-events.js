// Slack Events → .eml検知 → 解析 → 同スレッドに .txt 添付（3MB上限）
// 本文は要約せず「そのまま」。text/plain優先、無ければhtml→text。暗号化はスキップ。

import crypto from "crypto";
import fetch from "node-fetch";
import { simpleParser } from "mailparser";
import { htmlToText } from "html-to-text";

// ===== 設定（環境変数で上書き可） =====
const MAX_TXT_BYTES = parseInt(process.env.MAX_TXT_BYTES || `${3 * 1024 * 1024}`, 10); // 3MB
const FILENAME_MAX  = parseInt(process.env.FILENAME_MAX  || "200", 10);
const TARGET_CHANNELS = (process.env.TARGET_CHANNELS || "")
  .split(",").map(s => s.trim()).filter(Boolean); // 例: "DXXXX,CXXXX"
const ALLOWED_FROM_DOMAINS = (process.env.ALLOWED_FROM_DOMAINS || "")
  .split(",").map(s => s.trim().toLowerCase()).filter(Boolean); // 例: "example.com,partner.co.jp"
// =====================================

export async function handler(event) {
  const rawBody = event.body || "";

  // 1) Slack署名検証
  if (!verifySlackSignature(event.headers, rawBody, process.env.SLACK_SIGNING_SECRET)) {
    return { statusCode: 401, body: "invalid signature" };
  }

  // 2) URL検証
  const body = JSON.parse(rawBody || "{}");
  if (body.type === "url_verification") {
    return { statusCode: 200, body: body.challenge };
  }

  // 3) 再試行の重複抑止
  if (event.headers["x-slack-retry-num"]) return ok();

  const evt = body.event || {};
  if (!evt || evt.type !== "message" || evt.subtype !== "file_share") return ok();

  // 対象チャンネル制限（任意）
  if (TARGET_CHANNELS.length && !TARGET_CHANNELS.includes(evt.channel)) return ok();

  // .eml 判定
  const file = (evt.files || []).find(f =>
    f && (f.mimetype === "message/rfc822" || f.filetype === "eml")
  );
  if (!file) return ok();

  // .eml取得
  const emlBuf = await fetch(file.url_private, {
    headers: { Authorization: `Bearer ${process.env.SLACK_BOT_TOKEN}` }
  }).then(r => r.arrayBuffer());

  // 暗号化/S-MIMEはスキップ（ざっくり判定）
  const headStr = Buffer.from(emlBuf).slice(0, 4096).toString("utf8").toLowerCase();
  if (headStr.includes("application/pkcs7-mime")) {
    await postMessage(evt.channel, evt.ts,
      "このメールは暗号化(S/MIME)のため本文を展開できませんでした（元の .eml を参照してください）。"
    );
    return ok();
  }

  // MIME解析
  const mail = await simpleParser(Buffer.from(emlBuf));
  const subject = mail.subject || "(no subject)";
  const from = mail.from?.text || "";
  const date = mail.date ? mail.date.toISOString() : "";

  // 送信元ドメイン制限（任意）
  if (ALLOWED_FROM_DOMAINS.length && from) {
    const dom = (from.toLowerCase().match(/@([a-z0-9.-]+)/) || [])[1] || "";
    if (!ALLOWED_FROM_DOMAINS.includes(dom)) return ok();
  }

  // 本文：text/plain優先、無ければhtml→text（要約なし）
  let text = (mail.text || "").trim();
  if (!text && mail.html) {
    text = htmlToText(mail.html, {
      wordwrap: false,
      preserveNewlines: true,
      selectors: [{ selector: "a", options: { hideLinkHrefIfSameAsText: true } }]
    }).trim();
  }
  if (!text) text = "(本文なし)";

  // ヘッダ+本文（LF統一）
  const header = `${subject}\nFrom: ${from}\nDate: ${date}\n\n`;
  let content = (header + text).replace(/\r\n/g, "\n");

  // 3MBバイト上限
  if (Buffer.byteLength(content, "utf8") > MAX_TXT_BYTES) {
    content = truncateByBytes(content, MAX_TXT_BYTES - 200)
      + "\n\n--- この先は元の .eml を参照してください（自動カット）";
  }

  // .txtファイル名（元eml名ベース）
  const originalName = file.name || file.title || "mail.eml";
  const filename = toTxtFilename(originalName);

  // .txtをスレッドに添付（コメントは付けない）
  await filesUpload({
    channels: evt.channel,
    thread_ts: evt.ts,
    filename,
    filetype: "text",
    content
  });

  return ok();
}

// ============ Slack API helpers ============
async function postMessage(channel, thread_ts, text) {
  const payload = new URLSearchParams({ channel, text, thread_ts });
  const r = await fetch("https://slack.com/api/chat.postMessage", {
    method: "POST",
    headers: { Authorization: `Bearer ${process.env.SLACK_BOT_TOKEN}`, "Content-Type": "application/x-www-form-urlencoded" },
    body: payload
  });
  const j = await r.json();
  if (!j.ok) throw new Error("chat.postMessage error: " + JSON.stringify(j));
}

async function filesUpload({ channels, thread_ts, filename, filetype, content }) {
  const form = new URLSearchParams();
  form.append("channels", channels);
  form.append("thread_ts", thread_ts);
  form.append("filename", filename);
  form.append("filetype", filetype);
  form.append("content", content);

  const r = await fetch("https://slack.com/api/files.upload", {
    method: "POST",
    headers: { Authorization: `Bearer ${process.env.SLACK_BOT_TOKEN}`, "Content-Type": "application/x-www-form-urlencoded" },
    body: form
  });
  const j = await r.json();
  if (!j.ok) throw new Error("files.upload error: " + JSON.stringify(j));
}

// ============ utils ============
function toTxtFilename(original) {
  const base = (original || "mail.eml").replace(/\.eml$/i, "") || "mail";
  const sanitized = base.replace(/[\\/:*?"<>|]/g, "_").slice(0, FILENAME_MAX);
  return (sanitized || "mail") + ".txt";
}
function truncateByBytes(s, maxBytes) {
  if (Buffer.byteLength(s, "utf8") <= maxBytes) return s;
  let lo = 0, hi = s.length;
  while (lo < hi) {
    const mid = Math.floor((lo + hi) / 2);
    if (Buffer.byteLength(s.slice(0, mid), "utf8") <= maxBytes) lo = mid + 1; else hi = mid;
  }
  return s.slice(0, lo - 1);
}
function verifySlackSignature(headers, rawBody, signingSecret) {
  const ts = headers["x-slack-request-timestamp"];
  const sig = headers["x-slack-signature"];
  if (!ts || !sig || !signingSecret) return false;
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - parseInt(ts, 10)) > 300) return false; // 5分
  const base = `v0:${ts}:${rawBody}`;
  const hmac = crypto.createHmac("sha256", signingSecret).update(base).digest("hex");
  const expected = `v0=${hmac}`;
  try { return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sig)); }
  catch { return false; }
}
function ok() { return { statusCode: 200, body: "ok" }; }
