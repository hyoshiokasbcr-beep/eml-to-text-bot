// netlify/functions/slack-events.js
// シンプル版：ファイル付き投稿があった場合のみ本文をパースして1回返信する
import crypto from "node:crypto";
import { simpleParser } from "mailparser";
import { htmlToText } from "html-to-text";
import MsgReader from "@kenjiuno/msgreader"; // unscoped msgreader は不要です

const BOT_TOKEN = process.env.SLACK_BOT_TOKEN || "";
const SIGNING_SECRET = (process.env.SLACK_SIGNING_SECRET || "").trim();
const MAX_PREVIEW = parseInt(process.env.MAX_PREVIEW_CHARS || "3000", 10);

// Slack 署名検証
function verifySlackSignature({ rawBody, timestamp, slackSig }) {
  if (!SIGNING_SECRET || !slackSig || !timestamp) return false;
  const base = `v0:${timestamp}:${rawBody}`;
  const hmac = crypto.createHmac("sha256", SIGNING_SECRET);
  hmac.update(base);
  const expected = `v0=${hmac.digest("hex")}`;
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(slackSig));
}

// Slack メッセージ送信
async function postMessage({ channel, text, thread_ts }) {
  const res = await fetch("https://slack.com/api/chat.postMessage", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${BOT_TOKEN}`,
      "Content-Type": "application/json; charset=utf-8"
    },
    body: JSON.stringify({ channel, text, thread_ts })
  });
  return res.json();
}

// ファイル情報取得
async function filesInfo(fileId) {
  const res = await fetch(`https://slack.com/api/files.info?file=${encodeURIComponent(fileId)}`, {
    headers: { Authorization: `Bearer ${BOT_TOKEN}` }
  });
  return res.json();
}

// プライベート URL からダウンロード
async function downloadFile(url) {
  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${BOT_TOKEN}` }
  });
  if (!res.ok) throw new Error(`download failed: ${res.status}`);
  const buf = Buffer.from(await res.arrayBuffer());
  return buf;
}

// EML 解析
async function parseEML(buf) {
  const mail = await simpleParser(buf);
  let body = "";
  if (mail.html) {
    body = htmlToText(mail.html, { wordwrap: false });
  } else if (mail.text) {
    body = mail.text;
  }
  const header = [
    `From: ${mail.from?.text ?? ""}`,
    `To: ${mail.to?.text ?? ""}`,
    mail.cc ? `Cc: ${mail.cc.text}` : null,
    `Date: ${mail.date ?? ""}`,
    `Subject: ${mail.subject ?? ""}`
  ].filter(Boolean).join("\n");
  return `# ${mail.subject ?? ""}\n${header}\n\n${body ?? ""}`;
}

// MSG/OFT 解析
async function parseMSGorOFT(buf) {
  // MsgReader は ArrayBuffer または Uint8Array を受け取る
  const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  const reader = new MsgReader(u8);
  const info = reader.getFileData();
  const html = info.bodyHTML ?? info.messageComps?.htmlBody ?? null;
  const text = info.body ?? info.messageComps?.plainText ?? null;
  const rtf  = info.bodyRTF ?? info.messageComps?.rtfBody ?? null;

  let body = "";
  if (html) {
    body = htmlToText(html, { wordwrap: false });
  } else if (text) {
    body = text;
  } else if (rtf) {
    body = rtf.replace(/\\[a-z]+\d* ?|[{}]/gi, " ").replace(/\s+/g, " ").trim();
  }

  const header = [
    `From: ${info.senderName || info.senderEmail || ""}`,
    `To: ${Array.isArray(info.recipients) ? info.recipients.map(r => r.name || r.email).join(", ") : ""}`,
    info.cc ? `Cc: ${info.cc}` : null,
    `Date: ${info.messageDeliveryTime || info.creationTime || ""}`,
    `Subject: ${info.subject || ""}`
  ].filter(Boolean).join("\n");

  return `# ${info.subject || ""}\n${header}\n\n${body || ""}`;
}

// 拡張子判定
function isSupported(fileName = "") {
  const lower = fileName.toLowerCase();
  return lower.endsWith(".eml") || lower.endsWith(".msg") || lower.endsWith(".oft");
}

// 受信イベントハンドラー
export default async function handler(req) {
  // 署名確認
  const rawBody = await req.text();
  const timestamp = req.headers.get("x-slack-request-timestamp");
  const slackSig = req.headers.get("x-slack-signature");
  if (!verifySlackSignature({ rawBody, timestamp, slackSig })) {
    return new Response("invalid signature", { status: 401 });
  }

  // URL verification
  let payload;
  try {
    payload = JSON.parse(rawBody);
  } catch {
    return new Response("bad request", { status: 400 });
  }
  if (payload.type === "url_verification") {
    return new Response(payload.challenge, { headers: { "Content-Type": "text/plain" } });
  }

  // イベント処理
  if (payload.type === "event_callback") {
    const ev = payload.event;

    // Slack のファイル共有イベント
    if ((ev.type === "file_shared") || (ev.type === "message" && ev.subtype === "file_share")) {
      const fileId = ev.file_id || (ev.files?.[0]?.id);
      if (!fileId) return new Response("", { status: 200 });

      // ファイル情報取得
      const info = await filesInfo(fileId);
      if (!info.ok) return new Response("", { status: 200 });
      const file = info.file;

      // 対応していない拡張子は無視
      if (!isSupported(file.name)) {
        return new Response("", { status: 200 });
      }

      // ダウンロード
      const buf = await downloadFile(file.url_private_download || file.url_private);

      // 解析
      let parsed = "";
      const lower = file.name.toLowerCase();
      if (lower.endsWith(".eml")) {
        parsed = await parseEML(buf);
      } else {
        parsed = await parseMSGorOFT(buf);
      }

      // プレビュー生成
      const clean = parsed.replace(/\r/g, "");
      const preview = clean.length <= MAX_PREVIEW ? clean : clean.slice(0, MAX_PREVIEW) + "\n…(truncated)";
      const codeBlock = "```\n" + preview + "\n```";

      // チャンネルとスレッドを決定
      const channel = ev.channel_id || ev.channel || file.channels?.[0];
      const thread_ts = ev.event_ts || ev.ts;
      if (!channel) return new Response("", { status: 200 });

      // Slack に送信（解析終了メッセージのみ）
      await postMessage({
        channel,
        thread_ts,
        text: `🧾 解析結果（${file.name}）\n${codeBlock}`
      });

      return new Response("", { status: 200 });
    }
  }

  return new Response("", { status: 200 });
}
