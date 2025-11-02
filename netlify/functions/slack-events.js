// netlify/functions/slack-events.js
// EMLは常に変換／Slackは1通のコードブロック／長文は安全長でカット＋案内文
import crypto from "node:crypto";
import { simpleParser } from "mailparser";
import { htmlToText } from "html-to-text";

const BOT_TOKEN = process.env.SLACK_BOT_TOKEN;             // xoxb-...
const SIGNING_SECRET = process.env.SLACK_SIGNING_SECRET;   // Slack App > Basic Information
const TZ = process.env.TZ || "Asia/Tokyo";

// 空なら全チャンネル許可。指定時はそのCHのみ処理（省トークン）
const TARGET_CHANNELS = (process.env.TARGET_CHANNELS || "")
  .split(",").map(s => s.trim()).filter(Boolean);

// Slack出力の安全長（1通固定）
const MAX_SAFE_LEN = Number(process.env.MAX_SAFE_LEN || 35000);

// ---------- 共通ユーティリティ ----------
function verifySlackSignature(headers, rawBody) {
  const ts = headers["x-slack-request-timestamp"];
  const sig = headers["x-slack-signature"];
  if (!ts || !sig) return false;
  const base = `v0:${ts}:${rawBody}`;
  const hash = crypto.createHmac("sha256", SIGNING_SECRET).update(base).digest("hex");
  return `v0=${hash}` === sig;
}
const channelAllowed = (chid) => (!TARGET_CHANNELS.length) || (chid && TARGET_CHANNELS.includes(chid));

async function slackApi(method, body) {
  const res = await fetch(`https://slack.com/api/${method}`, {
    method: "POST",
    headers: { Authorization: `Bearer ${BOT_TOKEN}`, "Content-Type": "application/json; charset=utf-8" },
    body: JSON.stringify(body),
  });
  const j = await res.json();
  if (!j.ok) throw new Error(`${method} failed: ${JSON.stringify(j)}`);
  return j;
}

function html2txt(html) {
  return htmlToText(html, {
    wordwrap: false,
    selectors: [{ selector: "a", options: { hideLinkHrefIfSameAsText: true } }],
  });
}
function sanitizeForCodeBlock(text) {
  return (text || "")
    .replace(/```/g, "'''")   // コードブロック内の```事故防止
    .replace(/^>/gm, "＞");   // 行頭>の引用色付き防止（宛名など）
}
function extractUrls(text) {
  if (!text) return [];
  const urls = text.match(/https?:\/\/[^\s<>"')]+/g) || [];
  return [...new Set(urls)].slice(0, 10);
}
function fmtDate(d) {
  try { return new Date(d).toLocaleString("ja-JP", { timeZone: TZ, hour12: false }); }
  catch { return String(d || ""); }
}

// ---------- EML パース ----------
async function parseEml(buf) {
  const mail = await simpleParser(buf);
  const subject = mail.subject || "(no subject)";
  const from = mail.from?.text || mail.headers.get("from") || "";
  const to = mail.to?.text || mail.headers.get("to") || "";
  const date = mail.date || mail.headers.get("date") || "";

  let bodyText = "";
  if (mail.text && mail.text.trim()) bodyText = mail.text;
  else if (mail.html && mail.html.trim()) bodyText = html2txt(mail.html);
  else bodyText = "(no body)";

  // 改行を統一
  bodyText = bodyText.replace(/\r\n/g, "\n");

  return { subject, from, to, date, bodyText, urls: extractUrls(bodyText) };
}

// ---------- 投稿（1メッセージ固定） ----------
async function postOne({ channel, fileName, parsed }) {
  const headerLines = [
    `*件名:* ${parsed.subject}`,
    parsed.from ? `*From:* ${parsed.from}` : null,
    parsed.to   ? `*To:* ${parsed.to}`     : null,
    parsed.date ? `*Date:* ${fmtDate(parsed.date)}` : null,
    `*ファイル:* ${fileName || "mail.eml"}`
  ].filter(Boolean);

  if (parsed.urls.length) {
    headerLines.push(`*URLs:*`);
    parsed.urls.forEach(u => headerLines.push(`• ${u}`));
  }

  // 本文を安全化 → 既定長でトリム → 長文案内を追加
  let body = sanitizeForCodeBlock(parsed.bodyText);
  if (body.length > MAX_SAFE_LEN) {
    body = body.slice(0, MAX_SAFE_LEN) +
      "\n\n---\n💡 *このメールは長文のため一部省略されています。*\n" +
      "続きを参照したい場合は `.eml` ファイルを生成AIなどでご確認ください。";
  }

  const postText = `${headerLines.join("\n")}\n\n\`\`\`\n${body}\n\`\`\``;
  await slackApi("chat.postMessage", { channel, text: postText });
}

// ---------- メインハンドラ ----------
export default async (event) => {
  const rawBody = event.body || "";

  // 1) SlackのURL検証（challenge）
  try {
    const j = JSON.parse(rawBody);
    if (j?.type === "url_verification" && j?.challenge) {
      return { statusCode: 200, body: j.challenge };
    }
  } catch {}

  // 2) 低コスト・テスト（Slack APIを呼ばずに解析プレビューを返す）
  try {
    const t = JSON.parse(rawBody);
    if (t?.__test_base64_eml) {
      const buf = Buffer.from(t.__test_base64_eml, "base64");
      const p = await parseEml(buf);
      const headerPreview = `件名: ${p.subject} / From: ${p.from}`;
      const preview = p.bodyText.replace(/\s+/g, " ").slice(0, 220);
      return {
        statusCode: 200,
        headers: { "Content-Type": "application/json; charset=utf-8" },
        body: JSON.stringify({ ok: true, headerPreview, preview }),
      };
    }
  } catch {}

  // 3) 本番ルート：署名検証 & 早期return
  if (!verifySlackSignature(event.headers, rawBody)) return { statusCode: 401, body: "invalid signature" };
  if (event.headers["x-slack-retry-num"]) return { statusCode: 200, body: "" };

  const body = JSON.parse(rawBody || "{}");
  if (body?.type !== "event_callback") return { statusCode: 200, body: "" };
  const ev = body.event;
  if (ev?.type !== "file_shared") return { statusCode: 200, body: "" };

  const channel_id = ev.channel_id;
  if (!channelAllowed(channel_id)) return { statusCode: 200, body: "" };

  // 4) file 情報
  let file;
  try {
    const info = await slackApi("files.info", { file: ev.file_id });
    file = info.file;
  } catch { return { statusCode: 200, body: "" }; }

  // .eml 判定（拡張子 / mimetype）
  const isEml = (file?.filetype === "eml") ||
                (file?.mimetype || "").includes("message/rfc822") ||
                (file?.name || "").toLowerCase().endsWith(".eml");
  if (!isEml) return { statusCode: 200, body: "" };

  // 5) ダウンロード（サイズに関係なく常に実行）
  const url = file?.url_private_download || file?.url_private;
  if (!url) return { statusCode: 200, body: "" };

  let emlBuf;
  try {
    const res = await fetch(url, { headers: { Authorization: `Bearer ${BOT_TOKEN}` } });
    if (!res.ok) throw new Error(`download failed: ${res.status}`);
    emlBuf = Buffer.from(await res.arrayBuffer());
  } catch {
    try { await slackApi("chat.postMessage", { channel: channel_id, text: `:x: \`${file.name}\` のダウンロードに失敗しました。` }); } catch {}
    return { statusCode: 200, body: "" };
  }

  // 6) 解析 → 投稿（1メッセージ固定）
  try {
    const parsed = await parseEml(emlBuf);
    await postOne({ channel: channel_id, fileName: file.name || "mail.eml", parsed });
  } catch {
    try { await slackApi("chat.postMessage", { channel: channel_id, text: `:x: \`${file.name}\` の解析・展開に失敗しました。` }); } catch {}
  }

  return { statusCode: 200, body: "" };
};
