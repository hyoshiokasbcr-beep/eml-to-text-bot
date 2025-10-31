// ESM (Node18+)。本番は従来どおり、テスト時は __test_base64_eml を受けてローカル実行だけで確認可能。

import { createHmac, timingSafeEqual } from "node:crypto";
import { simpleParser } from "mailparser";
import { htmlToText } from "html-to-text";

// ===== Env =====
const BOT_TOKEN = process.env.SLACK_BOT_TOKEN || "";
const SIGNING_SECRET = process.env.SLACK_SIGNING_SECRET || "";
const MAX_TXT_BYTES = parseInt(process.env.MAX_TXT_BYTES || `${3 * 1024 * 1024}`, 10); // 3MB
const FILENAME_MAX = parseInt(process.env.FILENAME_MAX || "200", 10);
const TARGET_CHANNELS = (process.env.TARGET_CHANNELS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean); // 空なら全チャンネル許可

// ===== Utils =====
const ok = (body = "ok") => ({ statusCode: 200, body });
const bad = (code, msg) => ({ statusCode: code, body: msg });

function secureEquals(a, b) {
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}
function verifySlackSignature(headers, rawBody) {
  const ts = headers["x-slack-request-timestamp"];
  const sig = headers["x-slack-signature"];
  if (!ts || !sig || Math.abs(Date.now() / 1000 - Number(ts)) > 60 * 5) return false;
  const base = `v0:${ts}:${rawBody}`;
  const hmac = createHmac("sha256", SIGNING_SECRET).update(base).digest("hex");
  const expected = `v0=${hmac}`;
  return secureEquals(expected, sig);
}
function toTxtFilename(original) {
  const base = (original || "mail.eml").replace(/\.eml$/i, "") || "mail";
  const sanitized = base.replace(/[\\/:*?"<>|]/g, "_").slice(0, FILENAME_MAX);
  return (sanitized || "mail") + ".txt";
}
function truncateByBytes(str, maxBytes) {
  const enc = new TextEncoder();
  const bytes = enc.encode(str);
  if (bytes.length <= maxBytes) return str;
  const suffix = "\n\n--- この先は元の .eml を参照してください（自動カット）";
  const suffixBytes = enc.encode(suffix).length;
  const target = Math.max(0, maxBytes - suffixBytes);
  let lo = 0, hi = str.length;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (enc.encode(str.slice(0, mid)).length <= target) lo = mid;
    else hi = mid - 1;
  }
  return str.slice(0, lo) + suffix;
}
function pickEmlFile(evt) {
  const files = evt.files || [];
  return files.find((f) => {
    if (!f) return false;
    const name = (f.name || f.title || "").toLowerCase();
    const byExt = name.endsWith(".eml");
    const byType = f.mimetype === "message/rfc822" || f.filetype === "eml";
    return byExt || byType;
  });
}
async function downloadPrivateFile(file) {
  const url = file.url_private_download || file.url_private;
  const res = await fetch(url, { headers: { Authorization: `Bearer ${BOT_TOKEN}` } });
  if (!res.ok) {
    const txt = await res.text().catch(() => "");
    console.error("DOWNLOAD_FAIL", res.status, txt.slice(0, 200));
    throw new Error(`download failed: ${res.status}`);
  }
  const ab = await res.arrayBuffer();
  return Buffer.from(ab);
}
async function parseEmlToText(emlBuf) {
  const parsed = await simpleParser(emlBuf);
  if (parsed.text && parsed.text.trim()) return parsed.text;
  if (parsed.html && parsed.html.trim()) return htmlToText(parsed.html, { wordwrap: false });
  return emlBuf.toString("utf8");
}
async function uploadTxtToSlack({ channel, thread_ts, filename, content }) {
  const form = new FormData();
  form.set("channels", channel);
  if (thread_ts) form.set("thread_ts", thread_ts);
  form.set("filename", filename);
  form.set("title", filename);
  form.set("filetype", "text");
  form.set("content", content);
  const res = await fetch("https://slack.com/api/files.upload", {
    method: "POST",
    headers: { Authorization: `Bearer ${BOT_TOKEN}` },
    body: form,
  });
  const j = await res.json();
  if (!j.ok) throw new Error(`files.upload error: ${JSON.stringify(j)}`);
  return j;
}

// ===== Handler =====
export async function handler(event) {
  const rawBody = event.body || "";

  // ---------- [テスト専用] ここだけで通る特別経路 ----------
  // 本番のSlackイベントでは決して使われないフィールド名 "__test_base64_eml" をキーにしています。
  // netlify dev でローカル起動 → curl で base64化した .eml を投げると、解析結果の preview を返します。
 // ---------- [テスト専用] ----------
try {
  const j = JSON.parse(event.body || "{}");
  if (j.__test_base64_eml) {
    const emlBuf = Buffer.from(j.__test_base64_eml, "base64");
    let text;
    try { text = await parseEmlToText(emlBuf); }
    catch { text = emlBuf.toString("utf8"); }
    text = truncateByBytes(text, MAX_TXT_BYTES);

    // ← ここで charset を明示
    return {
      statusCode: 200,
      headers: { "Content-Type": "application/json; charset=utf-8" },
      body: JSON.stringify({ ok: true, preview: text.slice(0, 4000) }),
    };
  }
} catch {}
// ---------------------------------

  // ----------------------------------------------------------

  // URL検証（最優先）
  try {
    const j = JSON.parse(rawBody || "{}");
    if (j.type === "url_verification" && j.challenge) return ok(j.challenge);
  } catch {}

  // 署名検証
  if (!verifySlackSignature(event.headers, rawBody)) return bad(401, "invalid signature");

  // 本体
  const body = JSON.parse(rawBody || "{}");
  const evt = body.event || {};

  if (TARGET_CHANNELS.length && !TARGET_CHANNELS.includes(evt.channel)) return ok("ignored: channel not allowed");
  if (evt.type !== "message") return ok("ignored: not a message");

  const file = pickEmlFile(evt);
  if (!file) return ok("ignored: no eml file");

  try {
    // 取得
    const emlBuf = await downloadPrivateFile(file);

    // 解析（失敗時フォールバック）
    let text;
    try {
      text = await parseEmlToText(emlBuf);
    } catch (pe) {
      console.warn("PARSE_ERROR_fallback_to_raw", String(pe));
      text = emlBuf.toString("utf8");
    }
    text = truncateByBytes(text, MAX_TXT_BYTES);

    // 添付
    const filename = toTxtFilename(file.name || file.title);
    await uploadTxtToSlack({
      channel: evt.channel,
      thread_ts: evt.thread_ts || evt.ts,
      filename,
      content: text,
    });

    return ok("done");
  } catch (e) {
    console.error("PROCESS_ERROR", e && (e.stack || e));
    try {
      await fetch("https://slack.com/api/chat.postMessage", {
        method: "POST",
        headers: { Authorization: `Bearer ${BOT_TOKEN}`, "Content-Type": "application/json; charset=utf-8" },
        body: JSON.stringify({
          channel: evt.channel,
          thread_ts: evt.thread_ts || evt.ts,
          text: "⚠️ .eml の展開に失敗しました。元ファイルをご確認ください。",
        }),
      });
    } catch {}
    return ok("error handled");
  }
}
