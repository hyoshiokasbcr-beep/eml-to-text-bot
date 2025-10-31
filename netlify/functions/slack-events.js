// ESM (Node 18+) ベスト実装。拡張子 .eml でも検出し、3MBで安全カットし、同スレッドに .txt を添付。
import { createHmac, timingSafeEqual } from "node:crypto";
import { simpleParser } from "mailparser";
import { htmlToText } from "html-to-text";

// ===== 環境変数 =====
const BOT_TOKEN = process.env.SLACK_BOT_TOKEN || "";
const SIGNING_SECRET = process.env.SLACK_SIGNING_SECRET || "";
const MAX_TXT_BYTES = parseInt(process.env.MAX_TXT_BYTES || `${3 * 1024 * 1024}`, 10); // 3MB
const FILENAME_MAX = parseInt(process.env.FILENAME_MAX || "200", 10);
const TARGET_CHANNELS = (process.env.TARGET_CHANNELS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean); // 空なら全チャンネル許可

// ===== ユーティリティ =====
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
  // 末尾メッセージ分の余白を残す
  const suffix = "\n\n--- この先は元の .eml を参照してください（自動カット）";
  const suffixBytes = enc.encode(suffix).length;
  const target = Math.max(0, maxBytes - suffixBytes);
  // バイト境界で安全に切る
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
  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${BOT_TOKEN}` },
  });
  if (!res.ok) throw new Error(`download failed: ${res.status}`);
  const ab = await res.arrayBuffer();
  return Buffer.from(ab);
}

async function parseEmlToText(emlBuf) {
  const parsed = await simpleParser(emlBuf);
  if (parsed.text && parsed.text.trim()) return parsed.text;
  if (parsed.html && parsed.html.trim()) return htmlToText(parsed.html, { wordwrap: false });
  // 最終手段：そのままテキスト化（バイナリ混入回避のため UTF-8 想定）
  return emlBuf.toString("utf8");
}

async function uploadTxtToSlack({ channel, thread_ts, filename, content }) {
  // files.upload に content で投げる（バイナリ不要・軽量）
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

// ===== Netlify Function =====
export async function handler(event) {
  const rawBody = event.body || "";

  // 0) URL 検証（まずこれを返すとセットアップがスムーズ）
-  try {
-    // 3) .eml 取得 → 解析 → テキスト化
-    const emlBuf = await downloadPrivateFile(file);
-    let text = await parseEmlToText(emlBuf);
-    text = truncateByBytes(text, MAX_TXT_BYTES);
-
-    // 4) アップロード（同スレッド）
-    const filename = toTxtFilename(file.name || file.title);
-    await uploadTxtToSlack({
-      channel: evt.channel,
-      thread_ts: evt.thread_ts || evt.ts,
-      filename,
-      content: text,
-    });
-
-    return ok("done");
-  } catch (e) {
+  try {
+    // 3) .eml 取得
+    const emlBuf = await downloadPrivateFile(file);
+
+    // 3.1) まずは mailparser でテキスト化を試す
+    let text;
+    try {
+      text = await parseEmlToText(emlBuf);
+    } catch (pe) {
+      console.warn("PARSE_ERROR_fallback_to_raw", String(pe));
+      // 失敗時は“そのまま”をUTF-8として扱う（要望どおり）
+      text = emlBuf.toString("utf8");
+    }
+    // 上限適用
+    text = truncateByBytes(text, MAX_TXT_BYTES);
+
+    // 4) アップロード（同スレッド）
+    const filename = toTxtFilename(file.name || file.title);
+    await uploadTxtToSlack({
+      channel: evt.channel,
+      thread_ts: evt.thread_ts || evt.ts,
+      filename,
+      content: text,
+    });
+    return ok("done");
+  } catch (e) {
+    // ダウンロード失敗などの詳細をログに出す
+    console.error("PROCESS_ERROR", e && (e.stack || e));
     // 失敗時はスレッドに簡単なエラーを返す（本文ログは残さない）
     try {
       await fetch("https://slack.com/api/chat.postMessage", {
         method: "POST",
         headers: {
           Authorization: `Bearer ${BOT_TOKEN}`,
           "Content-Type": "application/json; charset=utf-8",
         },
         body: JSON.stringify({
           channel: evt.channel,
           thread_ts: evt.thread_ts || evt.ts,
           text: "⚠️ .eml の展開に失敗しました。元ファイルをご確認ください。",
         }),
       });
     } catch {}
     return ok("error handled");
   }


  // 1) 署名検証
  if (!verifySlackSignature(event.headers, rawBody)) {
    return bad(401, "invalid signature");
  }

  // 2) イベント本体
  const body = JSON.parse(rawBody || "{}");
  const evt = body.event || {};

  // 対象チャンネル制限（設定されている場合のみ）
  if (TARGET_CHANNELS.length && !TARGET_CHANNELS.includes(evt.channel)) {
    return ok("ignored: channel not allowed");
  }

  // message + file_share を想定（.eml がぶら下がる）
  if (evt.type !== "message") return ok("ignored: not a message");
  // subtype が 'file_share' でなくても files が付く場合がある
  const file = pickEmlFile(evt);
  if (!file) return ok("ignored: no eml file");

  try {
    // 3) .eml 取得 → 解析 → テキスト化
    const emlBuf = await downloadPrivateFile(file);
    let text = await parseEmlToText(emlBuf);
    text = truncateByBytes(text, MAX_TXT_BYTES);

    // 4) アップロード（同スレッド）
    const filename = toTxtFilename(file.name || file.title);
    await uploadTxtToSlack({
      channel: evt.channel,
      thread_ts: evt.thread_ts || evt.ts, // 元メッセージのスレッドに
      filename,
      content: text,
    });

    return ok("done");
  } catch (e) {
    // 失敗時はスレッドに簡単なエラーを返す（本文ログは残さない）
    try {
      await fetch("https://slack.com/api/chat.postMessage", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${BOT_TOKEN}`,
          "Content-Type": "application/json; charset=utf-8",
        },
        body: JSON.stringify({
          channel: evt.channel,
          thread_ts: evt.thread_ts || evt.ts,
          text: "⚠️ .eml の展開に失敗しました。元ファイルをご確認ください。",
        }),
      });
    } catch { /* noop */ }
    console.error("PROCESS_ERROR", e);
    return ok("error handled");
  }
}
