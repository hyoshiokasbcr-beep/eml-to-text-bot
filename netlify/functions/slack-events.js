// netlify/functions/slack-events.js
// EML / MSG → 文字起こし → Slackへコードブロック投稿
// 署名検証 + Blobs への軽量ログ(任意)

import crypto from "node:crypto";
import fetch from "node-fetch";
import { simpleParser } from "mailparser";
import { htmlToText } from "html-to-text";
import { getStore } from "@netlify/blobs";

// msgreader は default export
import MSGReader from "msgreader";

/** ========= 環境変数 =========
 * SLACK_BOT_TOKEN        : Slack Bot User OAuth Token (xoxb-...)
 * SLACK_SIGNING_SECRET   : Slack Signing Secret
 * TARGET_CHANNELS        : (任意) 投稿先チャンネルIDをカンマ区切り。空なら「ファイルが共有されたチャンネルに投稿」
 * LOG_TO_BLOBS           : "true" なら Netlify Blobs に簡易ログを書き込む（手動デプロイ不要）
 * BLOB_STORE_NAME        : Blobs ストア名（省略時 "logs"）
 * MAX_PREVIEW_CHARS      : Slackへ投稿する最大文字数(既定 3000)
 * =========================== */

const BOT_TOKEN = process.env.SLACK_BOT_TOKEN;
const SIGNING_SECRET = process.env.SLACK_SIGNING_SECRET;
const TARGET_CHANNELS = (process.env.TARGET_CHANNELS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

const LOG_TO_BLOBS = (process.env.LOG_TO_BLOBS || "false").toLowerCase() === "true";
const BLOB_STORE_NAME = process.env.BLOB_STORE_NAME || "logs";
const MAX_PREVIEW_CHARS = Number(process.env.MAX_PREVIEW_CHARS || 3000); // 分割なし、末尾に誘導文を付与

/** --------- 署名検証 --------- */
function verifySlackSignature({ body, timestamp, signature }) {
  if (!SIGNING_SECRET) return false;
  const fiveMinutes = 60 * 5;
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - Number(timestamp)) > fiveMinutes) return false;

  const base = `v0:${timestamp}:${body}`;
  const hmac = crypto.createHmac("sha256", SIGNING_SECRET);
  hmac.update(base);
  const digest = `v0=${hmac.digest("hex")}`;
  try {
    return crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(signature));
  } catch {
    return false;
  }
}

/** --------- 軽量ログ(BLOBS) --------- */
async function logBlob(key, obj) {
  if (!LOG_TO_BLOBS) return;
  try {
    const store = getStore(BLOB_STORE_NAME);
    const time = new Date().toISOString();
    await store.setJSON(`${key}-${time}.json`, obj, { metadata: { key, time } });
  } catch (e) {
    // 失敗しても機能に影響しない
    console.error("blobs log error:", e);
  }
}

/** --------- Slack Web API ヘルパー --------- */
async function slackFetch(path, init = {}) {
  const url = `https://slack.com/api/${path}`;
  const res = await fetch(url, {
    ...init,
    headers: {
      Authorization: `Bearer ${BOT_TOKEN}`,
      "Content-Type": "application/json; charset=utf-8",
      ...(init.headers || {}),
    },
  });
  return res.json();
}

async function slackDownloadPrivate(url) {
  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${BOT_TOKEN}` },
  });
  if (!res.ok) throw new Error(`download failed: ${res.status}`);
  return Buffer.from(await res.arrayBuffer());
}

/** --------- 投稿(末尾に誘導文) --------- */
function buildSlackTextBlock(text) {
  const capped = text.length > MAX_PREVIEW_CHARS ? text.slice(0, MAX_PREVIEW_CHARS) : text;
  const suffix =
    text.length > MAX_PREVIEW_CHARS
      ? "\n\n…（※続きはアップロードされた元のファイルをご参照ください）"
      : "";
  return `\`\`\`\n${capped}${suffix}\n\`\`\``;
}

async function postToSlack({ channel, thread_ts, text }) {
  return slackFetch("chat.postMessage", {
    method: "POST",
    body: JSON.stringify({
      channel,
      text,
      thread_ts,
      // Escape を避けるために "text" だけ使用（blocks 未使用）
      // 必要なら blocks にしてもOK
    }),
  });
}

/** --------- 文字起こし --------- */
async function parseEML(buffer) {
  const mail = await simpleParser(buffer);

  // 優先: text → html からの変換
  let body = "";
  if (mail.text) {
    body = mail.text;
  } else if (mail.html) {
    body = htmlToText(mail.html, {
      wordwrap: false,
      preserveNewlines: true,
    });
  }

  // 先頭に簡単なヘッダ
  const from = mail.from?.text || "";
  const to = mail.to?.text || "";
  const subject = mail.subject || "";
  const head = [
    `From   : ${from}`,
    `To     : ${to}`,
    `Subject: ${subject}`,
    "",
  ].join("\n");
  return `${head}${body || "(本文なし)"}`;
}

async function parseMSG(buffer) {
  // msgreader は ArrayBuffer を要求
  const reader = new MSGReader(buffer);
  const data = reader.getFileData();
  const subject = data.subject || "";
  const from = data.senderName || "";
  const to = (data.recipients || [])
    .map((r) => r.name || r.email || "")
    .filter(Boolean)
    .join(", ");

  let body = data.body || data.bodyHTML || "";
  if (data.bodyHTML && !data.body) {
    body = htmlToText(data.bodyHTML, { wordwrap: false, preserveNewlines: true });
  }

  const head = [
    `From   : ${from}`,
    `To     : ${to}`,
    `Subject: ${subject}`,
    "",
  ].join("\n");

  return `${head}${body || "(本文なし)"}`;
}

/** --------- Slack ファイル共有イベント処理 --------- */
async function handleFileShared(fileId, hintChannels = []) {
  // files.info で実体を取得
  const info = await slackFetch(`files.info?file=${encodeURIComponent(fileId)}`);
  if (!info.ok) throw new Error(`files.info failed: ${info.error}`);
  const file = info.file;

  // ダウンロードURL
  const urlPriv = file.url_private_download || file.url_private;
  if (!urlPriv) throw new Error("no downloadable url");

  // 拡張子・MIME で分岐
  const name = file.name || "";
  const lower = name.toLowerCase();

  const buf = await slackDownloadPrivate(urlPriv);

  let extracted = "";
  if (lower.endsWith(".eml") || file.mimetype === "message/rfc822") {
    extracted = await parseEML(buf);
  } else if (lower.endsWith(".msg") || file.filetype === "email") {
    // Slackの filetype "email" は Outlook MSG にも使われることあり
    extracted = await parseMSG(buf);
  } else {
    // 対応外 → そのまま断る（クレジット節約のため変換はしない）
    extracted = `(対応外のファイルです) ${name}`;
  }

  const text = buildSlackTextBlock(extracted);

  // 投稿先: 環境変数で固定されていればそれを使う。
  // なければ元の共有チャンネル群へ（通常は file.channels に入る）
  const destChannels =
    TARGET_CHANNELS.length > 0 ? TARGET_CHANNELS : (file.channels || hintChannels || []);

  const results = [];
  for (const ch of destChannels) {
    const r = await postToSlack({ channel: ch, thread_ts: file.shares?.public?.[ch]?.[0]?.ts, text });
    results.push({ channel: ch, ok: r.ok, error: r.error });
  }

  await logBlob("posted", { fileId, name, channels: destChannels, results });
  return results;
}

/** --------- 入口（Netlify Functions handler） --------- */
export default async (req) => {
  const rawBody = await req.text(); // 署名検証のため生ボディ
  const ts = req.headers.get("x-slack-request-timestamp") || "";
  const sig = req.headers.get("x-slack-signature") || "";

  // URL verification (Slack UI に Request URL を設定したときの検証)
  try {
    const body = JSON.parse(rawBody);
    if (body && body.type === "url_verification" && body.challenge) {
      return new Response(JSON.stringify({ challenge: body.challenge }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    }
  } catch {
    // noop
  }

  // 署名検証
  if (!verifySlackSignature({ body: rawBody, timestamp: ts, signature: sig })) {
    await logBlob("invalid-signature", { ts, sigPreview: sig?.slice(0, 10) });
    return new Response("invalid signature", { status: 401 });
  }

  let payload;
  try {
    payload = JSON.parse(rawBody);
  } catch {
    return new Response("bad request", { status: 400 });
  }

  // event_callback
  if (payload.type === "event_callback") {
    const ev = payload.event || {};

    // 1) file_shared: ファイルが共有されたら本文抽出→投稿
    if (ev.type === "file_shared" && ev.file_id) {
      try {
        const results = await handleFileShared(ev.file_id, ev.channel ? [ev.channel] : []);
        return json({ ok: true, results });
      } catch (e) {
        await logBlob("file_shared-error", { err: String(e) });
        return json({ ok: false, error: String(e) }, 500);
      }
    }

    // 2) 手動テスト用: "ping" 等のメッセージに対し簡易応答（クレジット節約のため最低限）
    if (ev.type === "message" && ev.text && ev.channel) {
      if (/^ping$/i.test(ev.text.trim())) {
        const r = await postToSlack({ channel: ev.channel, thread_ts: ev.ts, text: "```pong```" });
        return json({ ok: r.ok });
      }
      // ファイル投稿とは無関係の通常メッセージはスルー
      return json({ ok: true, skipped: true });
    }

    // その他イベント
    return json({ ok: true, ignored: ev.type });
  }

  // 3) テスト注入（手元テスト時のみ）：__test_base64_eml を受けたら Slack に投げず JSON を返す
  try {
    const t = JSON.parse(rawBody);
    if (t.__test_base64_eml) {
      const buf = Buffer.from(t.__test_base64_eml, "base64");
      const txt = await parseEML(buf);
      return json({ ok: true, preview: txt.slice(0, 300) });
    }
  } catch {
    // noop
  }

  return json({ ok: true, noop: true });
};

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" }
  });
}
