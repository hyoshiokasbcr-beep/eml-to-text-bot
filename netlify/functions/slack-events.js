// EML/MSG 自動変換 Bot - Slack Events handler (Netlify Functions / ESM)
import crypto from "node:crypto";
import { htmlToText } from "html-to-text";
import { simpleParser } from "mailparser";
import MsgReader from "@kenjiuno/msgreader";
import { getStore } from "@netlify/blobs";

// ==== 環境変数 ====
const {
  SLACK_BOT_TOKEN,
  SLACK_SIGNING_SECRET,
  TARGET_CHANNELS, // 任意: 固定チャンネルへ流したい場合
  LOG_TO_BLOBS = "true",
  BLOB_STORE_NAME = "logs",
  MAX_PREVIEW_CHARS = "3000",
  MAX_FILE_SIZE = String(10 * 1024 * 1024), // 10MB
} = process.env;

// ==== Slack API ====
const SLACK_API = "https://slack.com/api";
const slackFetch = (path, init = {}) =>
  fetch(`${SLACK_API}/${path}`, {
    ...init,
    headers: {
      Authorization: `Bearer ${SLACK_BOT_TOKEN}`,
      "Content-Type": "application/json; charset=utf-8",
      ...(init.headers || {}),
    },
  });

async function chatPostMessage({ channel, text, thread_ts }) {
  const body = { channel, text, ...(thread_ts ? { thread_ts } : {}) };
  return slackFetch("chat.postMessage", { method: "POST", body: JSON.stringify(body) });
}

async function filesInfo(file) {
  const body = typeof file === "string" ? { file } : { file: file.id };
  const res = await slackFetch("files.info", { method: "POST", body: JSON.stringify(body) });
  return res.json();
}

// file.shares から最初の共有場所と ts を得る
function findFirstShare(fileObj) {
  const s = fileObj?.shares || {};
  const areas = ["private", "public"];
  for (const area of areas) {
    const m = s[area];
    if (m && typeof m === "object") {
      for (const [channel, msgs] of Object.entries(m)) {
        const first = Array.isArray(msgs) && msgs.length > 0 ? msgs[0] : null;
        if (first?.ts) return { channel, thread_ts: first.ts };
      }
    }
  }
  // 見つからない場合はファイルの最初のチャネルへの共有を試みる
  if (fileObj?.channels && fileObj.channels.length > 0) {
    return { channel: fileObj.channels[0], thread_ts: undefined };
  }
  return null;
}

// ==== 署名検証 ====
async function verifySlackSignature(req) {
  const timestamp = req.headers.get("x-slack-request-timestamp");
  const signature = req.headers.get("x-slack-signature");
  if (!timestamp || !signature) return false;

  // 5分以上前/未来は拒否
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - Number(timestamp)) > 60 * 5) return false;

  const bodyText = await req.clone().text();
  const base = `v0:${timestamp}:${bodyText}`;
  const hmac = crypto.createHmac("sha256", SLACK_SIGNING_SECRET).update(base).digest("hex");
  const expected = `v0=${hmac}`;
  // timing-safe compare
  const a = Buffer.from(signature);
  const b = Buffer.from(expected);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// ==== ログ & 重複防止 ====
async function logBlob(key, payload) {
  if (LOG_TO_BLOBS !== "true") return;
  try {
    const store = getStore(BLOB_STORE_NAME);
    await store.setJSON(key, payload);
  } catch {}
}
async function seenEvent(eventId) {
  if (!eventId || LOG_TO_BLOBS !== "true") return false;
  const store = getStore(BLOB_STORE_NAME);
  const key = `events/${eventId}`;
  const exists = await store.get(key);
  if (exists) return true;
  await store.set(key, "1"); // 既読マーク
  return false;
}

// ==== 本文整形 ====
function cutAndFormatAsCodeBlock(text, max = Number(MAX_PREVIEW_CHARS)) {
  let out = text ?? "";
  if (out.length > max) {
    out = out.slice(0, max) + "\n\n[... cut ... 続きは元ファイルを参照してください]";
  }
  // 先頭末尾のバッククォート干渉を避ける
  out = out.replace(/```/g, "ʼʼʼ");
  return "```\n" + out + "\n```";
}

// ==== .eml を解析 ====
async function extractFromEml(arrayBuffer) {
  const buf = Buffer.from(arrayBuffer);
  const mail = await simpleParser(buf);
  // text or html -> text
  if (mail.text && mail.text.trim()) return mail.text;
  if (mail.html && mail.html.trim()) return htmlToText(mail.html, { wordwrap: false });
  return "(本文なし)";
}

// ==== .msg を解析 ====
async function extractFromMsg(arrayBuffer) {
  // MsgReader のコンストラクタは Uint8Array を想定
  const reader = new MsgReader(new Uint8Array(arrayBuffer));
  const data = reader.getFileData();
  const body = data?.body || (data?.bodyHTML ? htmlToText(data.bodyHTML, { wordwrap: false }) : "");
  return body?.trim() ? body : "(本文なし)";
}

// ==== Slack のファイルダウンロード ====
async function downloadSlackFile(url) {
  const res = await fetch(url, { headers: { Authorization: `Bearer ${SLACK_BOT_TOKEN}` } });
  if (!res.ok) throw new Error(`download failed: ${res.status}`);
  const size = Number(res.headers.get("content-length") || "0");
  if (size > Number(MAX_FILE_SIZE)) {
    throw new Error(`file too large: ${size} > ${MAX_FILE_SIZE}`);
  }
  return res.arrayBuffer();
}

function detectKind(file) {
  const name = (file?.name || "").toLowerCase();
  const mime = (file?.mimetype || "").toLowerCase();
  if (name.endsWith(".eml") || mime === "message/rfc822") return "eml";
  if (name.endsWith(".msg") || mime.includes("application/vnd.ms-outlook")) return "msg";
  return "unknown";
}

// ==== メイン処理 ====
async function handleFileShared(event) {
  // file_id から詳細取得
  const info = await filesInfo(event.file_id || event.file?.id);
  if (!info?.ok) throw new Error(`files.info failed: ${JSON.stringify(info)}`);
  const file = info.file;

  const share = findFirstShare(file);
  const channel = TARGET_CHANNELS || share?.channel || event.channel_id;
  const thread_ts = share?.thread_ts;

  // ダウンロード
  const url = file.url_private_download || file.url_private;
  if (!url) {
    await chatPostMessage({
      channel,
      thread_ts,
      text: "このファイルはダウンロードURLが取得できないためプレビューできませんでした。",
    });
    return;
  }

  let text = "";
  const kind = detectKind(file);
  try {
    const bin = await downloadSlackFile(url);
    if (kind === "eml") text = await extractFromEml(bin);
    else if (kind === "msg") text = await extractFromMsg(bin);
    else {
      await chatPostMessage({
        channel,
        thread_ts,
        text: `拡張子が .eml / .msg ではないためプレビューをスキップしました（${file.name}）`,
      });
      return;
    }
  } catch (e) {
    await logBlob(`errors/download/${file.id}`, { message: String(e), file });
    await chatPostMessage({
      channel,
      thread_ts,
      text: `ファイルの取得/解析に失敗しました: ${String(e)}`,
    });
    return;
  }

  const code = cutAndFormatAsCodeBlock(text);
  await chatPostMessage({
    channel,
    thread_ts,
    text: code,
  });
}

async function handleMessage(event) {
  // 簡易 ping テスト
  if ((event.text || "").trim().toLowerCase() === "ping") {
    await chatPostMessage({ channel: event.channel, thread_ts: event.ts, text: "pong" });
  }
}

// ==== Netlify Function エントリポイント ====
export default async (req, context) => {
  // 署名検証（URL verify は除外）
  const bodyText = await req.clone().text();
  let payload;
  try {
    payload = JSON.parse(bodyText || "{}");
  } catch {
    return new Response("bad request", { status: 400 });
  }

  if (payload.type === "url_verification" && payload.challenge) {
    return new Response(payload.challenge, { status: 200, headers: { "Content-Type": "text/plain" } });
  }

  // Slack 署名チェック
  if (!(await verifySlackSignature(req))) {
    return new Response("invalid signature", { status: 401 });
  }

  // 即時ACK（3秒ルール回避）し、処理は非同期で継続
  context.waitUntil(
    (async () => {
      try {
        const event = payload.event || {};

        // 重複排除
        if (await seenEvent(payload.event_id)) return;

        if (event.type === "file_shared") {
          await handleFileShared(event);
        } else if (event.type === "message") {
          await handleMessage(event);
        }

        // 軽量ログ
        await logBlob(`events/${payload.event_id}-detail`, {
          t: new Date().toISOString(),
          type: event.type,
        });
      } catch (e) {
        await logBlob(`errors/${Date.now()}`, { error: String(e), raw: payload });
      }
    })()
  );

  return new Response("", { status: 200 });
};
