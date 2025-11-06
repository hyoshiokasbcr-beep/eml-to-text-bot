// 複合板：自己診断 + EML/MSG 変換 を1イベントで実行
import crypto from "node:crypto";
import { htmlToText } from "html-to-text";
import { simpleParser } from "mailparser";
import MsgReader from "@kenjiuno/msgreader";
import { getStore } from "@netlify/blobs";

const {
  SLACK_BOT_TOKEN,
  SLACK_SIGNING_SECRET,
  TARGET_CHANNELS,
  LOG_TO_BLOBS = "true",
  BLOB_STORE_NAME = "logs",
  MAX_PREVIEW_CHARS = "3000",
  MAX_FILE_SIZE = String(10 * 1024 * 1024) // 10MB
} = process.env;

const SLACK_API = "https://slack.com/api";

// =============== 共通ユーティリティ ===============
const store = () => getStore(BLOB_STORE_NAME);
const nowISO = () => new Date().toISOString();

async function blobLog(key, data) {
  if (LOG_TO_BLOBS !== "true") return;
  try { await store().setJSON(key, { t: nowISO(), ...data }); } catch {}
}
function codeBlock(s) {
  return "```\n" + String(s ?? "").replace(/```/g, "ʼʼʼ") + "\n```";
}

async function slackFetch(path, init = {}) {
  const res = await fetch(`${SLACK_API}/${path}`, {
    ...init,
    headers: {
      Authorization: `Bearer ${SLACK_BOT_TOKEN}`,
      "Content-Type": "application/json; charset=utf-8",
      ...(init.headers || {})
    }
  });
  const json = await res.json().catch(() => ({}));
  return { status: res.status, json };
}
async function chatPostMessage({ channel, text, thread_ts }) {
  const body = { channel, text, ...(thread_ts ? { thread_ts } : {}) };
  const { status, json } = await slackFetch("chat.postMessage", {
    method: "POST",
    body: JSON.stringify(body)
  });
  await blobLog(`chat/${Date.now()}`, { status, json, channel, hasThread: !!thread_ts, preview: (text||"").slice(0,120) });
  return json;
}
async function filesInfo(fileId) {
  const { json } = await slackFetch("files.info", {
    method: "POST", body: JSON.stringify({ file: fileId })
  });
  return json;
}
function findFirstShare(file) {
  const s = file?.shares || {};
  for (const area of ["private", "public"]) {
    const m = s[area];
    if (m && typeof m === "object") {
      for (const [channel, msgs] of Object.entries(m)) {
        const first = Array.isArray(msgs) && msgs[0];
        if (first?.ts) return { channel, thread_ts: first.ts };
      }
    }
  }
  return null;
}

// 署名検証（±5分）
async function verifySlackSignature(req, raw) {
  try {
    const ts = req.headers.get("x-slack-request-timestamp");
    const sig = req.headers.get("x-slack-signature");
    if (!ts || !sig) return false;
    const skew = Math.abs(Math.floor(Date.now()/1000) - Number(ts));
    if (skew > 300) return false;
    const base = `v0:${ts}:${raw}`;
    const hmac = crypto.createHmac("sha256", SLACK_SIGNING_SECRET).update(base).digest("hex");
    const expected = `v0=${hmac}`;
    const a = Buffer.from(sig), b = Buffer.from(expected);
    return a.length === b.length && crypto.timingSafeEqual(a,b);
  } catch { return false; }
}

// =============== 診断（diag） ===============
// 1回の message イベントで一気にチェックして結果を同チャンネルに返す
async function runDiag({ channel, thread_ts, raw, req }) {
  const checks = [];

  // 0) メタ
  checks.push(["event", `channel=${channel} thread=${thread_ts||"-"}`]);

  // 1) 環境変数
  const missing = ["SLACK_BOT_TOKEN","SLACK_SIGNING_SECRET"].filter(k => !process.env[k]);
  checks.push(["env", missing.length ? `missing: ${missing.join(",")}` : "ok"]);

  // 2) 署名検証
  const sigOk = await verifySlackSignature(req, raw);
  checks.push(["signature", sigOk ? "ok" : "invalid"]);

  // 3) auth.test
  let auth = { ok:false };
  if (SLACK_BOT_TOKEN) {
    const { json } = await slackFetch("auth.test", { method:"POST", body: "{}" });
    auth = json || {};
  }
  checks.push(["auth.test", auth.ok ? `ok user=${auth.user_id}` : `fail ${auth.error||"unknown"}`]);

  // 4) postMessage 試験
  const pm = await chatPostMessage({ channel, thread_ts, text: "🩺 diag: postMessage test" });
  checks.push(["chat.postMessage", pm.ok ? "ok" : `fail ${pm.error}`]);

  // 5) まとめ表示
  const lines = checks.map(([k,v]) => `${k.padEnd(16)}: ${v}`).join("\n");
  await chatPostMessage({ channel, thread_ts, text: codeBlock(lines) });
  await blobLog(`diag/${Date.now()}`, { checks });
}

// =============== メール抽出 ===============
function cut(text, max = Number(MAX_PREVIEW_CHARS)) {
  let t = text ?? "";
  if (t.length > max) t = t.slice(0,max) + "\n\n[... cut ... 続きは元ファイルを参照してください]";
  return codeBlock(t);
}
async function extractFromEml(arrayBuffer) {
  const mail = await simpleParser(Buffer.from(arrayBuffer));
  if (mail.text?.trim()) return mail.text;
  if (mail.html?.trim()) return htmlToText(mail.html, { wordwrap:false });
  return "(本文なし)";
}
async function extractFromMsg(arrayBuffer) {
  const reader = new MsgReader(new Uint8Array(arrayBuffer));
  const data = reader.getFileData();
  const body = data?.body || (data?.bodyHTML ? htmlToText(data.bodyHTML, { wordwrap:false }) : "");
  return body?.trim() ? body : "(本文なし)";
}
function detectKind(file) {
  const name = (file?.name||"").toLowerCase();
  const mime = (file?.mimetype||"").toLowerCase();
  if (name.endsWith(".eml") || mime === "message/rfc822") return "eml";
  if (name.endsWith(".msg") || mime.includes("application/vnd.ms-outlook")) return "msg";
  return "unknown";
}
async function downloadSlackFile(url) {
  const res = await fetch(url, { headers: { Authorization: `Bearer ${SLACK_BOT_TOKEN}` } });
  if (!res.ok) throw new Error(`download ${res.status}`);
  const size = Number(res.headers.get("content-length") || "0");
  if (size > Number(MAX_FILE_SIZE)) throw new Error(`too large: ${size} > ${MAX_FILE_SIZE}`);
  return res.arrayBuffer();
}

// =============== メイン ===============
export default async (req, context) => {
  const raw = await req.clone().text();
  let payload = {};
  try { payload = JSON.parse(raw || "{}"); } catch {}

  // URL 検証
  if (payload.type === "url_verification" && payload.challenge) {
    return new Response(payload.challenge, { status:200, headers:{ "Content-Type":"text/plain" } });
  }

  // 署名NGは 401 （ただし diag のためにログは残す）
  if (!(await verifySlackSignature(req, raw))) {
    await blobLog(`errors/sign/${Date.now()}`, { msg:"invalid signature" });
    return new Response("invalid signature", { status:401 });
  }

  // 3秒ルール回避：即ACK、実処理は裏で
  context.waitUntil((async () => {
    try {
      const ev = payload.event || {};
      const channel = TARGET_CHANNELS || ev.channel || ev.channel_id;
      const thread_ts = ev.ts;

      // ----- 診断モード -----
      if (ev.type === "message" && /(^|\s)diag(\s|$)/i.test(ev.text||"")) {
        await runDiag({ channel, thread_ts, raw, req });
        return;
      }

      // ----- file_shared -----
      if (ev.type === "file_shared") {
        // まず検知メッセージ
        if (channel) await chatPostMessage({ channel, thread_ts, text: "📎 .eml/.msg を検知。解析中…" });

        const info = await filesInfo(ev.file_id || ev.file?.id);
        if (!info?.ok || !info.file) return;

        const share = findFirstShare(info.file);
        const targetChannel = TARGET_CHANNELS || share?.channel || channel;
        const targetThread = share?.thread_ts || thread_ts;

        const url = info.file.url_private_download || info.file.url_private;
        if (!url) {
          await chatPostMessage({ channel: targetChannel, thread_ts: targetThread, text: "⚠️ ダウンロードURLなし" });
          return;
        }

        let text = "";
        try {
          const bin = await downloadSlackFile(url);
          const kind = detectKind(info.file);
          if (kind === "eml") text = await extractFromEml(bin);
          else if (kind === "msg") text = await extractFromMsg(bin);
          else {
            await chatPostMessage({ channel: targetChannel, thread_ts: targetThread, text: `対象外: ${info.file.name}` });
            return;
          }
        } catch (e) {
          await blobLog(`errors/download/${info.file.id}`, { e: String(e) });
          await chatPostMessage({ channel: targetChannel, thread_ts: targetThread, text: `❌ 取得/解析失敗: ${String(e)}` });
          return;
        }

        await chatPostMessage({ channel: targetChannel, thread_ts: targetThread, text: cut(text) });
        return;
      }

      // ----- ping テスト -----
      if (ev.type === "message" && (ev.text||"").trim().toLowerCase() === "ping") {
        await chatPostMessage({ channel, thread_ts, text: "pong" });
      }

    } catch (e) {
      await blobLog(`errors/handler/${Date.now()}`, { e: String(e) });
    }
  })());

  return new Response("", { status:200 });
};
