// Netlify Function: slack-events (ESM)
// 目的:
//  - Slackの file_shared / message(files付き) から .eml / .msg / .oft を回収 → テキスト化 → コードブロックで投稿
//  - 設定は Netlify Blobs (config/runtime.json) から都度ロード：DRY_RUN/サイズ上限/本文長/チャンネル/ログレベル
//  - 手動テスト：__test_base64_eml / __test_base64_msg / __test_base64_oft を受け付け
//  - 文字化け/漏洩を避ける軽量ログ（ログレベル切替）

import crypto from "crypto";
import fetch from "node-fetch";
import { simpleParser } from "mailparser";
import { convert as htmlToText } from "html-to-text";
import MsgReader from "msgreader";
import { getStore } from "@netlify/blobs";

// ====== 秘密情報（環境変数：デプロイ時に設定） ======
const SLACK_BOT_TOKEN = process.env.SLACK_BOT_TOKEN || "";
const SLACK_SIGNING_SECRET = process.env.SLACK_SIGNING_SECRET || "";

// ====== 既定値（Blobsが無い/壊れている時のフォールバック） ======
const DEFAULTS = {
  DRY_RUN: true,
  MAX_FILE_BYTES: 4 * 1024 * 1024, // 4MB
  MAX_POST_CHARS: 3600,            // Slack安全長（余白あり）
  TARGET_CHANNELS: [],             // 例: ["C0123456789"]
  LOG_LEVEL: "minimal"             // off|minimal|errors|verbose
};

// ====== ランタイム設定のロード (Netlify Blobs) ======
async function loadConfig() {
  try {
    const store = getStore({ name: "config" }); // Blobs ストア名
    const json = await store.get("runtime.json", { type: "json" });
    if (!json) return DEFAULTS;
    return {
      DRY_RUN: typeof json.DRY_RUN === "boolean" ? json.DRY_RUN : DEFAULTS.DRY_RUN,
      MAX_FILE_BYTES: Number(json.MAX_FILE_BYTES ?? DEFAULTS.MAX_FILE_BYTES),
      MAX_POST_CHARS: Number(json.MAX_POST_CHARS ?? DEFAULTS.MAX_POST_CHARS),
      TARGET_CHANNELS: Array.isArray(json.TARGET_CHANNELS) ? json.TARGET_CHANNELS : DEFAULTS.TARGET_CHANNELS,
      LOG_LEVEL: String(json.LOG_LEVEL || DEFAULTS.LOG_LEVEL)
    };
  } catch (e) {
    console.error("[cfg] loadRuntimeConfig error:", e?.message || e);
    return DEFAULTS;
  }
}

// ====== ログ（レベル別） ======
function makeLogger(level = "minimal") {
  const order = { off: 0, errors: 1, minimal: 2, verbose: 3 };
  const allow = (want) => (order[level] >= order[want]);

  return {
    v: (...a) => { if (allow("verbose"))  console.log(...a); },
    m: (...a) => { if (allow("minimal"))  console.log(...a); },
    e: (...a) => { if (allow("errors"))   console.error(...a); }
  };
}

// ====== ユーティリティ ======
const json = (status, body) => new Response(JSON.stringify(body), {
  status,
  headers: { "content-type": "application/json; charset=utf-8" }
});

function verifySlackSignature(request, bodyRaw) {
  if (!SLACK_SIGNING_SECRET) return true; // テスト時の救済
  const ts  = request.headers.get("x-slack-request-timestamp");
  const sig = request.headers.get("x-slack-signature");
  if (!ts || !sig) return false;
  const base = `v0:${ts}:${bodyRaw}`;
  const hmac = crypto.createHmac("sha256", SLACK_SIGNING_SECRET).update(base).digest("hex");
  const expect = `v0=${hmac}`;
  try {
    return crypto.timingSafeEqual(Buffer.from(expect), Buffer.from(sig));
  } catch {
    return false;
  }
}

// RTF簡易プレーン化（依存増やさず軽量で）
function stripRTF(maybeRtf) {
  if (!maybeRtf) return "";
  if (!/\\rtf1/.test(maybeRtf)) return maybeRtf;
  return maybeRtf
    .replace(/\\par[d]?/g, "\n")
    .replace(/\\'([0-9a-fA-F]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/\\[a-z]+\d*(?:-?\d+)?\s?/g, "")
    .replace(/[{}]/g, "")
    .replace(/\n{3,}/g, "\n\n");
}

function html2text(html) {
  return htmlToText(html || "", {
    wordwrap: false,
    selectors: [{ selector: "a", options: { hideLinkHrefIfSameAsText: true } }]
  });
}

// ====== 解析（EML / MSG/OFT） ======
async function emlToText(buffer) {
  const mail = await simpleParser(buffer);
  const from = mail.from?.text || "";
  const subject = mail.subject || "";
  const date = mail.date ? new Date(mail.date).toISOString() : "";
  let body = mail.text || "";
  if (!body && mail.html) body = html2text(mail.html);

  const header = [
    from ? `From: ${from}` : "",
    subject ? `Subject: ${subject}` : "",
    date ? `Date: ${date}` : ""
  ].filter(Boolean).join("\n");

  return header + "\n\n" + (body || "");
}

async function msgToText(buffer) {
  const reader = new MsgReader(buffer);
  const m = reader.getFileData(); // subject, senderEmail, body, bodyHTML, bodyRTF, creationTime 等
  let body = m.body || "";
  if (!body && m.bodyHTML) body = html2text(m.bodyHTML);
  if (!body && m.bodyRTF)  body = stripRTF(m.bodyRTF);

  const header = [
    (m.senderEmail || m.senderName) ? `From: ${m.senderEmail || m.senderName}` : "",
    m.subject ? `Subject: ${m.subject}` : "",
    m.creationTime ? `Date: ${new Date(m.creationTime).toISOString()}` : ""
  ].filter(Boolean).join("\n");

  return header + "\n\n" + (body || "");
}

async function autoToText(filename, buffer) {
  const lower = (filename || "").toLowerCase();
  if (lower.endsWith(".eml")) return emlToText(buffer);
  if (lower.endsWith(".msg")) return msgToText(buffer);
  if (lower.endsWith(".oft")) return msgToText(buffer);
  throw new Error("Unsupported file type");
}

// ====== Slack API ======
async function postToSlackCodeBlock(channel, text, thread_ts, cfg, log) {
  const tail = "\n\n---\n※ この続き/完全版は eml を生成AIで参照ください。";
  const safe   = (text || "");
  const merged = safe.slice(0, Math.max(0, (cfg.MAX_POST_CHARS || 3600) - tail.length)) + tail;

  const payload = {
    channel,
    text: "```" + merged + "```",
    mrkdwn: true
  };

  if (cfg.DRY_RUN) {
    log.m("[DRY_RUN] would post", { channel, length: payload.text.length });
    return { ok: true, dry_run: true };
  }

  const res = await fetch("https://slack.com/api/chat.postMessage", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${SLACK_BOT_TOKEN}`,
      "Content-Type": "application/json; charset=utf-8"
    },
    body: JSON.stringify(thread_ts ? { ...payload, thread_ts } : payload)
  });
  const txt = await res.text();
  log.m("[slack-resp]", res.status, txt.slice(0, 400));
  try { return JSON.parse(txt); } catch { return { ok: false, raw: txt }; }
}

async function getFileInfo(fileId) {
  const res = await fetch("https://slack.com/api/files.info", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${SLACK_BOT_TOKEN}`,
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: new URLSearchParams({ file: fileId })
  });
  return await res.json();
}

async function downloadSlackFile(url_private_download) {
  const res = await fetch(url_private_download, {
    headers: { Authorization: `Bearer ${SLACK_BOT_TOKEN}` }
  });
  if (!res.ok) throw new Error(`download failed: ${res.status}`);
  const buf = await res.arrayBuffer();
  return Buffer.from(buf);
}

// ====== イベント処理 ======
async function handleSlackEvent(evt, cfg, log) {
  // file_shared: ファイルIDから詳細を引くパターン
  if (evt.type === "file_shared" && evt.file_id) {
    const info = await getFileInfo(evt.file_id);
    if (!info.ok) { log.e("files.info failed", info); return { ok: false, error: "files.info_failed" }; }
    const f = info.file;
    const name = f.name || "";
    const lower = name.toLowerCase();

    if (!(/\.(eml|msg|oft)$/.test(lower))) {
      log.m("[skip] unsupported ext", name);
      return { ok: true, skipped: true };
    }
    if (f.size && f.size > cfg.MAX_FILE_BYTES) {
      log.m("[skip] too large", name, f.size, "limit", cfg.MAX_FILE_BYTES);
      return { ok: false, error: "too_large" };
    }

    const buf = await downloadSlackFile(f.url_private_download);
    const text = await autoToText(name, buf);
    const channel = (cfg.TARGET_CHANNELS[0] || evt.channel_id || evt.channel);
    return await postToSlackCodeBlock(channel, text, null, cfg, log);
  }

  // message: チャンネルに直にファイルが付いているパターン
  if (evt.type === "message" && Array.isArray(evt.files) && evt.files.length > 0) {
    for (const f of evt.files) {
      const name = f.name || "";
      const lower = name.toLowerCase();
      if (!(/\.(eml|msg|oft)$/.test(lower))) continue;
      if (f.size && f.size > cfg.MAX_FILE_BYTES) { log.m("[skip] too large", name); continue; }

      const buf = await downloadSlackFile(f.url_private_download);
      const text = await autoToText(name, buf);
      const channel = (cfg.TARGET_CHANNELS[0] || evt.channel);
      return await postToSlackCodeBlock(channel, text, evt.thread_ts || evt.ts, cfg, log);
    }
    return { ok: true, skipped: true };
  }

  return { ok: true, ignored: true };
}

// 手動テスト: base64 を直で渡して投稿（Slack経由なし）
async function handleTestBody(body, cfg, log) {
  const { __test_base64_eml, __test_base64_msg, __test_base64_oft } = body || {};
  if (!__test_base64_eml && !__test_base64_msg && !__test_base64_oft) return null;
  const b64 = __test_base64_eml || __test_base64_msg || __test_base64_oft;
  const filename = __test_base64_eml ? "sample.eml" : (__test_base64_msg ? "sample.msg" : "sample.oft");
  const buf = Buffer.from(b64, "base64");
  if (buf.byteLength > cfg.MAX_FILE_BYTES) return { ok: false, error: "too_large" };

  const text = await autoToText(filename, buf);
  const channel = cfg.TARGET_CHANNELS[0] || "";
  const res = await postToSlackCodeBlock(channel, text, null, cfg, log);
  return { ok: true, posted: !!res.ok || !!res.dry_run, preview: (text || "").slice(0, 120) };
}

// ====== Netlify エントリポイント (Edge-like fetch) ======
export default {
  async fetch(request) {
    const cfg = await loadConfig();
    const log = makeLogger(cfg.LOG_LEVEL);

    const bodyRaw = await request.text();
    if (cfg.LOG_LEVEL !== "off") {
      const head = bodyRaw.slice(0, 600);
      log.m("[recv]", { len: bodyRaw.length, head });
    }

    // SlackのURL検証
    try {
      const obj = JSON.parse(bodyRaw || "{}");
      if (obj.type === "url_verification" && obj.challenge) {
        return json(200, { challenge: obj.challenge });
      }
    } catch { /* noop */ }

    // 署名検証（本物のSlack → 署名あり / 手動テストは __test_* を許可）
    const verified = verifySlackSignature(request, bodyRaw);
    if (!verified) {
      try {
        const testObj = JSON.parse(bodyRaw || "{}");
        const testRes = await handleTestBody(testObj, cfg, log);
        if (testRes) return json(200, testRes);
      } catch {}
      return json(401, { ok: false, error: "invalid_signature" });
    }

    // Slackイベント本体
    let payload = {};
    try { payload = JSON.parse(bodyRaw || "{}"); }
    catch { return json(400, { ok: false, error: "bad_json" }); }

    if (payload.type === "event_callback" && payload.event) {
      try {
        const result = await handleSlackEvent(payload.event, cfg, log);
        // Slackの再送対策：基本200返し
        return json(200, result || { ok: true });
      } catch (e) {
        log.e("handler error", e?.message || e);
        return json(200, { ok: false, error: String(e?.message || e) });
      }
    }

    // その他: __test_* など
    try {
      const testRes = await handleTestBody(payload, cfg, log);
      if (testRes) return json(200, testRes);
    } catch (e) {
      log.e("test handler error", e?.message || e);
      return json(200, { ok: false, error: String(e?.message || e) });
    }

    return json(200, { ok: true, noop: true });
  }
};
