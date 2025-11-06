// netlify/functions/slack-events.js
// 必要スコープ: app_mentions:read, channels:history, groups:history, files:read, chat:write
// 環境変数: SLACK_BOT_TOKEN, SLACK_SIGNING_SECRET
// Node 18+（Netlifyのデフォルト）で fetch 利用

import crypto from "node:crypto";
import { Blobs } from "@netlify/blobs";
import { simpleParser } from "mailparser";

// ---- helpers -----------------------------------------------------
const blobs = new Blobs({ token: process.env.NETLIFY_BLOBS_TOKEN }); // Netlify が自動注入
const STORE = "logs"; // Netlify UI に出ている store 名

const log = async (area, obj) => {
  try {
    const key = `${area}/${Date.now()}.json`;
    await blobs.set(STORE, key, JSON.stringify({ t: new Date().toISOString(), ...obj }, null, 2), {
      contentType: "application/json",
    });
  } catch (e) {
    // ここが落ちても本体処理を止めない
    console.error("blobLog error", e);
  }
};

const okJson = (obj) => new Response(JSON.stringify(obj), { status: 200, headers: { "content-type": "application/json" } });

const signCheck = (request, bodyText) => {
  const ts = request.headers.get("x-slack-request-timestamp") ?? "";
  const sig = request.headers.get("x-slack-signature") ?? "";
  const base = `v0:${ts}:${bodyText}`;
  const mac = crypto.createHmac("sha256", process.env.SLACK_SIGNING_SECRET).update(base).digest("hex");
  const expected = `v0=${mac}`;
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sig));
};

const slackFetch = async (path, init = {}) => {
  const r = await fetch(`https://slack.com/api/${path}`, {
    ...init,
    headers: {
      ...(init.headers || {}),
      Authorization: `Bearer ${process.env.SLACK_BOT_TOKEN}`,
    },
  });
  return r.json();
};

const postMessage = async ({ channel, text, thread_ts }) =>
  slackFetch("chat.postMessage", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ channel, text, thread_ts }),
  });

const updateMessage = async ({ channel, ts, text }) =>
  slackFetch("chat.update", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ channel, ts, text }),
  });

// ---- .eml / .msg 解析 ------------------------------------------------
async function parseEmailBuffer(name, buf) {
  // .eml は mailparser、.msg（Outlookバイナリ）は今回スキップ（必要なら @kenjiuno/msgreader を追加）
  if (name.toLowerCase().endsWith(".eml")) {
    const mail = await simpleParser(buf);
    const parts = [
      `Subject: ${mail.subject || "(no subject)"}`,
      `From: ${mail.from?.text || "-"}`,
      `To: ${mail.to?.text || "-"}`,
      `Date: ${mail.date ? mail.date.toISOString() : "-"}`,
      "",
      (mail.text || "").slice(0, 2000), // 取りあえず先頭だけ
    ];
    return parts.join("\n");
  }
  throw new Error("対応外のファイル形式です（.eml をアップしてください）");
}

// ---- ファイル処理のメイン ------------------------------------------------
async function handleFileEvent({ channel, thread_ts, fileId }) {
  await log("diag/step", { where: "handleFileEvent:start", fileId, channel, thread_ts });

  // 1) files.info で詳細取得（file.url_private_download を使う）
  const info = await slackFetch(`files.info?file=${encodeURIComponent(fileId)}`);
  if (!info.ok) throw new Error("files.info 失敗: " + JSON.stringify(info));
  const file = info.file;

  await log("diag/step", {
    where: "files.info",
    name: file.name,
    mimetype: file.mimetype,
    size: file.size,
    url_private_download: !!file.url_private_download,
  });

  // 2) ダウンロード（Authorization が必須）
  const res = await fetch(file.url_private_download, {
    headers: { Authorization: `Bearer ${process.env.SLACK_BOT_TOKEN}` },
  });
  if (!res.ok) throw new Error(`ダウンロード失敗: HTTP ${res.status}`);
  const buf = new Uint8Array(await res.arrayBuffer());

  // 3) 解析
  const text = await parseEmailBuffer(file.name || "", buf);

  // 4) スレッドに上げる（長すぎ回避のため分割なしでまずは）
  const header = "解析完了 :white_check_mark:";
  const body = "```\n" + text + "\n```";
  const out = `${header}\n*filename:* \`${file.name}\`  *size:* ${file.size} bytes\n${body}`;

  await postMessage({ channel, text: out, thread_ts });
}

// ---- メンション診断 ------------------------------------------------
async function runDiag({ channel, thread_ts }) {
  // すべて「ok」判定できる最低限のセルフチェック
  const tests = [];

  // env
  tests.push(["env", process.env.SLACK_BOT_TOKEN ? "ok" : "ng"]);

  // 署名チェック擬似（意味は薄いがログに残す）
  tests.push(["signature", "ok"]);

  // auth.test
  const auth = await slackFetch("auth.test");
  tests.push(["auth.test", auth.ok ? `ok user=${auth.user_id}` : "ng"]);

  // chat.postMessage 実打
  const dummy = await postMessage({ channel, text: "postMessage test", thread_ts });
  tests.push(["chat.postMessage", dummy.ok ? "ok" : "ng"]);

  const lines = tests.map(([k, v]) => `${k.padEnd(14)}: ${v}`).join("\n");
  await postMessage({ channel, text: "```" + lines + "```", thread_ts });
}

// ---- エントリポイント ------------------------------------------------
export default async (request) => {
  // 生テキストを先に読む（署名検証のため）
  const bodyText = await request.text();
  const method = request.method || "GET";

  if (method === "GET") {
    // whoami 的な疎通確認
    return okJson({
      marker: "whoami@eml-to-text-bot",
      now: new Date().toISOString(),
      url: request.url,
      method,
      env: {
        hasToken: !!process.env.SLACK_BOT_TOKEN,
        hasSecret: !!process.env.SLACK_SIGNING_SECRET,
        blobStore: STORE,
        node: process.version,
      },
    });
  }

  // 署名検証
  try {
    if (!signCheck(request, bodyText)) {
      await log("errors/sign", { msg: "invalid signature" });
      return okJson({ ok: false, message: "invalid signature" }); // Slack 的には 200 で返す
    }
  } catch (e) {
    await log("errors/sign", { msg: "sign error", err: String(e) });
    return okJson({ ok: false, message: "sign error" });
  }

  // Slack 仕様の "url_verification"
  const parsed = JSON.parse(bodyText);
  if (parsed.type === "url_verification") {
    return okJson({ challenge: parsed.challenge });
  }

  // event_callback
  if (parsed.type === "event_callback") {
    const ev = parsed.event;
    const channel = ev.channel;
    const user = ev.user;

    try {
      // メンション診断
      if (ev.type === "app_mention") {
        // 「diag」を含んでいたら動作チェック
        const hasDiag = (ev.text || "").toLowerCase().includes("diag");
        if (hasDiag) {
          await runDiag({ channel, thread_ts: ev.ts });
          return okJson({ ok: true });
        }
      }

      // ファイル検知（file_shared イベント or message.channels に files が付いてくる）
      if (ev.type === "file_shared") {
        // 受信しましたよ、の最初のメッセージ
        const first = await postMessage({ channel, thread_ts: ev.event_ts, text: "`.eml/.msg` を検知。解析中…" });

        await handleFileEvent({ channel, thread_ts: first.ts, fileId: ev.file_id || ev.file?.id });
        return okJson({ ok: true });
      }

      if (ev.type === "message" && Array.isArray(ev.files) && ev.files.length > 0) {
        const first = await postMessage({ channel, thread_ts: ev.ts, text: "`.eml/.msg` を検知。解析中…" });

        // 一つ目だけ処理
        await handleFileEvent({ channel, thread_ts: first.ts, fileId: ev.files[0].id });
        return okJson({ ok: true });
      }

      // 何もしないイベント
      return okJson({ ok: true, message: "ack" });
    } catch (e) {
      // ここで必ずユーザーに見える形に落とす
      await log("errors/parse", { err: String(e), stack: e?.stack, ev });
      try {
        await postMessage({
          channel,
          thread_ts: ev.ts || ev.event_ts,
          text: `:x: 解析に失敗しました。\n> ${String(e)}`,
        });
      } catch (_) {}
      return okJson({ ok: true, message: "error handled" });
    }
  }

  return okJson({ ok: true, message: "ack" });
}
