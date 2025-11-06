// netlify/functions/slack-events.js  --- ESM
import crypto from "node:crypto";
import { getStore } from "@netlify/blobs";

/** ====== 設定 ====== */
const STORE_NAME = "logs";                    // Netlify Blobs のストア名（ダッシュボード上の "logs"）
const store = getStore({ name: STORE_NAME }); // Functions からはトークン不要でOK
const BOT_TOKEN = process.env.SLACK_BOT_TOKEN;
const SIGNING_SECRET = process.env.SLACK_SIGNING_SECRET;

/** 共通: JSON Response */
const json = (obj, init = {}) =>
  new Response(JSON.stringify(obj, null, 2), {
    status: init.status ?? 200,
    headers: { "content-type": "application/json; charset=utf-8" },
  });

/** ログ出力（Blobs） */
async function putLog(path, data) {
  try {
    const key = `${path}/${Date.now()}`;
    await store.set(
      key,
      JSON.stringify({ t: new Date().toISOString(), ...data }, null, 2),
      { contentType: "application/json" }
    );
  } catch (e) {
    // ここで throw はしない（Slack への応答を優先）
    console.error("blob log error:", e);
  }
}

/** Slack 署名検証 */
function verifySlackSignature({ bodyText, timestamp, slackSig }) {
  if (!SIGNING_SECRET) return { ok: false, reason: "no signing secret" };
  if (!timestamp || !slackSig) return { ok: false, reason: "missing headers" };

  const base = `v0:${timestamp}:${bodyText}`;
  const hmac = crypto.createHmac("sha256", SIGNING_SECRET.trim());
  hmac.update(base);
  const hex = hmac.digest("hex");
  const mySig = `v0=${hex}`;
  const ok = crypto.timingSafeEqual(Buffer.from(mySig), Buffer.from(slackSig));
  return { ok, mySig, hex };
}

/** Slack 投稿（診断や結果返しに使用） */
async function chatPostMessage({ channel, text, thread_ts }) {
  if (!BOT_TOKEN) throw new Error("no SLACK_BOT_TOKEN");
  const r = await fetch("https://slack.com/api/chat.postMessage", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${BOT_TOKEN}`,
      "Content-Type": "application/json; charset=utf-8",
    },
    body: JSON.stringify({
      channel,
      text,
      thread_ts,
    }),
  });
  const j = await r.json();
  return j;
}

/** メインハンドラ */
export default async function handler(request) {
  // 生ボディ（署名検証で必要）
  const bodyText = await request.text();

  // URL verification（Slack イベントサブスクリプション最初の疎通）
  try {
    const probe = JSON.parse(bodyText);
    if (probe?.type === "url_verification" && probe?.challenge) {
      await putLog("diag/url_verification", { challenge: probe.challenge });
      return json({ challenge: probe.challenge });
    }
  } catch {
    /* noop: 普通の event_callback のときはここを素通り */
  }

  // 署名検証
  const timestamp = request.headers.get("x-slack-request-timestamp");
  const slackSig = request.headers.get("x-slack-signature");
  const v = verifySlackSignature({ bodyText, timestamp, slackSig });

  if (!v.ok) {
    await putLog("errors/sign", { msg: "invalid signature", reason: v.reason });
    return json({ ok: false, message: "invalid signature" }, { status: 401 });
  }

  // ここから payload を処理
  let payload;
  try {
    payload = JSON.parse(bodyText);
  } catch (e) {
    await putLog("errors/parse", { msg: "json parse error", bodyText });
    return json({ ok: false, message: "bad json" }, { status: 400 });
  }

  // まずは Slack に 200 を返せるように、重い処理は後ろに寄せる
  // （Netlify の実行時間内で軽い投稿だけ行う）
  // イベント種別
  if (payload?.type === "event_callback") {
    const ev = payload.event;

    // --- 診断コマンド（@メンションで「diag」を含む） ---
    if (ev?.type === "app_mention" && typeof ev?.text === "string") {
      if (ev.text.toLowerCase().includes("diag")) {
        const diag = {
          event: `channel=${ev.channel} thread=${(ev.thread_ts ?? ev.ts)}`,
          env: "ok",
          signature: "ok",
          "auth.test": BOT_TOKEN ? "ok" : "ng (no token)",
        };
        try {
          const r = await chatPostMessage({
            channel: ev.channel,
            thread_ts: ev.thread_ts ?? ev.ts,
            text:
              "diag: postMessage test\n" +
              "```\n" +
              Object.entries(diag)
                .map(([k, v]) => `${k.padEnd(15)}: ${v}`)
                .join("\n") +
              "\n```",
          });
          diag["chat.postMessage"] = r?.ok ? "ok" : `ng ${r?.error ?? ""}`;
        } catch (e) {
          diag["chat.postMessage"] = `ng ${e.message}`;
        }
        await putLog("diag/mention", { diag, ev });
        return json({ ok: true, message: "ack" }); // Slack への即時応答
      }
    }

    // --- 添付ファイル/EML の検出（簡易） ---
    // ここでは「解析中…」のポストだけ行い、詳細解析は別実装に委ねる前提
    if (ev?.files && Array.isArray(ev.files) && ev.files.length > 0) {
      // EML っぽいものがあれば、とりあえず「検知 → 解析中」と返信
      const emls = ev.files.filter(
        (f) =>
          typeof f.name === "string" &&
          f.name.toLowerCase().endsWith(".eml")
      );
      if (emls.length > 0) {
        try {
          await chatPostMessage({
            channel: ev.channel,
            thread_ts: ev.thread_ts ?? ev.ts,
            text: "`.eml` を検知。解析中…",
          });
        } catch (e) {
          await putLog("errors/chat", { msg: "post fail", error: e.message });
        }
        await putLog("diag/eml-detected", { files: emls.map((f) => f.name) });
        return json({ ok: true, message: "ack" });
      }
    }
  }

  // 特に何もしないイベントはそのまま ACK
  return json({ ok: true, message: "ack" });
}
