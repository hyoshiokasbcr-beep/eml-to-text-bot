// netlify/functions/slack-events.js
// ESM（import/export）& Response で返す版
import { simpleParser } from "mailparser";
import { htmlToText } from "html-to-text";

// Slackに投げる前に要約コードブロックを作る（本文は安全長でカット）
const SAFE_BODY_LIMIT = Number(process.env.SAFE_BODY_LIMIT ?? 3400);

// 本文のプレビュー（Slack用コードブロック）を作成
function buildCodeBlockPreview(mail) {
  // text が乏しい or 無いときは html からテキスト化
  let text = (mail.text || "").trim();
  if ((!text || text.length < 10) && mail.html) {
    text = htmlToText(mail.html, {
      wordwrap: false,
      selectors: [{ selector: "a", options: { hideLinkHrefIfSameAsText: true } }],
    }).trim();
  }

  // 改行を統一・不要文字除去
  text = (text || "").replace(/\r?\n/g, "\n").replace(/\u0000/g, "").trim();

  // ヘッダ部（見やすさ優先）
  const head = [
    `From: ${mail.from?.text ?? ""}`,
    `To: ${mail.to?.text ?? ""}`,
    `Subject: ${mail.subject ?? ""}`,
    `Date: ${mail.date ? new Date(mail.date).toISOString() : ""}`,
  ].join("\n");

  // 安全長で本文を切る
  const body = text.slice(0, SAFE_BODY_LIMIT);

  // Slack コードブロック
  const code =
    "```text\n" + head + "\n\n" + body + "\n```\n" +
    "_※続きは元メール（.eml）をご確認ください_";

  return code;
}

export default async (req) => {
  try {
    if (req.method !== "POST") {
      return new Response("Method Not Allowed", { status: 405 });
    }

    let body;
    try {
      body = await req.json();
    } catch {
      return new Response(
        JSON.stringify({ ok: false, error: "invalid_json" }),
        { status: 400, headers: { "content-type": "application/json; charset=utf-8" } }
      );
    }

    // --- Slack の URL 検証（challenge） ---
    if (body?.type === "url_verification" && body?.challenge) {
      // Slack は 200 で challenge 文字列をそのまま返す必要あり（text/plain）
      return new Response(body.challenge, {
        status: 200,
        headers: { "content-type": "text/plain" },
      });
    }

    // --- CLI/PowerShell テスト経路: base64 の .eml を直送 ---
    if (body?.__test_base64_eml) {
      const buf = Buffer.from(body.__test_base64_eml, "base64");
      const mail = await simpleParser(buf);
      const preview = buildCodeBlockPreview(mail);

      // ここでは Slack 投稿は行わず、プレビューだけ返す
      return new Response(
        JSON.stringify({ ok: true, preview }),
        { status: 200, headers: { "content-type": "application/json; charset=utf-8" } }
      );
    }

    // --- 本番の Slack Events（ここでは即 200 応答だけ。必要に応じて拡張してOK）---
    // 例：署名検証・files.info で EML を取りに行く・Slackに投稿…などはここに実装
    return new Response(
      JSON.stringify({ ok: true, message: "ack" }),
      { status: 200, headers: { "content-type": "application/json; charset=utf-8" } }
    );

  } catch (err) {
    return new Response(
      JSON.stringify({ ok: false, error: err?.message ?? String(err) }),
      { status: 500, headers: { "content-type": "application/json; charset=utf-8" } }
    );
  }
};
