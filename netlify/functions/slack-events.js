// eml/msg/oft → スレッドに1行プレビュー + 「全文を見る（モーダル）」
// 修正点：
// - Interactivity 受信の堅牢化（payloadパース/署名検証/ログ）
// - 重複防止を強化：lock + processing + done の3段ガード
// - 可能なら必ずスレッド返信（root tsが無い場合も shares から復元）

import crypto from "node:crypto";
import { simpleParser } from "mailparser";
import { htmlToText } from "html-to-text";
import { getStore } from "@netlify/blobs";

const BOT_TOKEN      = process.env.SLACK_BOT_TOKEN ?? "";
const SIGNING_SECRET = (process.env.SLACK_SIGNING_SECRET ?? "").trim();
const MAX_PREVIEW    = parseInt(process.env.MAX_PREVIEW_CHARS ?? "3000", 10);

const ENABLE_DM_COPY = (process.env.ENABLE_DM_COPY  ?? "false").toLowerCase() === "true";
const ENABLE_LOGS    = (process.env.LOG_TO_BLOBS    ?? "false").toLowerCase() === "true";
const ENABLE_DEBUG   = (process.env.DEBUG_MODE      ?? "off").toLowerCase() === "on";

const PREVIEW_STORE  = getStore({ name: process.env.PREVIEW_STORE_NAME || "previews" });
const LOG_STORE      = ENABLE_LOGS ? getStore({ name: process.env.BLOB_STORE_NAME || "logs" }) : null;

/* ── helpers ── */
function tseq(a,b){const A=Buffer.from(a),B=Buffer.from(b); if(A.length!==B.length)return false; return crypto.timingSafeEqual(A,B);}
function verifySig(raw,ts,sig){ if(!SIGNING_SECRET||!sig||!ts) return false; const base=`v0:${ts}:${raw}`; const h=crypto.createHmac("sha256",SIGNING_SECRET); h.update(base); return tseq(`v0=${h.digest("hex")}`,sig); }
async function blog(path,data){ if(!ENABLE_LOGS||!LOG_STORE) return; try{ await LOG_STORE.set(path, typeof data==="string"?data:JSON.stringify(data)); }catch{} }

async function api(path, body){
  const r = await fetch(`https://slack.com/api/${path}`, {
    method: "POST",
    headers: { Authorization: `Bearer ${BOT_TOKEN}`, "Content-Type": "application/json; charset=utf-8" },
    body: JSON.stringify(body),
  });
  return r.json();
}
const post      = (p)=>api("chat.postMessage", p);
const viewsOpen = (p)=>api("views.open", p);
const openDM    = (users)=>api("conversations.open", { users });

async function filesInfo(file){ const r=await fetch(`https://slack.com/api/files.info?file=${encodeURIComponent(file)}`,{headers:{Authorization:`Bearer ${BOT_TOKEN}`}}); return r.json(); }
async function dl(url){ const r=await fetch(url,{headers:{Authorization:`Bearer ${BOT_TOKEN}`}}); if(!r.ok) throw new Error(`download failed: ${r.status}`); return Buffer.from(await r.arrayBuffer()); }

/* ── parse ── */
function normalize(t){ const s=(t??"").replace(/\r\n/g,"\n").replace(/\t/g,"  ").trim(); return s.length<=MAX_PREVIEW?s:s.slice(0,MAX_PREVIEW)+"\n…(truncated)"; }
function firstLine(t){ const l=(t??"").split("\n").find(s=>s.trim())??""; return l.length>120?l.slice(0,120)+" …":(l||"(no content)"); }

async function parseEML(buf){
  const mail=await simpleParser(buf);
  let body=""; if(mail.html) body=htmlToText(mail.html,{wordwrap:false}); else if(mail.text) body=mail.text;
  const header=[
    `From: ${mail.from?.text??""}`,
    `To: ${mail.to?.text??""}`,
    mail.cc?`Cc: ${mail.cc.text}`:null,
    `Date: ${mail.date??""}`,
    `Subject: ${mail.subject??""}`
  ].filter(Boolean).join("\n");
  return `# ${mail.subject??""}\n${header}\n\n${body??""}`;
}

function toU8(b){ if(b instanceof Uint8Array && !(b instanceof Buffer)) return b; return new Uint8Array(b.buffer,b.byteOffset??0,b.byteLength); }
function tightAB(u8){ return u8.buffer.slice(u8.byteOffset,u8.byteOffset+u8.byteLength); }

async function parseMSGorOFT(buf){
  const mod = await import("@kenjiuno/msgreader");
  const Ctor = [mod.MSGReader, mod.default, mod.MsgReader].find(x=>typeof x==="function");
  if(!Ctor) throw new Error("MSGReader constructor not found");
  const u8 = toU8(buf);
  let info;
  try { info = new Ctor(tightAB(u8)).getFileData(); }
  catch(e1){
    try { info = new Ctor(u8).getFileData(); }
    catch(e2){ await blog(`errors/msgreader/${Date.now()}`, {e1:String(e1),e2:String(e2)}); throw new Error("failed to construct MSGReader"); }
  }
  const html = info.bodyHTML ?? info.messageComps?.htmlBody ?? null;
  const text = info.body ?? info.messageComps?.plainText ?? null;
  const rtf  = info.bodyRTF ?? info.messageComps?.rtfBody ?? null;
  let body=""; if(html) body=htmlToText(html,{wordwrap:false}); else if(text) body=text;
  else if(rtf) body=rtf.replace(/\\[a-z]+\d* ?|[{}]/gi," ").replace(/\s+/g," ").trim();

  const header=[
    `From: ${info.senderName||info.senderEmail||""}`,
    `To: ${Array.isArray(info.recipients)?info.recipients.map(r=>r.name||r.email).join(", "):""}`,
    info.cc?`Cc: ${info.cc}`:null,
    `Date: ${info.messageDeliveryTime||info.creationTime||""}`,
    `Subject: ${info.subject||""}`
  ].filter(Boolean).join("\n");
  return `# ${info.subject||""}\n${header}\n\n${body||""}`;
}

function supported(name=""){ const n=name.toLowerCase(); return n.endsWith(".eml")||n.endsWith(".msg")||n.endsWith(".oft"); }

/* ── UI ── */
function blocksPreview(filename, preview, payload){
  return [
    { type:"section", text:{ type:"mrkdwn", text:`🧾 解析結果（${filename}）\n\`\`\`\n${preview}\n\`\`\`` } },
    { type:"actions", elements:[
      { type:"button", action_id:"open_modal", text:{ type:"plain_text", text:"全文を見る（モーダル）" }, value:payload }
    ]}
  ];
}
function chunk(s,n){ const a=[]; for(let i=0;i<s.length;i+=n)a.push(s.slice(i,i+n)); return a; }
function modalView(filename, body, meta){
  const title=(filename||"解析結果").slice(0,24);
  const blocks = chunk(body, 2900).map(c=>({type:"section", text:{ type:"mrkdwn", text:"```\n"+c+"\n```" }}));
  if(blocks.length===0) blocks.push({type:"section", text:{ type:"mrkdwn", text:"（内容なし）" }});
  const actions=[];
  if(ENABLE_DM_COPY) actions.push({ type:"button", action_id:"send_copy_dm", text:{ type:"plain_text", text:"📋 自分に送る（コピー用）" } });
  if(actions.length) blocks.push({ type:"actions", elements: actions });
  return { type:"modal", title:{ type:"plain_text", text:title }, close:{ type:"plain_text", text:"閉じる" }, private_metadata: JSON.stringify(meta||{}), blocks };
}

/* ── shares → 返信先復元 ── */
async function filesInfoWithShares(fileId, tries=6, wait=700){
  let last=null;
  for(let i=0;i<tries;i++){
    const info=await filesInfo(fileId); last=info;
    if(info.ok){
      const f=info.file;
      if(f?.shares?.private || f?.shares?.public || (Array.isArray(f?.channels)&&f.channels.length>0)) return f;
    }
    await new Promise(r=>setTimeout(r,wait));
  }
  if(!last?.ok) throw new Error(`files.info failed: ${JSON.stringify(last)}`);
  return last.file;
}
function placeFromShares(file){
  const s=file?.shares||{};
  for(const scope of ["private","public"]){
    const m=s[scope]; if(!m) continue;
    for(const [cid,posts] of Object.entries(m)){
      if(Array.isArray(posts)&&posts.length){
        const p=posts[0]; return { channel: cid, thread_ts: p.thread_ts || p.ts };
      }
    }
  }
  if(Array.isArray(file?.channels)&&file.channels.length>0) return { channel:file.channels[0], thread_ts: undefined };
  return { channel:null, thread_ts:null };
}

/* ── core（重複防止を強化：lock + processing + done） ── */
async function handleFileById({ fileId, channelHint, threadHint }){
  if(!fileId) return;

  const lock = `lock:${fileId}`;
  if(await PREVIEW_STORE.get(lock)) return;                 // すでに誰かが開始
  await PREVIEW_STORE.set(lock, String(Date.now()));

  try{
    if(await PREVIEW_STORE.get(`done:${fileId}`)) return;   // 完了済みなら抜ける
    if(await PREVIEW_STORE.get(`processing:${fileId}`)) return; // 実行中なら抜ける
    await PREVIEW_STORE.set(`processing:${fileId}`, "1");   // 実行開始マーク

    const f = await filesInfoWithShares(fileId, 6, 700);
    if(!supported(f.name)){ await PREVIEW_STORE.set(`done:${fileId}`,"1"); return; }

    let channel = channelHint;
    let thread_ts = threadHint;
    if(!channel || !thread_ts){
      const r=placeFromShares(f);
      channel = channel || r.channel;
      thread_ts = thread_ts || r.thread_ts;
    }
    if(!channel){ await PREVIEW_STORE.set(`done:${fileId}`,"1"); return; }

    const url = f.url_private_download || f.url_private;
    if(!url){ await PREVIEW_STORE.set(`done:${fileId}`,"1"); return; }

    const buf = await dl(url);
    const parsed = f.name.toLowerCase().endsWith(".eml") ? await parseEML(buf) : await parseMSGorOFT(buf);
    const body = normalize(parsed);
    const key = `p:${Date.now()}:${fileId}`; await PREVIEW_STORE.set(key, body);

    const preview = firstLine(body);
    await post({ channel, thread_ts, text:"解析結果（プレビュー）", blocks: blocksPreview(f.name, preview, JSON.stringify({ key, filename: f.name })) });

    await PREVIEW_STORE.set(`done:${fileId}`,"1");          // 完了
  } finally {
    await PREVIEW_STORE.set(`processing:${fileId}`, "0");   // 処理終了
    await PREVIEW_STORE.set(lock, "done");                  // ロック解放（念のため）
  }
}

/* ── interactivity（モーダル/DM） ── */
async function handleBlockActions(payload){
  try{
    if(ENABLE_DEBUG) await blog(`raw/interactivity/${Date.now()}`, payload);

    const a = payload?.actions?.[0];
    if(!a) return new Response("",{status:200});

    if(a.action_id === "open_modal"){
      const val = a.value ? JSON.parse(a.value) : {};
      const key = val.key, filename = val.filename || "解析結果";
      if(!payload.trigger_id || !key) return new Response("",{status:200});
      const body = (await PREVIEW_STORE.get(key)) ?? "(content expired)";
      await viewsOpen({ trigger_id: payload.trigger_id, view: modalView(filename, body, { key, filename }) });
      return new Response("",{status:200});
    }

    if(a.action_id === "send_copy_dm" && ENABLE_DM_COPY){
      const meta = payload.view?.private_metadata ? JSON.parse(payload.view.private_metadata) : {};
      const key = meta.key, filename = meta.filename || "解析結果";
      const uid = payload.user?.id;
      if(!uid || !key) return new Response("",{status:200});
      const body = (await PREVIEW_STORE.get(key)) ?? "(content expired)";
      const opened = await openDM(uid);
      if(opened?.ok && opened?.channel?.id){
        await post({ channel: opened.channel.id, text: `🧾 解析結果（${filename}）\n\`\`\`\n${body}\n\`\`\`` });
      }
      return new Response("",{status:200});
    }

    return new Response("",{status:200});
  }catch(e){
    await blog(`errors/interactivity/${Date.now()}`, String(e));
    return new Response("",{status:200});
  }
}

/* ── entry ── */
export default async function handler(req){
  // GET: 生存確認（DEBUG時）
  if(ENABLE_DEBUG && req.method==="GET"){
    return new Response("alive: "+new Date().toISOString(), { status: 200 });
  }

  const raw = await req.text();
  const ts  = req.headers.get("x-slack-request-timestamp");
  const sig = req.headers.get("x-slack-signature");
  const ct  = req.headers.get("content-type") || "";

  if(!verifySig(raw, ts, sig)){
    await blog(`errors/sign/${Date.now()}`, { note:"invalid-signature" });
    return new Response("invalid signature",{status:401});
  }

  // ─ Interactivity: x-www-form-urlencoded で payload=... が来る
  if(ct.includes("application/x-www-form-urlencoded")){
    const m = /(^|&)payload=([^&]*)/.exec(raw);
    if(!m){ return new Response("",{status:200}); }
    const json = decodeURIComponent(m[2]);
    let payload; try{ payload = JSON.parse(json); } catch { await blog(`errors/payload/${Date.now()}`, json.slice(0,1200)); return new Response("",{status:200}); }
    if(payload?.type === "block_actions") return handleBlockActions(payload);
    return new Response("",{status:200});
  }

  // ─ Events API
  let payload; try{ payload=JSON.parse(raw); } catch { await blog(`errors/json/${Date.now()}`, raw.slice(0,1200)); return new Response("bad request",{status:400}); }
  if(ENABLE_DEBUG) await blog(`raw/events/${Date.now()}`, payload);

  if(payload.type === "url_verification"){
    return new Response(payload.challenge, { headers:{ "Content-Type":"text/plain" } });
  }

  if(payload.type === "event_callback"){
    const ev = payload.event;

    // diag
    if(ev.type === "app_mention" && /diag/i.test(ev.text ?? "")){
      if(ev.channel) await post({ channel: ev.channel, thread_ts: ev.ts, text: "diag: ok ✅" });
      return new Response("",{status:200});
    }

    // message + files[]（subtype無し）
    if(ev.type === "message" && Array.isArray(ev.files) && ev.files.length>0){
      await handleFileById({ fileId: ev.files[0]?.id, channelHint: ev.channel, threadHint: ev.ts });
      return new Response("",{status:200});
    }

    // subtype:file_share
    if(ev.type === "message" && ev.subtype === "file_share"){
      await handleFileById({ fileId: ev.files?.[0]?.id, channelHint: ev.channel, threadHint: ev.ts });
      return new Response("",{status:200});
    }

    // file_shared（shares の反映を待って、thread を復元）
    if(ev.type === "file_shared"){
      await handleFileById({ fileId: ev.file_id, channelHint: ev.channel_id || null, threadHint: ev.event_ts || undefined });
      return new Response("",{status:200});
    }
  }

  return new Response("",{status:200});
}
