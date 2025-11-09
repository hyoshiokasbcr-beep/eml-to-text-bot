// netlify/functions/slack-events.js

import crypto from "node:crypto";
import { simpleParser } from "mailparser";
import { getStore } from "@netlify/blobs";
import { htmlToText } from "html-to-text";

const BOT_TOKEN = process.env.SLACK_BOT_TOKEN ?? "";
const SIGNING_SECRET = (process.env.SLACK_SIGNING_SECRET ?? "").trim();
const MAX_PREVIEW_CHARS = parseInt(process.env.MAX_PREVIEW_CHARS ?? "3000", 10);

const DEBUG_MODE = (process.env.DEBUG_MODE ?? "").toLowerCase() === "on";
const LOG_TO_BLOBS = (process.env.LOG_TO_BLOBS ?? "false").toLowerCase() === "true";
const LOG_STORE = LOG_TO_BLOBS ? getStore({ name: process.env.BLOB_STORE_NAME || "logs" }) : null;
const STORE = getStore({ name: process.env.PREVIEW_STORE_NAME || "previews" });

/* ── util ── */
function tEq(a,b){const A=Buffer.from(a),B=Buffer.from(b); if(A.length!==B.length) return false; return crypto.timingSafeEqual(A,B);}
function verifySig({raw,timestamp,sig}){if(!SIGNING_SECRET||!sig||!timestamp) return false; const base=`v0:${timestamp}:${raw}`; const h=crypto.createHmac("sha256",SIGNING_SECRET); h.update(base); return tEq(`v0=${h.digest("hex")}`,sig);}
async function api(path,body){const r=await fetch(`https://slack.com/api/${path}`,{method:"POST",headers:{Authorization:`Bearer ${BOT_TOKEN}`,"Content-Type":"application/json; charset=utf-8"},body:JSON.stringify(body)}); return r.json();}
const postMessage = (p)=>api("chat.postMessage",p);
const viewsOpen   = (p)=>api("views.open",p);
const openDM      = (uid)=>api("conversations.open",{users:uid});
async function filesInfo(file){const r=await fetch(`https://slack.com/api/files.info?file=${encodeURIComponent(file)}`,{headers:{Authorization:`Bearer ${BOT_TOKEN}`}}); return r.json();}
async function dl(url){const r=await fetch(url,{headers:{Authorization:`Bearer ${BOT_TOKEN}`}}); if(!r.ok) throw new Error(`download failed: ${r.status}`); return Buffer.from(await r.arrayBuffer());}
async function blog(path,data){ if(!LOG_TO_BLOBS||!LOG_STORE) return; try{ await LOG_STORE.set(path, typeof data==="string"?data:JSON.stringify(data) ); }catch{} }

/* ── parse ── */
function norm(t){const s=(t??"").replace(/\r\n/g,"\n").replace(/\t/g,"  ").trim(); return s.length<=MAX_PREVIEW_CHARS? s : s.slice(0,MAX_PREVIEW_CHARS)+"\n…(truncated)";}
function firstLine(t){const l=(t??"").split("\n").find(s=>s.trim())??""; return l.length>120? l.slice(0,120)+" …" : (l||"(no content)");}
async function parseEML(buf){const mail=await simpleParser(buf); let body=""; if(mail.html) body=htmlToText(mail.html,{wordwrap:false}); else if(mail.text) body=mail.text;
  const heads=[`From: ${mail.from?.text??""}`,`To: ${mail.to?.text??""}`,mail.cc?`Cc: ${mail.cc.text}`:null,`Date: ${mail.date??""}`,`Subject: ${mail.subject??""}`].filter(Boolean);
  return `# ${mail.subject??""}\n${heads.join("\n")}\n\n${body??""}`;}
function u8(buf){ if(buf instanceof Uint8Array && !(buf instanceof Buffer)) return buf; return new Uint8Array(buf.buffer,buf.byteOffset??0,buf.byteLength); }
function abTight(u){ return u.buffer.slice(u.byteOffset, u.byteOffset+u.byteLength); }
async function getMsgCtor(){ const m=await import("@kenjiuno/msgreader"); const C=[m.MSGReader, m.default, m.MsgReader].find(x=>typeof x==="function"); if(!C) throw new Error("MSGReader constructor not found"); return C; }
async function parseMSG(buf){
  const Ctor=await getMsgCtor(); const U=u8(buf); let info;
  try{ info=new Ctor(abTight(U)).getFileData(); }
  catch(e1){ try{ info=new Ctor(U).getFileData(); } catch(e2){ await blog(`errors/msgreader/${Date.now()}`,{e1:String(e1),e2:String(e2)}); throw new Error("failed to construct MSGReader"); } }
  const html=info.bodyHTML??info.messageComps?.htmlBody??null, rtf=info.bodyRTF??info.messageComps?.rtfBody??null, text=info.body??info.messageComps?.plainText??null;
  let body=""; if(html) body=htmlToText(html,{wordwrap:false}); else if(text) body=text; else if(rtf) body=rtf.replace(/\\[a-z]+\d* ?|[{}]/gi," ").replace(/\s+/g," ").trim();
  const heads=[`From: ${info.senderName||info.senderEmail||""}`,`To: ${Array.isArray(info.recipients)?info.recipients.map(r=>r.name||r.email).join(", ") : ""}`, info.cc?`Cc: ${info.cc}`:null, `Date: ${info.messageDeliveryTime||info.creationTime||""}`, `Subject: ${info.subject||""}`].filter(Boolean);
  return `# ${info.subject||""}\n${heads.join("\n")}\n\n${body||""}`; }
const supported = (n="")=>{n=n.toLowerCase(); return n.endsWith(".eml")||n.endsWith(".msg")||n.endsWith(".oft");};

/* ── UI ── */
function blocksPreview(name,preview,payload){ return [
  {type:"section",text:{type:"mrkdwn",text:`🧾 解析結果（${name}）\n\`\`\`\n${preview}\n\`\`\``}},
  {type:"actions",elements:[{type:"button",action_id:"open_modal",text:{type:"plain_text",text:"全文を見る（モーダル）"},value:payload}]}
];}
function chunk(s,n){const a=[]; for(let i=0;i<s.length;i+=n) a.push(s.slice(i,i+n)); return a;}
function modal(name,body,meta){
  const blocks = chunk(body,2900).map(c=>({type:"section",text:{type:"mrkdwn",text:"```\n"+c+"\n`" +"`"}}));
  if(blocks.length===0) blocks.push({type:"section",text:{type:"mrkdwn",text:"（内容なし）"}});
  blocks.push({type:"actions",elements:[{type:"button",action_id:"send_copy_dm",text:{type:"plain_text",text:"📋 自分に送る（コピー用）"}}]});
  return {type:"modal",title:{type:"plain_text",text:(name||"解析結果").slice(0,24)},close:{type:"plain_text",text:"閉じる"},private_metadata:JSON.stringify(meta||{}),blocks};
}

/* ── helper: shares 待ち & 位置解決 ── */
async function filesInfoWithShares(fileId, tries=5, wait=1000){
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
function resolvePlace(file){
  const s=file?.shares||{};
  for(const scope of ["private","public"]){
    const m=s[scope]; if(!m) continue;
    for(const [cid,posts] of Object.entries(m)){
      const p=Array.isArray(posts)&&posts[0]; if(p){ return {channel:cid, thread_ts: p.thread_ts || p.ts}; }
    }
  }
  if(Array.isArray(file?.channels)&&file.channels.length>0) return {channel:file.channels[0], thread_ts: undefined};
  return {channel:null, thread_ts:null};
}

/* ── core ── */
async function processFile({fileId, channelHint, threadHint}){
  if(DEBUG_MODE) await blog(`debug/seen/${Date.now()}`,{fileId,channelHint,threadHint});
  const lock=`lock:${fileId}`; if(await STORE.get(lock)) return; await STORE.set(lock,Date.now().toString());
  try{
    if(await STORE.get(`done:${fileId}`)) return;

    const file = await filesInfoWithShares(fileId, 5, 1000);
    let channel = channelHint;
    let thread_ts = threadHint;

    if(!channel || !thread_ts){
      const r=resolvePlace(file);
      channel = channel || r.channel;
      thread_ts = thread_ts || r.thread_ts;
    }
    // 位置がなければ、最後の手段としてトップレベル投稿で生存確認
    if(DEBUG_MODE && channel){
      await postMessage({ channel, text:`👀 検知: ${file.name}（暫定処理）` });
    }
    if(!channel){ await blog(`errors/no-channel/${Date.now()}`,{fileId}); return; }

    if(!supported(file.name)){
      await postMessage({ channel, thread_ts, text:`⚠️ 未対応の拡張子です: \`${file.name}\`（.eml/.msg/.oft）` });
      await STORE.set(`done:${fileId}`,"1"); return;
    }

    const url=file.url_private_download || file.url_private; if(!url) throw new Error("no url_private_download");
    const buf=await dl(url);

    let parsed="";
    try{
      parsed = file.name.toLowerCase().endsWith(".eml") ? await parseEML(buf) : await parseMSG(buf);
    }catch(e){
      await blog(`errors/parse/${Date.now()}`,{name:file.name,e:String(e)});
      throw new Error("parse failed");
    }

    const body=norm(parsed);
    const key=`p:${Date.now()}:${fileId}`; await STORE.set(key,body);
    const preview=firstLine(body);

    await postMessage({
      channel, thread_ts,
      text:"解析結果（プレビュー）",
      blocks:blocksPreview(file.name, preview, JSON.stringify({key,filename:file.name}))
    });

    await STORE.set(`done:${fileId}`,"1");
  }finally{
    await STORE.set(lock,"done");
  }
}

/* ── interactivity ── */
async function handleBlocks(payload){
  const act=payload?.actions?.[0]; if(!act) return new Response("",{status:200});
  if(act.action_id==="open_modal"){
    const key = JSON.parse(act.value||"{}")?.key; const fn = JSON.parse(act.value||"{}")?.filename || "解析結果";
    const body=(await STORE.get(key)) ?? "(content expired)"; await viewsOpen({ trigger_id: payload.trigger_id, view: modal(fn, body, {key,filename:fn}) });
    return new Response("",{status:200});
  }
  if(act.action_id==="send_copy_dm"){
    const meta = payload.view?.private_metadata ? JSON.parse(payload.view.private_metadata) : {};
    const key=meta.key, fn=meta.filename||"解析結果"; if(!key) return new Response("",{status:200});
    const content=(await STORE.get(key)) ?? "(content expired)";
    const o=await openDM(payload.user?.id); if(o?.ok&&o?.channel?.id){ await postMessage({ channel:o.channel.id, text:`🧾 解析結果（${fn}）\n\`\`\`\n${content}\n\`\`\`` }); }
    else { await blog(`errors/open-dm-failed/${Date.now()}`, o||{}); }
    return new Response("",{status:200});
  }
  return new Response("",{status:200});
}

/* ── entry ── */
export default async function handler(req){
  const raw=await req.text(); const ts=req.headers.get("x-slack-request-timestamp"); const sig=req.headers.get("x-slack-signature"); const ct=req.headers.get("content-type")||"";

  if(req.headers.get("x-slack-retry-num")) return new Response("",{status:200,headers:{"X-Slack-No-Retry":"1"}});
  if(!verifySig({raw,timestamp:ts,sig})){ await blog(`errors/sign/${Date.now()}`,{note:"invalid"}); return new Response("invalid signature",{status:401}); }

  if(ct.includes("application/x-www-form-urlencoded")){
    const m=/^payload=(.*)$/.exec(raw); if(!m) return new Response("",{status:200});
    const payload=JSON.parse(decodeURIComponent(m[1])); return handleBlocks(payload);
  }

  let payload; try{ payload=JSON.parse(raw);} catch { await blog(`errors/json/${Date.now()}`, raw.slice(0,800)); return new Response("bad request",{status:400}); }

  // ヘッダログ（常時）
  await blog(`events/heads/${Date.now()}`,{type:payload.type, etype:payload.event?.type, subtype:payload.event?.subtype, file_id:payload.event?.file_id || payload.event?.files?.[0]?.id || null});

  if(payload.type==="url_verification") return new Response(payload.challenge,{headers:{"Content-Type":"text/plain"}});

  if(payload.type==="event_callback"){
    const ev=payload.event;

    if(ev.type==="app_mention" && /diag/i.test(ev.text??"")){
      if(ev.channel) await postMessage({ channel:ev.channel, thread_ts: ev.ts, text:"diag: ok ✅" });
      return new Response("",{status:200});
    }

    // 1) message（subtype なしでも files があれば処理）
    if(ev.type==="message" && Array.isArray(ev.files) && ev.files.length>0){
      const fileId = ev.files[0]?.id;
      await processFile({ fileId, channelHint: ev.channel, threadHint: ev.ts });
      return new Response("",{status:200});
    }

    // 2) 従来の file_share
    if(ev.type==="message" && ev.subtype==="file_share"){
      const fileId=ev.files?.[0]?.id;
      await processFile({ fileId, channelHint: ev.channel, threadHint: ev.ts });
      return new Response("",{status:200});
    }

    // 3) file_shared（channel_id がある場合は即そこに暫定通知）
    if(ev.type==="file_shared"){
      const fileId = ev.file_id;
      const ch     = ev.channel_id || null;
      const th     = ev.event_ts   || undefined;
      await processFile({ fileId, channelHint: ch, threadHint: th });
      return new Response("",{status:200});
    }
  }

  return new Response("",{status:200});
}
