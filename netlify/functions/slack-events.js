// netlify/functions/slack-events.js
// 確実起動版：message(filesあり) も file_shared も拾う / file_shared は shares を5回まで待って解決 / 取れなければチャンネルにトップ投稿
// モーダル全文 + 「📋 自分に送る」付き（im:write が必要）

import crypto from "node:crypto";
import { simpleParser } from "mailparser";
import { getStore } from "@netlify/blobs";
import { htmlToText } from "html-to-text";

const BOT_TOKEN = process.env.SLACK_BOT_TOKEN ?? "";
const SIGNING_SECRET = (process.env.SLACK_SIGNING_SECRET ?? "").trim();
const MAX_PREVIEW_CHARS = parseInt(process.env.MAX_PREVIEW_CHARS ?? "3000", 10);

const LOG_TO_BLOBS = (process.env.LOG_TO_BLOBS ?? "false").toLowerCase() === "true";
const LOG_STORE = LOG_TO_BLOBS ? getStore({ name: process.env.BLOB_STORE_NAME || "logs" }) : null;
const STORE = getStore({ name: process.env.PREVIEW_STORE_NAME || "previews" });

/* ─── utils ─── */
function timingSafeEq(a,b){const ab=Buffer.from(a),bb=Buffer.from(b);if(ab.length!==bb.length)return false;return crypto.timingSafeEqual(ab,bb);}
function verifySlackSignature({rawBody,timestamp,slackSig}){if(!SIGNING_SECRET||!slackSig||!timestamp)return false;const base=`v0:${timestamp}:${rawBody}`;const h=crypto.createHmac("sha256",SIGNING_SECRET);h.update(base);return timingSafeEq(`v0=${h.digest("hex")}`,slackSig);}
async function slackApi(path,payload){const r=await fetch(`https://slack.com/api/${path}`,{method:"POST",headers:{Authorization:`Bearer ${BOT_TOKEN}`,"Content-Type":"application/json; charset=utf-8"},body:JSON.stringify(payload)});return r.json();}
async function postMessage({channel,text,thread_ts,blocks}){return slackApi("chat.postMessage",{channel,text,thread_ts,blocks});}
async function viewsOpen({trigger_id,view}){return slackApi("views.open",{trigger_id,view});}
async function conversationsOpen(userId){return slackApi("conversations.open",{users:userId});}
async function filesInfoRaw(file){const r=await fetch(`https://slack.com/api/files.info?file=${encodeURIComponent(file)}`,{headers:{Authorization:`Bearer ${BOT_TOKEN}`}});return r.json();}
async function downloadPrivate(url){const r=await fetch(url,{headers:{Authorization:`Bearer ${BOT_TOKEN}`}});if(!r.ok)throw new Error(`download failed: ${r.status}`);return Buffer.from(await r.arrayBuffer());}
async function blobLog(kind,data){if(!LOG_TO_BLOBS||!LOG_STORE)return;try{await LOG_STORE.set(`${kind}/${Date.now()}`,typeof data==="string"?data:JSON.stringify(data));}catch{}}

/* ─── parsing ─── */
function normalizeText(t){const s=(t??"").replace(/\r\n/g,"\n").replace(/\t/g,"  ").trim();return s.length<=MAX_PREVIEW_CHARS?s:s.slice(0,MAX_PREVIEW_CHARS)+"\n…(truncated)";}
function firstLine(t){const l=(t??"").split("\n").find(s=>s.trim())??"";return l.length>120?l.slice(0,120)+" …":l||"(no content)";}
async function parseEML(buf){const mail=await simpleParser(buf);let body="";if(mail.html)body=htmlToText(mail.html,{wordwrap:false});else if(mail.text)body=mail.text;const heads=[`From: ${mail.from?.text??""}`,`To: ${mail.to?.text??""}`,mail.cc?`Cc: ${mail.cc.text}`:null,`Date: ${mail.date??""}`,`Subject: ${mail.subject??""}`].filter(Boolean);return `# ${mail.subject??""}\n${heads.join("\n")}\n\n${body??""}`;}
function toUint8(buf){if(buf instanceof Uint8Array && !(buf instanceof Buffer))return buf;return new Uint8Array(buf.buffer,buf.byteOffset??0,buf.byteLength);}
function tightAB(u8){return u8.buffer.slice(u8.byteOffset,u8.byteOffset+u8.byteLength);}
async function getMSGReaderCtor(){const mod=await import("@kenjiuno/msgreader");const C=[mod.MSGReader,mod.default,mod.MsgReader].find(v=>typeof v==="function");if(!C)throw new Error("MSGReader constructor not found");return C;}
async function parseMSGorOFT(buf){const MSGReader=await getMSGReaderCtor();const u8=toUint8(buf);let info;try{info=new MSGReader(tightAB(u8)).getFileData();}catch(e1){try{info=new MSGReader(u8).getFileData();}catch(e2){await blobLog("errors/msgreader",{e1:String(e1),e2:String(e2)});throw new Error("failed to construct MSGReader");}}const html=info.bodyHTML??info.messageComps?.htmlBody??null;const rtf=info.bodyRTF??info.messageComps?.rtfBody??null;const text=info.body??info.messageComps?.plainText??null;let body="";if(html)body=htmlToText(html,{wordwrap:false});else if(text)body=text;else if(rtf)body=rtf.replace(/\\[a-z]+\d* ?|[{}]/gi," ").replace(/\s+/g," ").trim();const heads=[`From: ${info.senderName||info.senderEmail||""}`,`To: ${Array.isArray(info.recipients)?info.recipients.map(r=>r.name||r.email).join(", "):""}`,info.cc?`Cc: ${info.cc}`:null,`Date: ${info.messageDeliveryTime||info.creationTime||""}`,`Subject: ${info.subject||""}`].filter(Boolean);return `# ${info.subject||""}\n${heads.join("\n")}\n\n${body||""}`;}
function isSupported(name=""){const n=name.toLowerCase();return n.endsWith(".eml")||n.endsWith(".msg")||n.endsWith(".oft");}

/* ─── UI ─── */
function blocksPreview(filename,preview,payload){return[{type:"section",text:{type:"mrkdwn",text:`🧾 解析結果（${filename}）\n\`\`\`\n${preview}\n\`\`\``}},{type:"actions",elements:[{type:"button",text:{type:"plain_text",text:"全文を見る（モーダル）"},action_id:"open_modal",value:payload}]}];}
function chunk(s,n){const a=[];for(let i=0;i<s.length;i+=n)a.push(s.slice(i,i+n));return a;}
function buildModalView(filename,body,meta){const title=(filename||"解析結果").slice(0,24);const blocks=(chunk(body,2900).map(c=>({type:"section",text:{type:"mrkdwn",text:"```\n"+c+"\n```"}})));if(blocks.length===0)blocks.push({type:"section",text:{type:"mrkdwn",text:"（内容なし）"}});blocks.push({type:"actions",elements:[{type:"button",action_id:"send_copy_dm",text:{type:"plain_text",text:"📋 自分に送る（コピー用）"}}]});return{type:"modal",title:{type:"plain_text",text:title},close:{type:"plain_text",text:"閉じる"},private_metadata:JSON.stringify(meta||{}),blocks};}

/* ─── files.info を shares 出るまで待つ ─── */
async function fetchFileWithShares(fileId,maxTries=5,delayMs=1000){
  for(let i=1;i<=maxTries;i++){
    const info=await filesInfoRaw(fileId);
    if(!info.ok) throw new Error(`files.info failed: ${JSON.stringify(info)}`);
    const f=info.file;
    const shares=f?.shares;
    const channelsArr = f?.channels || []; // 旧APIの簡易配列
    if (shares?.private || shares?.public || (Array.isArray(channelsArr) && channelsArr.length>0)) {
      return f;
    }
    await new Promise(r=>setTimeout(r,delayMs));
  }
  const last=await filesInfoRaw(fileId); // 最後に返す
  if(!last.ok) throw new Error(`files.info failed: ${JSON.stringify(last)}`);
  return last.file;
}
function resolveFromShares(file){
  const shares=file?.shares||{};
  for(const area of ["private","public"]){
    const m=shares[area]; if(!m) continue;
    for(const [cid,posts] of Object.entries(m)){
      if(Array.isArray(posts)&&posts.length){
        const p=posts[0]; const ts=p.thread_ts||p.ts;
        if(cid) return {channel:cid, thread_ts: ts||undefined};
      }
    }
  }
  // 古い構造（channels 配列）だけでも拾う
  if (Array.isArray(file?.channels) && file.channels.length>0) {
    return { channel: file.channels[0], thread_ts: undefined };
  }
  return {channel:null, thread_ts:null};
}

/* ─── core ─── */
async function processFile({fileId, channelHint, threadHint}){
  await blobLog("events/seen",{fileId,channelHint,threadHint});
  const lock=`lock:${fileId}`; if(await STORE.get(lock)) return; await STORE.set(lock,Date.now().toString());
  try{
    if(await STORE.get(`done:${fileId}`)) return;

    // file_shared の場合は共有情報が載るまで待つ
    const f = await fetchFileWithShares(fileId, 5, 1000);

    let channel = channelHint;
    let thread_ts = threadHint;
    if(!channel || !thread_ts){
      const fromShares = resolveFromShares(f);
      channel = channel || fromShares.channel;
      thread_ts = thread_ts || fromShares.thread_ts;
    }
    if(!channel){
      await blobLog("errors/no-channel",{fileId});
      return; // どこにも出せない
    }

    if(!isSupported(f.name)){
      await postMessage({channel,thread_ts,text:`⚠️ 未対応の拡張子です: \`${f.name}\`（.eml/.msg/.oft）`});
      await STORE.set(`done:${fileId}`,"1");
      return;
    }

    const url=f.url_private_download||f.url_private;
    if(!url) throw new Error("no url_private_download");
    const buf=await downloadPrivate(url);

    let parsed="";
    try{
      parsed = f.name.toLowerCase().endsWith(".eml") ? await parseEML(buf) : await parseMSGorOFT(buf);
    }catch(e){
      await blobLog("errors/parse",{name:f.name,e:String(e)});
      throw new Error("parse failed");
    }

    const body=normalizeText(parsed);
    const key=`p:${Date.now()}:${fileId}`;
    await STORE.set(key,body);

    const preview=firstLine(body);
    await postMessage({
      channel,
      thread_ts, // 取れない場合は undefined → トップレベル投稿
      text:"解析結果（プレビュー）",
      blocks:blocksPreview(f.name,preview,JSON.stringify({key,filename:f.name}))
    });

    await STORE.set(`done:${fileId}`,"1");
  }finally{
    await STORE.set(lock,"done");
  }
}

/* ─── interactivity ─── */
async function handleBlockActions(payload){
  const action=payload?.actions?.[0];
  if(!action) return new Response("",{status:200});

  if(action.action_id==="open_modal"){
    const trigger_id=payload.trigger_id;
    const val=action.value?JSON.parse(action.value):null;
    const key=val?.key, filename=val?.filename||"解析結果";
    if(!trigger_id||!key) return new Response("",{status:200});
    const body=(await STORE.get(key))??"(content expired)";
    await viewsOpen({trigger_id,view:buildModalView(filename,body,{key,filename})});
    return new Response("",{status:200});
  }

  if(action.action_id==="send_copy_dm"){
    const userId=payload.user?.id;
    const meta=payload.view?.private_metadata?JSON.parse(payload.view.private_metadata):{};
    const key=meta.key, filename=meta.filename||"解析結果";
    if(!userId||!key) return new Response("",{status:200});
    const content=(await STORE.get(key))??"(content expired)";
    const opened=await conversationsOpen(userId);
    if(opened?.ok&&opened?.channel?.id){
      await postMessage({channel:opened.channel.id,text:`🧾 解析結果（${filename}）\n\`\`\`\n${content}\n\`\`\``});
    }else{
      await blobLog("errors/open-dm-failed",opened||{});
    }
    return new Response("",{status:200});
  }

  return new Response("",{status:200});
}

/* ─── entry ─── */
export default async function handler(req){
  const raw=await req.text();
  const ts=req.headers.get("x-slack-request-timestamp");
  const sig=req.headers.get("x-slack-signature");
  const ctype=req.headers.get("content-type")||"";

  if(req.headers.get("x-slack-retry-num")){
    return new Response("",{status:200,headers:{"X-Slack-No-Retry":"1"}});
  }
  if(!verifySlackSignature({rawBody:raw,timestamp:ts,slackSig:sig})){
    await blobLog("errors/sign",{ts,note:"invalid-signature"}); 
    return new Response("invalid signature",{status:401});
  }

  if(ctype.includes("application/x-www-form-urlencoded")){
    const m=/^payload=(.*)$/.exec(raw); if(!m) return new Response("",{status:200});
    const payload=JSON.parse(decodeURIComponent(m[1]));
    return handleBlockActions(payload);
  }

  let payload; try{payload=JSON.parse(raw);}catch{await blobLog("errors/json-parse",raw.slice(0,800)); return new Response("bad request",{status:400});}

  await blobLog("events/heads",{type:payload.type,etype:payload.event?.type,subtype:payload.event?.subtype,file_id:payload.event?.file_id||payload.event?.files?.[0]?.id||null});

  if(payload.type==="url_verification"){
    return new Response(payload.challenge,{headers:{"Content-Type":"text/plain"}});
  }

  if(payload.type==="event_callback"){
    const ev=payload.event;

    if(ev.type==="app_mention" && /diag/i.test(ev.text??"")){
      if(ev.channel) await postMessage({channel:ev.channel,thread_ts:ev.ts,text:"diag: ok ✅"});
      return new Response("",{status:200});
    }

    // ✅ message イベント：subtype 無しでも files があれば処理
    if(ev.type==="message" && Array.isArray(ev.files) && ev.files.length>0){
      const fileId=ev.files[0]?.id;
      if(fileId) await processFile({fileId,channelHint:ev.channel,threadHint:ev.ts});
      return new Response("",{status:200});
    }

    // ✅ 従来の file_share / file_shared も拾う
    if(ev.type==="message" && ev.subtype==="file_share"){
      const fileId=ev.files?.[0]?.id;
      if(fileId) await processFile({fileId,channelHint:ev.channel,threadHint:ev.ts});
      return new Response("",{status:200});
    }
    if(ev.type==="file_shared"){
      const fileId=ev.file_id;
      if(fileId) await processFile({fileId});
      return new Response("",{status:200});
    }
  }

  return new Response("",{status:200});
}
