// Slack events handler for EML/MSG preview bot
//
// This function receives Slack Events API payloads via the Netlify
// Functions runtime.  It performs several critical tasks:
//   • Verifies requests using your Slack signing secret to prevent
//     forgery or replay attacks.
//   • Detects file uploads and retrieves the corresponding .eml or
//     .msg file using the files.info API.  The file is downloaded
//     privately using the bot token’s authorization header.
//   • Parses email content with mailparser (for .eml) or msgreader
//     (for .msg) and converts HTML bodies to plain text via
//     html-to-text.
//   • Posts the extracted text back into the same Slack thread using
//     chat.postMessage.  Long messages are truncated to
//     `MAX_PREVIEW_CHARS` characters (defaults to 3000) with a tail
//     notice.
//   • Optionally logs all events and errors to a Netlify Blobs store
//     when the LOG_TO_BLOBS environment variable is set to "true".
//
// IMPORTANT: This implementation does not use Slack’s deprecated
// files.upload API.  Instead it posts the preview as a normal
// message.  If you need to upload files, follow the migration path
// described by Slack: use files.getUploadURLExternal and
// files.completeUploadExternal.

import crypto from 'crypto';
import { simpleParser } from 'mailparser';
import { MSGReader } from 'msgreader';
import { htmlToText } from 'html-to-text';
import { getStore } from '@netlify/blobs';

// Read environment variables once at module scope.  If
// MAX_PREVIEW_CHARS or MAX_FILE_SIZE aren’t defined, fall back to
// sane defaults.  MAX_FILE_SIZE is in bytes and limits the size of
// email attachments downloaded from Slack (10 MB by default).  You
// should adjust MAX_FILE_SIZE to control execution time and memory
// usage of your function.
const {
  SLACK_BOT_TOKEN,
  SLACK_SIGNING_SECRET,
  TARGET_CHANNELS,
  LOG_TO_BLOBS,
  BLOB_STORE_NAME,
  MAX_PREVIEW_CHARS,
  MAX_FILE_SIZE
} = process.env;

const PREVIEW_LIMIT = parseInt(MAX_PREVIEW_CHARS, 10) || 3000;
const FILE_SIZE_LIMIT = parseInt(MAX_FILE_SIZE, 10) || 10 * 1024 * 1024; // 10 MB

// Helper: verify Slack request signature.  Slack sends a timestamp and
// signature header with every Events API request.  We reject
// requests if the timestamp is older than ±5 minutes or the HMAC
// doesn’t match.  See Slack documentation for details:
// https://api.slack.com/authentication/verifying-requests-from-slack
function verifySlackSignature({ rawBody, timestamp, signature }) {
  if (!timestamp || !signature) return false;
  // Protect against replay attacks by checking the timestamp is
  // within ±5 minutes of the current time.  Use 300 seconds (5
  // minutes) as a safe window.  Slack recommends rejecting requests
  // outside this window.
  const fiveMinutes = 60 * 5;
  const now = Math.floor(Date.now() / 1000);
  const ts = parseInt(timestamp, 10);
  if (Number.isNaN(ts) || Math.abs(now - ts) > fiveMinutes) {
    return false;
  }
  // Create the basestring: `v0:${timestamp}:${rawBody}` and HMAC it
  // using your signing secret.
  const basestring = `v0:${timestamp}:${rawBody}`;
  const hmac = crypto.createHmac('sha256', SLACK_SIGNING_SECRET || '');
  hmac.update(basestring);
  const digest = `v0=${hmac.digest('hex')}`;
  // Use timingSafeEqual to avoid timing attacks.
  const sigBuf = Buffer.from(signature, 'utf8');
  const digestBuf = Buffer.from(digest, 'utf8');
  if (sigBuf.length !== digestBuf.length) return false;
  return crypto.timingSafeEqual(sigBuf, digestBuf);
}

// Helper: save logs to Netlify Blobs if enabled.  Each log entry is
// stored under a key based on the current date and a random UUID.
async function logEvent(keySuffix, data) {
  if (!LOG_TO_BLOBS || LOG_TO_BLOBS.toLowerCase() !== 'true') return;
  try {
    const storeName = BLOB_STORE_NAME || 'logs';
    const store = getStore(storeName);
    const key = `${new Date().toISOString()}-${keySuffix}.json`;
    await store.setJSON(key, data);
  } catch (err) {
    // Swallow logging errors so they don’t affect primary flow.
    console.error('Failed to write log', err);
  }
}

// Helper: parse an email file.  Accepts a Buffer containing the
// attachment and a filename to determine the parser.  Returns a
// string with plain text content.  Throws if parsing fails or if
// the file extension is not supported.
async function parseEmail(buffer, filename) {
  const lower = filename.toLowerCase();
  if (lower.endsWith('.eml')) {
    // Use mailparser to parse .eml files.  The returned object may
    // have .text and .html fields.  Prefer text when available; fall
    // back to converting HTML to plain text.
    const parsed = await simpleParser(buffer);
    if (parsed.text?.trim()) return parsed.text;
    if (parsed.html) {
      return htmlToText(parsed.html, { wordwrap: false });
    }
    return '';
  } else if (lower.endsWith('.msg')) {
    // Use msgreader for .msg files (Outlook format).  The getFileData
    // method returns an object with body and bodyHTML properties.
    const reader = new MSGReader(buffer);
    const data = reader.getFileData();
    if (data.body?.trim()) return data.body;
    if (data.bodyHTML) {
      return htmlToText(data.bodyHTML, { wordwrap: false });
    }
    return '';
  }
  throw new Error(`Unsupported file type: ${filename}`);
}

// Helper: determine thread timestamp and channel from a file object.
// Slack’s files.info response contains a `shares` object keyed by
// public and private channels.  Each entry includes the timestamp
// (ts) where the file was posted.  We return the first channel and
// its ts.  If no shares exist, fall back to TARGET_CHANNELS or
// null.
function extractShareInfo(file) {
  let channel = null;
  let threadTs = null;
  if (file.shares) {
    // public channels
    if (file.shares.public) {
      for (const [chan, shares] of Object.entries(file.shares.public)) {
        channel = chan;
        if (shares && shares.length > 0) {
          threadTs = shares[0].ts;
        }
        break;
      }
    }
    // private channels or groups if not found in public
    if (!channel && file.shares.private) {
      for (const [chan, shares] of Object.entries(file.shares.private)) {
        channel = chan;
        if (shares && shares.length > 0) {
          threadTs = shares[0].ts;
        }
        break;
      }
    }
  }
  // If no share information is available, use the optional
  // TARGET_CHANNELS environment variable (comma separated list).  Use
  // the first channel in that list as the default.  Without a
  // channel the message cannot be posted.
  if (!channel && TARGET_CHANNELS) {
    const channels = TARGET_CHANNELS.split(',').map((c) => c.trim()).filter(Boolean);
    if (channels.length > 0) channel = channels[0];
  }
  return { channel, threadTs };
}

// Helper: post a message back to Slack.  Accepts a channel, text and
// optional thread_ts.  Returns the response JSON from Slack.  If
// Slack returns an error, throws.
async function postMessage(channel, text, threadTs) {
  const payload = {
    channel,
    text,
    mrkdwn: true
  };
  if (threadTs) {
    payload.thread_ts = threadTs;
  }
  const res = await fetch('https://slack.com/api/chat.postMessage', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      Authorization: `Bearer ${SLACK_BOT_TOKEN}`
    },
    body: JSON.stringify(payload)
  });
  const json = await res.json();
  if (!json.ok) {
    throw new Error(`Slack API error: ${json.error || 'unknown'}`);
  }
  return json;
}

// Main handler entry point for Netlify functions.  Note that Netlify
// runs your function whenever Slack sends an event.  The function
// must return a Response object.  Slack enforces a 3 second
// response window; heavy work should complete quickly or Slack will
// retry.
export default async (req, context) => {
  try {
    // Extract raw body.  Netlify’s req.text() returns the body as a
    // string.  Preserve the raw body for signature verification.
    const rawBody = await req.text();
    const headers = req.headers;
    const slackTimestamp = headers.get('x-slack-request-timestamp');
    const slackSignature = headers.get('x-slack-signature');
    // Verify Slack signature.  If verification fails, return 401.
    const isValid = verifySlackSignature({ rawBody, timestamp: slackTimestamp, signature: slackSignature });
    if (!isValid) {
      return new Response('Unauthorized', { status: 401 });
    }
    // Parse the JSON payload.  Slack sends JSON encoded events.
    const body = JSON.parse(rawBody);
    // Slack URL verification challenge (during initial setup).  Echo
    // back the challenge to confirm the endpoint.
    if (body.type === 'url_verification' && body.challenge) {
      return new Response(body.challenge, { status: 200 });
    }
    // If this is a test ping message (message event with text "ping")
    // then respond with "pong" in the same channel.  This is
    // convenient for smoke testing the function without uploading
    // files.
    if (body?.event?.type === 'message' && typeof body.event.text === 'string' && body.event.text.trim().toLowerCase() === 'ping') {
      const channel = body.event.channel;
      try {
        await postMessage(channel, 'pong', body.event.thread_ts);
      } catch (err) {
        await logEvent('error', { error: err.message, event: body });
      }
      return new Response('OK', { status: 200 });
    }
    // We’re only interested in file_shared events.  Ignore other
    // events to minimize unnecessary processing.
    if (body?.event?.type !== 'file_shared') {
      return new Response('ignored', { status: 200 });
    }
    const eventId = body.event_id || '';
    // Deduplicate using event_id.  If Netlify Blobs logging is
    // enabled, we’ll store a marker for each processed event.  If we
    // see the same event again (due to Slack retries) we exit early.
    if (LOG_TO_BLOBS && LOG_TO_BLOBS.toLowerCase() === 'true') {
      try {
        const store = getStore(BLOB_STORE_NAME || 'logs');
        const existing = await store.get(`event-${eventId}`);
        if (existing) {
          return new Response('duplicate', { status: 200 });
        }
        await store.setJSON(`event-${eventId}`, { processedAt: new Date().toISOString() });
      } catch (err) {
        // Logging failure shouldn’t block processing.  Continue.
        console.error('Failed to check/set dedupe key', err);
      }
    }
    // Fetch file information.  The file ID is provided in the event.
    const fileId = body.event.file_id || body.event.file?.id;
    if (!fileId) {
      // Without a file ID we can’t proceed.  Log and return.
      await logEvent('missing-file-id', { event: body });
      return new Response('No file ID', { status: 200 });
    }
    // Call files.info to get details about the file, including its
    // download URL.  The file may not be immediately available; if
    // Slack returns error we log and exit.
    const infoRes = await fetch(`https://slack.com/api/files.info?file=${encodeURIComponent(fileId)}`, {
      headers: { Authorization: `Bearer ${SLACK_BOT_TOKEN}` }
    });
    const infoJson = await infoRes.json();
    if (!infoJson.ok) {
      await logEvent('files-info-error', { error: infoJson.error, fileId });
      return new Response('files.info error', { status: 200 });
    }
    const file = infoJson.file;
    if (!file || !file.name) {
      await logEvent('file-missing', { file });
      return new Response('File missing', { status: 200 });
    }
    // Enforce file size limit.  Prevent very large files from being
    // downloaded and parsed, which could exhaust memory or slow
    // responses beyond Slack’s timeout window.
    if (file.size && file.size > FILE_SIZE_LIMIT) {
      const { channel, threadTs } = extractShareInfo(file);
      const notice = `ファイルサイズが大きすぎるためプレビューできません（${(file.size / 1024 / 1024).toFixed(2)} MB）。元のファイルを参照してください。`;
      if (channel) {
        await postMessage(channel, notice, threadTs);
      }
      await logEvent('size-limit', { fileId, size: file.size });
      return new Response('File too large', { status: 200 });
    }
    // Determine the channel and thread for reply.  If the file
    // hasn’t been shared to a channel and no TARGET_CHANNELS is set,
    // bail out gracefully.
    const { channel, threadTs } = extractShareInfo(file);
    if (!channel) {
      await logEvent('no-channel', { file });
      return new Response('No channel', { status: 200 });
    }
    // Download the attachment using the private download URL.  Use the
    // bot token for authorization.  We request as an ArrayBuffer to
    // convert it into a Buffer.
    const downloadRes = await fetch(file.url_private_download, {
      headers: { Authorization: `Bearer ${SLACK_BOT_TOKEN}` }
    });
    if (!downloadRes.ok) {
      await logEvent('download-error', { status: downloadRes.status, statusText: downloadRes.statusText, fileId });
      return new Response('Download failed', { status: 200 });
    }
    const arrayBuffer = await downloadRes.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);
    // Parse the email content.  If parsing fails, catch and
    // inform the user.
    let emailText;
    try {
      emailText = await parseEmail(buffer, file.name);
    } catch (err) {
      const errorMsg = `ファイルの解析に失敗しました: ${err.message}`;
      await postMessage(channel, errorMsg, threadTs);
      await logEvent('parse-error', { error: err.message, file: file.name });
      return new Response('Parse error', { status: 200 });
    }
    if (!emailText || emailText.trim().length === 0) {
      const errorMsg = '本文が見つかりませんでした。元のファイルを参照してください。';
      await postMessage(channel, errorMsg, threadTs);
      await logEvent('empty-content', { file: file.name });
      return new Response('Empty content', { status: 200 });
    }
    // Truncate long previews.  Slack code blocks have a maximum
    // message length; additionally large messages impact display.
    let preview = emailText;
    if (preview.length > PREVIEW_LIMIT) {
      preview = `${preview.slice(0, PREVIEW_LIMIT)}\n\n…（続きは元のファイルを参照してください）`;
    }
    // Wrap the preview in triple backticks to preserve formatting.  Use
    // a code block rather than inline code to make multiline content
    // readable.  Slack respects backtick fences inside messages.
    const messageText = `\`\`\`\n${preview}\n\`\`\``;
    await postMessage(channel, messageText, threadTs);
    await logEvent('success', { file: file.name, channel, threadTs });
    // Return OK so Slack doesn’t retry.  Note that all asynchronous
    // operations above run within this single invocation; Netlify
    // does not currently support background tasks in synchronous
    // functions.  If Slack retries due to timeouts, our dedupe
    // mechanism prevents duplicate replies.
    return new Response('OK', { status: 200 });
  } catch (err) {
    // Catch-all error handler.  Log the error and respond with 500.
    await logEvent('unhandled-exception', { error: err.message, stack: err.stack });
    return new Response('Internal error', { status: 500 });
  }
};
