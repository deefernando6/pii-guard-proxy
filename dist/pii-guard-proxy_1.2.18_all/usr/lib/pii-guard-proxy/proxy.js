#!/usr/bin/env node
'use strict';

const http = require('http');
const https = require('https');
const tls = require('tls');
const net = require('net');
const { detectPII } = require('./lib/detector');
const { placeholderFor } = require('./lib/anonymizer');
const { promptUser } = require('./prompt');
const { ensureCa, getSecureContext, getCaCertPath } = require('./lib/cert-manager');
const { findParser, isLLMHost, hasSpecificParser, walkJsonStrings } = require('./lib/web-parsers');
const { recordWebAnonymization, getCurrentTurn, maskOriginal, injectSidebar } = require('./lib/web-injector');

const PORT = parseInt(process.env.PII_GUARD_PORT || '8765', 10);
const UPSTREAM_HOST = process.env.PII_GUARD_UPSTREAM || 'api.anthropic.com';
const REVEAL_IN_RESPONSE =
  (process.env.PII_GUARD_REVEAL || 'true').toLowerCase() !== 'false';
const ENABLE_MITM =
  (process.env.PII_GUARD_MITM || 'true').toLowerCase() !== 'false';

let promptChain = Promise.resolve();
function serializePrompt(fn) {
  const p = promptChain.then(fn, fn);
  promptChain = p.catch(() => {});
  return p;
}

// ──────────────────────────────────────────────────────────────────────
// Session-persistent placeholder map. Same value always gets the same
// placeholder for the lifetime of the proxy process, across all requests
// and all messages in the conversation history.
// ──────────────────────────────────────────────────────────────────────
const persistentMap = new Map(); // `${type}\0${value}` -> { placeholder, type, label, original }
const counters = {};             // type -> next index

function getOrCreate(type, value, label) {
  const key = `${type}\0${value}`;
  if (persistentMap.has(key)) {
    return { entry: persistentMap.get(key), isNew: false };
  }
  counters[type] = (counters[type] || 0) + 1;
  const entry = {
    placeholder: placeholderFor(type, counters[type]),
    type, label, original: value,
  };
  persistentMap.set(key, entry);
  return { entry, isNew: true };
}

function rollbackEntries(entries) {
  for (const e of entries) {
    persistentMap.delete(`${e.type}\0${e.original}`);
  }
}

// Identify every persistent-map entry whose placeholder is present in
// the rewritten body but not in the original. Used to feed the in-page
// sidebar both the brand-new mappings AND the reused ones from earlier
// turns — the user cares about the full set that was applied this
// request, not only the new detections.
function collectAppliedEntries(originalBody, rewrittenBody, allKnown) {
  if (!rewrittenBody || !allKnown || allKnown.length === 0) return [];
  const applied = [];
  for (const e of allKnown) {
    if (!e.placeholder) continue;
    if (rewrittenBody.includes(e.placeholder) && (!originalBody || !originalBody.includes(e.placeholder))) {
      applied.push(e);
    }
  }
  return applied;
}

// Replace PII in a single text block using the persistent map.
function anonymizeText(text) {
  if (!text || typeof text !== 'string') {
    return { text, substitutions: 0, newEntries: [] };
  }
  const detections = detectPII(text);
  if (detections.length === 0) {
    return { text, substitutions: 0, newEntries: [] };
  }
  const sorted = [...detections].sort((a, b) => a.start - b.start);
  const newEntries = [];
  let out = '';
  let cursor = 0;
  let substitutions = 0;
  for (const d of sorted) {
    if (d.start < cursor) continue;
    out += text.slice(cursor, d.start);
    const { entry, isNew } = getOrCreate(d.type, d.value, d.label);
    if (isNew) newEntries.push(entry);
    out += entry.placeholder;
    cursor = d.end;
    substitutions++;
  }
  out += text.slice(cursor);
  return { text: out, substitutions, newEntries };
}

// Walk every message in /v1/messages and anonymize text content in place.
// Returns aggregate stats so we know whether to forward, prompt, or pass through.
function anonymizeAllMessages(parsed) {
  let substitutions = 0;
  const newEntries = [];
  const newInLastUser = [];

  if (!parsed || !Array.isArray(parsed.messages)) {
    return { substitutions, newEntries, newInLastUser };
  }

  const lastIdx = parsed.messages.length - 1;
  for (let i = 0; i < parsed.messages.length; i++) {
    const msg = parsed.messages[i];
    if (!msg) continue;
    const isLastUser = i === lastIdx && msg.role === 'user';

    if (typeof msg.content === 'string') {
      const r = anonymizeText(msg.content);
      if (r.substitutions > 0) {
        msg.content = r.text;
        substitutions += r.substitutions;
        newEntries.push(...r.newEntries);
        if (isLastUser) newInLastUser.push(...r.newEntries);
      }
    } else if (Array.isArray(msg.content)) {
      for (const item of msg.content) {
        if (item && item.type === 'text' && typeof item.text === 'string') {
          const r = anonymizeText(item.text);
          if (r.substitutions > 0) {
            item.text = r.text;
            substitutions += r.substitutions;
            newEntries.push(...r.newEntries);
            if (isLastUser) newInLastUser.push(...r.newEntries);
          }
        }
      }
    }
  }
  return { substitutions, newEntries, newInLastUser };
}

// ──────────────────────────────────────────────────────────────────────
// Anthropic /v1/messages helpers
// ──────────────────────────────────────────────────────────────────────

function extractTextFromContent(content) {
  if (typeof content === 'string') return content;
  if (!Array.isArray(content)) return '';
  const parts = [];
  for (const item of content) {
    if (typeof item === 'string') parts.push(item);
    else if (item && item.type === 'text' && typeof item.text === 'string') parts.push(item.text);
  }
  return parts.join('\n');
}

// ──────────────────────────────────────────────────────────────────────
// Streaming response: replace placeholders with originals on the way back
// so the user sees real values even though the model only saw placeholders.
// ──────────────────────────────────────────────────────────────────────

function jsonEscapeForStringValue(s) {
  // Strip surrounding quotes — leaves \"-escaped, \n-escaped string body.
  return JSON.stringify(s).slice(1, -1);
}

// Build a regex that matches the placeholder regardless of how its `[`,
// `]`, and `_` chars were encoded. For each special char we accept:
//   * the literal char preceded by 0–8 backslashes (plain, Markdown
//     `\[`/`\_`/`\]`, JSON `\\[`, etc., up to deeply-nested encodings)
//   * a JSON Unicode escape: `[` `]` `_` (any case)
//   * an HTML numeric entity: `&#91;` `&#93;` `&#95;`
//   * an HTML named entity: `&lbrack;` `&rbrack;` `&lowbar;`
// Type letters and digits stay literal — collisions with non-placeholders
// are vanishingly unlikely given the type-name + digit shape.
function buildFlexibleRegex(placeholder) {
  let pattern = '';
  for (const ch of placeholder) {
    if (ch === '[' || ch === ']' || ch === '_') {
      const code = ch.charCodeAt(0).toString(16);
      const named = ch === '[' ? 'lbrack' : ch === ']' ? 'rbrack' : 'lowbar';
      const ent = ch === '[' ? '91' : ch === ']' ? '93' : '95';
      pattern += '(?:\\\\{0,8}\\' + ch
              + '|\\\\u00' + code + '|\\\\u00' + code.toUpperCase()
              + '|&#' + ent + ';|&' + named + ';)';
    } else {
      pattern += ch;
    }
  }
  return new RegExp(pattern, 'g');
}

// Catch-all for placeholder-shaped strings we don't have a specific
// regex for (defensive — never used to authoritatively replace, only
// to detect leftovers for logging). Up to 8 backslashes anywhere.
const PLACEHOLDER_CATCHALL = /\\{0,8}\[[A-Z][A-Z_]*\\{0,8}_\d+\\{0,8}\]/g;

function buildPlaceholderReplacer(_mapping) {
  // Mapping arg ignored — we query live `persistentMap` at replace time
  // so concurrent requests' placeholders are visible.
  return function replace(text, escapeForJson) {
    // Cache compiled flex-regexes per placeholder for the lifetime of
    // this replace() call (rebuild table each call from live map).
    const entries = [...persistentMap.values()];
    let out = text;

    for (const e of entries) {
      const re = buildFlexibleRegex(e.placeholder);
      const replacement = escapeForJson ? jsonEscapeForStringValue(e.original) : e.original;
      out = out.replace(re, () => replacement);
    }

    // Diagnostic: log any leftover placeholder shapes so we can target
    // unknown variants in future fixes. ON by default — set
    // PII_GUARD_VERBOSE=quiet to silence.
    if (String(process.env.PII_GUARD_VERBOSE || '').toLowerCase() !== 'quiet') {
      const leftover = out.match(PLACEHOLDER_CATCHALL);
      if (leftover && leftover.length) {
        const lookup = Object.create(null);
        for (const e of entries) lookup[e.placeholder] = true;
        const u = [...new Set(leftover.map(s => s.replace(/\\/g, '')))];
        const known = u.filter(s => s in lookup);
        const unknown = u.filter(s => !(s in lookup));
        if (known.length) {
          // Capture a small surrounding-context sample of the FIRST stuck
          // placeholder so we can see the actual byte form in the log.
          const stuck = leftover.find(m => m.replace(/\\/g, '') in lookup);
          if (stuck) {
            const idx = out.indexOf(stuck);
            const sample = out.slice(Math.max(0, idx - 40), idx + stuck.length + 40);
            console.error(`[PII Guard] KNOWN-but-stuck: ${known.join(', ')}`);
            console.error(`[PII Guard]   raw bytes around it: ${JSON.stringify(sample)}`);
          }
        }
        if (unknown.length) {
          console.error(`[PII Guard] LLM emitted unknown placeholder: ${unknown.join(', ')}`);
        }
      }
    }

    return out;
  };
}

function streamWithReplacement(upstreamRes, clientRes, mapping) {
  const replace = buildPlaceholderReplacer(mapping);

  // Default: full-response buffering. We hold the whole response in
  // memory, run the replacer ONCE on the complete bytes, then ship it.
  // This eliminates the entire class of chunk-boundary bugs that earlier
  // streaming logic kept hitting (placeholders split across SSE events,
  // unexpected escape depths, the LLM tokenising `[`/`NAME`/`_`/`1`/`]`
  // as separate tokens, etc.). Trade-off: the user sees the full response
  // appear at once instead of streaming progressively.
  //
  // For long responses where progressive output matters more than
  // perfect revert, set PII_GUARD_STREAMING=true to fall back to the
  // chunk-aware streamer below.
  const STREAMING = String(process.env.PII_GUARD_STREAMING || '').toLowerCase() === 'true';

  if (!STREAMING) {
    const chunks = [];
    upstreamRes.on('data', (c) => chunks.push(c));
    upstreamRes.on('end', () => {
      try {
        const text = Buffer.concat(chunks).toString('utf8');

        // Heartbeat so we can confirm replace runs for every response.
        // Counts placeholder-shapes before vs after, and dumps a sample
        // of any KNOWN-but-stuck leftovers so the user can paste it.
        const beforeCount = (text.match(PLACEHOLDER_CATCHALL) || []).length;
        const replaced = replace(text, true);
        const afterCount = (replaced.match(PLACEHOLDER_CATCHALL) || []).length;

        if (String(process.env.PII_GUARD_VERBOSE || '').toLowerCase() !== 'quiet') {
          if (beforeCount > 0 || afterCount > 0) {
            console.error(`[PII Guard] replace: ${text.length}b, before=${beforeCount} placeholder-shapes, after=${afterCount}, mapSize=${persistentMap.size}`);
            if (afterCount > 0) {
              const stuckMatches = replaced.match(PLACEHOLDER_CATCHALL) || [];
              const lookup = Object.create(null);
              for (const e of persistentMap.values()) lookup[e.placeholder] = true;
              for (const stuck of [...new Set(stuckMatches)].slice(0, 3)) {
                const stripped = stuck.replace(/\\/g, '');
                const idx = replaced.indexOf(stuck);
                const sample = replaced.slice(Math.max(0, idx - 60), idx + stuck.length + 60);
                const status = stripped in lookup ? 'KNOWN' : 'unknown';
                console.error(`[PII Guard]   ${status}: ${JSON.stringify(stuck)}  context=${JSON.stringify(sample)}`);
              }
            }
          }
        }

        clientRes.write(replaced);
      } catch (e) {
        console.error('[PII Guard] Buffered-replace error:', e.message);
      }
      clientRes.end();
    });
    upstreamRes.on('error', (err) => {
      console.error('[PII Guard] Stream error:', err.message);
      clientRes.end();
    });
    return;
  }

  // ── Streaming mode (opt-in) ─────────────────────────────────────────
  // Match an in-progress placeholder at the buffer tail. Includes the
  // optional `_\d*` segment + trailing backslashes so chunks ending with
  // `[EMAIL\\\\_` aren't flushed prematurely.
  const PARTIAL_PLACEHOLDER = /(\\{0,4}\[[A-Z_]*(?:\\{0,4}_\d*)?\\{0,4})$/;
  let buffer = '';

  upstreamRes.on('data', (chunk) => {
    buffer += chunk.toString('utf8');
    let safeLen = buffer.length;
    const partial = buffer.match(PARTIAL_PLACEHOLDER);
    if (partial) {
      safeLen = buffer.length - partial[0].length;
      while (safeLen > 0 && buffer[safeLen - 1] === '\\') safeLen -= 1;
    }
    if (safeLen <= 0) return;
    const out = replace(buffer.slice(0, safeLen), true);
    buffer = buffer.slice(safeLen);
    clientRes.write(out);
  });

  upstreamRes.on('end', () => {
    if (buffer.length > 0) clientRes.write(replace(buffer, true));
    clientRes.end();
  });
  upstreamRes.on('error', (err) => {
    console.error('[PII Guard] Stream error:', err.message);
    clientRes.end();
  });
}

// ──────────────────────────────────────────────────────────────────────
// Forwarding to upstream (api.anthropic.com or any LLM domain after MITM)
// ──────────────────────────────────────────────────────────────────────

function forwardRequest(req, clientRes, body, mapping, overrideHost) {
  const upstreamHost = overrideHost || UPSTREAM_HOST;
  const headers = { ...req.headers };
  delete headers['content-length'];
  // Force uncompressed responses so we can scan/rewrite SSE bytes as UTF-8.
  delete headers['accept-encoding'];
  // Make sure the Host header matches the real upstream so the LLM
  // backend's TLS/HTTP routing accepts the request.
  headers.host = upstreamHost;
  if (body) headers['content-length'] = Buffer.byteLength(body);

  const isWebUI = !!overrideHost;

  const upstreamReq = https.request({
    host: upstreamHost,
    port: 443,
    method: req.method,
    path: req.url,
    headers,
    servername: upstreamHost,
  }, (upstreamRes) => {
    const willReplace = REVEAL_IN_RESPONSE && mapping && mapping.length > 0;
    const respHeaders = { ...upstreamRes.headers };

    // For MITM'd web-UI traffic: strip CSP so the inline sidebar script
    // we inject below is allowed to execute. Also drop COEP/COOP that
    // can break the fetch('/__pii-guard/recent') call.
    if (isWebUI) {
      delete respHeaders['content-security-policy'];
      delete respHeaders['content-security-policy-report-only'];
      delete respHeaders['cross-origin-embedder-policy'];
      delete respHeaders['cross-origin-opener-policy'];
    }

    const ctype = String(upstreamRes.headers['content-type'] || '').toLowerCase();
    const isHtml = isWebUI && ctype.startsWith('text/html');

    if (isHtml) {
      // Buffer the full HTML, splice in the sidebar (and run placeholder
      // revert if a mapping is set), then write it back. accept-encoding
      // was stripped on the way out so the upstream body is uncompressed.
      const buf = [];
      upstreamRes.on('data', c => buf.push(c));
      upstreamRes.on('end', () => {
        let html = Buffer.concat(buf).toString('utf8');
        if (willReplace) html = buildPlaceholderReplacer(mapping)(html, false);
        html = injectSidebar(html);
        delete respHeaders['content-length'];
        delete respHeaders['content-encoding'];
        respHeaders['content-length'] = Buffer.byteLength(html);
        clientRes.writeHead(upstreamRes.statusCode, respHeaders);
        clientRes.end(html);
      });
      upstreamRes.on('error', () => {
        if (!clientRes.headersSent) clientRes.writeHead(502);
        clientRes.end();
      });
      return;
    }

    if (willReplace) {
      // We're rewriting the body; discard length/encoding markers so the
      // client doesn't try to decompress or expect a fixed size.
      delete respHeaders['content-length'];
      delete respHeaders['content-encoding'];
    }
    clientRes.writeHead(upstreamRes.statusCode, respHeaders);
    if (willReplace) {
      streamWithReplacement(upstreamRes, clientRes, mapping);
    } else {
      upstreamRes.pipe(clientRes);
    }
  });

  upstreamReq.on('error', (err) => {
    console.error('[PII Guard] Upstream error:', err.message);
    if (!clientRes.headersSent) {
      clientRes.writeHead(502, { 'content-type': 'application/json' });
    }
    clientRes.end(JSON.stringify({
      type: 'error',
      error: { type: 'upstream_error', message: err.message },
    }));
  });

  if (body) upstreamReq.write(body);
  upstreamReq.end();
}

// ──────────────────────────────────────────────────────────────────────
// Main request handler
// ──────────────────────────────────────────────────────────────────────

// Forward-proxy path. When a browser (or any HTTPS_PROXY-respecting client)
// sends us a plain-HTTP request, the request line is an absolute URL like
// `GET http://example.com/path HTTP/1.1`. We must forward it to that URL,
// NOT to UPSTREAM_HOST. Without this, Chrome's connectivity probes
// (gen_204, ocsp.digicert.com, captive-portal checks) get routed to
// api.anthropic.com and fail, causing Chrome to declare "no internet".
function forwardAsProxy(req, clientRes, body) {
  let parsedUrl;
  try { parsedUrl = new URL(req.url); }
  catch (e) {
    if (!clientRes.headersSent) clientRes.writeHead(400);
    clientRes.end('Bad request URL');
    return;
  }
  const isHttps = parsedUrl.protocol === 'https:';
  const transport = isHttps ? https : http;
  const port = parsedUrl.port || (isHttps ? 443 : 80);
  const path = (parsedUrl.pathname || '/') + (parsedUrl.search || '');

  const headers = { ...req.headers };
  delete headers['proxy-connection'];
  delete headers['proxy-authorization'];
  headers.host = parsedUrl.host;
  if (body) headers['content-length'] = Buffer.byteLength(body);

  const upstream = transport.request({
    host: parsedUrl.hostname,
    port,
    method: req.method,
    path,
    headers,
    maxHeaderSize: 65536,
  }, (upstreamRes) => {
    clientRes.writeHead(upstreamRes.statusCode, upstreamRes.headers);
    upstreamRes.pipe(clientRes);
  });

  upstream.on('error', (err) => {
    console.error(`[PII Guard] forward-proxy error for ${parsedUrl.host}: ${err.message}`);
    if (!clientRes.headersSent) clientRes.writeHead(502, { 'content-type': 'text/plain' });
    clientRes.end(`Bad gateway: ${err.message}`);
  });

  if (body) upstream.write(body);
  upstream.end();
}

async function handleProxyRequest(req, clientRes) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const body = Buffer.concat(chunks).toString('utf8');

  // Browser HTTP traffic carries an absolute URL (forward-proxy mode).
  // Send it to the actual destination so general browsing still works.
  if (req.url.startsWith('http://') || req.url.startsWith('https://')) {
    return forwardAsProxy(req, clientRes, body);
  }

  if (req.method !== 'POST' || !req.url.startsWith('/v1/messages')) {
    return forwardRequest(req, clientRes, body, null);
  }

  let parsed;
  try { parsed = JSON.parse(body); } catch (e) {
    return forwardRequest(req, clientRes, body, null);
  }

  // Walk every message in the conversation; anonymize text using the
  // persistent map so the same value gets the same placeholder across turns.
  const stats = anonymizeAllMessages(parsed);

  if (stats.substitutions === 0) {
    // Nothing to anonymize, but still revert any placeholders the model
    // may emit that we know about from prior turns.
    const allKnown = [...persistentMap.values()];
    return forwardRequest(req, clientRes, body, allKnown.length ? allKnown : null);
  }

  // Prompt only when NEW PII appeared in the latest user message.
  // Existing values that were already anonymized in past turns just
  // get re-applied silently.
  if (stats.newInLastUser.length > 0) {
    const detections = stats.newInLastUser.map(e => ({
      label: e.label, value: e.original, type: e.type,
    }));
    const decision = await serializePrompt(() => promptUser(
      // The "preview" feature wants the text — reconstruct it from the last user msg
      extractTextFromContent(parsed.messages[parsed.messages.length - 1].content),
      detections,
    ));

    if (decision === 'decline') {
      // Roll back the new entries we just registered so a future retry
      // will detect them again.
      rollbackEntries(stats.newEntries);
      console.log('[PII Guard] Request declined.\n');
      clientRes.writeHead(403, { 'content-type': 'application/json' });
      clientRes.end(JSON.stringify({
        type: 'error',
        error: { type: 'cancelled', message: 'Cancelled by PII Guard' },
      }));
      return;
    }
    if (decision === 'accept') {
      // Send the ORIGINAL body, but keep the persistent entries we registered
      // so previously-known values still anonymize on the next turn.
      console.log('[PII Guard] Sending original (this turn only).\n');
      const allKnown = [...persistentMap.values()];
      return forwardRequest(req, clientRes, body, allKnown.length ? allKnown : null);
    }
    // anonymize: fall through
  }

  // Send the modified body; revert ALL known placeholders on the way back.
  const newBody = JSON.stringify(parsed);
  const allKnown = [...persistentMap.values()];

  console.log(`[PII Guard] Anonymized ${stats.substitutions} value${stats.substitutions === 1 ? '' : 's'} across ${parsed.messages.length} message${parsed.messages.length === 1 ? '' : 's'} (${stats.newEntries.length} new).`);
  if (process.env.PII_GUARD_VERBOSE) {
    if (stats.newEntries.length > 0) {
      console.log(`[PII Guard]   new mappings: ${stats.newEntries.map(e => e.placeholder + '=' + e.original).join(', ')}`);
    }
    console.log(`[PII Guard]   total known: ${allKnown.length}\n`);
  } else {
    console.log('');
  }
  forwardRequest(req, clientRes, newBody, allKnown);
}

// ──────────────────────────────────────────────────────────────────────
// Web-UI request handler (post-MITM): scan/rewrite using site parsers
// ──────────────────────────────────────────────────────────────────────

async function handleWebUiRequest(req, clientRes, hostname) {
  // Special same-origin endpoint used by the injected sidebar to poll
  // the current turn's anonymization events. We MITM the LLM host, so
  // the page can fetch this as a relative URL with no CORS / extra-
  // origin gymnastics. Each new prompt replaces the turn (so the
  // sidebar shows only what was anonymized in the latest submission),
  // and the original value is included so the in-page click-to-copy
  // works without a second round-trip.
  if (req.url === '/__pii-guard/recent') {
    const turn = getCurrentTurn();
    const events = (turn.events || []).map(e => ({
      ts: e.ts,
      placeholder: e.placeholder,
      type: e.type,
      label: e.label,
      host: e.host,
      original: e.original,
      maskedOriginal: maskOriginal(e.original),
    }));
    const body = JSON.stringify({
      turn: { id: turn.id, ts: turn.ts, host: turn.host, events },
    });
    clientRes.writeHead(200, {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'content-length': Buffer.byteLength(body),
    });
    clientRes.end(body);
    return;
  }

  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const body = Buffer.concat(chunks).toString('utf8');

  // GET / non-POST: pass through, with placeholder revert in case the
  // response references PII we know from earlier turns.
  if (req.method !== 'POST' || !body) {
    const allKnown = [...persistentMap.values()];
    return forwardRequest(req, clientRes, body, allKnown.length ? allKnown : null, hostname);
  }

  // Try a site-specific parser first (highest fidelity).
  const parser = findParser(hostname, req.url);
  if (parser) {
    const extracted = parser.extract(body);
    if (extracted && extracted.text && extracted.text.trim()) {
      return processWithParser(req, clientRes, hostname, body, parser, extracted);
    }
  }

  // For hosts that have a specific parser at all (chatgpt.com, claude.ai,
  // api.openai.com, api.anthropic.com), do NOT fall back to the generic
  // JSON walker. Those sites emit lots of non-prompt traffic (auth pings,
  // telemetry, conversation listings) where strings often look like phones
  // or credit cards to the regex detector. Anonymizing those breaks the
  // site (e.g. ChatGPT returns "Something went wrong").
  if (hasSpecificParser(hostname)) {
    const allKnown = [...persistentMap.values()];
    return forwardRequest(req, clientRes, body, allKnown.length ? allKnown : null, hostname);
  }

  // Generic JSON walker — only for LLM hosts where we have no specific
  // parser at all (Gemini, Copilot, Perplexity, DeepSeek, etc.).
  return processGenericJson(req, clientRes, hostname, body);
}

async function processWithParser(req, clientRes, hostname, body, parser, extracted) {
  const result = anonymizeText(extracted.text);
  if (result.substitutions === 0) {
    const allKnown = [...persistentMap.values()];
    return forwardRequest(req, clientRes, body, allKnown.length ? allKnown : null, hostname);
  }

  if (result.newEntries.length > 0) {
    const detections = result.newEntries.map(e => ({
      label: e.label, value: e.original, type: e.type,
    }));
    const decision = await serializePrompt(() => promptUser(extracted.text, detections));
    if (decision === 'decline') {
      rollbackEntries(result.newEntries);
      console.log(`[PII Guard] ${parser.name} declined.\n`);
      clientRes.writeHead(403, { 'content-type': 'application/json' });
      clientRes.end(JSON.stringify({ error: 'cancelled by PII Guard' }));
      return;
    }
    if (decision === 'accept') {
      console.log(`[PII Guard] ${parser.name} sending original (this turn).\n`);
      const allKnown = [...persistentMap.values()];
      return forwardRequest(req, clientRes, body, allKnown.length ? allKnown : null, hostname);
    }
  }

  const newBody = parser.rewrite(extracted.parsed, extracted.locator, result.text);
  const allKnown = [...persistentMap.values()];
  // Surface every applied placeholder (new + reused) to the in-page
  // sidebar — users care that "this turn anonymized X", not just "X is
  // a brand-new mapping". For reused entries we look them up by their
  // placeholder appearing in result.text.
  const appliedThisTurn = collectAppliedEntries(extracted.text, result.text, allKnown);
  recordWebAnonymization(hostname, appliedThisTurn);
  console.log(`[PII Guard] ${parser.name} anonymized ${result.substitutions} value${result.substitutions === 1 ? '' : 's'} (${result.newEntries.length} new).`);
  if (process.env.PII_GUARD_VERBOSE) {
    if (result.newEntries.length > 0) {
      console.log(`[PII Guard]   new mappings: ${result.newEntries.map(e => e.placeholder + '=' + e.original).join(', ')}`);
    }
  }
  console.log('');
  forwardRequest(req, clientRes, newBody, allKnown, hostname);
}

async function processGenericJson(req, clientRes, hostname, body) {
  let parsed;
  try { parsed = JSON.parse(body); } catch (e) {
    // Not JSON — passthrough. Could add raw-text scanning later.
    const allKnown = [...persistentMap.values()];
    return forwardRequest(req, clientRes, body, allKnown.length ? allKnown : null, hostname);
  }

  let totalSubs = 0;
  const newEntries = [];
  let firstChangedText = '';

  walkJsonStrings(parsed, (str) => {
    if (!str || !str.trim() || str.length > 500000) return str;
    const r = anonymizeText(str);
    if (r.substitutions > 0) {
      totalSubs += r.substitutions;
      newEntries.push(...r.newEntries);
      if (!firstChangedText) firstChangedText = str;
      return r.text;
    }
    return str;
  });

  if (totalSubs === 0) {
    const allKnown = [...persistentMap.values()];
    return forwardRequest(req, clientRes, body, allKnown.length ? allKnown : null, hostname);
  }

  if (newEntries.length > 0) {
    const detections = newEntries.map(e => ({ label: e.label, value: e.original, type: e.type }));
    const decision = await serializePrompt(() => promptUser(firstChangedText, detections));
    if (decision === 'decline') {
      rollbackEntries(newEntries);
      console.log(`[PII Guard] ${hostname} (generic) declined.\n`);
      clientRes.writeHead(403, { 'content-type': 'application/json' });
      clientRes.end(JSON.stringify({ error: 'cancelled by PII Guard' }));
      return;
    }
    if (decision === 'accept') {
      console.log(`[PII Guard] ${hostname} (generic) sending original.\n`);
      const allKnown = [...persistentMap.values()];
      return forwardRequest(req, clientRes, body, allKnown.length ? allKnown : null, hostname);
    }
  }

  const newBody = JSON.stringify(parsed);
  const allKnown = [...persistentMap.values()];
  // Same as the parser path: feed the sidebar with everything anonymized
  // this turn, not just the new entries.
  const appliedThisTurn = collectAppliedEntries(body, newBody, allKnown);
  recordWebAnonymization(hostname, appliedThisTurn);
  console.log(`[PII Guard] ${hostname} (generic JSON) anonymized ${totalSubs} value${totalSubs === 1 ? '' : 's'} (${newEntries.length} new).`);
  if (process.env.PII_GUARD_VERBOSE && newEntries.length > 0) {
    console.log(`[PII Guard]   new mappings: ${newEntries.map(e => e.placeholder + '=' + e.original).join(', ')}`);
  }
  console.log('');
  forwardRequest(req, clientRes, newBody, allKnown, hostname);
}

// ──────────────────────────────────────────────────────────────────────
// Server: handles three traffic types on the same port
//   1. HTTP requests to the proxy directly (Claude Code via ANTHROPIC_BASE_URL)
//   2. CONNECT for HTTPS browser traffic — MITM if LLM domain, else tunnel
//   3. Decrypted browser traffic re-fed into mitmServer for parsing
// ──────────────────────────────────────────────────────────────────────

function dispatch(req, clientRes) {
  // The MITM'd socket carries the real hostname for the request
  const mitmHost = req.socket && req.socket._mitmHost;
  if (mitmHost) {
    return handleWebUiRequest(req, clientRes, mitmHost).catch((err) => {
      console.error('[PII Guard] Web UI handler error:', err);
      if (!clientRes.headersSent) clientRes.writeHead(502);
      clientRes.end();
    });
  }
  return handleProxyRequest(req, clientRes).catch((err) => {
    console.error('[PII Guard] Handler error:', err);
    if (!clientRes.headersSent) {
      clientRes.writeHead(500, { 'content-type': 'application/json' });
    }
    clientRes.end(JSON.stringify({
      type: 'error',
      error: { type: 'proxy_error', message: String(err && err.message || err) },
    }));
  });
}

// 256 KB header budget — ChatGPT's anti-bot tokens + cookie jars regularly
// blow past Node's 16 KB default and trigger "Parse Error: Header overflow",
// which surfaces here as a `TLS error for chatgpt.com` because the parser
// runs inside the MITM TLSSocket. 256 KB is harmless on a localhost-only
// proxy.
const SERVER_OPTS = { maxHeaderSize: 262144 };

const server = http.createServer(SERVER_OPTS, dispatch);

// Internal HTTP server for decrypted browser traffic. Each MITM'd TLS
// socket is fed in via emit('connection') so this server parses HTTP
// off it and dispatches via the same handler.
const mitmServer = http.createServer(SERVER_OPTS, dispatch);

server.on('connect', (req, clientSocket, head) => {
  const [host, portStr] = req.url.split(':');
  const port = parseInt(portStr || '443', 10);

  const mitm = ENABLE_MITM && isLLMHost(host);

  if (!mitm) {
    // Plain TCP tunnel for non-LLM hosts. The proxy just relays bytes —
    // no inspection, no MITM. Chrome's TLS handshake flows through
    // unmodified, ALPN negotiates HTTP/2 with the real origin, etc.
    const upstream = net.connect({ host, port });
    let connectAcked = false;
    upstream.setTimeout(15000); // 15s connect/idle timeout
    upstream.once('connect', () => {
      connectAcked = true;
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head && head.length) upstream.write(head);
      clientSocket.pipe(upstream);
      upstream.pipe(clientSocket);
    });
    upstream.on('error', (err) => {
      // Don't spam the journal with every closed connection — only log
      // pre-handshake failures the client cares about.
      if (!connectAcked) {
        console.error(`[PII Guard] tunnel connect failed for ${host}:${port}: ${err.message}`);
        if (!clientSocket.destroyed) {
          clientSocket.write(`HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n`);
        }
      }
      clientSocket.destroy();
    });
    upstream.on('timeout', () => {
      if (!connectAcked) console.error(`[PII Guard] tunnel timeout for ${host}:${port}`);
      upstream.destroy();
      clientSocket.destroy();
    });
    clientSocket.on('error', () => upstream.destroy());
    return;
  }

  // MITM: terminate TLS to the client using a leaf cert signed by our CA,
  // then re-feed the decrypted stream into mitmServer for HTTP parsing.
  // ALPN forced to http/1.1: without this, modern Chrome may negotiate
  // h2 and our HTTP/1.1 parser would see HTTP/2 frames as garbage and
  // emit "Parse Error: Header overflow" on every chatgpt.com request.
  clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
  try {
    const secureContext = getSecureContext(host);
    const tlsSocket = new tls.TLSSocket(clientSocket, {
      isServer: true,
      secureContext,
      ALPNProtocols: ['http/1.1'],
    });
    tlsSocket._mitmHost = host;
    tlsSocket.on('error', (err) => {
      // Common when the client doesn't trust our CA — emit a clear log
      if (err.code !== 'ECONNRESET') {
        console.error(`[PII Guard] TLS error for ${host}: ${err.message}`);
      }
    });
    if (head && head.length) tlsSocket.unshift(head);
    mitmServer.emit('connection', tlsSocket);
  } catch (err) {
    console.error(`[PII Guard] MITM setup failed for ${host}:`, err.message);
    clientSocket.destroy();
  }
});

server.listen(PORT, '127.0.0.1', () => {
  if (ENABLE_MITM) {
    try { ensureCa(); } catch (err) {
      console.error('[PII Guard] CA setup failed; MITM disabled:', err.message);
    }
  }
  const banner = [
    '',
    '\x1b[1m\x1b[36m═══ PII Guard Proxy ═══\x1b[0m',
    `  Listening on \x1b[1mhttp://127.0.0.1:${PORT}\x1b[0m`,
    `  Browser MITM: \x1b[1m${ENABLE_MITM ? 'on' : 'off'}\x1b[0m  (LLM web UIs + API hosts)`,
    `  Reveal placeholders in responses: \x1b[1m${REVEAL_IN_RESPONSE}\x1b[0m`,
    `  Headless action when no TTY: \x1b[1m${(process.env.PII_GUARD_HEADLESS_ACTION || 'decline').toLowerCase()}\x1b[0m`,
    '',
    '\x1b[1mUse it in any of these modes:\x1b[0m',
    '',
    '\x1b[2m1) Claude Code (or any Anthropic SDK app):\x1b[0m',
    `   \x1b[33mexport ANTHROPIC_BASE_URL=http://127.0.0.1:${PORT}\x1b[0m`,
    '',
    '\x1b[2m2) Any CLI / SDK (OpenAI, etc.) — route all HTTPS through the proxy:\x1b[0m',
    `   \x1b[33mexport HTTPS_PROXY=http://127.0.0.1:${PORT}\x1b[0m`,
    `   \x1b[33mexport HTTP_PROXY=http://127.0.0.1:${PORT}\x1b[0m`,
    `   \x1b[33mexport NODE_EXTRA_CA_CERTS=${getCaCertPath()}\x1b[0m`,
    '',
    '\x1b[2m3) Web browser (ChatGPT, Claude.ai, Gemini, Copilot, Perplexity, …):\x1b[0m',
    `   1. Trust the CA cert: \x1b[33m${getCaCertPath()}\x1b[0m`,
    `   2. Set browser HTTP/HTTPS proxy to \x1b[33m127.0.0.1:${PORT}\x1b[0m`,
    '   (Tip: FoxyProxy can route only LLM hostnames so the rest of your',
    '    browsing stays direct.)',
    '',
    '\x1b[2mAll three modes share the same persistent placeholder map: a value',
    'anonymized in Claude Code is reused as the same placeholder in the browser.\x1b[0m',
    '',
  ].join('\n');
  console.log(banner);
});
