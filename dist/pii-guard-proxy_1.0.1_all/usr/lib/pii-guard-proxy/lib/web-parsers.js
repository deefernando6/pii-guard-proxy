'use strict';

// Per-site request body parsers. Each parser knows the JSON shape of one
// LLM provider's prompt endpoint. The proxy falls back to a generic JSON
// walker for any matched LLM domain that doesn't have a specific parser.

const PARSERS = [
  {
    name: 'ChatGPT',
    matchHost: /^(?:chatgpt\.com|chat\.openai\.com)$/i,
    matchPath: /\/(?:backend-api|backend-anon)\/.*conversation/,
    extract(body) {
      try {
        const j = JSON.parse(body);
        if (!Array.isArray(j.messages)) return null;
        for (let i = j.messages.length - 1; i >= 0; i--) {
          const m = j.messages[i];
          if (m && m.author && m.author.role === 'user' && m.content && Array.isArray(m.content.parts)) {
            const text = m.content.parts.filter(p => typeof p === 'string').join('\n');
            if (text) return { text, locator: { idx: i }, parsed: j };
          }
        }
      } catch (e) {}
      return null;
    },
    rewrite(parsed, locator, newText) {
      parsed.messages[locator.idx].content.parts = [newText];
      return JSON.stringify(parsed);
    },
  },
  {
    name: 'Claude.ai',
    matchHost: /(?:^|\.)claude\.ai$/i,
    matchPath: /\/api\/.+\/completion/,
    extract(body) {
      try {
        const j = JSON.parse(body);
        if (typeof j.prompt === 'string' && j.prompt.length > 0) {
          return { text: j.prompt, locator: { kind: 'prompt' }, parsed: j };
        }
      } catch (e) {}
      return null;
    },
    rewrite(parsed, locator, newText) {
      parsed.prompt = newText;
      return JSON.stringify(parsed);
    },
  },
  {
    name: 'OpenAI API',
    matchHost: /^api\.openai\.com$/i,
    matchPath: /\/v1\/(?:chat\/completions|completions|responses)/,
    extract(body) {
      try {
        const j = JSON.parse(body);
        if (Array.isArray(j.messages)) {
          for (let i = j.messages.length - 1; i >= 0; i--) {
            const m = j.messages[i];
            if (m && m.role === 'user') {
              const text = typeof m.content === 'string'
                ? m.content
                : Array.isArray(m.content)
                  ? m.content.filter(p => p && p.type === 'text').map(p => p.text).join('\n')
                  : '';
              if (text) return { text, locator: { kind: 'chat', idx: i }, parsed: j };
            }
          }
        }
        if (typeof j.prompt === 'string' && j.prompt) {
          return { text: j.prompt, locator: { kind: 'completion' }, parsed: j };
        }
        if (typeof j.input === 'string' && j.input) {
          return { text: j.input, locator: { kind: 'responses' }, parsed: j };
        }
      } catch (e) {}
      return null;
    },
    rewrite(parsed, locator, newText) {
      if (locator.kind === 'chat') {
        const m = parsed.messages[locator.idx];
        if (typeof m.content === 'string') {
          m.content = newText;
        } else if (Array.isArray(m.content)) {
          let replaced = false;
          for (const p of m.content) {
            if (p && p.type === 'text' && !replaced) { p.text = newText; replaced = true; }
          }
          if (!replaced) m.content.unshift({ type: 'text', text: newText });
        }
      } else if (locator.kind === 'completion') {
        parsed.prompt = newText;
      } else if (locator.kind === 'responses') {
        parsed.input = newText;
      }
      return JSON.stringify(parsed);
    },
  },
  {
    name: 'Anthropic API',
    matchHost: /^api\.anthropic\.com$/i,
    matchPath: /\/v1\/messages/,
    // The Anthropic /v1/messages flow uses the multi-message walker in proxy.js
    // — return null here so the existing handler picks it up.
    extract() { return null; },
    rewrite(parsed) { return JSON.stringify(parsed); },
  },
  {
    // Google Gemini / Bard. The chat endpoints don't use plain JSON — they
    // use Google's batch RPC format with a form-encoded body
    //   f.req=<urlencoded JSON-stringified-array>&at=<token>
    // The user's prompt is buried inside f.req. We treat the URL-decoded
    // f.req as plain text, scan it for PII, replace any matches with their
    // placeholders, and re-encode back into the form. Placeholders survive
    // because `[`, `]`, `_` are safe inside JSON strings — Gemini's parser
    // round-trips them cleanly.
    name: 'Gemini',
    matchHost: /^(?:gemini|bard)\.google\.com$/i,
    matchPath: /^\/_\//,
    extract(body) {
      if (!body || !body.includes('f.req=')) return null;
      let formData;
      try { formData = new URLSearchParams(body); }
      catch (e) { return null; }
      const fReq = formData.get('f.req');
      if (!fReq) return null;
      return { text: fReq, locator: { kind: 'gemini-form', formData }, parsed: null };
    },
    rewrite(parsed, locator, newText) {
      locator.formData.set('f.req', newText);
      return locator.formData.toString();
    },
  },
];

// Domains we MITM. Keeping this conservative — only sites where chat is the
// primary purpose, plus dedicated API hosts. Adding mixed-use sites
// (x.com, duckduckgo.com) would interfere with normal browsing.
const MITM_HOST_PATTERNS = [
  // Chat web UIs
  /^(?:chatgpt\.com|chat\.openai\.com)$/i,
  /(?:^|\.)claude\.ai$/i,
  /^(?:gemini|bard)\.google\.com$/i,
  /^copilot\.microsoft\.com$/i,
  /(?:^|\.)perplexity\.ai$/i,
  /^chat\.deepseek\.com$/i,
  /^chat\.mistral\.ai$/i,
  /^poe\.com$/i,
  /^pi\.ai$/i,
  /^character\.ai$/i,
  /^grok\.com$/i,
  /^chat\.qwenlm\.ai$/i,
  // API hosts
  /^api\.anthropic\.com$/i,
  /^api\.openai\.com$/i,
  /^api\.mistral\.ai$/i,
  /^api\.cohere\.ai$/i,
  /^api\.deepseek\.com$/i,
  /^generativelanguage\.googleapis\.com$/i,
];

function findParser(hostname, urlPath) {
  for (const p of PARSERS) {
    if (p.matchHost.test(hostname) && p.matchPath.test(urlPath)) return p;
  }
  return null;
}

function isLLMHost(hostname) {
  return MITM_HOST_PATTERNS.some(re => re.test(hostname));
}

// True when at least one specific parser matches this host (regardless of
// path). The proxy uses this to suppress the generic JSON walker for hosts
// where we already understand the request shape — non-prompt traffic
// (auth, telemetry, conversation listings) gets passed through untouched.
function hasSpecificParser(hostname) {
  for (const p of PARSERS) {
    if (p.matchHost.test(hostname)) return true;
  }
  return false;
}

// Generic JSON walker: recursively visits every string value in a parsed
// JSON tree, applying `mutate(str)` to each. Mutates in place. Used as a
// catch-all for matched LLM domains that don't have a specific parser.
function walkJsonStrings(node, mutate) {
  if (Array.isArray(node)) {
    for (let i = 0; i < node.length; i++) {
      const v = node[i];
      if (typeof v === 'string') node[i] = mutate(v);
      else if (v !== null && typeof v === 'object') walkJsonStrings(v, mutate);
    }
  } else if (node !== null && typeof node === 'object') {
    for (const k of Object.keys(node)) {
      const v = node[k];
      if (typeof v === 'string') node[k] = mutate(v);
      else if (v !== null && typeof v === 'object') walkJsonStrings(v, mutate);
    }
  }
}

module.exports = { findParser, isLLMHost, hasSpecificParser, walkJsonStrings };
