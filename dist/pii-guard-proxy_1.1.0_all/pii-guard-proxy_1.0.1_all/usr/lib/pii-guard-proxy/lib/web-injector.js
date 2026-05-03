'use strict';

// Records the *current turn's* web-UI anonymization events and serves
// them to the in-page sidebar (injected into LLM host HTML responses,
// polls the proxy on `/__pii-guard/recent`).
//
//   1. recordWebAnonymization(host, entries) — REPLACES the current
//      turn with these entries. Each user prompt produces one POST
//      to the LLM host's chat endpoint; we treat each call as a new
//      turn so the sidebar always reflects "what got anonymized in
//      the prompt I just submitted" rather than a growing log.
//   2. injectSidebar(html) — splices a self-contained <style>+<script>
//      block before </body> in any HTML page served from an LLM host.
//
// Same-origin: the injected script polls /__pii-guard/recent on the
// host the page is loaded from. The proxy is MITM'ing that host, so
// the path resolves locally with no CORS / extra-origin gymnastics.

let currentTurn = {
  id: 0,
  ts: 0,
  host: '',
  events: [],
};

function recordWebAnonymization(host, entries) {
  if (!entries || entries.length === 0) return;
  currentTurn = {
    id: currentTurn.id + 1,
    ts: Date.now(),
    host: host || '',
    events: entries.map(e => ({
      ts: Date.now(),
      host: host || '',
      placeholder: e.placeholder,
      type: e.type,
      label: e.label || e.type,
      original: e.original,
    })),
  };
}

function getCurrentTurn() {
  return {
    id: currentTurn.id,
    ts: currentTurn.ts,
    host: currentTurn.host,
    events: currentTurn.events,
  };
}

// Mask the middle of a sensitive value so the sidebar shows enough
// context to recognize it without exposing the full string in the
// browser DOM. Email/phone/etc. all get the same treatment.
function maskOriginal(s) {
  if (typeof s !== 'string') return '';
  if (s.length <= 4) return s[0] + '•'.repeat(Math.max(s.length - 1, 0));
  if (s.length <= 8) return s.slice(0, 2) + '•'.repeat(s.length - 3) + s.slice(-1);
  return s.slice(0, 3) + '•'.repeat(Math.min(s.length - 5, 6)) + s.slice(-2);
}

const SIDEBAR_HTML = `
<style id="pii-guard-sidebar-style">
  #pii-guard-sidebar, #pii-guard-sidebar * {
    all: revert;
    box-sizing: border-box;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  }
  #pii-guard-sidebar {
    position: fixed !important;
    top: 16px !important;
    right: 16px !important;
    z-index: 2147483647 !important;
    width: 320px;
    max-height: calc(100vh - 32px);
    background: #0e1116;
    color: #e7e9ee;
    border: 1px solid #1d2330;
    border-radius: 12px;
    box-shadow: 0 12px 40px rgba(0,0,0,0.45), 0 0 0 1px rgba(34,211,238,0.18);
    display: flex;
    flex-direction: column;
    overflow: hidden;
    font-size: 13px;
    transition: transform 0.18s ease, opacity 0.18s ease;
  }
  #pii-guard-sidebar.collapsed {
    transform: translateX(calc(100% + 24px));
    opacity: 0;
    pointer-events: none;
  }
  #pii-guard-toggle {
    position: fixed !important;
    top: 16px !important;
    right: 16px !important;
    z-index: 2147483647 !important;
    width: 44px;
    height: 44px;
    border-radius: 50%;
    background: #0e1116;
    border: 1px solid rgba(34,211,238,0.4);
    color: #22d3ee;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    box-shadow: 0 8px 24px rgba(0,0,0,0.4);
    font-size: 20px;
    transition: transform 0.18s ease, opacity 0.18s ease;
  }
  #pii-guard-toggle.hidden { transform: scale(0.6); opacity: 0; pointer-events: none; }
  #pii-guard-toggle:hover { transform: scale(1.05); }
  #pii-guard-toggle .pg-badge {
    position: absolute;
    top: -4px;
    right: -4px;
    min-width: 18px;
    height: 18px;
    padding: 0 4px;
    border-radius: 9px;
    background: #f59e0b;
    color: #08090c;
    font-size: 10px;
    font-weight: 700;
    display: none;
    align-items: center;
    justify-content: center;
  }
  #pii-guard-toggle.has-events .pg-badge { display: flex; }
  #pii-guard-sidebar header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 14px;
    border-bottom: 1px solid #1d2330;
    background: #11151b;
  }
  #pii-guard-sidebar header .pg-title {
    display: flex;
    align-items: center;
    gap: 8px;
    font-weight: 600;
    color: #f3f5f9;
    font-size: 14px;
  }
  #pii-guard-sidebar header .pg-dot {
    width: 8px; height: 8px;
    border-radius: 50%;
    background: #22d3ee;
    box-shadow: 0 0 0 4px rgba(34,211,238,0.18);
  }
  #pii-guard-sidebar header .pg-close {
    background: transparent;
    border: 0;
    color: #9aa3b2;
    cursor: pointer;
    font-size: 18px;
    line-height: 1;
    padding: 2px 6px;
    border-radius: 4px;
  }
  #pii-guard-sidebar header .pg-close:hover { color: #e7e9ee; background: #1d2330; }
  #pii-guard-sidebar .pg-blurb {
    padding: 10px 14px;
    color: #9aa3b2;
    font-size: 12px;
    border-bottom: 1px solid #1d2330;
    background: #0e1116;
    line-height: 1.5;
  }
  #pii-guard-sidebar .pg-list {
    flex: 1 1 auto;
    overflow-y: auto;
    padding: 6px 10px 12px;
    margin: 0;
    list-style: none;
  }
  #pii-guard-sidebar .pg-empty {
    padding: 30px 14px;
    text-align: center;
    color: #6b7283;
    font-size: 12px;
  }
  #pii-guard-sidebar .pg-item {
    padding: 10px 12px;
    border-radius: 8px;
    margin-top: 6px;
    background: #11151b;
    border: 1px solid #1d2330;
    cursor: pointer;
    position: relative;
    transition: border-color 0.15s ease, background 0.15s ease;
  }
  #pii-guard-sidebar .pg-item:hover {
    border-color: rgba(34,211,238,0.45);
    background: #161b23;
  }
  #pii-guard-sidebar .pg-item.copied {
    border-color: rgba(34,211,238,0.7);
    background: rgba(34,211,238,0.10);
  }
  #pii-guard-sidebar .pg-item .pg-copyhint {
    position: absolute;
    top: 8px;
    right: 10px;
    font-size: 10px;
    color: #22d3ee;
    opacity: 0;
    transition: opacity 0.15s ease;
    pointer-events: none;
  }
  #pii-guard-sidebar .pg-item:hover .pg-copyhint { opacity: 0.7; }
  #pii-guard-sidebar .pg-item.copied .pg-copyhint {
    opacity: 1;
    color: #22d3ee;
    font-weight: 600;
  }
  #pii-guard-sidebar .pg-item .pg-row1 {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 8px;
    margin-bottom: 4px;
  }
  #pii-guard-sidebar .pg-item .pg-ph {
    font-family: ui-monospace, 'SF Mono', Menlo, Consolas, monospace;
    font-size: 12px;
    color: #a78bfa;
    background: rgba(167,139,250,0.10);
    padding: 1px 6px;
    border-radius: 4px;
    border: 1px solid rgba(167,139,250,0.25);
  }
  #pii-guard-sidebar .pg-item .pg-type {
    font-size: 10px;
    color: #22d3ee;
    background: rgba(34,211,238,0.12);
    border: 1px solid rgba(34,211,238,0.3);
    padding: 1px 6px;
    border-radius: 999px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    font-weight: 600;
  }
  #pii-guard-sidebar .pg-item .pg-orig {
    font-family: ui-monospace, 'SF Mono', Menlo, Consolas, monospace;
    font-size: 11px;
    color: #cbd5e1;
    word-break: break-all;
  }
  #pii-guard-sidebar .pg-item .pg-meta {
    margin-top: 4px;
    font-size: 10px;
    color: #6b7283;
  }
  #pii-guard-sidebar footer {
    padding: 8px 14px;
    border-top: 1px solid #1d2330;
    color: #6b7283;
    font-size: 10px;
    text-align: center;
    background: #11151b;
  }
</style>
<button id="pii-guard-toggle" type="button" aria-label="PII Guard sidebar">
  <span class="pg-badge">0</span>
  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
    <path d="M12 2L4 6v6c0 5 3.5 9.4 8 10 4.5-.6 8-5 8-10V6l-8-4z"/>
  </svg>
</button>
<aside id="pii-guard-sidebar" class="collapsed" aria-label="PII Guard anonymization log" role="complementary">
  <header>
    <div class="pg-title"><span class="pg-dot"></span><span>PII Guard</span></div>
    <button class="pg-close" type="button" aria-label="Close">×</button>
  </header>
  <div class="pg-blurb">
    These values from your <strong>last prompt</strong> were detected and replaced with placeholders before being sent. Click any row to copy the original value.
  </div>
  <ul class="pg-list" id="pii-guard-list">
    <li class="pg-empty">Nothing anonymized yet. Type a prompt with sensitive data — it'll show up here when you submit.</li>
  </ul>
  <footer>Resets each prompt · click row to copy original</footer>
</aside>
<script>
(function() {
  if (window.__piiGuardSidebarLoaded) return;
  window.__piiGuardSidebarLoaded = true;

  var sidebar = document.getElementById('pii-guard-sidebar');
  var toggle = document.getElementById('pii-guard-toggle');
  var list = document.getElementById('pii-guard-list');
  var badge = toggle.querySelector('.pg-badge');
  var closeBtn = sidebar.querySelector('.pg-close');
  var lastTurnId = -1;
  var lastSeenTurnId = -1; // last turn the user has actually viewed

  // ── DOM-level placeholder revert ────────────────────────────────────
  // The proxy already does its best to revert placeholders on the wire,
  // but byte-stream rewriting on SSE is fragile (chunk boundaries, JSON
  // escapes, the LLM tokenising "[" and "_1" separately, etc.). By the
  // time text hits the DOM it's plain rendered text — so we walk it and
  // replace any known placeholder. This is the authoritative revert.
  var mappings = Object.create(null);  // { '[PHONE_1]': '0712312312', ... }
  // Permissive shape: optional backslash escapes around each metachar
  // (covers markdown's \\[, \\_, \\] forms). The regex literal here is
  // inside a server-side template literal, so backslashes get doubled.
  var PH_SHAPE = /\\\\?\\[[A-Z][A-Z_]*\\\\?_\\d+\\\\?\\]/g;

  function refreshMappings() {
    return fetch('/__pii-guard/mappings', { credentials: 'omit', cache: 'no-store' })
      .then(function(r) { return r.ok ? r.json() : null; })
      .then(function(payload) {
        if (!payload || !Array.isArray(payload.mappings)) return;
        var next = Object.create(null);
        payload.mappings.forEach(function(m) {
          if (m && m.placeholder) next[m.placeholder] = m.original;
        });
        mappings = next;
      })
      .catch(function() {});
  }

  function canonicalize(match) {
    // Strip backslash escapes — covers markdown’s \\[, \\_, \\] forms.
    return match.replace(/\\\\/g, '');
  }

  function revertText(s) {
    if (!s || s.indexOf('[') === -1) return s;
    var changed = false;
    var out = s.replace(PH_SHAPE, function(m) {
      var canon = canonicalize(m);
      if (canon in mappings) {
        changed = true;
        return mappings[canon];
      }
      return m;
    });
    return changed ? out : s;
  }

  // Walk every text node under root. We avoid scripts, styles, and our
  // own sidebar — and we never touch nodes inside form fields the user
  // is typing into.
  function revertSubtree(root) {
    if (!root || !root.nodeType) return;
    if (root.nodeType === 3) {
      var v = root.nodeValue;
      var next = revertText(v);
      if (next !== v) root.nodeValue = next;
      return;
    }
    if (root.nodeType !== 1 && root.nodeType !== 9 && root.nodeType !== 11) return;
    var tag = root.nodeName;
    if (tag === 'SCRIPT' || tag === 'STYLE' || tag === 'TEXTAREA' || tag === 'INPUT') return;
    if (root.id === 'pii-guard-sidebar' || root.id === 'pii-guard-toggle') return;
    // Walk via TreeWalker for speed on big subtrees.
    var w = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
      acceptNode: function(n) {
        var p = n.parentNode;
        while (p && p.nodeType === 1) {
          var t = p.nodeName;
          if (t === 'SCRIPT' || t === 'STYLE' || t === 'TEXTAREA' || t === 'INPUT') return NodeFilter.FILTER_REJECT;
          if (p.id === 'pii-guard-sidebar' || p.id === 'pii-guard-toggle') return NodeFilter.FILTER_REJECT;
          if (p.isContentEditable) return NodeFilter.FILTER_REJECT;
          p = p.parentNode;
        }
        return NodeFilter.FILTER_ACCEPT;
      }
    });
    var nodes = [];
    var node;
    while ((node = w.nextNode())) nodes.push(node);
    nodes.forEach(function(n) {
      var v = n.nodeValue;
      var next = revertText(v);
      if (next !== v) n.nodeValue = next;
    });
  }

  var revertTimer = null;
  function scheduleRevert(target) {
    if (revertTimer) return;
    revertTimer = setTimeout(function() {
      revertTimer = null;
      revertSubtree(target || document.body);
    }, 50);
  }

  function startObserver() {
    if (!document.body) return;
    revertSubtree(document.body);
    var mo = new MutationObserver(function(records) {
      for (var i = 0; i < records.length; i++) {
        var r = records[i];
        if (r.type === 'characterData') {
          scheduleRevert(r.target);
        } else if (r.type === 'childList') {
          for (var j = 0; j < r.addedNodes.length; j++) {
            scheduleRevert(r.addedNodes[j]);
          }
        }
      }
    });
    mo.observe(document.body, { subtree: true, characterData: true, childList: true });
  }

  // Refresh mappings periodically so newly-anonymized values are
  // available for revert immediately. We trigger an extra refresh
  // whenever the polling tick sees a new turn.
  refreshMappings().then(function() {
    if (document.body) startObserver();
    else document.addEventListener('DOMContentLoaded', startObserver);
  });
  setInterval(refreshMappings, 1500);

  function openSidebar() {
    sidebar.classList.remove('collapsed');
    toggle.classList.add('hidden');
    toggle.classList.remove('has-events');
    badge.textContent = '0';
    lastSeenTurnId = lastTurnId;
  }
  function closeSidebar() {
    sidebar.classList.add('collapsed');
    toggle.classList.remove('hidden');
  }
  toggle.addEventListener('click', openSidebar);
  closeBtn.addEventListener('click', closeSidebar);

  function fmtTime(ts) {
    var d = new Date(ts);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }
  function maskOriginal(s) {
    if (typeof s !== 'string') return '';
    if (s.length <= 4) return s[0] + '\\u2022'.repeat(Math.max(s.length - 1, 0));
    if (s.length <= 8) return s.slice(0, 2) + '\\u2022'.repeat(s.length - 3) + s.slice(-1);
    return s.slice(0, 3) + '\\u2022'.repeat(Math.min(s.length - 5, 6)) + s.slice(-2);
  }

  function copyToClipboard(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text);
    }
    // Fallback for non-secure contexts: hidden textarea + execCommand.
    return new Promise(function(resolve, reject) {
      try {
        var ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        var ok = document.execCommand('copy');
        document.body.removeChild(ta);
        ok ? resolve() : reject(new Error('execCommand copy failed'));
      } catch (e) { reject(e); }
    });
  }

  function flashCopied(item, hint) {
    item.classList.add('copied');
    var prev = hint.textContent;
    hint.textContent = 'Copied!';
    setTimeout(function() {
      item.classList.remove('copied');
      hint.textContent = prev;
    }, 1100);
  }

  function render(turn) {
    var events = (turn && turn.events) || [];
    if (!events.length) {
      list.innerHTML = '<li class="pg-empty">No PII detected in your last prompt.</li>';
      return;
    }
    list.innerHTML = '';
    events.forEach(function(e) {
      var li = document.createElement('li');
      li.className = 'pg-item';
      li.title = 'Click to copy the original value';
      // Stash the original on the element so click-to-copy doesn't need
      // another fetch. Same-origin only — the LLM page is the only thing
      // that can read this DOM, and it already had access to whatever
      // the user typed before we anonymized it.
      li.dataset.original = e.original || '';

      var hint = document.createElement('span');
      hint.className = 'pg-copyhint';
      hint.textContent = 'Click to copy';

      var row1 = document.createElement('div');
      row1.className = 'pg-row1';
      var ph = document.createElement('span');
      ph.className = 'pg-ph';
      ph.textContent = e.placeholder;
      var type = document.createElement('span');
      type.className = 'pg-type';
      type.textContent = (e.label || e.type || '').toLowerCase();
      row1.appendChild(ph);
      row1.appendChild(type);

      var orig = document.createElement('div');
      orig.className = 'pg-orig';
      orig.textContent = e.maskedOriginal || maskOriginal(e.original || '');

      var meta = document.createElement('div');
      meta.className = 'pg-meta';
      meta.textContent = fmtTime(e.ts) + ' \\u00b7 ' + (e.host || location.hostname);

      li.appendChild(hint);
      li.appendChild(row1);
      li.appendChild(orig);
      li.appendChild(meta);

      li.addEventListener('click', function() {
        var v = li.dataset.original || '';
        if (!v) return;
        copyToClipboard(v).then(
          function() { flashCopied(li, hint); },
          function() {
            hint.textContent = 'Copy failed';
            setTimeout(function() { hint.textContent = 'Click to copy'; }, 1500);
          }
        );
      });

      list.appendChild(li);
    });
  }

  function tick() {
    fetch('/__pii-guard/recent', { credentials: 'omit', cache: 'no-store' })
      .then(function(r) { return r.ok ? r.json() : null; })
      .then(function(payload) {
        if (!payload) return;
        var turn = payload.turn || { id: 0, events: [] };
        if (turn.id === lastTurnId) return; // no new prompt since last poll
        lastTurnId = turn.id;
        render(turn);
        // New prompt → new mappings may have been added on the proxy.
        // Pull them and immediately re-revert so the assistant's reply
        // (which is about to start streaming in) reverts cleanly even
        // for placeholders the proxy missed on the wire.
        refreshMappings().then(function() {
          revertSubtree(document.body);
        });
        // Badge: only flag a new turn if the user hasn't already viewed it.
        if (sidebar.classList.contains('collapsed') && turn.id > lastSeenTurnId && (turn.events || []).length > 0) {
          badge.textContent = String((turn.events || []).length);
          toggle.classList.add('has-events');
        } else if (!sidebar.classList.contains('collapsed')) {
          lastSeenTurnId = turn.id;
        }
      })
      .catch(function() {});
  }

  tick();
  setInterval(tick, 1500);
})();
</script>
`.trim();

function injectSidebar(html) {
  if (typeof html !== 'string' || !html) return html;
  if (html.includes('id="pii-guard-sidebar"')) return html; // already injected
  // Inject before </body>; fall back to end-of-document if no </body>.
  const idx = html.lastIndexOf('</body>');
  if (idx >= 0) {
    return html.slice(0, idx) + SIDEBAR_HTML + html.slice(idx);
  }
  // Some SPAs ship a stub <html><head>...</head></html> — append anyway so
  // the sidebar appears once the SPA hydrates the body.
  return html + SIDEBAR_HTML;
}

module.exports = {
  recordWebAnonymization,
  getCurrentTurn,
  maskOriginal,
  injectSidebar,
};
