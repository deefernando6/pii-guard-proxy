'use strict';

// Records recent web-UI anonymization events and serves them to the
// in-page sidebar (injected into LLM host HTML responses, polls the
// proxy on `/__pii-guard/recent`). Two pieces:
//
//   1. recordWebAnonymization(host, entries) — appends to a ring buffer.
//   2. injectSidebar(html) — splices a self-contained <style>+<script>
//      block before </body> in any HTML page served from an LLM host.
//
// Same-origin: the injected script polls /__pii-guard/recent on the
// host the page is loaded from. The proxy is MITM'ing that host, so
// the path resolves locally with no CORS / extra-origin gymnastics.

const RING_SIZE = 100;
const recentEvents = [];

function recordWebAnonymization(host, entries) {
  if (!entries || entries.length === 0) return;
  const now = Date.now();
  for (const e of entries) {
    recentEvents.push({
      ts: now,
      host: host || '',
      placeholder: e.placeholder,
      type: e.type,
      label: e.label || e.type,
      original: e.original,
    });
  }
  // Cap the ring.
  if (recentEvents.length > RING_SIZE) {
    recentEvents.splice(0, recentEvents.length - RING_SIZE);
  }
}

function getRecentEvents(limit = 50) {
  // Newest first.
  return recentEvents.slice(-limit).reverse();
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
    These values were detected in your prompts and replaced with placeholders before being sent. The model never received the originals.
  </div>
  <ul class="pg-list" id="pii-guard-list">
    <li class="pg-empty">Nothing anonymized yet on this page. Type a prompt with sensitive data — it'll show up here.</li>
  </ul>
  <footer>Polls every 2s · last 50 events</footer>
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
  var seenIds = Object.create(null);
  var lastCount = 0;

  function open() {
    sidebar.classList.remove('collapsed');
    toggle.classList.add('hidden');
    toggle.classList.remove('has-events');
  }
  function close() {
    sidebar.classList.add('collapsed');
    toggle.classList.remove('hidden');
  }
  toggle.addEventListener('click', open);
  closeBtn.addEventListener('click', close);

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

  function render(events) {
    if (!events.length) {
      if (list.firstChild && list.firstChild.classList && list.firstChild.classList.contains('pg-empty')) return;
      list.innerHTML = '<li class="pg-empty">Nothing anonymized yet on this page.</li>';
      return;
    }
    list.innerHTML = '';
    events.forEach(function(e) {
      var li = document.createElement('li');
      li.className = 'pg-item';
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
      li.appendChild(row1);
      li.appendChild(orig);
      li.appendChild(meta);
      list.appendChild(li);
    });
  }

  function tick() {
    fetch('/__pii-guard/recent', { credentials: 'omit', cache: 'no-store' })
      .then(function(r) { return r.ok ? r.json() : { events: [] }; })
      .then(function(payload) {
        var events = (payload && payload.events) || [];
        render(events);
        // Badge: items the user hasn't acknowledged (i.e. since last open).
        if (sidebar.classList.contains('collapsed') && events.length > lastCount) {
          var delta = events.length - lastCount;
          badge.textContent = delta > 99 ? '99+' : String(delta);
          toggle.classList.add('has-events');
        }
        if (!sidebar.classList.contains('collapsed')) {
          lastCount = events.length;
        }
      })
      .catch(function() {});
  }

  tick();
  setInterval(tick, 2000);
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
  getRecentEvents,
  maskOriginal,
  injectSidebar,
};
