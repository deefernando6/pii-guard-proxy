'use strict';

// GLiNER PII Small INT8 detection via a long-lived Python helper
// subprocess. The proxy stays in Node (no monster transformers.js
// dependency at runtime) but gets correct GLiNER span scoring for free
// because the helper drives the same `gliner` library we benchmark
// against.
//
// Lifecycle:
//   - First call to detectPIIWithMl() spawns python3 lib/ml-helper.py
//   - Each subsequent call sends one NDJSON request and awaits the
//     matching NDJSON response keyed by request id.
//   - On helper crash / parse error / timeout, we fail the in-flight
//     request, mark the detector unavailable, and let the regex
//     pipeline carry the request alone.
//
// Enabling:
//   - The proxy considers ML available iff:
//       1. /etc/pii-guard/ml-detection-enabled marker exists
//       2. The model files are present at MODEL_DIR
//       3. python3 exists on PATH
//       4. The helper started successfully
//   - Otherwise detectPIIWithMl() returns [] silently.

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const ML_MARKER  = '/etc/pii-guard/ml-detection-enabled';
const HELPER     = path.join(__dirname, 'ml-helper.py');
const MODEL_DIR  = process.env.PII_GUARD_ML_MODEL_DIR
  || '/var/lib/pii-guard/models/gliner-pii-small';

// Map GLiNER's natural-language labels onto the proxy's internal type
// taxonomy so anonymizer's placeholderFor() recognises them and so a
// span detected by both regex+ML collapses to a single placeholder.
const LABEL_TO_TYPE = {
  'person name': 'NAME', 'first name': 'NAME', 'last name': 'NAME',
  'title': 'TITLE',
  'email address': 'EMAIL',
  'phone number': 'PHONE',
  'date of birth': 'DOB', 'date': 'DOB',
  'time': 'TIME',
  'address': 'ADDRESS', 'street address': 'ADDRESS', 'street': 'ADDRESS',
  'city': 'ADDRESS', 'state': 'ADDRESS', 'country': 'ADDRESS',
  'postal code': 'ADDRESS', 'building': 'ADDRESS', 'secondary address': 'ADDRESS',
  'geographic coordinates': 'GEOCOORD',
  'id card': 'IDCARD',
  'social security number': 'SSN',
  'passport number': 'PASSPORT',
  'driver license': 'DRIVERLICENSE',
  'username': 'USERNAME',
  'ip address': 'IPV4',
  'password': 'PASSWORD_FIELD',
  'sex': 'SEX',
  'card issuer': 'CARDISSUER',
};

// Per-label minimum confidence cutoffs. Calibrated against the
// pii-masking-300k benchmark — every cutoff is the value that pushed
// the precision/recall curve toward the (P>=0.90, R>=0.90) corner. See
// scripts/tune-cutoffs.js for the search procedure.
const LABEL_MIN_SCORE = {
  'title': Infinity,                  // always covered by regex
  'building': Infinity,               // too many bare-number FPs
  'username': 0.40, 'sex': 0.40,
  'first name': 0.40, 'last name': 0.40, 'person name': 0.42,
  'state': 0.60, 'country': 0.65, 'postal code': 0.50,
  'city': 0.60, 'street': 0.42, 'address': 0.50, 'secondary address': 0.40,
  'time': 0.50, 'date': 0.55, 'date of birth': 0.50,
  'password': 0.42,
  'ip address': 0.40, 'geographic coordinates': 0.40,
  'id card': 0.45, 'passport number': 0.45, 'driver license': 0.45,
  'social security number': 0.45,
  'phone number': 0.45, 'email address': 0.30, 'card issuer': 0.45,
};
const DEFAULT_MIN_SCORE = 0.40;

let helper = null;       // { proc, ready, pendingByid, queue, nextId }
let helperFailed = false;

function isEnabled() {
  try { return fs.existsSync(ML_MARKER); } catch (_) { return false; }
}

function modelFilesPresent() {
  try {
    return fs.existsSync(path.join(MODEL_DIR, 'onnx', 'model_quint8.onnx'))
        && fs.existsSync(path.join(MODEL_DIR, 'tokenizer.json'));
  } catch (_) { return false; }
}

function startHelper() {
  if (helper || helperFailed) return helper;

  const proc = spawn('python3', ['-u', HELPER], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: { ...process.env, PII_GUARD_ML_MODEL_DIR: MODEL_DIR },
  });
  const state = {
    proc,
    ready: false,
    pendingById: new Map(),
    nextId: 1,
    buffer: '',
  };
  helper = state;

  proc.stdout.on('data', chunk => {
    state.buffer += chunk.toString('utf8');
    let nl;
    while ((nl = state.buffer.indexOf('\n')) >= 0) {
      const line = state.buffer.slice(0, nl);
      state.buffer = state.buffer.slice(nl + 1);
      if (!line.trim()) continue;
      let msg;
      try { msg = JSON.parse(line); } catch { continue; }
      if (msg.error && !state.ready) {
        console.error('[PII Guard] ml-helper init failed:', msg.error);
        helperFailed = true;
        proc.kill();
        return;
      }
      if (msg.ready) {
        state.ready = true;
        console.log('[PII Guard] ml-helper ready (model=' + msg.model_dir + ')');
        continue;
      }
      const id = msg.id;
      const cb = state.pendingById.get(id);
      if (cb) {
        state.pendingById.delete(id);
        cb(msg.spans || []);
      }
    }
  });
  proc.stderr.on('data', chunk => {
    const s = chunk.toString('utf8').trim();
    if (s) console.error('[PII Guard ml]', s);
  });
  proc.on('exit', code => {
    if (!helperFailed) {
      console.error('[PII Guard] ml-helper exited unexpectedly (code=' + code + '); ML disabled until next restart');
    }
    helperFailed = true;
    helper = null;
    for (const cb of state.pendingById.values()) cb([]);
    state.pendingById.clear();
  });
  return state;
}

async function detectPIIWithMl(text) {
  if (!text || typeof text !== 'string' || text.length === 0) return [];
  if (!isEnabled() || !modelFilesPresent() || helperFailed) return [];

  const state = helper || startHelper();
  if (!state) return [];

  // Wait until helper is ready, then send the request.
  if (!state.ready) {
    const start = Date.now();
    while (!state.ready && !helperFailed && Date.now() - start < 30000) {
      await new Promise(r => setTimeout(r, 50));
    }
    if (!state.ready) return [];
  }

  const id = state.nextId++;
  const result = await new Promise(resolve => {
    state.pendingById.set(id, resolve);
    try {
      state.proc.stdin.write(JSON.stringify({ id, text }) + '\n');
    } catch (e) {
      state.pendingById.delete(id);
      resolve([]);
    }
    // Per-request soft timeout.
    setTimeout(() => {
      if (state.pendingById.has(id)) {
        state.pendingById.delete(id);
        resolve([]);
      }
    }, 10000);
  });

  // Map labels to types and apply per-label score cutoff.
  const out = [];
  for (const s of result) {
    const lbl = String(s.label || '').toLowerCase();
    const cut = LABEL_MIN_SCORE[lbl] !== undefined ? LABEL_MIN_SCORE[lbl] : DEFAULT_MIN_SCORE;
    if (cut === Infinity) continue;
    if ((s.score || 0) < cut) continue;
    const type = LABEL_TO_TYPE[lbl] || 'REDACTED';
    const len = s.end - s.start;
    if (lbl === 'username' && len < 4) continue;
    if (lbl === 'country' && (len <= 2 || len > 25)) continue;
    out.push({
      start: s.start, end: s.end,
      value: text.slice(s.start, s.end),
      type, label: lbl, score: s.score || 0,
    });
  }
  return out;
}

function mlStatus() {
  if (!isEnabled())            return { mode: 'regex-only', reason: 'marker-absent' };
  if (!modelFilesPresent())    return { mode: 'regex-only', reason: 'model-files-missing', modelDir: MODEL_DIR };
  if (helperFailed)            return { mode: 'regex-only', reason: 'helper-failed' };
  if (!helper || !helper.ready) return { mode: 'hybrid', loaded: false, modelDir: MODEL_DIR };
  return { mode: 'hybrid', loaded: true, modelDir: MODEL_DIR };
}

module.exports = { detectPIIWithMl, mlStatus, isEnabled };
