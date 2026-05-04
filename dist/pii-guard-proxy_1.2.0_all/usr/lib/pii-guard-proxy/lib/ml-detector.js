'use strict';

// Hybrid PII detection via a long-lived Python helper that loads both
// GLiNER PII Small INT8 and GLiNER PII Base INT8 ONNX models. Each
// inference call returns predictions from BOTH models; this Node side
// applies per-(model, label) score cutoffs that were learned by the
// scripts/tune-merged.js search on ai4privacy/pii-masking-300k.
//
// The ensemble exists for one reason: neither model alone broke
// recall ≥ 90% on the benchmark (each plateaued around F1 84%).
// Combining them and tuning cutoffs lands the deployed proxy at:
//   P=87.23%  R=90.62%  F1=88.89%   (LENIENT any-type span overlap)
//
// Lifecycle:
//   - First call to detectPIIWithMl() spawns python3 lib/ml-helper.py
//   - Each call sends one NDJSON request and awaits one NDJSON response
//   - On crash / timeout, we fail the in-flight request, mark the
//     detector unavailable, and let regex carry the request alone.

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const ML_MARKER  = '/etc/pii-guard/ml-detection-enabled';
const HELPER     = path.join(__dirname, 'ml-helper.py');
const SMALL_DIR  = process.env.PII_GUARD_ML_SMALL_DIR
  || '/var/lib/pii-guard/models/gliner-pii-small';
const BASE_DIR   = process.env.PII_GUARD_ML_BASE_DIR
  || '/var/lib/pii-guard/models/gliner-pii-base';

const LABEL_TO_TYPE = {
  'person name': 'NAME', 'full name': 'NAME',
  'first name': 'NAME', 'given name': 'NAME', 'middle name': 'NAME',
  'last name': 'NAME', 'surname': 'NAME', 'family name': 'NAME',
  'title': 'TITLE', 'honorific': 'TITLE', 'salutation': 'TITLE',
  'email address': 'EMAIL',
  'phone number': 'PHONE', 'telephone': 'PHONE',
  'date of birth': 'DOB', 'birthdate': 'DOB', 'date': 'DOB',
  'time': 'TIME',
  'address': 'ADDRESS', 'street address': 'ADDRESS', 'street': 'ADDRESS',
  'city': 'ADDRESS', 'state': 'ADDRESS', 'country': 'ADDRESS',
  'postal code': 'ADDRESS', 'zipcode': 'ADDRESS', 'building': 'ADDRESS',
  'building number': 'ADDRESS', 'secondary address': 'ADDRESS',
  'apartment': 'ADDRESS', 'suite': 'ADDRESS',
  'geographic coordinates': 'GEOCOORD', 'latitude': 'GEOCOORD', 'longitude': 'GEOCOORD',
  'id card': 'IDCARD', 'national id': 'IDCARD',
  'social security number': 'SSN',
  'passport number': 'PASSPORT',
  'driver license': 'DRIVERLICENSE', 'drivers licence': 'DRIVERLICENSE',
  'username': 'USERNAME', 'user name': 'USERNAME',
  'ip address': 'IPV4', 'ipv4': 'IPV4', 'ipv6': 'IPV6',
  'password': 'PASSWORD_FIELD',
  'sex': 'SEX', 'gender': 'SEX',
  'card issuer': 'CARDISSUER',
};

// Per-(model, label) score cutoffs found by scripts/tune-merged.js.
// "Infinity" means drop every prediction with that label (the model is
// too noisy on this category to be worth keeping).
const CUT_SMALL = {
  "person name": 0.45, "full name": 0.35, "first name": 0.4,
  "given name": 0.35, "middle name": 0.4, "last name": 0.3,
  "surname": 0.45, "family name": 0.4,
  "title": Infinity, "honorific": 0.45, "salutation": 0.65,
  "email address": Infinity, "phone number": 0.3, "telephone": 0.45,
  "date of birth": Infinity, "birthdate": Infinity, "date": Infinity,
  "time": 0.45,
  "address": 0.3, "street address": 0.2, "city": 0.6,
  "state": Infinity, "country": Infinity,
  "postal code": 0.4, "zipcode": 0.45, "street": 0.4,
  "building": Infinity, "building number": 0.4,
  "secondary address": 0.35, "apartment": 0.45, "suite": Infinity,
  "geographic coordinates": Infinity, "latitude": 0.6, "longitude": 0.4,
  "id card": 0.4, "national id": 0.45,
  "social security number": 0.5, "passport number": 0.4,
  "driver license": 0.4, "drivers licence": 0.45,
  "username": 0.45, "user name": 0.4,
  "ip address": Infinity, "ipv4": 0.3, "ipv6": 0.55,
  "password": 0.45, "sex": Infinity, "gender": 0.6,
  "card issuer": 0.3,
};
const CUT_BASE = {
  "person name": 0.35, "full name": 0.4, "first name": 0.35,
  "given name": 0.4, "middle name": 0.4, "last name": 0.3,
  "surname": 0.4, "family name": 0.4,
  "title": 0.75, "honorific": 0.4, "salutation": 0.4,
  "email address": Infinity, "phone number": Infinity, "telephone": 0.4,
  "date of birth": Infinity, "birthdate": 0.4, "date": Infinity,
  "time": 0.4,
  "address": 0.35, "street address": 0.4, "city": 0.3,
  "state": 0.35, "country": Infinity,
  "postal code": 0.3, "zipcode": 0.4, "street": 0.3,
  "building": Infinity, "building number": 0.4,
  "secondary address": 0.3, "apartment": 0.4, "suite": 0.4,
  "geographic coordinates": Infinity, "latitude": 0.4, "longitude": 0.4,
  "id card": 0.3, "national id": 0.4,
  "social security number": 0.6, "passport number": 0.55,
  "driver license": 0.45, "drivers licence": 0.4,
  "username": 0.8, "user name": 0.4,
  "ip address": Infinity, "ipv4": 0.4, "ipv6": 0.4,
  "password": Infinity, "sex": Infinity, "gender": 0.4,
  "card issuer": 0.4,
};
const DEFAULT_MIN = 0.40;

let helper = null;
let helperFailed = false;

function isEnabled() {
  try { return fs.existsSync(ML_MARKER); } catch (_) { return false; }
}

function modelFilesPresent() {
  try {
    return fs.existsSync(path.join(SMALL_DIR, 'onnx', 'model_quint8.onnx'))
        && fs.existsSync(path.join(BASE_DIR,  'onnx', 'model_quint8.onnx'))
        && fs.existsSync(path.join(SMALL_DIR, 'tokenizer.json'))
        && fs.existsSync(path.join(BASE_DIR,  'tokenizer.json'));
  } catch (_) { return false; }
}

function startHelper() {
  if (helper || helperFailed) return helper;
  const proc = spawn('python3', ['-u', HELPER], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: { ...process.env,
      PII_GUARD_ML_SMALL_DIR: SMALL_DIR,
      PII_GUARD_ML_BASE_DIR: BASE_DIR,
    },
  });
  const state = { proc, ready: false, pendingById: new Map(), nextId: 1, buffer: '' };
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
        console.log('[PII Guard] ml-helper ready (small=' + msg.small_dir + ', base=' + msg.base_dir + ')');
        continue;
      }
      const id = msg.id;
      const cb = state.pendingById.get(id);
      if (cb) {
        state.pendingById.delete(id);
        cb(msg);
      }
    }
  });
  proc.stderr.on('data', chunk => {
    const s = chunk.toString('utf8').trim();
    if (s) console.error('[PII Guard ml]', s);
  });
  proc.on('exit', code => {
    if (!helperFailed) {
      console.error('[PII Guard] ml-helper exited (code=' + code + '); ML disabled until next restart');
    }
    helperFailed = true;
    helper = null;
    for (const cb of state.pendingById.values()) cb({ spans_small: [], spans_base: [] });
    state.pendingById.clear();
  });
  return state;
}

function spanOverlap(a, b) { return a.start < b.end && b.start < a.end; }

function applyCutoffs(spans, cuts, text) {
  const out = [];
  for (const s of spans) {
    const lbl = String(s.label || '').toLowerCase();
    const cut = cuts[lbl] !== undefined ? cuts[lbl] : DEFAULT_MIN;
    if (cut === Infinity) continue;
    if ((s.score || 0) < cut) continue;
    const type = LABEL_TO_TYPE[lbl];
    if (!type) continue;
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

async function detectPIIWithMl(text) {
  if (!text || typeof text !== 'string' || text.length === 0) return [];
  if (!isEnabled() || !modelFilesPresent() || helperFailed) return [];

  const state = helper || startHelper();
  if (!state) return [];
  if (!state.ready) {
    const start = Date.now();
    while (!state.ready && !helperFailed && Date.now() - start < 60000) {
      await new Promise(r => setTimeout(r, 100));
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
      resolve({ spans_small: [], spans_base: [] });
    }
    setTimeout(() => {
      if (state.pendingById.has(id)) {
        state.pendingById.delete(id);
        resolve({ spans_small: [], spans_base: [] });
      }
    }, 15000);
  });

  // Apply per-model cutoffs, then merge: small first, base only adds
  // spans that don't overlap any small/regex span (regex+small wins overlaps).
  const small = applyCutoffs(result.spans_small || [], CUT_SMALL, text);
  const base  = applyCutoffs(result.spans_base  || [], CUT_BASE,  text);
  const merged = [...small];
  for (const b of base) {
    let overlap = false;
    for (const s of small) if (spanOverlap(b, s)) { overlap = true; break; }
    if (!overlap) merged.push(b);
  }
  return merged;
}

function mlStatus() {
  if (!isEnabled())            return { mode: 'regex-only', reason: 'marker-absent' };
  if (!modelFilesPresent())    return { mode: 'regex-only', reason: 'model-files-missing', smallDir: SMALL_DIR, baseDir: BASE_DIR };
  if (helperFailed)            return { mode: 'regex-only', reason: 'helper-failed' };
  if (!helper || !helper.ready) return { mode: 'hybrid', loaded: false, smallDir: SMALL_DIR, baseDir: BASE_DIR };
  return { mode: 'hybrid', loaded: true, smallDir: SMALL_DIR, baseDir: BASE_DIR };
}

module.exports = { detectPIIWithMl, mlStatus, isEnabled };
