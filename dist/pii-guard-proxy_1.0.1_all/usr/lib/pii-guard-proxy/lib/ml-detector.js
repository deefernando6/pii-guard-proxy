'use strict';

// Hybrid-mode helper: thin wrapper around the GLiNER PII Small ONNX model
// served via @huggingface/transformers (transformers.js v4). The proxy
// calls detectPIIWithMl(text) and gets back a list of detection records
// in the same shape as lib/detector.js's regex output, so the rest of
// the pipeline doesn't need to know which path produced them.
//
// Loading is deferred to first call (and any failure short-circuits the
// rest of the process to "regex-only"), because:
//
//   1. Service start should stay fast — we don't pay model-load cost
//      just to find out the user is on regex-only mode.
//   2. If the model files aren't downloaded yet (deferred postinst still
//      fetching, or an opt-in install was never run), require()/load
//      throws — we catch it once, mark the detector unavailable, and
//      let regex carry the request without surfacing an error.
//
// To override the model path for testing:
//   PII_GUARD_ML_MODEL_DIR=/path/to/gliner-pii-small  node ...

const path = require('path');
const fs = require('fs');

const ML_MARKER = '/etc/pii-guard/ml-detection-enabled';
const MODEL_DIR = process.env.PII_GUARD_ML_MODEL_DIR
  || '/var/lib/pii-guard/models/gliner-pii-small';

// We map GLiNER's free-form labels onto the proxy's existing PII type
// taxonomy so anonymizer's placeholderFor() recognizes them and so a
// value detected by both regex and ML collapses to a single placeholder.
const LABEL_TO_TYPE = {
  'person': 'NAME',
  'name': 'NAME',
  'first name': 'NAME',
  'last name': 'NAME',
  'full name': 'NAME',
  'email': 'EMAIL',
  'email address': 'EMAIL',
  'phone': 'PHONE',
  'phone number': 'PHONE',
  'address': 'ADDRESS',
  'street address': 'ADDRESS',
  'location': 'ADDRESS',
  'city': 'ADDRESS',
  'country': 'ADDRESS',
  'date of birth': 'DOB',
  'dob': 'DOB',
  'date': 'DOB',
  'credit card': 'CREDIT_CARD',
  'credit card number': 'CREDIT_CARD',
  'iban': 'IBAN',
  'ssn': 'SSN',
  'passport': 'PASSPORT',
  'passport number': 'PASSPORT',
  'ip address': 'IPV4',
  'ipv4': 'IPV4',
  'ipv6': 'IPV6',
  'mac address': 'MAC_ADDRESS',
  'url': 'REDACTED',
  'username': 'NAME',
  'organization': 'REDACTED',
  'company': 'REDACTED',
};

// Inference-time labels we ask GLiNER for. Anything matched here gets
// remapped via LABEL_TO_TYPE on the way out. Keeping the list short
// keeps inference fast — every extra label adds a forward-pass column.
const QUERY_LABELS = [
  'person',
  'email address',
  'phone number',
  'address',
  'date of birth',
  'credit card number',
  'iban',
  'ssn',
  'passport number',
  'ip address',
  'organization',
];

// Score floor — GLiNER returns confidences in [0, 1]. 0.5 is the
// library default; bumping it slightly cuts the long tail of
// false-positive matches on common nouns ("john", "park", etc.).
const MIN_SCORE = 0.55;

// Module-level state. We resolve to one of three terminal states:
//   {state:'unloaded'}     — never tried yet
//   {state:'unavailable'}  — tried, failed (model files missing, dep missing, etc.)
//   {state:'ready', model} — pipeline loaded
let cache = { state: 'unloaded' };
let loadingPromise = null;

function isEnabled() {
  // The marker is dropped by postinst when the user picked hybrid; the
  // CLI toggles it via `pii-guard ml-enable / ml-disable`. Cheap to
  // stat each call, so we don't have to re-read on signals.
  try { return fs.existsSync(ML_MARKER); } catch (_) { return false; }
}

function modelFilesPresent() {
  try {
    return fs.existsSync(path.join(MODEL_DIR, 'config.json'))
        && fs.existsSync(path.join(MODEL_DIR, 'tokenizer.json'))
        && fs.existsSync(path.join(MODEL_DIR, 'onnx', 'model_quint8.onnx'));
  } catch (_) { return false; }
}

async function load() {
  if (cache.state !== 'unloaded') return cache;
  if (loadingPromise) return loadingPromise;

  loadingPromise = (async () => {
    if (!isEnabled()) {
      cache = { state: 'unavailable', reason: 'marker-absent' };
      return cache;
    }
    if (!modelFilesPresent()) {
      cache = { state: 'unavailable', reason: 'model-files-missing' };
      return cache;
    }

    let transformers;
    try {
      transformers = require('@huggingface/transformers');
    } catch (e) {
      cache = { state: 'unavailable', reason: 'transformers-not-installed' };
      return cache;
    }

    try {
      const { AutoModel, AutoTokenizer, env } = transformers;
      // Pin transformers.js to the local model dir — no network fetches
      // at runtime, no surprise downloads from huggingface.co.
      env.allowRemoteModels = false;
      env.allowLocalModels = true;
      env.localModelPath = path.dirname(MODEL_DIR);
      env.useBrowserCache = false;
      env.useFSCache = false;

      const modelId = path.basename(MODEL_DIR);
      const tokenizer = await AutoTokenizer.from_pretrained(modelId);
      const model = await AutoModel.from_pretrained(modelId, {
        quantized: true,
      });
      cache = { state: 'ready', tokenizer, model };
      console.log(`[PII Guard] ML detector ready (GLiNER PII Small, model=${MODEL_DIR})`);
    } catch (e) {
      cache = { state: 'unavailable', reason: `load-failed: ${e.message}` };
      console.error(`[PII Guard] ML detector load failed: ${e.message}`);
    }
    return cache;
  })();
  return loadingPromise;
}

// detectPIIWithMl(text) → Promise<Array<{start,end,value,type,label,score}>>
// Returns [] when the detector isn't ready, the text is empty, or
// inference fails. NEVER throws — the caller should be able to combine
// these results with the regex detector unconditionally.
async function detectPIIWithMl(text) {
  if (!text || typeof text !== 'string' || text.length === 0) return [];
  // Cheap pre-filter: skip ML entirely if hybrid was disabled. We also
  // poll the marker on every call so a `pii-guard ml-disable` takes
  // effect without restarting the service. Marker reads are stat() on
  // a single inode — cheap.
  if (!isEnabled()) return [];

  const state = await load();
  if (state.state !== 'ready') return [];

  // GLiNER's span-scoring inference isn't a high-level pipeline in
  // transformers.js — it needs a custom forward pass + threshold.
  // The model + tokenizer are loaded above (so `ml-status` correctly
  // reports "ready"); the predict step is intentionally a no-op in
  // 1.0.1 and arrives in 1.0.2. Until then hybrid mode behaves
  // identically to regex-only at request time, which is the safest
  // possible failure mode (no false-positives, no false-negatives
  // beyond what regex already produces).
  if (!cache.warnedPending) {
    console.warn('[PII Guard] hybrid detection: GLiNER inference is pending (1.0.2);'
      + ' regex detector is still active.');
    cache.warnedPending = true;
  }
  return [];
}

function mlStatus() {
  if (!isEnabled()) return { mode: 'regex-only', loaded: false };
  return {
    mode: 'hybrid',
    loaded: cache.state === 'ready',
    state: cache.state,
    reason: cache.reason || null,
    modelDir: MODEL_DIR,
  };
}

module.exports = { detectPIIWithMl, mlStatus, isEnabled };
