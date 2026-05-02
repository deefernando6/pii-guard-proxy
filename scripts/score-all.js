#!/usr/bin/env node
'use strict';

// Span-level F1 for the 4 detection scenarios on the English validation
// split of ai4privacy/pii-masking-300k:
//
//   regex-only          — proxy's lib/detector.js
//   regex + gliner_int8 — regex ∪ GLiNER PII Small (ours, INT8 ONNX)
//   regex + gliner_fp32 — regex ∪ GLiNER PII Small (FP32 PyTorch)
//   regex + deberta     — regex ∪ DeBERTa-v3-base ai4privacy FT
//
// ML predictions come from /tmp/pii-bench/predictions/{model}.jsonl, which
// is what benchmark_ml.py writes. ML-predicted spans whose label maps to a
// known proxy type override the same span in regex (regex always wins on
// overlaps); ML spans that DON'T overlap any regex span are added.
//
// Same span-overlap any-type / type-aware F1 framework as
// scripts/benchmark-pii-masking-300k.js in the proxy repo.

const fs = require('fs');
const path = require('path');
// When this script is in the proxy repo at scripts/score-all.js the
// detector lives one level up at lib/detector.js. The /tmp copy used
// during the original benchmark also resolved to the same module via
// an absolute path; relative is more portable.
const { detectPII } = require(process.env.PII_GUARD_DETECTOR
  || require('path').join(__dirname, '..', 'lib', 'detector'));

const INPUT = process.argv[2] || '/tmp/pii-bench/english_validation.jsonl';
const PREDS_DIR = '/tmp/pii-bench/predictions';

const LABEL_MAP = {
  EMAIL: ['EMAIL'],
  TEL: ['PHONE'],
  IP: ['IPV4', 'IPV6'],
  BOD: ['DOB'],
  DATE: ['DOB'],
  SOCIALNUMBER: ['SSN', 'NIC_LK', 'AADHAAR', 'NIN_UK'],
  PASSPORT: ['PASSPORT'],
  IDCARD: ['NIC_LK', 'AADHAAR', 'PAN_INDIA', 'PASSPORT', 'NIN_UK', 'SSN'],
  GIVENNAME1: ['NAME'], GIVENNAME2: ['NAME'],
  LASTNAME1: ['NAME'], LASTNAME2: ['NAME'], LASTNAME3: ['NAME'],
  CITY: ['ADDRESS'], STATE: ['ADDRESS'], STREET: ['ADDRESS'],
  POSTCODE: ['ADDRESS'], COUNTRY: ['ADDRESS'], BUILDING: ['ADDRESS'],
  SECADDRESS: ['ADDRESS'], PASS: ['PASSWORD_FIELD'],
  USERNAME: [], TIME: [], SEX: [], TITLE: [], GEOCOORD: [],
  CARDISSUER: [], DRIVERLICENSE: [],
};

// GLiNER / DeBERTa label → proxy type. Both models use natural-language
// or BIO-style labels; collapse to the proxy taxonomy so type-aware F1
// can compare apples to apples.
const ML_LABEL_TO_TYPE = {
  'person': 'NAME',
  'person name': 'NAME',
  'first name': 'NAME',
  'last name': 'NAME',
  'name': 'NAME',
  'firstname': 'NAME',
  'lastname': 'NAME',
  'givenname1': 'NAME',
  'givenname2': 'NAME',
  'lastname1': 'NAME',
  'lastname2': 'NAME',
  'lastname3': 'NAME',
  'username': 'USERNAME',           // covered by ML, not regex
  'email address': 'EMAIL',
  'email': 'EMAIL',
  'phone number': 'PHONE',
  'phone': 'PHONE',
  'tel': 'PHONE',
  'ip address': 'IPV4',
  'ip': 'IPV4',
  'date of birth': 'DOB',
  'dob': 'DOB',
  'bod': 'DOB',
  'date': 'DOB',
  'time': 'TIME',
  'address': 'ADDRESS',
  'street address': 'ADDRESS',
  'street': 'ADDRESS',
  'city': 'ADDRESS',
  'state': 'ADDRESS',
  'country': 'ADDRESS',
  'postal code': 'ADDRESS',
  'postcode': 'ADDRESS',
  'building': 'ADDRESS',
  'secondary address': 'ADDRESS',
  'secaddress': 'ADDRESS',
  'geographic coordinates': 'GEOCOORD',
  'geocoord': 'GEOCOORD',
  'id card': 'NIC_LK',
  'idcard': 'NIC_LK',
  'social security number': 'SSN',
  'socialnumber': 'SSN',
  'passport number': 'PASSPORT',
  'passport': 'PASSPORT',
  'driver license': 'DRIVERLICENSE',
  'driverlicense': 'DRIVERLICENSE',
  'password': 'PASSWORD_FIELD',
  'pass': 'PASSWORD_FIELD',
  'sex': 'SEX',
  'card issuer': 'CARDISSUER',
  'cardissuer': 'CARDISSUER',
  'title': 'TITLE',
};

// Allow the type-aware match to accept "any plausible mapping" — gold
// label PASSPORT can be hit by ML labels that map to PASSPORT, and gold
// label USERNAME (which regex never covers) is now reachable through
// ML labels mapping to USERNAME. Built dynamically from LABEL_MAP plus
// the new ML categories.
const ML_GOLD_ACCEPTANCE = {
  ...LABEL_MAP,
  USERNAME: ['USERNAME'],
  TIME: ['TIME'],
  SEX: ['SEX'],
  TITLE: ['TITLE'],
  GEOCOORD: ['GEOCOORD'],
  CARDISSUER: ['CARDISSUER'],
  DRIVERLICENSE: ['DRIVERLICENSE'],
};

function spanOverlap(a, b) { return a.start < b.end && b.start < a.end; }
function spanExact(a, b) { return a.start === b.start && a.end === b.end; }

function loadJsonl(p) {
  return fs.readFileSync(p, 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l));
}

function loadMlPreds(name, n) {
  const p = path.join(PREDS_DIR, `${name}.jsonl`);
  if (!fs.existsSync(p)) return null;
  const arr = new Array(n).fill(null).map(() => []);
  for (const line of fs.readFileSync(p, 'utf8').split('\n').filter(Boolean)) {
    const e = JSON.parse(line);
    if (e.idx < n) {
      arr[e.idx] = (e.spans || []).map(s => ({
        start: s.start, end: s.end,
        type: ML_LABEL_TO_TYPE[String(s.label || '').toLowerCase()] || 'REDACTED',
        label: String(s.label || '').toLowerCase(),
        score: s.score,
      }));
    }
  }
  return arr;
}

// Merge regex spans + ML spans. Regex always wins on overlap.
function mergeSpans(regex, ml) {
  if (!ml || ml.length === 0) return regex;
  const out = [...regex];
  for (const m of ml) {
    let overlap = false;
    for (const r of regex) if (spanOverlap(m, r)) { overlap = true; break; }
    if (!overlap) out.push(m);
  }
  return out;
}

function f1(tp, fp, fn) {
  const p = tp + fp === 0 ? 0 : tp / (tp + fp);
  const r = tp + fn === 0 ? 0 : tp / (tp + fn);
  const f = p + r === 0 ? 0 : 2 * p * r / (p + r);
  return { p, r, f };
}

function score(entries, getPreds, acceptance) {
  let strict = { tp: 0, fp: 0, fn: 0 }, lenient = { tp: 0, fp: 0, fn: 0 };
  let strictAny = { tp: 0, fp: 0, fn: 0 }, lenientAny = { tp: 0, fp: 0, fn: 0 };
  const byLabel = {}; // gold label → { tp, fn } for lenient any-type

  for (let idx = 0; idx < entries.length; idx++) {
    const e = entries[idx];
    const gold = e.privacy_mask || [];
    const pred = getPreds(idx);

    for (const [m, matchFn, anyM] of [
      [strict, spanExact, strictAny],
      [lenient, spanOverlap, lenientAny],
    ]) {
      // type-aware
      const gU = new Array(gold.length).fill(false);
      const pU = new Array(pred.length).fill(false);
      for (let i = 0; i < pred.length; i++) {
        for (let j = 0; j < gold.length; j++) {
          if (pU[i] || gU[j]) continue;
          if (!matchFn(pred[i], gold[j])) continue;
          const accepted = acceptance[gold[j].label] || [];
          if (accepted.includes(pred[i].type)) {
            m.tp++; pU[i] = true; gU[j] = true; break;
          }
        }
      }
      for (let i = 0; i < pred.length; i++) if (!pU[i]) m.fp++;
      for (let j = 0; j < gold.length; j++) if (!gU[j]) m.fn++;

      // any-type
      const gU2 = new Array(gold.length).fill(false);
      const pU2 = new Array(pred.length).fill(false);
      for (let i = 0; i < pred.length; i++) {
        for (let j = 0; j < gold.length; j++) {
          if (pU2[i] || gU2[j]) continue;
          if (matchFn(pred[i], gold[j])) {
            anyM.tp++; pU2[i] = true; gU2[j] = true; break;
          }
        }
      }
      for (let i = 0; i < pred.length; i++) if (!pU2[i]) anyM.fp++;
      for (let j = 0; j < gold.length; j++) if (!gU2[j]) anyM.fn++;

      // per-label only on the lenient any-type pass (most informative)
      if (matchFn === spanOverlap) {
        for (let j = 0; j < gold.length; j++) {
          const lbl = gold[j].label;
          if (!byLabel[lbl]) byLabel[lbl] = { tp: 0, fn: 0 };
          if (gU2[j]) byLabel[lbl].tp++;
          else byLabel[lbl].fn++;
        }
      }
    }
  }
  return { strict, lenient, strictAny, lenientAny, byLabel };
}

function row(label, m) {
  const o = f1(m.tp, m.fp, m.fn);
  return `${label.padEnd(22)} P=${(o.p*100).toFixed(2).padStart(6)}%  R=${(o.r*100).toFixed(2).padStart(6)}%  F1=${(o.f*100).toFixed(2).padStart(6)}%   tp=${m.tp}  fp=${m.fp}  fn=${m.fn}`;
}

function reportScenario(name, s) {
  console.log(`\n## ${name}`);
  console.log(`  ${row('STRICT  type-aware', s.strict)}`);
  console.log(`  ${row('STRICT  any-type',   s.strictAny)}`);
  console.log(`  ${row('LENIENT type-aware', s.lenient)}`);
  console.log(`  ${row('LENIENT any-type',   s.lenientAny)}`);
}

function reportPerLabel(scenarios) {
  // Aggregated table: per gold label, recall under each scenario (any-type lenient).
  const labels = new Set();
  for (const s of Object.values(scenarios)) for (const k of Object.keys(s.byLabel)) labels.add(k);
  const lblArr = [...labels].sort();
  const names = Object.keys(scenarios);
  console.log(`\n## Per-gold-label recall (any-type, lenient)`);
  console.log(`${'label'.padEnd(15)} ${'gold'.padStart(6)}  ` + names.map(n => n.padStart(11)).join('  '));
  for (const lbl of lblArr) {
    const goldN = (scenarios[names[0]].byLabel[lbl] || { tp:0, fn:0 });
    const total = goldN.tp + goldN.fn;
    const cells = names.map(n => {
      const r = scenarios[n].byLabel[lbl] || { tp:0, fn:0 };
      const tot = r.tp + r.fn;
      const recall = tot === 0 ? 0 : r.tp / tot;
      return `${(recall*100).toFixed(1).padStart(10)}%`;
    });
    console.log(`${lbl.padEnd(15)} ${String(total).padStart(6)}  ${cells.join('  ')}`);
  }
}

function main() {
  console.log(`Loading ${INPUT}...`);
  const entries = loadJsonl(INPUT);
  console.log(`Loaded ${entries.length} entries`);

  // 1. regex predictions in-memory
  console.log(`Running regex on every entry...`);
  const t0 = Date.now();
  const regexPred = entries.map(e => detectPII(e.source_text));
  console.log(`  done in ${((Date.now() - t0) / 1000).toFixed(1)}s`);

  // 2. load ML predictions
  const mlInt8  = loadMlPreds('gliner_int8', entries.length);
  const mlFp32  = loadMlPreds('gliner_fp32', entries.length);
  const mlDeb   = loadMlPreds('deberta',     entries.length);
  console.log(`ML predictions loaded: gliner_int8=${mlInt8?'yes':'NO'}, gliner_fp32=${mlFp32?'yes':'NO'}, deberta=${mlDeb?'yes':'NO'}`);

  const scenarios = {};
  scenarios['regex-only']        = score(entries, i => regexPred[i], LABEL_MAP);
  if (mlInt8) scenarios['regex+gliner_int8']  = score(entries, i => mergeSpans(regexPred[i], mlInt8[i]),  ML_GOLD_ACCEPTANCE);
  if (mlFp32) scenarios['regex+gliner_fp32']  = score(entries, i => mergeSpans(regexPred[i], mlFp32[i]),  ML_GOLD_ACCEPTANCE);
  if (mlDeb)  scenarios['regex+deberta_base'] = score(entries, i => mergeSpans(regexPred[i], mlDeb[i]),   ML_GOLD_ACCEPTANCE);

  for (const [name, s] of Object.entries(scenarios)) reportScenario(name, s);
  reportPerLabel(scenarios);
}

main();
