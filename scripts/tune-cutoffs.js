#!/usr/bin/env node
'use strict';

// Brute-force cutoff search over GLiNER per-label score thresholds to
// find the operating point that maximises min(P, R) >= 0.90 (or the
// best achievable point if 0.90 is unreachable).
//
// Reuses score-all.js's loaders by overriding GLINER_LABEL_MIN_SCORE
// at runtime via env var GLINER_CUTOFF_OVERRIDE='label=val,label=val'.

const fs = require('fs');
const path = require('path');
const { detectPII } = require('../lib/detector');
const { detectSupplementary } = require('../lib/supplementary-detector');

const INPUT = process.argv[2]
  || path.join(__dirname, 'data', 'english_validation.jsonl');
const PREDS_DIR = process.env.PII_GUARD_PREDS_DIR || '/tmp/pii-bench/predictions';

const GLINER_TO_GOLD = {
  'person name':           ['GIVENNAME1', 'GIVENNAME2', 'LASTNAME1', 'LASTNAME2', 'LASTNAME3'],
  'first name':            ['GIVENNAME1', 'GIVENNAME2'],
  'last name':             ['LASTNAME1', 'LASTNAME2', 'LASTNAME3'],
  'title':                 ['TITLE'],
  'email address':         ['EMAIL'],
  'phone number':          ['TEL'],
  'date of birth':         ['BOD'],
  'date':                  ['DATE'],
  'time':                  ['TIME'],
  'address':               ['STREET','BUILDING','SECADDRESS','CITY','STATE','COUNTRY','POSTCODE'],
  'street address':        ['STREET'],
  'city':                  ['CITY'],
  'state':                 ['STATE'],
  'country':               ['COUNTRY'],
  'postal code':           ['POSTCODE'],
  'street':                ['STREET'],
  'building':              ['BUILDING'],
  'secondary address':     ['SECADDRESS'],
  'geographic coordinates': ['GEOCOORD'],
  'id card':               ['IDCARD'],
  'social security number': ['SOCIALNUMBER'],
  'passport number':       ['PASSPORT'],
  'driver license':        ['DRIVERLICENSE'],
  'username':              ['USERNAME'],
  'ip address':            ['IP'],
  'password':              ['PASS'],
  'sex':                   ['SEX'],
  'card issuer':           ['CARDISSUER'],
};

const REGEX_GOLD_ACCEPTANCE = {
  EMAIL: ['EMAIL'], TEL: ['PHONE'], IP: ['IPV4', 'IPV6'],
  BOD: ['DOB'], DATE: ['DOB'],
  SOCIALNUMBER: ['SSN', 'NIC_LK', 'AADHAAR', 'NIN_UK'],
  PASSPORT: ['PASSPORT'],
  IDCARD: ['NIC_LK','AADHAAR','PAN_INDIA','PASSPORT','NIN_UK','SSN','IDCARD'],
  GIVENNAME1: ['NAME'], GIVENNAME2: ['NAME'],
  LASTNAME1: ['NAME'], LASTNAME2: ['NAME'], LASTNAME3: ['NAME'],
  CITY: ['ADDRESS'], STATE: ['ADDRESS','US_STATE'], STREET: ['ADDRESS'],
  POSTCODE: ['ADDRESS','POSTCODE'], COUNTRY: ['ADDRESS','COUNTRY'],
  BUILDING: ['ADDRESS'], SECADDRESS: ['ADDRESS','ADDRESS_UNIT'],
  PASS: ['PASSWORD_FIELD'], USERNAME: ['USERNAME','NAME'],
  TIME: ['TIME'], SEX: ['SEX'], TITLE: ['TITLE'],
  GEOCOORD: ['GEOCOORD'],
  DRIVERLICENSE: ['DRIVERLICENSE'],
  CARDISSUER: [],
};

function loadJsonl(p) {
  return fs.readFileSync(p, 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l));
}
function spanOverlap(a, b) { return a.start < b.end && b.start < a.end; }

function loadRegexPreds(entries) {
  return entries.map(e => {
    const text = e.source_text;
    const all = [...detectPII(text), ...detectSupplementary(text)];
    all.sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));
    const out = [];
    for (const d of all) {
      let overlap = false;
      for (const o of out) if (d.start < o.end && o.start < d.end && d.type === o.type) { overlap = true; break; }
      if (overlap) continue;
      const accepted = [];
      for (const [g, types] of Object.entries(REGEX_GOLD_ACCEPTANCE))
        if (types.includes(d.type)) accepted.push(g);
      out.push({ start: d.start, end: d.end, accepted, type: d.type });
    }
    return out;
  });
}

function loadMlRaw(name, n) {
  const p = path.join(PREDS_DIR, `${name}.jsonl`);
  if (!fs.existsSync(p)) { console.error(`missing ${p}`); process.exit(1); }
  const arr = new Array(n).fill(null).map(() => []);
  for (const line of fs.readFileSync(p, 'utf8').split('\n').filter(Boolean)) {
    const e = JSON.parse(line);
    if (e.idx < n) arr[e.idx] = (e.spans || []).map(s => ({
      start: s.start, end: s.end, label: String(s.label || '').toLowerCase(),
      score: typeof s.score === 'number' ? s.score : 1.0,
    }));
  }
  return arr;
}

function applyCutoffs(rawMl, cutoffs, defaultMin) {
  return rawMl.map(spans => {
    const out = [];
    for (const s of spans) {
      const cut = cutoffs[s.label] !== undefined ? cutoffs[s.label] : defaultMin;
      if (cut === Infinity) continue;
      if (s.score < cut) continue;
      const accepted = GLINER_TO_GOLD[s.label] || null;
      if (accepted === null) continue;
      // length filters borrowed from score-all v2
      const len = s.end - s.start;
      if (s.label === 'username' && len < 4) continue;
      if (s.label === 'country' && (len <= 2 || len > 25)) continue;
      out.push({ start: s.start, end: s.end, accepted, score: s.score, label: s.label });
    }
    return out;
  });
}

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

function score(entries, getPreds) {
  let tp = 0, fp = 0, fn = 0;
  for (let idx = 0; idx < entries.length; idx++) {
    const gold = entries[idx].privacy_mask || [];
    const pred = getPreds(idx);
    const gU = new Array(gold.length).fill(false);
    const pU = new Array(pred.length).fill(false);
    for (let i = 0; i < pred.length; i++) {
      for (let j = 0; j < gold.length; j++) {
        if (pU[i] || gU[j]) continue;
        if (spanOverlap(pred[i], gold[j])) { tp++; pU[i] = true; gU[j] = true; break; }
      }
    }
    for (let i = 0; i < pred.length; i++) if (!pU[i]) fp++;
    for (let j = 0; j < gold.length; j++) if (!gU[j]) fn++;
  }
  const p = tp / (tp + fp || 1);
  const r = tp / (tp + fn || 1);
  const f = p + r === 0 ? 0 : 2 * p * r / (p + r);
  return { p, r, f, tp, fp, fn };
}

function fmt(s) {
  return `P=${(s.p*100).toFixed(2)}%  R=${(s.r*100).toFixed(2)}%  F1=${(s.f*100).toFixed(2)}%   tp=${s.tp}  fp=${s.fp}  fn=${s.fn}`;
}

const BASE_CUTOFFS = {
  'title': Infinity, 'building': Infinity,
  'username': 0.40, 'sex': 0.40, 'first name': 0.40, 'last name': 0.40,
  'person name': 0.42, 'state': 0.60, 'country': 0.65, 'postal code': 0.50,
  'city': 0.60, 'street': 0.42, 'address': 0.50, 'secondary address': 0.40,
  'time': 0.50, 'date': 0.55, 'date of birth': 0.50, 'password': 0.42,
  'ip address': 0.40, 'geographic coordinates': 0.40, 'id card': 0.45,
  'passport number': 0.45, 'driver license': 0.45, 'social security number': 0.45,
  'phone number': 0.45, 'email address': 0.30, 'card issuer': 0.45,
};

function main() {
  console.log(`Loading ${INPUT}...`);
  const entries = loadJsonl(INPUT);
  console.log(`Loaded ${entries.length} entries`);

  console.log('Running regex+supplementary...');
  const regexPred = loadRegexPreds(entries);
  const modelTag = process.env.PII_GUARD_BENCH_MODEL || 'gliner_int8';
  console.log(`Loading raw GLiNER predictions (${modelTag})...`);
  const rawMl = loadMlRaw(modelTag, entries.length);

  // 1. Baseline
  console.log('\n## Baseline (current cutoffs)');
  const mlBase = applyCutoffs(rawMl, BASE_CUTOFFS, 0.40);
  const baseScore = score(entries, i => mergeSpans(regexPred[i], mlBase[i]));
  console.log('  ' + fmt(baseScore));

  // 2. Cutoff sweep — try 5 perturbations per label and find the
  // monotonically-best F1 setting.
  const labels = Object.keys(GLINER_TO_GOLD);
  let best = { ...BASE_CUTOFFS };
  let bestScore = baseScore;
  let bestF = baseScore.f;
  // Two-pass: lower cutoffs (gain recall), then raise (gain precision).
  const candidates = [0.30, 0.32, 0.35, 0.38, 0.40, 0.42, 0.45, 0.50, 0.55, 0.60, 0.65, 0.70, Infinity];
  for (let pass = 0; pass < 3; pass++) {
    let improved = false;
    for (const lbl of labels) {
      const cur = best[lbl];
      let bestCutForLbl = cur;
      let bestFForLbl = bestF;
      for (const c of candidates) {
        const trial = { ...best, [lbl]: c };
        const ml = applyCutoffs(rawMl, trial, 0.40);
        const s = score(entries, i => mergeSpans(regexPred[i], ml[i]));
        // Maximise min(P,R) when both are <0.90; otherwise maximise F1.
        const targetA = Math.min(s.p, s.r);
        const targetB = Math.min(bestScore.p, bestScore.r);
        const better = targetA >= 0.90 && targetB >= 0.90 ? s.f > bestF : targetA > targetB;
        if (better) {
          bestCutForLbl = c; bestFForLbl = s.f; bestScore = s;
        }
      }
      if (bestCutForLbl !== cur) {
        best[lbl] = bestCutForLbl; bestF = bestFForLbl; improved = true;
      }
    }
    console.log(`\n## After pass ${pass+1}: ` + fmt(bestScore));
    if (!improved) break;
  }

  console.log('\n## Final cutoffs:');
  for (const [k, v] of Object.entries(best)) {
    if (v !== BASE_CUTOFFS[k]) console.log(`  ${k}: ${BASE_CUTOFFS[k]} → ${v}`);
  }
  console.log('\n## Final score: ' + fmt(bestScore));
}

main();
