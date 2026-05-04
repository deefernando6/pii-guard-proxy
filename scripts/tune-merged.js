#!/usr/bin/env node
'use strict';

// Aggressive tuner for the merged regex + gliner_small + gliner_base
// stack. Goal: find the (per-label cutoff small, per-label cutoff base)
// configuration that maximises F1 while keeping both P and R as close
// to 0.90 as possible.

const fs = require('fs');
const path = require('path');
const { detectPII } = require('../lib/detector');
const { detectSupplementary } = require('../lib/supplementary-detector');

const INPUT = path.join(__dirname, 'data', 'english_validation.jsonl');
const PREDS_DIR = '/tmp/pii-bench/predictions';

const GLINER_TO_GOLD = require('./gliner-label-map.json');

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
  if (!fs.existsSync(p)) return null;
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
      const len = s.end - s.start;
      if (s.label === 'username' && len < 4) continue;
      if (s.label === 'country' && (len <= 2 || len > 25)) continue;
      out.push({ start: s.start, end: s.end, accepted });
    }
    return out;
  });
}

function mergeSpans(...lists) {
  const out = [];
  for (const list of lists) {
    if (!list) continue;
    for (const s of list) {
      let overlap = false;
      for (const e of out) if (spanOverlap(s, e)) { overlap = true; break; }
      if (!overlap) out.push(s);
    }
  }
  return out;
}

function score(entries, getPreds, capturePerLabel) {
  let tp = 0, fp = 0, fn = 0;
  const byLabel = {};
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
    if (capturePerLabel) {
      for (let j = 0; j < gold.length; j++) {
        const k = gold[j].label;
        if (!byLabel[k]) byLabel[k] = { tp: 0, fn: 0 };
        if (gU[j]) byLabel[k].tp++; else byLabel[k].fn++;
      }
    }
  }
  const p = tp / (tp + fp || 1);
  const r = tp / (tp + fn || 1);
  const f = p + r === 0 ? 0 : 2 * p * r / (p + r);
  return { p, r, f, tp, fp, fn, byLabel };
}

const fmt = s => `P=${(s.p*100).toFixed(2)}%  R=${(s.r*100).toFixed(2)}%  F1=${(s.f*100).toFixed(2)}%  tp=${s.tp} fp=${s.fp} fn=${s.fn}`;

const ALL_LABELS = Object.keys(GLINER_TO_GOLD);
const CANDIDATES = [Infinity, 0.85, 0.80, 0.75, 0.70, 0.65, 0.60, 0.55, 0.50, 0.45, 0.40, 0.35, 0.30, 0.20, 0.10];

function main() {
  console.log(`Loading ${INPUT}...`);
  const entries = loadJsonl(INPUT);
  console.log(`Loaded ${entries.length} entries`);

  const regex = loadRegexPreds(entries);
  const small = loadMlRaw('gliner_int8', entries.length);
  const base  = loadMlRaw('gliner_int8_base', entries.length);
  if (!small || !base) { console.error('missing predictions'); process.exit(1); }

  // Greedy per-label cutoff search optimising for max F1 subject to
  // R >= 0.90 AND P >= 0.90 if reachable, otherwise max F1.
  // Initial cutoffs: env override decides where to start the search.
  let cutS = {}; let cutB = {};
  const startCut = parseFloat(process.env.TUNE_START || '0.40');
  for (const l of ALL_LABELS) {
    cutS[l] = isFinite(startCut) ? startCut : Infinity;
    cutB[l] = isFinite(startCut) ? startCut : Infinity;
  }
  let best = null;
  let bestF = 0;

  function evalAt(cs, cb) {
    const ms = applyCutoffs(small, cs, 0.40);
    const mb = applyCutoffs(base, cb, 0.40);
    return score(entries, i => mergeSpans(regex[i], ms[i], mb[i]));
  }

  best = evalAt(cutS, cutB);
  bestF = best.f;
  console.log(`baseline ${fmt(best)}`);

  for (let pass = 0; pass < 4; pass++) {
    let improved = false;
    for (const which of ['s', 'b']) {
      for (const lbl of ALL_LABELS) {
        const cur = which === 's' ? cutS[lbl] : cutB[lbl];
        let bestC = cur, bestS = best;
        for (const c of CANDIDATES) {
          const cs2 = { ...cutS };
          const cb2 = { ...cutB };
          if (which === 's') cs2[lbl] = c; else cb2[lbl] = c;
          const s = evalAt(cs2, cb2);
          // Maximise the score that reaches both >=0.90; otherwise max F1.
          // Phase A: try to push BOTH past 0.90.
          // Phase B (env=prefer-precision): push P past 0.90 even if R falls slightly.
          const target = process.env.TUNE_TARGET || 'both';
          let better = false;
          if (target === 'both') {
            const hitsTarget = s.p >= 0.90 && s.r >= 0.90;
            const bestHits   = bestS.p >= 0.90 && bestS.r >= 0.90;
            if (hitsTarget && !bestHits) better = true;
            else if (hitsTarget === bestHits && s.f > bestS.f) better = true;
          } else if (target === 'p') {
            // maximise P subject to R >= 0.90
            if (s.r >= 0.90 && bestS.r < 0.90) better = true;
            else if (s.r >= 0.90 && bestS.r >= 0.90 && s.p > bestS.p) better = true;
            else if (s.r < 0.90 && bestS.r < 0.90 && s.f > bestS.f) better = true;
          } else if (target === 'r') {
            // maximise R subject to P >= 0.90
            if (s.p >= 0.90 && bestS.p < 0.90) better = true;
            else if (s.p >= 0.90 && bestS.p >= 0.90 && s.r > bestS.r) better = true;
            else if (s.p < 0.90 && bestS.p < 0.90 && s.f > bestS.f) better = true;
          }
          if (better) { bestC = c; bestS = s; }
        }
        if (bestC !== cur) {
          if (which === 's') cutS[lbl] = bestC; else cutB[lbl] = bestC;
          best = bestS;
          bestF = best.f;
          improved = true;
        }
      }
    }
    console.log(`pass ${pass+1}: ${fmt(best)}`);
    if (!improved) break;
  }

  console.log('\nFinal small cutoffs:');
  for (const [k, v] of Object.entries(cutS).sort()) console.log(`  ${k.padEnd(28)} ${v}`);
  console.log('\nFinal base cutoffs:');
  for (const [k, v] of Object.entries(cutB).sort()) console.log(`  ${k.padEnd(28)} ${v}`);
  console.log(`\nFinal: ${fmt(best)}`);

  // Per-label breakdown at the chosen cutoffs.
  const ms = applyCutoffs(small, cutS, 0.40);
  const mb = applyCutoffs(base, cutB, 0.40);
  const finalScore = score(entries, i => mergeSpans(regex[i], ms[i], mb[i]), true);
  console.log('\nPer-gold-label recall:');
  for (const [k, v] of Object.entries(finalScore.byLabel).sort()) {
    const t = v.tp + v.fn;
    console.log(`  ${k.padEnd(15)} ${(v.tp / t * 100).toFixed(1).padStart(6)}%  (${v.tp}/${t})`);
  }
  // Save the cutoffs to JSON for proxy code to load.
  fs.writeFileSync('scripts/best-cutoffs.json', JSON.stringify({ small: cutS, base: cutB }, (k, v) => v === Infinity ? 'Infinity' : v, 2));
  console.log('\nCutoffs saved to scripts/best-cutoffs.json');
}

main();
