#!/usr/bin/env node
'use strict';

// Span-level evaluation of pii-guard-proxy's regex detector against
// ai4privacy/pii-masking-300k (English validation split).
//
// Two F1 numbers per dataset label and overall:
//   * STRICT  — predicted span exactly matches a gold span AND the
//               predicted type maps to the gold label
//   * LENIENT — predicted span overlaps a gold span (any byte overlap)
//               AND maps to the gold label
// Plus an "any-type" aggregate that ignores label mismatch — measures
// "did we catch this PII at all", which is what an anonymisation proxy
// actually cares about.

const fs = require('fs');
const path = require('path');
const { detectPII } = require('../lib/detector');

// Usage:
//   node scripts/benchmark-pii-masking-300k.js [input.jsonl] [limit]
//
// Default input is the English validation split, expected at
// scripts/data/english_validation.jsonl. To download it:
//   mkdir -p scripts/data && curl -L -o scripts/data/english_validation.jsonl \
//     'https://huggingface.co/datasets/ai4privacy/pii-masking-300k/resolve/main/data/validation/1english_openpii_8k.jsonl'

const INPUT = process.argv[2]
  || path.join(__dirname, 'data', 'english_validation.jsonl');
const LIMIT = parseInt(process.argv[3] || '0', 10) || Infinity;

// pii-masking-300k label → set of our regex types we'd accept as a
// correct hit for that gold span. Multiple regex types map to one
// gold label (e.g. our IPV4 and IPV6 both match the dataset's IP
// label). Gold labels we don't cover at all → empty array (every gold
// span of that type is a guaranteed false negative).
const LABEL_MAP = {
  EMAIL:        ['EMAIL'],
  TEL:          ['PHONE'],
  IP:           ['IPV4', 'IPV6'],
  BOD:          ['DOB'],
  DATE:         ['DOB'],                                  // dataset DATE often = DOB-shaped
  SOCIALNUMBER: ['SSN', 'NIC_LK', 'AADHAAR', 'NIN_UK'],   // any "social-number-like" national ID
  PASSPORT:     ['PASSPORT'],
  IDCARD:       ['NIC_LK', 'AADHAAR', 'PAN_INDIA', 'PASSPORT', 'NIN_UK', 'SSN'],
  GIVENNAME1:   ['NAME'],
  GIVENNAME2:   ['NAME'],
  LASTNAME1:    ['NAME'],
  LASTNAME2:    ['NAME'],
  LASTNAME3:    ['NAME'],
  CITY:         ['ADDRESS'],
  STATE:        ['ADDRESS'],
  STREET:       ['ADDRESS'],
  POSTCODE:     ['ADDRESS'],
  COUNTRY:      ['ADDRESS'],
  BUILDING:     ['ADDRESS'],
  SECADDRESS:   ['ADDRESS'],
  PASS:         ['PASSWORD_FIELD'],
  // Categories the proxy doesn't cover — empty list ⇒ guaranteed FN
  USERNAME:     [],
  TIME:         [],
  SEX:          [],
  TITLE:        [],
  GEOCOORD:     [],
  CARDISSUER:   [],
  DRIVERLICENSE: [],
};

function spanOverlap(a, b) {
  return a.start < b.end && b.start < a.end;
}
function spanExact(a, b) {
  return a.start === b.start && a.end === b.end;
}

function score(matchFn) {
  // tp/fp/fn aggregated across the corpus.
  // Per-label tp/fn (gold label) and per-prediction-type fp.
  return {
    overall: { tp: 0, fp: 0, fn: 0 },
    byGoldLabel: {},   // label → { tp, fn }
    anyType: { tp: 0, fp: 0, fn: 0 },
    matchFn,
  };
}

function bumpLabel(metric, label, key) {
  if (!metric.byGoldLabel[label]) metric.byGoldLabel[label] = { tp: 0, fn: 0 };
  metric.byGoldLabel[label][key]++;
}

function f1(tp, fp, fn) {
  const p = tp + fp === 0 ? 0 : tp / (tp + fp);
  const r = tp + fn === 0 ? 0 : tp / (tp + fn);
  const f = p + r === 0 ? 0 : 2 * p * r / (p + r);
  return { p, r, f, tp, fp, fn };
}

function evaluate(entries) {
  const strict  = score(spanExact);
  const lenient = score(spanOverlap);

  let lines = 0;
  for (const e of entries) {
    lines++;
    if (lines % 1000 === 0) process.stderr.write(`  ${lines}/${entries.length}\r`);

    const text = e.source_text;
    const gold = e.privacy_mask || [];
    const pred = detectPII(text).map(d => ({
      start: d.start,
      end: d.end,
      type: d.type,
      value: d.value,
    }));

    // Per-metric matching pass.
    for (const metric of [strict, lenient]) {
      const goldUsed = new Array(gold.length).fill(false);
      const predUsed = new Array(pred.length).fill(false);

      // First pass: typed match (predicted type ∈ accepted-types-for-gold-label)
      for (let i = 0; i < pred.length; i++) {
        for (let j = 0; j < gold.length; j++) {
          if (predUsed[i] || goldUsed[j]) continue;
          if (!metric.matchFn(pred[i], gold[j])) continue;
          const accepted = LABEL_MAP[gold[j].label] || [];
          if (accepted.includes(pred[i].type)) {
            metric.overall.tp++;
            bumpLabel(metric, gold[j].label, 'tp');
            predUsed[i] = true;
            goldUsed[j] = true;
            break;
          }
        }
      }

      // any-type pass: same span, any predicted type counts as a TP
      const goldUsedAny = new Array(gold.length).fill(false);
      const predUsedAny = new Array(pred.length).fill(false);
      for (let i = 0; i < pred.length; i++) {
        for (let j = 0; j < gold.length; j++) {
          if (predUsedAny[i] || goldUsedAny[j]) continue;
          if (!metric.matchFn(pred[i], gold[j])) continue;
          metric.anyType.tp++;
          predUsedAny[i] = true;
          goldUsedAny[j] = true;
          break;
        }
      }

      // Tally remaining as FP / FN.
      for (let i = 0; i < pred.length; i++) if (!predUsed[i])    metric.overall.fp++;
      for (let j = 0; j < gold.length; j++) if (!goldUsed[j])    { metric.overall.fn++; bumpLabel(metric, gold[j].label, 'fn'); }
      for (let i = 0; i < pred.length; i++) if (!predUsedAny[i]) metric.anyType.fp++;
      for (let j = 0; j < gold.length; j++) if (!goldUsedAny[j]) metric.anyType.fn++;
    }
  }
  process.stderr.write('\n');
  return { strict, lenient, lines };
}

function reportMetric(name, m) {
  const o = f1(m.overall.tp, m.overall.fp, m.overall.fn);
  const a = f1(m.anyType.tp, m.anyType.fp, m.anyType.fn);
  console.log(`\n## ${name}`);
  console.log(`  TYPE-AWARE  precision=${(o.p*100).toFixed(2)}%  recall=${(o.r*100).toFixed(2)}%  F1=${(o.f*100).toFixed(2)}%   (tp=${o.tp}, fp=${o.fp}, fn=${o.fn})`);
  console.log(`  ANY-TYPE    precision=${(a.p*100).toFixed(2)}%  recall=${(a.r*100).toFixed(2)}%  F1=${(a.f*100).toFixed(2)}%   (tp=${a.tp}, fp=${a.fp}, fn=${a.fn})`);

  console.log(`\n  Per-gold-label recall (type-aware):`);
  const labels = Object.keys(m.byGoldLabel).sort();
  console.log(`  ${'label'.padEnd(14)} ${'recall'.padStart(8)} ${'tp'.padStart(6)} ${'fn'.padStart(6)} covered?`);
  for (const lbl of labels) {
    const { tp, fn } = m.byGoldLabel[lbl];
    const r = tp + fn === 0 ? 0 : tp / (tp + fn);
    const covered = (LABEL_MAP[lbl] || []).length > 0 ? 'yes' : 'no (out-of-scope for regex)';
    console.log(`  ${lbl.padEnd(14)} ${(r*100).toFixed(2).padStart(6)}%  ${String(tp).padStart(6)} ${String(fn).padStart(6)}  ${covered}`);
  }
}

function main() {
  console.log(`Loading ${INPUT}...`);
  const raw = fs.readFileSync(INPUT, 'utf8').split('\n').filter(Boolean);
  const entries = [];
  for (const line of raw) {
    try { entries.push(JSON.parse(line)); } catch (e) {}
    if (entries.length >= LIMIT) break;
  }
  console.log(`Loaded ${entries.length} entries`);
  console.log(`Running detectPII on each source_text and matching against privacy_mask spans...`);
  const t0 = Date.now();
  const { strict, lenient, lines } = evaluate(entries);
  const t1 = Date.now();
  console.log(`\nProcessed ${lines} entries in ${((t1 - t0) / 1000).toFixed(1)}s (${(lines / ((t1 - t0) / 1000)).toFixed(0)} entries/s)`);

  reportMetric('STRICT (exact span match)', strict);
  reportMetric('LENIENT (any-overlap span match)', lenient);
}

main();
