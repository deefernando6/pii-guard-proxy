#!/usr/bin/env node
'use strict';

// Score the SHIPPED v1.2.0 detector against ai4privacy/pii-masking-300k
// (English validation split). Uses the same regex + supplementary +
// per-(model, label) cutoff merge logic that lib/ml-detector.js applies
// at runtime, so the F1 here matches what the deployed proxy delivers.

const fs = require('fs');
const path = require('path');
const { detectPII } = require('../lib/detector');
const { detectSupplementary } = require('../lib/supplementary-detector');

const INPUT = '/tmp/pii-bench/english_validation.jsonl';
const PREDS_DIR = '/tmp/pii-bench/predictions';
const GLINER_TO_GOLD = require('./gliner-label-map.json');
const cutsRaw = require('./best-cutoffs.json');

function unInf(o) {
  const out = {};
  for (const [k, v] of Object.entries(o)) out[k] = v === 'Infinity' ? Infinity : v;
  return out;
}
const CUT_SMALL = unInf(cutsRaw.small);
const CUT_BASE  = unInf(cutsRaw.base);

const REGEX_GOLD = {
  EMAIL: ['EMAIL'], TEL: ['PHONE'], IP: ['IPV4','IPV6'],
  BOD: ['DOB'], DATE: ['DOB'],
  SOCIALNUMBER: ['SSN','NIC_LK','AADHAAR','NIN_UK'],
  PASSPORT: ['PASSPORT'],
  IDCARD: ['NIC_LK','AADHAAR','PAN_INDIA','PASSPORT','NIN_UK','SSN','IDCARD'],
  GIVENNAME1: ['NAME'], GIVENNAME2: ['NAME'],
  LASTNAME1: ['NAME'], LASTNAME2: ['NAME'], LASTNAME3: ['NAME'],
  CITY: ['ADDRESS'], STATE: ['ADDRESS','US_STATE'], STREET: ['ADDRESS'],
  POSTCODE: ['ADDRESS','POSTCODE'], COUNTRY: ['ADDRESS','COUNTRY'],
  BUILDING: ['ADDRESS'], SECADDRESS: ['ADDRESS','ADDRESS_UNIT'],
  PASS: ['PASSWORD_FIELD'], USERNAME: ['USERNAME','NAME'],
  TIME: ['TIME'], SEX: ['SEX'], TITLE: ['TITLE'],
  GEOCOORD: ['GEOCOORD'], DRIVERLICENSE: ['DRIVERLICENSE'],
  CARDISSUER: [],
};

const ovl = (a, b) => a.start < b.end && b.start < a.end;
const loadJsonl = p => fs.readFileSync(p, 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l));

function loadRegex(entries) {
  return entries.map(e => {
    const all = [...detectPII(e.source_text), ...detectSupplementary(e.source_text)];
    all.sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));
    const out = [];
    for (const d of all) {
      let dup = false;
      for (const o of out) if (d.start < o.end && o.start < d.end && d.type === o.type) { dup = true; break; }
      if (dup) continue;
      const accepted = [];
      for (const [g, types] of Object.entries(REGEX_GOLD)) if (types.includes(d.type)) accepted.push(g);
      out.push({ start: d.start, end: d.end, accepted });
    }
    return out;
  });
}

function loadMl(name, n, cuts) {
  const arr = new Array(n).fill(null).map(() => []);
  for (const line of fs.readFileSync(path.join(PREDS_DIR, name + '.jsonl'), 'utf8').split('\n').filter(Boolean)) {
    const e = JSON.parse(line);
    if (e.idx >= n) continue;
    for (const s of (e.spans || [])) {
      const lbl = String(s.label || '').toLowerCase();
      const cut = cuts[lbl] !== undefined ? cuts[lbl] : 0.40;
      if (cut === Infinity || (s.score || 0) < cut) continue;
      const accepted = GLINER_TO_GOLD[lbl];
      if (!accepted) continue;
      const len = s.end - s.start;
      if (lbl === 'username' && len < 4) continue;
      if (lbl === 'country' && (len <= 2 || len > 25)) continue;
      arr[e.idx].push({ start: s.start, end: s.end, accepted });
    }
  }
  return arr;
}

function merge(...lists) {
  const out = [];
  for (const list of lists) for (const s of list) {
    let dup = false; for (const o of out) if (ovl(s, o)) { dup = true; break; }
    if (!dup) out.push(s);
  }
  return out;
}

function score(entries, getP) {
  let tp = 0, fp = 0, fn = 0;
  const byLabel = {};
  for (let i = 0; i < entries.length; i++) {
    const g = entries[i].privacy_mask || []; const p = getP(i);
    const gU = new Array(g.length).fill(false), pU = new Array(p.length).fill(false);
    for (let a = 0; a < p.length; a++) for (let b = 0; b < g.length; b++) {
      if (pU[a] || gU[b]) continue;
      if (ovl(p[a], g[b])) { tp++; pU[a] = true; gU[b] = true; break; }
    }
    for (let a = 0; a < p.length; a++) if (!pU[a]) fp++;
    for (let b = 0; b < g.length; b++) {
      if (!gU[b]) fn++;
      const k = g[b].label;
      if (!byLabel[k]) byLabel[k] = { tp: 0, fn: 0 };
      if (gU[b]) byLabel[k].tp++; else byLabel[k].fn++;
    }
  }
  const P = tp / (tp + fp || 1);
  const R = tp / (tp + fn || 1);
  const F = P + R === 0 ? 0 : 2 * P * R / (P + R);
  return { P, R, F, tp, fp, fn, byLabel };
}

const fmt = s => `P=${(s.P*100).toFixed(2)}%  R=${(s.R*100).toFixed(2)}%  F1=${(s.F*100).toFixed(2)}%   (tp=${s.tp}, fp=${s.fp}, fn=${s.fn})`;

function main() {
  const t0 = Date.now();
  console.log('Dataset:  ai4privacy/pii-masking-300k — English validation split');
  console.log(`Loading ${INPUT}...`);
  const entries = loadJsonl(INPUT);
  const totalGold = entries.reduce((n, e) => n + (e.privacy_mask || []).length, 0);
  console.log(`Loaded ${entries.length} prompts, ${totalGold} gold spans\n`);

  console.log('Running detectors...');
  const regex = loadRegex(entries);
  const small = loadMl('gliner_int8',      entries.length, CUT_SMALL);
  const base  = loadMl('gliner_int8_base', entries.length, CUT_BASE);

  const regexOnly = score(entries, i => regex[i]);
  const shipped   = score(entries, i => merge(regex[i], small[i], base[i]));

  console.log('\n=== Regex-only baseline ===');
  console.log(`  ${fmt(regexOnly)}`);
  console.log('\n=== Shipped configuration (regex + supplementary + on-device ML) ===');
  console.log(`  ${fmt(shipped)}`);

  console.log('\n=== Per-gold-label recall (shipped config) ===');
  const lbls = Object.keys(shipped.byLabel).sort((a, b) => {
    const ra = shipped.byLabel[a]; const rb = shipped.byLabel[b];
    return (rb.tp / (rb.tp + rb.fn || 1)) - (ra.tp / (ra.tp + ra.fn || 1));
  });
  for (const lbl of lbls) {
    const v = shipped.byLabel[lbl];
    const total = v.tp + v.fn;
    console.log(`  ${lbl.padEnd(15)} ${(v.tp / total * 100).toFixed(1).padStart(6)}%   (${v.tp}/${total})`);
  }
  console.log(`\nElapsed: ${((Date.now() - t0) / 1000).toFixed(1)}s`);
}

main();
