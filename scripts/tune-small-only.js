#!/usr/bin/env node
'use strict';

// Tuner for the regex + supplementary + gliner_int8 (small only) stack.
// This is what actually ships in the .deb. Search for the best F1
// while preferring to hit P>=0.90 AND R>=0.90.

const fs = require('fs');
const path = require('path');
const { detectPII } = require('../lib/detector');
const { detectSupplementary } = require('../lib/supplementary-detector');

const INPUT = path.join(__dirname, 'data', 'english_validation.jsonl');
const PREDS_DIR = '/tmp/pii-bench/predictions';
const GLINER_TO_GOLD = require('./gliner-label-map.json');

const REGEX_GOLD_ACCEPTANCE = {
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

const loadJsonl = p => fs.readFileSync(p,'utf8').split('\n').filter(Boolean).map(l=>JSON.parse(l));
const ovl = (a,b) => a.start < b.end && b.start < a.end;

function loadRegex(entries) {
  return entries.map(e => {
    const all = [...detectPII(e.source_text), ...detectSupplementary(e.source_text)];
    all.sort((a,b)=>a.start-b.start || (b.end-b.start)-(a.end-a.start));
    const out = [];
    for (const d of all) {
      let dup = false;
      for (const o of out) if (d.start < o.end && o.start < d.end && d.type === o.type) { dup = true; break; }
      if (dup) continue;
      const accepted = [];
      for (const [g,types] of Object.entries(REGEX_GOLD_ACCEPTANCE)) if (types.includes(d.type)) accepted.push(g);
      out.push({ start: d.start, end: d.end, accepted });
    }
    return out;
  });
}
function loadMl(name, n) {
  const p = path.join(PREDS_DIR, `${name}.jsonl`);
  const arr = new Array(n).fill(null).map(()=>[]);
  for (const line of fs.readFileSync(p,'utf8').split('\n').filter(Boolean)) {
    const e = JSON.parse(line);
    if (e.idx<n) arr[e.idx] = (e.spans||[]).map(s=>({
      start:s.start, end:s.end, label:String(s.label||'').toLowerCase(),
      score: typeof s.score==='number'? s.score : 1.0,
    }));
  }
  return arr;
}
function applyCut(raw, cuts, def) {
  return raw.map(spans => {
    const out = [];
    for (const s of spans) {
      const c = cuts[s.label]!==undefined ? cuts[s.label] : def;
      if (c===Infinity || s.score < c) continue;
      const ac = GLINER_TO_GOLD[s.label] || null;
      if (!ac) continue;
      const len = s.end-s.start;
      if (s.label==='username' && len<4) continue;
      if (s.label==='country' && (len<=2 || len>25)) continue;
      out.push({ start:s.start, end:s.end, accepted:ac });
    }
    return out;
  });
}
function merge(a, b) {
  const out = [...a];
  for (const m of b) { let dup=false; for (const r of a) if (ovl(m,r)){dup=true;break;} if (!dup) out.push(m); }
  return out;
}
function score(entries, getP) {
  let tp=0,fp=0,fn=0;
  for (let i=0;i<entries.length;i++) {
    const g = entries[i].privacy_mask||[]; const p = getP(i);
    const gU = new Array(g.length).fill(false), pU = new Array(p.length).fill(false);
    for (let a=0;a<p.length;a++) for (let b=0;b<g.length;b++) {
      if (pU[a]||gU[b]) continue; if (ovl(p[a],g[b])) { tp++; pU[a]=true; gU[b]=true; break; }
    }
    for (let a=0;a<p.length;a++) if (!pU[a]) fp++;
    for (let b=0;b<g.length;b++) if (!gU[b]) fn++;
  }
  const P = tp/(tp+fp||1), R = tp/(tp+fn||1);
  const F = P+R===0?0:2*P*R/(P+R);
  return {p:P,r:R,f:F,tp,fp,fn};
}
const fmt = s => `P=${(s.p*100).toFixed(2)}%  R=${(s.r*100).toFixed(2)}%  F1=${(s.f*100).toFixed(2)}%  tp=${s.tp} fp=${s.fp} fn=${s.fn}`;

const LABELS = Object.keys(GLINER_TO_GOLD);
const CANDIDATES = [Infinity, 0.85, 0.80, 0.75, 0.70, 0.65, 0.60, 0.55, 0.50, 0.45, 0.40, 0.35, 0.30, 0.25, 0.20, 0.15, 0.10];

function main() {
  const entries = loadJsonl(INPUT);
  const regex = loadRegex(entries);
  const small = loadMl('gliner_int8', entries.length);

  let cut = {};
  const start = parseFloat(process.env.TUNE_START || '0.40');
  for (const l of LABELS) cut[l] = isFinite(start) ? start : Infinity;

  function evalAt(c) {
    const m = applyCut(small, c, 0.40);
    return score(entries, i => merge(regex[i], m[i]));
  }
  let best = evalAt(cut);
  console.log(`baseline ${fmt(best)}`);

  for (let pass = 0; pass < 5; pass++) {
    let imp = false;
    for (const lbl of LABELS) {
      const cur = cut[lbl];
      let bC = cur, bS = best;
      for (const c of CANDIDATES) {
        const c2 = { ...cut, [lbl]: c };
        const s = evalAt(c2);
        const hits = s.p>=0.90 && s.r>=0.90;
        const bestHits = bS.p>=0.90 && bS.r>=0.90;
        if (hits && !bestHits) { bC = c; bS = s; }
        else if (hits === bestHits && s.f > bS.f) { bC = c; bS = s; }
      }
      if (bC !== cur) { cut[lbl] = bC; best = bS; imp = true; }
    }
    console.log(`pass ${pass+1}: ${fmt(best)}`);
    if (!imp) break;
  }

  console.log('\nFinal cutoffs (only non-Infinity shown):');
  for (const [k,v] of Object.entries(cut).sort()) {
    if (v !== Infinity) console.log(`  ${k.padEnd(28)} ${v}`);
  }
  const dropped = Object.entries(cut).filter(([_,v])=>v===Infinity).map(([k])=>k);
  if (dropped.length) console.log(`Dropped (Infinity): ${dropped.join(', ')}`);
  console.log(`\nFinal: ${fmt(best)}`);
}

main();
