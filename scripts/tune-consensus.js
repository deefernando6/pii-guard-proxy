#!/usr/bin/env node
'use strict';

// Consensus ensemble tuner. Each ML span is kept only if BOTH small
// and base produced an overlapping span (with their respective per-
// label cutoffs satisfied). Forces the two models to agree before a
// span counts — sacrifices recall for precision.
//
// Two operating modes:
//   STRICT: every ML span must be confirmed by an overlap from the
//           OTHER model. Regex/supplementary spans pass through
//           unchanged (they're already high-precision).
//   UNION:  for high-recall regions, allow either model. Used as the
//           fall-through when consensus drops too much recall.

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
function consensus(small, base) {
  // Each ML span survives iff the other model emitted an overlapping span.
  return small.map((sp, i) => {
    const bp = base[i] || [];
    const out = [];
    for (const a of sp) for (const b of bp) if (ovl(a, b)) { out.push(a); break; }
    return out;
  });
}
function unionAfterRegex(regex, ml) {
  const out = [...regex];
  for (const m of ml) { let dup=false; for (const r of regex) if (ovl(m,r)){dup=true;break;} if (!dup) out.push(m); }
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

function main() {
  const entries = loadJsonl(INPUT);
  const regex = loadRegex(entries);
  const small_raw = loadMl('gliner_int8', entries.length);
  const base_raw  = loadMl('gliner_int8_base', entries.length);

  // Try several cutoff regimes for the consensus ensemble.
  const regimes = [
    { name: 'consensus@0.30',     cs: 0.30, cb: 0.30 },
    { name: 'consensus@0.40',     cs: 0.40, cb: 0.40 },
    { name: 'consensus@0.50',     cs: 0.50, cb: 0.50 },
    { name: 'consensus@0.60',     cs: 0.60, cb: 0.60 },
    { name: 'consensus@0.70',     cs: 0.70, cb: 0.70 },
    { name: 'consensus@0.45/0.55', cs: 0.45, cb: 0.55 },
    { name: 'consensus@0.55/0.45', cs: 0.55, cb: 0.45 },
  ];

  for (const r of regimes) {
    const cuts = {};
    for (const lbl of Object.keys(GLINER_TO_GOLD)) cuts[lbl] = 0.40; // dummy
    // Map each label to a uniform cutoff per regime.
    const cs = {}, cb = {};
    for (const lbl of Object.keys(GLINER_TO_GOLD)) { cs[lbl] = r.cs; cb[lbl] = r.cb; }
    const sp = applyCut(small_raw, cs, r.cs);
    const bp = applyCut(base_raw,  cb, r.cb);
    const cons = consensus(sp, bp);
    const s = score(entries, i => unionAfterRegex(regex[i], cons[i]));
    console.log(`${r.name.padEnd(24)} ${fmt(s)}`);
  }

  // And as a sanity check — union (regex + small + base merged) at the
  // best per-label cutoffs from tune-merged.js for comparison.
  const best = require('./best-cutoffs.json');
  const cs = {}, cb = {};
  for (const [k, v] of Object.entries(best.small)) cs[k] = v === 'Infinity' ? Infinity : v;
  for (const [k, v] of Object.entries(best.base))  cb[k] = v === 'Infinity' ? Infinity : v;
  const sp = applyCut(small_raw, cs, 0.40);
  const bp = applyCut(base_raw,  cb, 0.40);
  // Union ensemble (current ship)
  let s = score(entries, i => {
    const u = unionAfterRegex(regex[i], sp[i]);
    return unionAfterRegex(u, bp[i]);
  });
  console.log(`${'union (best cutoffs)'.padEnd(24)} ${fmt(s)}`);
  // Consensus with per-label cutoffs
  const cons = consensus(sp, bp);
  s = score(entries, i => unionAfterRegex(regex[i], cons[i]));
  console.log(`${'consensus (best cutoffs)'.padEnd(24)} ${fmt(s)}`);
}

main();
