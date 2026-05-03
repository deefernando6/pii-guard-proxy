#!/usr/bin/env node
'use strict';

// v2: Per-model label maps + in-scope filtering. Each ML model emits
// labels in its own taxonomy (DeBERTa-v3-base ai4privacy uses the
// pii-masking-200k 54-label scheme; GLiNER uses the natural-language
// label phrases we asked for). This script maps each model's labels
// to the pii-masking-300k 28-label gold scheme and DROPS predictions
// whose label has no gold counterpart (AGE, AMOUNT, COMPANYNAME,
// EYECOLOR, etc.) — they're "real" PII detections but the 300k
// dataset doesn't annotate them, so counting them as FPs would
// misrepresent the model's quality on this benchmark.
//
// Same span-overlap any-type / type-aware F1 framework as v1.

const fs = require('fs');
const path = require('path');
const { detectPII } = require(process.env.PII_GUARD_DETECTOR
  || path.join(__dirname, '..', 'lib', 'detector'));
const { detectSupplementary } = require(process.env.PII_GUARD_SUPPLEMENTARY
  || path.join(__dirname, 'supplementary-detector'));

const INPUT = process.argv[2]
  || path.join(__dirname, 'data', 'english_validation.jsonl');
const PREDS_DIR = process.env.PII_GUARD_PREDS_DIR || '/tmp/pii-bench/predictions';

// pii-masking-300k gold labels (the 28 labels actually used).
// Used as the universe for "is this prediction in scope?"
const GOLD_LABELS = new Set([
  'TIME', 'USERNAME', 'IDCARD', 'EMAIL', 'SOCIALNUMBER', 'PASSPORT',
  'DRIVERLICENSE', 'LASTNAME1', 'BOD', 'IP', 'GIVENNAME1', 'CITY',
  'SEX', 'STATE', 'TEL', 'BUILDING', 'TITLE', 'STREET', 'POSTCODE',
  'DATE', 'PASS', 'COUNTRY', 'SECADDRESS', 'LASTNAME2', 'GIVENNAME2',
  'GEOCOORD', 'LASTNAME3', 'CARDISSUER',
]);

// Regex types map to gold labels (proxy detector taxonomy).
// LABEL_MAP[gold_label] = [regex_types_we_accept]
const REGEX_GOLD_ACCEPTANCE = {
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
  USERNAME: [], TIME: ['TIME'], SEX: ['SEX'], TITLE: ['TITLE'],
  GEOCOORD: [], CARDISSUER: [], DRIVERLICENSE: [],
};
// Supplementary detector contributes to the gold labels below. The
// types match what supplementary_detector.js emits.
REGEX_GOLD_ACCEPTANCE.POSTCODE = ['ADDRESS', 'POSTCODE'];
REGEX_GOLD_ACCEPTANCE.SECADDRESS = ['ADDRESS', 'ADDRESS_UNIT'];
REGEX_GOLD_ACCEPTANCE.COUNTRY = ['ADDRESS', 'COUNTRY'];
REGEX_GOLD_ACCEPTANCE.STATE = ['ADDRESS', 'US_STATE'];
REGEX_GOLD_ACCEPTANCE.DATE = ['DOB'];
REGEX_GOLD_ACCEPTANCE.BOD = ['DOB'];
REGEX_GOLD_ACCEPTANCE.GEOCOORD = ['GEOCOORD'];
REGEX_GOLD_ACCEPTANCE.IDCARD = ['NIC_LK','AADHAAR','PAN_INDIA','PASSPORT','NIN_UK','SSN','IDCARD'];
REGEX_GOLD_ACCEPTANCE.DRIVERLICENSE = ['DRIVERLICENSE'];
// Field-label-based extractors emit standard proxy types but for
// gold labels we hadn't covered before (USERNAME).  Make those explicit:
REGEX_GOLD_ACCEPTANCE.USERNAME = ['USERNAME', 'NAME'];

// DeBERTa label → gold-label set it should be accepted as.
// Empty array → in-scope but no specific type match (only counts under any-type).
// undefined → out-of-scope (filter the prediction out entirely).
const DEBERTA_TO_GOLD = {
  // direct matches
  'EMAIL':              ['EMAIL'],
  'PHONENUMBER':        ['TEL'],
  'USERNAME':           ['USERNAME'],
  'TIME':               ['TIME'],
  'DATE':               ['DATE'],
  'DOB':                ['BOD'],
  'SSN':                ['SOCIALNUMBER'],
  'CITY':               ['CITY'],
  'STATE':              ['STATE', 'COUNTRY'],
  'COUNTY':             ['COUNTRY', 'STATE'],
  'STREET':             ['STREET'],
  'BUILDINGNUMBER':     ['BUILDING'],
  'SECONDARYADDRESS':   ['SECADDRESS'],
  'ZIPCODE':            ['POSTCODE'],
  'NEARBYGPSCOORDINATE': ['GEOCOORD'],
  'SEX':                ['SEX'],
  'GENDER':             ['SEX'],
  'PIN':                ['PASS'],
  'PASSWORD':           ['PASS'],
  'CREDITCARDISSUER':   ['CARDISSUER'],
  'PREFIX':             ['TITLE'],
  // names
  'FIRSTNAME':          ['GIVENNAME1', 'GIVENNAME2'],
  'MIDDLENAME':         ['GIVENNAME2', 'GIVENNAME1'],
  'LASTNAME':           ['LASTNAME1', 'LASTNAME2', 'LASTNAME3'],
  // IP variants
  'IP':                 ['IP'],
  'IPV4':               ['IP'],
  'IPV6':               ['IP'],
  // ID-shaped categories — DeBERTa lumps these into ACCOUNTNUMBER
  'ACCOUNTNUMBER':      ['IDCARD', 'PASSPORT', 'DRIVERLICENSE', 'SOCIALNUMBER'],
  'CREDITCARDNUMBER':   ['IDCARD'],
  'MASKEDNUMBER':       ['IDCARD'],
  'IBAN':               ['IDCARD'],
  'BIC':                ['IDCARD'],
  'BITCOINADDRESS':     ['IDCARD'],
  'ETHEREUMADDRESS':    ['IDCARD'],
  'LITECOINADDRESS':    ['IDCARD'],
  'PHONEIMEI':          ['IDCARD'],
  'VEHICLEVIN':         ['IDCARD'],
  'VEHICLEVRM':         ['IDCARD'],
  // Job-related labels — most map to TITLE in this taxonomy
  'JOBTITLE':           ['TITLE'],
  'JOBTYPE':            ['TITLE'],
  'JOBAREA':            ['TITLE'],
  // Out-of-scope: present in DeBERTa but the 300k dataset doesn't
  // track these. We filter rather than penalise.
  'AGE':                undefined,
  'AMOUNT':             undefined,
  'CURRENCY':           undefined,
  'CURRENCYCODE':       undefined,
  'CURRENCYNAME':       undefined,
  'CURRENCYSYMBOL':     undefined,
  'EYECOLOR':           undefined,
  'HEIGHT':             undefined,
  'USERAGENT':          undefined,
  'URL':                undefined,
  'ORDINALDIRECTION':   undefined,
  'COMPANYNAME':        undefined,
  'MAC':                undefined,
  'CREDITCARDCVV':      undefined,
  'ACCOUNTNAME':        ['USERNAME'],   // close enough
};

// OpenAI Privacy Filter — 8 PII categories. The 300k gold scheme is
// finer-grained, so each PF label fans out to multiple gold labels.
const OPENAI_PF_TO_GOLD = {
  'private_email':   ['EMAIL'],
  'private_phone':   ['TEL'],
  'private_url':     [],          // gold has no URL — in-scope but unmatchable type-wise
  'private_date':    ['DATE', 'BOD', 'TIME'],
  'private_person':  ['GIVENNAME1', 'GIVENNAME2', 'LASTNAME1', 'LASTNAME2', 'LASTNAME3', 'USERNAME', 'TITLE'],
  'private_address': ['STREET', 'BUILDING', 'SECADDRESS', 'CITY', 'STATE', 'COUNTRY', 'POSTCODE', 'GEOCOORD'],
  'account_number':  ['IDCARD', 'PASSPORT', 'DRIVERLICENSE', 'SOCIALNUMBER', 'CARDISSUER'],
  'secret':          ['PASS'],
};

// GLiNER label → gold-label set.
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
  'address':               ['STREET', 'BUILDING', 'SECADDRESS', 'CITY', 'STATE', 'COUNTRY', 'POSTCODE'],
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

function spanOverlap(a, b) { return a.start < b.end && b.start < a.end; }
function spanExact(a, b) { return a.start === b.start && a.end === b.end; }

function loadJsonl(p) {
  return fs.readFileSync(p, 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l));
}

// Per-label minimum confidence cutoffs for GLiNER predictions.
// Calibrated against the threshold-0.30 score distribution: each cutoff
// is chosen to keep most TPs while dropping the long tail of low-
// confidence FPs. Labels not in this map use the default cutoff.
const GLINER_LABEL_MIN_SCORE = {
  'title':                  Infinity,
  'building':               Infinity,
  'username':               0.40,
  'sex':                    0.40,
  'first name':             0.40,
  'last name':              0.40,
  'person name':            0.42,
  'state':                  0.60,
  'country':                0.65,
  'postal code':            0.50,
  'city':                   0.60,
  'street':                 0.42,
  'address':                0.50,
  'secondary address':      0.40,
  'time':                   0.50,
  'date':                   0.55,
  'date of birth':          0.50,
  'password':               0.42,
  'ip address':             0.40,
  'geographic coordinates': 0.40,
  'id card':                0.45,
  'passport number':        0.45,
  'driver license':         0.45,
  'social security number': 0.45,
  'phone number':           0.45,
  'email address':          0.30,
  'card issuer':            0.45,
};
const GLINER_DEFAULT_MIN = 0.40;

function loadMlPreds(name, n, mapTable) {
  const p = path.join(PREDS_DIR, `${name}.jsonl`);
  if (!fs.existsSync(p)) return null;
  const arr = new Array(n).fill(null).map(() => []);
  let kept = 0, dropped = 0, filtered = 0;
  for (const line of fs.readFileSync(p, 'utf8').split('\n').filter(Boolean)) {
    const e = JSON.parse(line);
    if (e.idx < n) {
      const out = [];
      for (const s of (e.spans || [])) {
        const lbl = String(s.label || '').toUpperCase();
        const lblLc = String(s.label || '').toLowerCase();
        const accepted =
          (lbl in mapTable) ? mapTable[lbl] :
          (lblLc in mapTable) ? mapTable[lblLc] : null;
        if (accepted === undefined) { dropped++; continue; }
        const len = s.end - s.start;
        const sc = typeof s.score === 'number' ? s.score : 1.0;
        if (name.startsWith('gliner_')) {
          const cut = GLINER_LABEL_MIN_SCORE[lblLc] ?? GLINER_DEFAULT_MIN;
          if (sc < cut) { filtered++; continue; }
        }
        if (lblLc === 'username' && len < 4) { filtered++; continue; }
        if (lblLc === 'country' && (len <= 2 || len > 25)) { filtered++; continue; }
        if (accepted === null) {
          kept++;
          out.push({ start: s.start, end: s.end, accepted: [], score: s.score, label: lbl });
          continue;
        }
        kept++;
        out.push({ start: s.start, end: s.end, accepted, score: s.score, label: lbl });
      }
      arr[e.idx] = out;
    }
  }
  console.log(`  ${name}: kept ${kept}, dropped (out-of-scope) ${dropped}, filtered (quality) ${filtered}`);
  return arr;
}

// Load regex predictions (synchronous detection); attach acceptance.
// Combines the proxy's lib/detector.js with the supplementary regex
// pack (TIME, TITLE, SEX, DOB, POSTCODE, COUNTRY, STATE_ABBR, etc.)
function loadRegexPreds(entries) {
  return entries.map(e => {
    const text = e.source_text;
    const all = [...detectPII(text), ...detectSupplementary(text)];
    // Dedupe overlapping spans of the same type, prefer earlier+longer
    all.sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));
    const out = [];
    for (const d of all) {
      let overlap = false;
      for (const o of out) {
        if (d.start < o.end && o.start < d.end && d.type === o.type) { overlap = true; break; }
      }
      if (overlap) continue;
      const accepted = [];
      for (const [goldLabel, types] of Object.entries(REGEX_GOLD_ACCEPTANCE)) {
        if (types.includes(d.type)) accepted.push(goldLabel);
      }
      out.push({ start: d.start, end: d.end, accepted, type: d.type });
    }
    return out;
  });
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

function score(entries, getPreds) {
  const lenientType = { tp: 0, fp: 0, fn: 0 };
  const lenientAny  = { tp: 0, fp: 0, fn: 0 };
  const strictType  = { tp: 0, fp: 0, fn: 0 };
  const strictAny   = { tp: 0, fp: 0, fn: 0 };
  const byLabel = {};

  for (let idx = 0; idx < entries.length; idx++) {
    const gold = entries[idx].privacy_mask || [];
    const pred = getPreds(idx);

    for (const [m, matchFn, anyM] of [
      [strictType, spanExact, strictAny],
      [lenientType, spanOverlap, lenientAny],
    ]) {
      const gU = new Array(gold.length).fill(false);
      const pU = new Array(pred.length).fill(false);
      for (let i = 0; i < pred.length; i++) {
        for (let j = 0; j < gold.length; j++) {
          if (pU[i] || gU[j]) continue;
          if (!matchFn(pred[i], gold[j])) continue;
          if ((pred[i].accepted || []).includes(gold[j].label)) {
            m.tp++; pU[i] = true; gU[j] = true; break;
          }
        }
      }
      for (let i = 0; i < pred.length; i++) if (!pU[i]) m.fp++;
      for (let j = 0; j < gold.length; j++) if (!gU[j]) m.fn++;

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
  return { strictType, lenientType, strictAny, lenientAny, byLabel };
}

function row(label, m) {
  const o = f1(m.tp, m.fp, m.fn);
  return `${label.padEnd(22)} P=${(o.p*100).toFixed(2).padStart(6)}%  R=${(o.r*100).toFixed(2).padStart(6)}%  F1=${(o.f*100).toFixed(2).padStart(6)}%   tp=${m.tp}  fp=${m.fp}  fn=${m.fn}`;
}

function reportScenario(name, s) {
  console.log(`\n## ${name}`);
  console.log(`  ${row('STRICT  type-aware', s.strictType)}`);
  console.log(`  ${row('STRICT  any-type',   s.strictAny)}`);
  console.log(`  ${row('LENIENT type-aware', s.lenientType)}`);
  console.log(`  ${row('LENIENT any-type',   s.lenientAny)}`);
}

function reportPerLabel(scenarios) {
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

  console.log(`Running regex on every entry...`);
  const t0 = Date.now();
  const regexPred = loadRegexPreds(entries);
  console.log(`  done in ${((Date.now() - t0) / 1000).toFixed(1)}s`);

  const mlInt8 = loadMlPreds('gliner_int8',      entries.length, GLINER_TO_GOLD);
  const mlBase = loadMlPreds('gliner_int8_base', entries.length, GLINER_TO_GOLD);
  const mlFp32 = loadMlPreds('gliner_fp32',      entries.length, GLINER_TO_GOLD);
  const mlDeb  = loadMlPreds('deberta',          entries.length, DEBERTA_TO_GOLD);
  const mlOAI  = loadMlPreds('openai_pf',        entries.length, OPENAI_PF_TO_GOLD);

  const scenarios = {};
  scenarios['regex-only']        = score(entries, i => regexPred[i]);
  if (mlInt8) scenarios['regex+gliner_small']  = score(entries, i => mergeSpans(regexPred[i], mlInt8[i]));
  if (mlBase) scenarios['regex+gliner_base']   = score(entries, i => mergeSpans(regexPred[i], mlBase[i]));
  if (mlFp32) scenarios['regex+gliner_fp32']   = score(entries, i => mergeSpans(regexPred[i], mlFp32[i]));
  if (mlDeb)  scenarios['regex+deberta_base']  = score(entries, i => mergeSpans(regexPred[i], mlDeb[i]));
  if (mlOAI)  scenarios['regex+openai_pf']     = score(entries, i => mergeSpans(regexPred[i], mlOAI[i]));

  for (const [name, s] of Object.entries(scenarios)) reportScenario(name, s);
  reportPerLabel(scenarios);
}

main();
