'use strict';

function placeholderFor(type, index) {
  const labels = {
    OPENAI_API_KEY: 'API_KEY',
    ANTHROPIC_API_KEY: 'API_KEY',
    GITHUB_TOKEN: 'TOKEN',
    AWS_ACCESS_KEY: 'AWS_KEY',
    AWS_SECRET_KEY: 'AWS_SECRET',
    GOOGLE_API_KEY: 'API_KEY',
    SLACK_TOKEN: 'TOKEN',
    STRIPE_KEY: 'STRIPE_KEY',
    JWT: 'JWT',
    PRIVATE_KEY: 'PRIVATE_KEY',
    PASSWORD_FIELD: 'PASSWORD',
    EMAIL: 'EMAIL',
    CREDIT_CARD: 'CARD',
    SSN: 'SSN',
    NIC_LK: 'NIC',
    AADHAAR: 'AADHAAR',
    PAN_INDIA: 'PAN',
    PASSPORT: 'PASSPORT',
    NIN_UK: 'NIN',
    IBAN: 'IBAN',
    BITCOIN_ADDRESS: 'BTC_ADDRESS',
    PHONE: 'PHONE',
    IPV4: 'IP',
    IPV6: 'IPV6',
    MAC_ADDRESS: 'MAC',
    DOB: 'DOB',
    NAME: 'NAME',
    NAME_AFTER_LABEL: 'NAME',
    ADDRESS: 'ADDRESS',
  };
  const tag = labels[type] || 'REDACTED';
  return `[${tag}_${index}]`;
}

function anonymize(text, detections) {
  if (!detections || detections.length === 0) {
    return { text, mapping: [] };
  }

  const valueToIndex = new Map();
  const counters = {};
  const mapping = [];

  function getPlaceholder(type, value, label) {
    const key = `${type}\0${value}`;
    if (valueToIndex.has(key)) return valueToIndex.get(key).placeholder;
    counters[type] = (counters[type] || 0) + 1;
    const idx = counters[type];
    const ph = placeholderFor(type, idx);
    valueToIndex.set(key, { placeholder: ph, index: idx });
    mapping.push({ placeholder: ph, original: value, type, label });
    return ph;
  }

  const sorted = [...detections].sort((a, b) => a.start - b.start);
  let out = '';
  let cursor = 0;
  for (const d of sorted) {
    if (d.start < cursor) continue;
    out += text.slice(cursor, d.start);
    out += getPlaceholder(d.type, d.value, d.label);
    cursor = d.end;
  }
  out += text.slice(cursor);

  return { text: out, mapping };
}

module.exports = { anonymize, placeholderFor };
