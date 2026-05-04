'use strict';

const fs = require('fs');

// Optional user-managed contact list. One name per line, comments with #.
// We compile it into a single regex so the detector loop doesn't gain a
// special case for it. Reload requires a service restart.
function loadContactsRegex() {
  const path = process.env.PII_GUARD_CONTACTS || '/etc/pii-guard/contacts.txt';
  let lines;
  try {
    if (!fs.existsSync(path)) return null;
    lines = fs.readFileSync(path, 'utf8')
      .split('\n')
      .map(l => l.trim())
      .filter(l => l && !l.startsWith('#'));
  } catch (e) { return null; }
  if (!lines.length) return null;
  // Sort longest-first so multi-word entries match before their substrings.
  lines.sort((a, b) => b.length - a.length);
  const escaped = lines.map(l => l.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  return new RegExp('\\b(' + escaped.join('|') + ')\\b', 'gi');
}
const CONTACTS_REGEX = loadContactsRegex();

function luhnCheck(num) {
  const digits = num.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let alternate = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = parseInt(digits.charAt(i), 10);
    if (alternate) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alternate = !alternate;
  }
  return sum % 10 === 0;
}

const PATTERNS = [
  { type: 'OPENAI_API_KEY',    label: 'OpenAI API key',
    regex: /\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b/g },
  { type: 'ANTHROPIC_API_KEY', label: 'Anthropic API key',
    regex: /\bsk-ant-[A-Za-z0-9_\-]{20,}\b/g },
  { type: 'GITHUB_TOKEN',      label: 'GitHub token',
    regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b/g },
  { type: 'AWS_ACCESS_KEY',    label: 'AWS access key',
    regex: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g },
  { type: 'AWS_SECRET_KEY',    label: 'AWS secret key (likely)',
    regex: /\b[A-Za-z0-9/+=]{40}\b/g,
    validate: (m, ctx) => /aws|secret|access/i.test(ctx) },
  { type: 'GOOGLE_API_KEY',    label: 'Google API key',
    regex: /\bAIza[0-9A-Za-z_\-]{35}\b/g },
  { type: 'SLACK_TOKEN',       label: 'Slack token',
    regex: /\bxox[baprs]-[A-Za-z0-9\-]{10,}\b/g },
  { type: 'STRIPE_KEY',        label: 'Stripe key',
    regex: /\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b/g },
  { type: 'JWT',               label: 'JWT token',
    regex: /\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b/g },
  { type: 'PRIVATE_KEY',       label: 'Private key block',
    regex: /-----BEGIN\s(?:RSA\s|DSA\s|EC\s|OPENSSH\s|PGP\s)?PRIVATE KEY-----[\s\S]+?-----END\s(?:RSA\s|DSA\s|EC\s|OPENSSH\s|PGP\s)?PRIVATE KEY-----/g },
  { type: 'PASSWORD_FIELD',    label: 'Password (in key=value form)',
    regex: /\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*["']?([A-Za-z0-9!@#$%^&*()_+\-=\[\]{}|;:,.<>?/~`]{6,})["']?/gi,
    captureGroup: 1 },
  { type: 'EMAIL',             label: 'Email address',
    regex: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g },
  { type: 'CREDIT_CARD',       label: 'Credit card number',
    regex: /\b(?:\d[ \-]?){13,19}\b/g,
    validate: (m) => luhnCheck(m) },
  { type: 'SSN',               label: 'US Social Security Number',
    regex: /\b(?!000|666|9\d\d)\d{3}[\- ](?!00)\d{2}[\- ](?!0000)\d{4}\b/g },
  { type: 'NIC_LK',            label: 'Sri Lankan NIC',
    regex: /\b(?:\d{9}[VvXx]|\d{12})\b/g },
  { type: 'AADHAAR',           label: 'Indian Aadhaar number',
    regex: /(?<![\d\-])[2-9]\d{3}[\s\-]?\d{4}[\s\-]?\d{4}(?![\d\-])/g },
  { type: 'PAN_INDIA',         label: 'Indian PAN number',
    regex: /\b[A-Z]{5}[0-9]{4}[A-Z]\b/g },
  { type: 'PASSPORT',          label: 'Passport number (likely)',
    regex: /\b[A-PR-WY][1-9]\d\s?\d{4}[1-9]\b|\b[A-Z]{1,2}\d{6,9}\b/g,
    validate: (m, ctx) => /passport|travel doc/i.test(ctx) },
  { type: 'NIN_UK',            label: 'UK National Insurance number',
    regex: /\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b/g },
  { type: 'IBAN',              label: 'IBAN',
    regex: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g },
  { type: 'BITCOIN_ADDRESS',   label: 'Bitcoin address',
    regex: /\b(?:bc1[a-z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g },
  { type: 'PHONE',             label: 'Phone number',
    regex: /(?:\+?\d{1,3}[\s\-.]?)?(?:\(?\d{2,4}\)?[\s\-.]?)?\d{3,4}[\s\-.]?\d{3,4}\b/g,
    validate: (m) => {
      const digits = m.replace(/\D/g, '');
      return digits.length >= 9 && digits.length <= 15;
    } },
  { type: 'IPV4',              label: 'IPv4 address',
    regex: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
    validate: (m) => !['0.0.0.0', '127.0.0.1', '255.255.255.255', '1.1.1.1', '8.8.8.8'].includes(m) },
  { type: 'IPV6',              label: 'IPv6 address',
    regex: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/g },
  { type: 'MAC_ADDRESS',       label: 'MAC address',
    regex: /\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b/g },
  { type: 'DOB',               label: 'Date of birth (likely)',
    regex: /\b(?:0?[1-9]|[12]\d|3[01])[\/\-.](?:0?[1-9]|1[0-2])[\/\-.](?:19|20)\d{2}\b/g,
    validate: (m, ctx) => /\b(?:dob|birth|born|birthday)\b/i.test(ctx) },
  // Names. All four NAME patterns share the same `type: 'NAME'` so the
  // persistent placeholder map dedups them — "Sarah" detected via the
  // contact list and "Sarah" detected after a verb both get the same
  // [NAME_N] placeholder. Order matters only for character-range claiming
  // (first match wins on overlapping text), not for placeholder identity.
  { type: 'NAME',              label: 'Personal name (labeled)',
    regex: /\b(?:my name is|i am|i'm|name[:=])\s+([A-Z][a-z]{1,15}(?:\s+[A-Z][a-z]{1,15}){0,2})\b/gi,
    captureGroup: 1 },
  { type: 'NAME',              label: 'Personal name (titled)',
    regex: /\b(?:Mr|Mrs|Ms|Dr|Prof|Sir|Madam|Mister|Miss)\.?\s+([A-Z][a-z]{1,15}(?:\s+[A-Z][a-z]{1,15}){0,2})\b/g,
    captureGroup: 1 },
  { type: 'NAME',              label: 'Personal name (recipient)',
    // "Tell Sarah …", "Email Bob about …", "Hi John,". Stays in titlecase
    // so "tell test" lowercase gets through unscanned (mostly noise).
    // Validator filters honorifics so "Dear Mr. Smith" doesn't capture
    // "Mr" — the titled-name pattern below handles those.
    regex: /\b(?:Tell|Email|Call|Send|Ask|Notify|Inform|Hi|Hello|Hey|Dear|From|For|To)\s+([A-Z][a-z]{1,15}(?:\s+[A-Z][a-z]{1,15})?)\b/g,
    captureGroup: 1,
    validate: (m) => !/^(Mr|Mrs|Ms|Dr|Prof|Sir|Madam|Mister|Miss)$/.test(m) },
  { type: 'NAME',              label: 'Personal name (possessive)',
    // "Bob's account", "Sarah's email", etc. — whitelist trailing nouns to
    // avoid matching every X's-foo construction.
    regex: /\b([A-Z][a-z]{1,15})'s\s+(?:account|accounts|email|emails|phone|address|name|file|files|password|info|details|number|case|order|payment|salary|ticket|profile|record|contact|inbox|invoice|booking|session)\b/g,
    captureGroup: 1 },
  ...(CONTACTS_REGEX ? [{ type: 'NAME', label: 'Personal name (contact list)',
                           regex: CONTACTS_REGEX, captureGroup: 1 }] : []),

  { type: 'ADDRESS',           label: 'Street address (likely)',
    regex: /\b\d{1,5}\s+[A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+)*\s+(?:Street|St|Road|Rd|Avenue|Ave|Boulevard|Blvd|Lane|Ln|Drive|Dr|Way|Place|Pl|Court|Ct)\b\.?/g },
];

function detectPII(text) {
  if (!text || typeof text !== 'string') return [];

  const found = [];
  const taken = [];

  function overlaps(start, end) {
    return taken.some(([s, e]) => !(end <= s || start >= e));
  }

  for (const pat of PATTERNS) {
    const re = new RegExp(pat.regex.source, pat.regex.flags);
    let m;
    while ((m = re.exec(text)) !== null) {
      const fullMatch = m[0];
      const captured = pat.captureGroup ? m[pat.captureGroup] : fullMatch;
      if (!captured) continue;

      const start = m.index + (pat.captureGroup ? fullMatch.indexOf(captured) : 0);
      const end = start + captured.length;
      if (overlaps(start, end)) continue;

      const ctxStart = Math.max(0, start - 60);
      const ctxEnd = Math.min(text.length, end + 60);
      const context = text.slice(ctxStart, ctxEnd);
      if (pat.validate && !pat.validate(captured, context)) continue;

      taken.push([start, end]);
      found.push({ type: pat.type, label: pat.label, value: captured, start, end });
    }
  }

  found.sort((a, b) => a.start - b.start);
  return found;
}

module.exports = { detectPII };
