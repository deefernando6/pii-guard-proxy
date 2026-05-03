'use strict';

// Supplementary regex patterns targeting categories the proxy's
// lib/detector.js + GLiNER PII Small INT8 currently miss on the
// pii-masking-300k validation split. Each pattern emits a span in the
// proxy's detection format: { start, end, value, type, label }.
//
// The "type" string mirrors the proxy's anonymizer.js taxonomy, with
// new placeholder buckets added for things our current taxonomy didn't
// have (TIME, TITLE, SEX, ADDRESS_UNIT, ZIP_CODE, COUNTRY, US_STATE).
// score-all.js's REGEX_GOLD_ACCEPTANCE map will be expanded to accept
// these new types for the right gold labels.

// Time formats:
//   HH:MM, HH:MM:SS, optional AM/PM
//   12-hour with AM/PM only ("7 PM")
const TIME_RE = /\b(?:\d{1,2}:\d{2}(?::\d{2})?(?:\s*[AaPp][Mm])?|\d{1,2}\s*[AaPp][Mm])\b/g;

// Titles. Built from the dataset's actual TITLE values + standard ones.
// Matched as whole words; the trailing dot is optional. Wrapped with
// word boundaries so "miss" inside "dismiss" doesn't match.
const TITLES = [
  'Mr', 'Mrs', 'Ms', 'Miss', 'Dr', 'Prof', 'Professor',
  'Sir', 'Madam', 'Madame', 'Lord', 'Lady',
  'Col', 'Colonel', 'Capt', 'Captain', 'Lt', 'Lieutenant',
  'Maj', 'Major', 'Gen', 'General', 'Sgt', 'Sergeant', 'Pvt',
  'Adm', 'Admiral', 'Cmdr', 'Commander',
  'Duchess', 'Duke', 'Earl', 'Countess', 'Count',
  'Prince', 'Princess', 'King', 'Queen', 'Empress', 'Emperor',
  'Marquess', 'Marquis', 'Marchioness',
  'Baron', 'Baroness', 'Viscount', 'Viscountess',
  'Archduchess', 'Archduke',
  'Bishop', 'Reverend', 'Rev', 'Father', 'Sister', 'Brother',
  'Imam', 'Rabbi', 'Pastor',
  'Hon', 'Honorable',
  'Ab',
];
const TITLE_RE = new RegExp(`\\b(?:${TITLES.join('|')})\\.?\\b`, 'g');

// Sex/gender values seen in the dataset. Single-letter forms (M, F)
// are too ambiguous to include without context — skipped.
const SEX_TERMS = [
  'Male', 'Female', 'Masculine', 'Feminine',
  'Non-binary', 'Nonbinary', 'Genderqueer', 'Gender-fluid', 'Genderfluid',
  'Trans', 'Transgender', 'Transmasculine', 'Transfeminine',
  'Agender', 'Bigender', 'Pangender',
];
const SEX_RE = new RegExp(`\\b(?:${SEX_TERMS.join('|')})\\b`, 'gi');

// Date formats (covers BOD too — the dataset uses identical shapes).
//   YYYY-MM-DD                (optional T HH:MM:SS suffix)
//   DD/MM/YYYY or MM/DD/YYYY  (any separator: / or -)
//   Month/YY or Month/YYYY
//   "October 10th, 1979"
//   "15th September 1940"
const MONTHS = '(?:January|February|March|April|May|June|July|August|September|October|November|December|Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)';
const DATE_RES = [
  // ISO: YYYY-MM-DD optionally with timestamp
  /\b\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?\b/g,
  // Numeric DD/MM/YYYY or MM/DD/YYYY (also DD-MM-YYYY)
  /\b\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}\b/g,
  // Month/YYYY or Month/YY
  new RegExp(`\\b${MONTHS}\\s*[\\/\\-]\\s*\\d{2,4}\\b`, 'g'),
  // "October 10th, 1979" / "October 10, 1979"
  new RegExp(`\\b${MONTHS}\\s+\\d{1,2}(?:st|nd|rd|th)?,?\\s+\\d{2,4}\\b`, 'g'),
  // "15th September 1940" / "15 Sept 1940"
  new RegExp(`\\b\\d{1,2}(?:st|nd|rd|th)?\\s+${MONTHS}\\s+\\d{2,4}\\b`, 'g'),
];

// Postal codes. Bare 5-digit numbers are everywhere in chat text (counts,
// IDs, etc.) so we don't fire on them in isolation. Three patterns:
//   ZIP+4 ("12345-6789") — distinctive enough to fire alone
//   US ZIP after a state abbr or full state name (", FL 12345")
//   UK postcode (full):  AAN NAA / AANN NAA / AN NAA / ANN NAA
const POSTCODE_RES = [
  /\b\d{5}-\d{4}\b/g,
  /(?:\b(?:AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY|DC)\b[,\s]+|\b(?:Alabama|Alaska|Arizona|Arkansas|California|Colorado|Connecticut|Delaware|Florida|Georgia|Hawaii|Idaho|Illinois|Indiana|Iowa|Kansas|Kentucky|Louisiana|Maine|Maryland|Massachusetts|Michigan|Minnesota|Mississippi|Missouri|Montana|Nebraska|Nevada|New Hampshire|New Jersey|New Mexico|New York|North Carolina|North Dakota|Ohio|Oklahoma|Oregon|Pennsylvania|Rhode Island|South Carolina|South Dakota|Tennessee|Texas|Utah|Vermont|Virginia|Washington|West Virginia|Wisconsin|Wyoming)\b[,\s]+)(\d{5})\b/g,
  /\b[A-Z]{1,2}\d{1,2}[A-Z]?\s+\d[A-Z]{2}\b/g,
];

// Secondary address: "Cottage 563", "Triplex 190", "Apt 5B", etc.
// Use a small whitelist to keep precision tight.
const SECADDR_KEYWORDS = [
  'Apt', 'Apartment', 'Suite', 'Unit', 'Bldg', 'Building',
  'Cottage', 'Triplex', 'Duplex', 'Office', 'Residence',
  'Cabin', 'Loft', 'Lodge', 'Dept', 'Department', 'Chalet',
  'Floor', 'Fl', 'Room', 'Rm',
];
const SECADDR_RE = new RegExp(
  `\\b(?:${SECADDR_KEYWORDS.join('|')})\\.?\\s+\\w+\\b`, 'g'
);

// Country — a focused list of full names + ISO codes. The dataset
// uses values like "US", "United States", "United Kingdom", "GB",
// "CH", "Italia", "Nederland". Casing is preserved.
const COUNTRIES = [
  'United States', 'United States of America', 'USA',
  'United Kingdom', 'Great Britain',
  'Italy', 'Italia', 'Spain', 'España', 'Germany', 'Deutschland',
  'France', 'Switzerland', 'Schweiz', 'Suisse', 'Netherlands', 'Nederland',
  'Belgium', 'Belgique', 'België', 'Austria', 'Österreich',
  'Portugal', 'Ireland', 'Sweden', 'Sverige', 'Norway', 'Norge',
  'Denmark', 'Danmark', 'Finland', 'Suomi', 'Iceland', 'Ísland',
  'Poland', 'Polska', 'Czech Republic', 'Czechia', 'Slovakia',
  'Hungary', 'Magyarország', 'Romania', 'Bulgaria', 'Greece',
  'Russia', 'Россия', 'Ukraine', 'Україна',
  'India', 'China', 'Japan', 'Korea', 'Vietnam', 'Thailand',
  'Australia', 'New Zealand', 'Canada', 'Mexico', 'Brazil', 'Brasil',
  'Argentina', 'Chile', 'Colombia', 'Peru',
  'Egypt', 'South Africa', 'Nigeria', 'Kenya', 'Ghana',
  'Saudi Arabia', 'UAE', 'Israel', 'Turkey', 'Iran', 'Pakistan',
  'Bangladesh', 'Sri Lanka', 'Indonesia', 'Malaysia', 'Singapore',
  'Philippines',
];
const COUNTRY_NAME_RE = new RegExp(
  `\\b(?:${COUNTRIES.map(c => c.replace(/\s+/g, '\\s+')).join('|')})\\b`, 'g'
);
// 2-letter ISO codes are too ambiguous to fire on in isolation
// ("US" / "IN" / "IT" / "AS" appear constantly as English words / ID
// suffixes). We only emit them when they appear immediately after a
// trailing comma or in a city-like context — checked further down via
// `findIsoCodeInContext`.
const ISO_CODES = [
  'US', 'GB', 'UK', 'CA', 'AU', 'NZ', 'IE', 'DE', 'FR', 'IT',
  'ES', 'PT', 'NL', 'BE', 'CH', 'AT', 'SE', 'NO', 'DK', 'FI',
  'PL', 'CZ', 'HU', 'GR', 'RU', 'UA', 'TR', 'IL', 'SA', 'AE',
  'CN', 'JP', 'KR', 'TH', 'VN', 'MY', 'SG', 'PH',
  'BR', 'MX', 'AR', 'CL', 'CO', 'PE', 'EG', 'ZA', 'NG', 'KE',
];
const ISO_CODE_CONTEXT_RE = new RegExp(
  `(?:[A-Z][a-z]+,\\s+|,\\s+)\\b(${ISO_CODES.join('|')})\\b`, 'g'
);

// US states / UK regions — only fire when in clear "City, ST" context.
// 2-letter abbrevs are heavily polluted otherwise (CA = "California"
// or just "California" the noun, IN = preposition, OR = conjunction).
const US_STATE_ABBR = [
  'AL','AK','AZ','AR','CA','CO','CT','DE','FL','GA','HI','ID',
  'IL','IN','IA','KS','KY','LA','ME','MD','MA','MI','MN','MS',
  'MO','MT','NE','NV','NH','NJ','NM','NY','NC','ND','OH','OK',
  'OR','PA','RI','SC','SD','TN','TX','UT','VT','VA','WA','WV',
  'WI','WY','DC',
];
const UK_REGION_ABBR = ['ENG', 'SCT', 'WLS', 'NIR', 'PAC'];
// Match "City, AZ" / "City, ENG" — must be preceded by a comma+space
// after a capitalised word.
const STATE_ABBR_CONTEXT_RE = new RegExp(
  `[A-Za-z]+,\\s+(${[...US_STATE_ABBR, ...UK_REGION_ABBR].join('|')})\\b`, 'g'
);

// Field-label-based extractors. The dataset is full of structured
// records like "Name: Signe Solodovnikova", `"Password": "2MxdP#"`,
// `<username>N0303</username>`, "Dear Mr. Smith,". When a recognisable
// label precedes the value the precision is essentially 100% — the
// label IS the context. We aggressively mine these.
//
// Each entry: [label-set, value-shape, type, label]
const FIELD_PATTERNS = [
  // names after Name:/given_name:/lastname: etc.  Captures up to 4 cap-
  // italised tokens. \p{L} covers accented chars (Gómez, Aljosha, etc.).
  {
    re: /(?:^|[\s\[\(\{,])(?:Name|Full[\s_-]?Name|Given[\s_-]?Name(?:1|2)?|First[\s_-]?Name|Last[\s_-]?Name(?:1|2|3)?|Surname|Family[\s_-]?Name|givenname[12]?|lastname[123]?)\s*[:=]\s*\[?"?([\p{Lu}][\p{L}\-']+(?:\s+(?:de\s+|van\s+|von\s+|del\s+|della\s+)?[\p{Lu}][\p{L}\-']+){0,3})"?\]?/gu,
    type: 'NAME', label: 'name_field',
  },
  // "Dear NAME(S),"  e.g. "Dear Revajete Visnja Fabjan,"
  {
    re: /\bDear\s+([\p{Lu}][\p{L}\-']+(?:\s+(?:Mr\.?|Mrs\.?|Ms\.?|Dr\.?|Prof\.?)?\s*[\p{Lu}][\p{L}\-']+){0,3}),/gu,
    type: 'NAME', label: 'name_dear',
  },
  // Usernames: Username: foo / user_id: foo / "User": "foo"
  {
    re: /(?:^|[\s\[\(\{,])(?:Username|User[\s_-]?Name|UserId|User[\s_-]?Id|user|userid|user[\s_-]?name|Initiator)\s*[:=]\s*\[?"?([A-Za-z0-9][A-Za-z0-9._\-]{2,})"?\]?/gi,
    type: 'USERNAME', label: 'username_field',
  },
  // <username>foo</username> XML
  {
    re: /<username>([^<]{1,80})<\/username>/gi,
    type: 'USERNAME', label: 'username_xml',
  },
  // Passwords: Password: foo / "Password": "foo" / UniqueID: foo
  {
    re: /(?:^|[\s\[\(\{,])(?:Password|Passwd|Pwd|UniqueID|Unique[\s_-]?Id|secret|api[\s_-]?key|token)\s*[:=]\s*\[?"?([^\s"\]\}\),]{4,200})"?\]?/gi,
    type: 'PASSWORD_FIELD', label: 'password_field',
  },
  // Sex/Gender field
  {
    re: /(?:^|[\s\[\(\{,])(?:Sex|Gender|Sex[\s_-]?Type|Gender[\s_-]?Identity)\s*[:=]\s*\[?"?([A-Za-z][A-Za-z\-]{0,30})"?\]?/gi,
    type: 'SEX', label: 'sex_field',
  },
  // Title field — captures whatever's there
  {
    re: /(?:^|[\s\[\(\{,])(?:Title|Honorific|Salutation)\s*[:=]\s*\[?"?([A-Za-z][A-Za-z\-\.\s]{0,40})"?\]?/gi,
    type: 'TITLE', label: 'title_field',
  },
  // Date of Birth field with arbitrary date shape
  {
    re: /(?:^|[\s\[\(\{,])(?:Date[\s_-]?of[\s_-]?Birth|DOB|BOD|Birth[\s_-]?Date|birthdate)\s*[:=]\s*\[?"?([^"\]\}\n\r]{4,40})"?\]?/gi,
    type: 'DOB', label: 'dob_field',
  },
  // Title + capitalised name(s):  "Mr. Smith", "Dr. John Adams", "Lady Catherine"
  // Captures the name part (skipping the title) for downstream type=NAME.
  {
    re: /\b(?:Mr|Mrs|Ms|Miss|Dr|Prof|Professor|Sir|Madam|Madame|Lord|Lady|Col|Colonel|Capt|Captain|Lt|Lieutenant|Maj|Major|Gen|General|Sgt|Sergeant|Pvt|Adm|Admiral|Cmdr|Commander|Duchess|Duke|Earl|Countess|Count|Prince|Princess|King|Queen|Empress|Emperor|Marquess|Marquis|Marchioness|Baron|Baroness|Viscount|Viscountess|Archduchess|Archduke|Bishop|Reverend|Rev|Father|Sister|Brother|Imam|Rabbi|Pastor|Hon|Honorable)\.?\s+([\p{Lu}][\p{L}\-']+(?:\s+(?:de|van|von|del|della|la|le)\s+|\s+)?(?:[\p{Lu}][\p{L}\-']+)?(?:\s+[\p{Lu}][\p{L}\-']+)?)/gu,
    type: 'NAME', label: 'name_after_title',
  },
  // Markdown / templating brackets: [Name], [john_doe], [Aljosha Robadey]
  // Used in prompts like "I hope this finds you well, [Yvetta Volpato],".
  // Capture group is the name; restrict to up to 4 cap-tokens or one
  // username-shaped token so we don't engulf large bracketed phrases.
  {
    re: /\[([\p{Lu}][\p{L}\-']+(?:\s+[\p{Lu}][\p{L}\-']+){0,3})\]/gu,
    type: 'NAME', label: 'name_brackets',
  },
  {
    re: /\[([a-z][a-z0-9._\-]{2,30})\]/g,
    type: 'USERNAME', label: 'username_brackets',
  },
  // Street-suffix patterns: "Imber Road", "State Route 103", "The Crescent",
  // "Holme Wood Lane". Capture the whole phrase as ADDRESS.
  {
    re: /\b((?:[\p{Lu}][\p{L}\-']*|The|State|County|Old|New|North|South|East|West|Upper|Lower)(?:\s+(?:[\p{Lu}][\p{L}\-']*|Wood|Hill|Park|View|Bridge|Cross|Field))*\s+(?:Road|Rd|Street|St|Lane|Ln|Drive|Dr|Avenue|Ave|Boulevard|Blvd|Way|Crescent|Court|Ct|Place|Pl|Trail|Trl|Highway|Hwy|Route|Rte|Square|Sq|Terrace|Ter|Park|Plaza|Mews|Walk|Close|Gardens?|Heights?|Hill|Rise|Vale|Strasse|Strase|Gasse))\b/gu,
    type: 'ADDRESS', label: 'street_suffix',
  },
  // "<digits> <words>" as street address (e.g. "123 Main St" prefix).
  // The full phrase is the address; the leading number is the building.
  {
    re: /\b(\d{1,5})\s+(?:[\p{Lu}][\p{L}\-']+\s*)+(?=Road|Rd|Street|St|Lane|Ln|Drive|Dr|Avenue|Ave|Boulevard|Blvd|Way|Crescent|Court|Ct|Place|Pl|Trail|Highway|Hwy|Route|Rte|Square|Sq)/gu,
    type: 'ADDRESS', label: 'building_number',
  },
];

function findAll(text, re, type, label) {
  re.lastIndex = 0;
  const out = [];
  let m;
  while ((m = re.exec(text)) !== null) {
    out.push({
      start: m.index,
      end: m.index + m[0].length,
      value: m[0],
      type,
      label,
    });
    if (m[0].length === 0) re.lastIndex++;   // safety
  }
  return out;
}

// For regexes with a capture group: emit the GROUP's span, not the
// outer match. Used by ISO/STATE context patterns (where the outer
// match includes the leading "City, " context but the actual entity
// is the trailing 2-letter code).
function findGroup(text, re, type, label) {
  re.lastIndex = 0;
  const out = [];
  let m;
  while ((m = re.exec(text)) !== null) {
    if (!m[1]) { if (m[0].length === 0) re.lastIndex++; continue; }
    const groupIdx = text.indexOf(m[1], m.index);
    if (groupIdx < 0) continue;
    out.push({
      start: groupIdx,
      end: groupIdx + m[1].length,
      value: m[1],
      type,
      label,
    });
    if (m[0].length === 0) re.lastIndex++;
  }
  return out;
}

// Main entry point. Pass a text, get supplementary detections back.
function detectSupplementary(text) {
  if (!text || typeof text !== 'string') return [];
  const out = [];
  out.push(...findAll(text, TIME_RE, 'TIME', 'time'));
  out.push(...findAll(text, TITLE_RE, 'TITLE', 'title'));
  out.push(...findAll(text, SEX_RE, 'SEX', 'sex'));
  for (const re of DATE_RES) out.push(...findAll(text, re, 'DOB', 'date'));
  // POSTCODE_RES has both pure regexes and a context regex with capture
  // group — handle each appropriately.
  out.push(...findAll(text, POSTCODE_RES[0], 'POSTCODE', 'postcode'));
  out.push(...findGroup(text, POSTCODE_RES[1], 'POSTCODE', 'postcode'));
  out.push(...findAll(text, POSTCODE_RES[2], 'POSTCODE', 'postcode'));
  out.push(...findAll(text, SECADDR_RE, 'ADDRESS_UNIT', 'secondary_address'));
  out.push(...findAll(text, COUNTRY_NAME_RE, 'COUNTRY', 'country'));
  out.push(...findGroup(text, ISO_CODE_CONTEXT_RE, 'COUNTRY', 'country'));
  out.push(...findGroup(text, STATE_ABBR_CONTEXT_RE, 'US_STATE', 'state'));
  // Field-label-based extractors (highest precision — explicit labels
  // anchor each match, capture group is the value).
  for (const fp of FIELD_PATTERNS) {
    out.push(...findGroup(text, fp.re, fp.type, fp.label));
  }
  // Drop overlaps inside this list so each char is covered by at most one rule.
  out.sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));
  const dedup = [];
  let cursor = 0;
  for (const d of out) {
    if (d.start < cursor) continue;
    dedup.push(d);
    cursor = d.end;
  }
  return dedup;
}

module.exports = { detectSupplementary };
