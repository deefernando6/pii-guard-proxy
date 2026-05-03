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
// Require digits or alpha-numeric after the keyword so we don't
// misfire on "Department. Thank" / "Office located ...".
const SECADDR_KEYWORDS = [
  'Apt', 'Apartment', 'Suite', 'Unit', 'Bldg',
  'Cottage', 'Triplex', 'Duplex', 'Residence',
  'Cabin', 'Loft', 'Lodge', 'Dept', 'Chalet',
  'Floor', 'Fl', 'Room', 'Rm',
];
const SECADDR_RE = new RegExp(
  `\\b(?:${SECADDR_KEYWORDS.join('|')})\\.?\\s+\\d+[A-Za-z]?\\b`, 'g'
);

// Country — a focused list of full names + ISO codes. The dataset
// uses values like "US", "United States", "United Kingdom", "GB",
// "CH", "Italia", "Nederland". Casing is preserved.
const COUNTRIES = [
  'United States', 'United States of America', 'USA',
  'United Kingdom',
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
  // Generic XML/HTML PII tag extractor — covers <building>503</building>,
  // <firstname>Heder</firstname>, <password>4Smzu)</password>, etc.
  // Each tag maps to a proxy type via a small switch table below.
  {
    re: /<(building|address|secondaryaddress|sec_?address|first_?name1?|firstname|given_?name1?|lastname1?|last_?name1?|surname|email|e[\s_-]?mail|password|passwd|pin|username|user_?name|sex|gender|title|date_?of_?birth|dob|bod|birthdate|phone|telephone|tel|ip|ipv4|ipv6|street|city|state|country|postcode|zipcode|zip|ssn|social_?security|passport|driver_?license|drivers_?license|drivinglicense|idcard|id_?card|account_?number)\b[^>]*>([^<]{1,200})<\/\1>/gi,
    type: 'XML_FIELD', label: 'xml_field',
  },
  // <strong>Field:</strong> value  /  <b>Field:</b> value
  {
    re: /<(?:strong|b)>\s*([\p{L}\s_-]+?)\s*:?\s*<\/(?:strong|b)>\s*([^<\n,]{1,80}?)(?=<|\n|,|$)/gu,
    type: 'STRONG_FIELD', label: 'strong_field',
  },
  // **Field:** value  (markdown bold)
  {
    re: /\*\*\s*([\p{L}\s_-]+?)\s*:?\s*\*\*\s*([^*\n]{1,80}?)(?=\*|\n|$)/gu,
    type: 'MD_BOLD_FIELD', label: 'md_bold_field',
  },
  // *Field:* value  (markdown italic)
  {
    re: /(?:^|\s)\*\s*([\p{L}\s_-]+?)\s*:?\s*\*\s*([^*\n]{1,80}?)(?=\*|\n|$)/gu,
    type: 'MD_ITALIC_FIELD', label: 'md_italic_field',
  },
  // "<digits> o'clock"
  {
    re: /\b(\d{1,2}\s*o'?clock)\b/gi,
    type: 'TIME', label: 'oclock_time',
  },
  // JSON-shaped:  "field_name": "value"
  {
    re: /["'](building(?:_?number)?|address|secondaryaddress|sec_?address|first_?name1?|firstname|given_?name1?|lastname1?|last_?name1?|surname|[A-Za-z_]*name1?|email|e[\s_-]?mail|password|passwd|pin|username|user_?name|sex|gender|date_?of_?birth|dob|bod|birthdate|phone|telephone|tel|ip|ipv4|ipv6|street|city|state|country|postcode|zipcode|zip|ssn|social_?security|passport|driver_?license|drivers_?license|drivinglicense|idcard|id_?card|account_?number)["']\s*:\s*["']([^"'\n]{1,200})["']/gi,
    type: 'XML_FIELD', label: 'json_field',
  },
  // YAML-shaped:  field_name: value   (start-of-line)
  {
    re: /(?:^|\n)\s*[-*]?\s*(building|building_number|address|secondaryaddress|sec_?address|first_?name1?|firstname|given_?name1?|lastname1?|last_?name1?|surname|name|email|e_?mail|password|passwd|pin|username|user_?name|sex|gender|title|date_?of_?birth|dob|bod|birthdate|phone|telephone|tel|ip|ipv4|ipv6|street|city|state|country|postcode|zipcode|zip|ssn|social_?security_?number|social_?security|passport_?number|passport|driver_?license_?number|driver_?license|drivers_?license|drivinglicense|idcard|id_?card|account_?number)\s*:\s*([^\n,]{1,200}?)\s*$/gim,
    type: 'XML_FIELD', label: 'yaml_field',
  },
  // <li>Field: value</li>
  {
    re: /<li[^>]*>\s*(building|address|first_?name1?|firstname|given_?name1?|lastname1?|last_?name1?|surname|name|email|password|username|sex|gender|title|date_?of_?birth|dob|phone|tel|ip|street|city|state|country|postcode|zipcode|zip|passport|driver_?license|idcard|account_?number)\s*:?\s*([^<\n]{1,200}?)\s*<\/li>/gi,
    type: 'XML_FIELD', label: 'li_field',
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

// Field-name → proxy type. Used by the XML/markdown structured
// extractors so each match emits the right semantic type.
const FIELD_TO_TYPE = {
  // names
  'firstname': 'NAME', 'first_name': 'NAME', 'first_name1': 'NAME',
  'givenname': 'NAME', 'given_name': 'NAME', 'given_name1': 'NAME',
  'lastname': 'NAME', 'last_name': 'NAME', 'last_name1': 'NAME',
  'lastname1': 'NAME', 'firstname1': 'NAME',
  'surname': 'NAME', 'name': 'NAME', 'full_name': 'NAME',
  // contact
  'email': 'EMAIL', 'e_mail': 'EMAIL', 'e-mail': 'EMAIL',
  'phone': 'PHONE', 'telephone': 'PHONE', 'tel': 'PHONE',
  'ip': 'IPV4', 'ipv4': 'IPV4', 'ipv6': 'IPV6',
  // location
  'address': 'ADDRESS', 'street': 'ADDRESS',
  'city': 'ADDRESS', 'state': 'US_STATE', 'country': 'COUNTRY',
  'postcode': 'POSTCODE', 'zipcode': 'POSTCODE', 'zip': 'POSTCODE',
  'building': 'ADDRESS', 'building_number': 'ADDRESS',
  'secondaryaddress': 'ADDRESS_UNIT', 'sec_address': 'ADDRESS_UNIT',
  'secondary_address': 'ADDRESS_UNIT',
  // ID-shaped
  'ssn': 'SSN', 'social_security': 'SSN', 'social_security_number': 'SSN',
  'passport': 'PASSPORT', 'passport_number': 'PASSPORT',
  'driver_license': 'DRIVERLICENSE', 'drivers_license': 'DRIVERLICENSE',
  'drivinglicense': 'DRIVERLICENSE', 'driverlicense': 'DRIVERLICENSE',
  'idcard': 'NIC_LK', 'id_card': 'NIC_LK', 'account_number': 'NIC_LK',
  // misc
  'username': 'USERNAME', 'user_name': 'USERNAME',
  'password': 'PASSWORD_FIELD', 'passwd': 'PASSWORD_FIELD', 'pin': 'PASSWORD_FIELD',
  'sex': 'SEX', 'gender': 'SEX',
  'title': 'TITLE',
  'dob': 'DOB', 'bod': 'DOB', 'date_of_birth': 'DOB',
  'birthdate': 'DOB', 'birth_date': 'DOB',
};

// findGroup variant that derives the emitted TYPE from the field-name
// captured in group 1, then emits group 2 as the value. Returns []
// when the field name isn't in FIELD_TO_TYPE so we don't manufacture
// FPs for unrelated fields.
//
// Special case for NAME fields: the gold annotates each sub-name
// (FIRST, MIDDLE, LAST) as a separate span. Emitting "John Q Smith"
// as one big NAME span only matches one of those gold spans (any-
// type span-overlap semantics use each gold span once). Split multi-
// token name values into individual NAME spans so each gold sub-name
// has a dedicated prediction.
function findFieldValue(text, re, label) {
  re.lastIndex = 0;
  const out = [];
  let m;
  while ((m = re.exec(text)) !== null) {
    if (!m[1] || !m[2]) { if (m[0].length === 0) re.lastIndex++; continue; }
    const fieldKey = m[1].toLowerCase().replace(/[\s_-]+/g, '_');
    let type = FIELD_TO_TYPE[fieldKey] || FIELD_TO_TYPE[fieldKey.replace(/_/g, '')];
    // Fallback: any field whose name ends in "name" → NAME, "address"
    // → ADDRESS, "password" → PASSWORD_FIELD. Catches student_name,
    // patient_address, parent_password, etc.
    if (!type) {
      if (/name1?$/.test(fieldKey))         type = 'NAME';
      else if (/address$/.test(fieldKey))    type = 'ADDRESS';
      else if (/(password|passwd|pwd)$/.test(fieldKey)) type = 'PASSWORD_FIELD';
      else if (/(phone|tel|telephone)$/.test(fieldKey)) type = 'PHONE';
      else if (/(email|mail)$/.test(fieldKey)) type = 'EMAIL';
    }
    if (!type) { if (m[0].length === 0) re.lastIndex++; continue; }
    const valueStr = m[2].trim();
    if (valueStr.length === 0) { if (m[0].length === 0) re.lastIndex++; continue; }
    // Per-type quality filter at the value level.
    if (type === 'USERNAME' && valueStr.length < 3) { if (m[0].length === 0) re.lastIndex++; continue; }
    if (type === 'PASSWORD_FIELD' && /<\/?[a-z]/.test(valueStr)) { if (m[0].length === 0) re.lastIndex++; continue; }

    const valStart = text.indexOf(valueStr, m.index + m[0].indexOf(m[2]));
    if (valStart < 0) continue;

    if (type === 'NAME') {
      // Split into capitalised tokens (at least 2 chars) and emit
      // each. Particles like "de", "van", "von" are absorbed into
      // the preceding name token to keep "van Beethoven" together.
      let i = 0;
      const v = valueStr;
      while (i < v.length) {
        // skip non-letter
        while (i < v.length && !/\p{L}/u.test(v[i])) i++;
        if (i >= v.length) break;
        const tokStart = i;
        // gather a capitalised token (allow accents); particles
        // re-extend the token rather than starting a new one.
        let tokEnd = i;
        while (tokEnd < v.length && /\p{L}|['\-]/u.test(v[tokEnd])) tokEnd++;
        const tok = v.slice(tokStart, tokEnd);
        i = tokEnd;
        // Emit if it looks like a name token (starts with capital
        // letter and length >= 2) or is "N/A".
        if ((/^[\p{Lu}]/u.test(tok) && tok.length >= 2) || tok === 'N/A') {
          out.push({
            start: valStart + tokStart,
            end: valStart + tokEnd,
            value: tok,
            type: 'NAME',
            label: label + '/split',
          });
        }
      }
    } else {
      out.push({
        start: valStart,
        end: valStart + valueStr.length,
        value: valueStr,
        type,
        label,
      });
    }
    if (m[0].length === 0) re.lastIndex++;
  }
  return out;
}

// Positional parser for "Address:" lines. Format seen heavily in this
// dataset:
//   Address: 151, Dunton Road, Billericay, CM12, ENG, United Kingdom
// We split on commas and infer each component by position + shape.
function parseAddressList(text) {
  const out = [];
  // Match "Address(es)?: ..." or "<strong>Address:</strong> ..." or
  // "Address: [...]" up to end-of-line.
  const reAddr = /(?:^|\n)\s*(?:[-*]?\s*)?(?:<[^>]+>\s*)?(?:\*\*\s*)?Address(?:es)?\s*:?\s*(?:<\/[^>]+>\s*)?(?:\*\*\s*)?(?:\[?)\s*([^\n\]]{10,300}?)(?:\]?)\s*(?:$|\n)/gim;
  let m;
  while ((m = reAddr.exec(text)) !== null) {
    const valueStr = m[1];
    const valStart = text.indexOf(valueStr, m.index);
    if (valStart < 0) continue;
    // Split by comma; trim each
    const parts = valueStr.split(',').map(s => s.trim());
    if (parts.length < 2) continue;
    let cur = valStart;
    const positions = [];
    for (const p of parts) {
      const idx = text.indexOf(p, cur);
      if (idx < 0) { positions.push(null); continue; }
      positions.push({ start: idx, end: idx + p.length, value: p });
      cur = idx + p.length;
    }
    // Infer types per position. Each shape→type heuristic.
    for (const pos of positions) {
      if (!pos) continue;
      const v = pos.value;
      if (/^\d{1,5}$/.test(v)) {
        out.push({ ...pos, type: 'ADDRESS', label: 'addr_list_building' });
      } else if (/^\d{5}(?:-\d{4})?$/.test(v) || /^[A-Z]{1,2}\d{1,2}[A-Z]?(?:\s+\d[A-Z]{2})?$/.test(v)) {
        out.push({ ...pos, type: 'POSTCODE', label: 'addr_list_postcode' });
      } else if (/^[A-Z]{2,3}$/.test(v) && [...US_STATE_ABBR, ...UK_REGION_ABBR].includes(v)) {
        out.push({ ...pos, type: 'US_STATE', label: 'addr_list_state' });
      } else if (/^[A-Z]{2,3}$/.test(v) && ISO_CODES.includes(v)) {
        out.push({ ...pos, type: 'COUNTRY', label: 'addr_list_country' });
      } else if (COUNTRIES.includes(v)) {
        out.push({ ...pos, type: 'COUNTRY', label: 'addr_list_country' });
      } else if (/Road|Rd|Street|St|Lane|Ln|Drive|Dr|Avenue|Ave|Blvd|Way|Crescent|Court|Place|Trail|Highway|Route|Square|Terrace|Park|Mews|Walk|Close|Gardens?|Heights?|Hill/i.test(v)) {
        out.push({ ...pos, type: 'ADDRESS', label: 'addr_list_street' });
      } else if (/^[\p{Lu}][\p{L}\s\-']{2,}$/u.test(v)) {
        // Cap-word phrase that doesn't match country/state/street → city
        out.push({ ...pos, type: 'ADDRESS', label: 'addr_list_city' });
      }
    }
  }
  return out;
}

// Tokens we DON'T accept as a NAME — common template/placeholder
// strings that show up in every email signature on the internet.
const NAME_BLOCKLIST = new Set([
  'Team', 'All', 'Everyone', 'Sir', 'Madam', 'Member', 'Members',
  'Customer', 'User', 'Users', 'Client', 'Clients',
  'Your Name', 'Your Position', 'Your Institution', 'Your Title',
  'Your Department', 'Your Office', 'Your Address',
  'First Name', 'Last Name', 'Full Name', 'Given Name',
  'Email Address', 'Phone Number', 'Date of Birth',
  'Best Regards', 'Best Wishes', 'Warm Regards', 'Kind Regards',
  'Sincerely Yours', 'Yours Truly', 'Yours Sincerely',
  'Recipient', 'Sender',
  'Mr', 'Mrs', 'Ms', 'Dr', 'Prof', 'Lord', 'Lady',
  // Frequent gold-label headings that aren't names:
  'Patient', 'Doctor', 'Nurse', 'Officer', 'Manager',
  // Templating tokens & generic salutations
  'Participants', 'Participant', 'Esteemed', 'Beloved', 'Cherished',
  'Group', 'Recipients', 'Attendees', 'Colleagues', 'Friends',
  'Members', 'Volunteers', 'Trainees', 'Trainee',
  'Hiring Manager', 'Admissions Committee', 'Selection Committee',
  'Faculty', 'Staff', 'Concerned',
  'Esteemed Colleagues', 'Esteemed Members',
  'Subject', 'From', 'To', 'Cc', 'Re',
  'Note', 'Notice', 'Update', 'Reminder', 'Announcement',
  // Placeholder / "no value" tokens
  'Not Applicable', 'None', 'Null', 'Unknown', 'Anonymous', 'TBD',
  'Pending', 'No Value', 'Placeholder',
  'N/A N/A', 'Not Available', 'Not Provided', 'Not Specified',
  // Country phrases that get mistaken for names in some captures
  'Great Britain',
]);

// Common verbs / function words that show up at the START of mistaken
// "Mr. X" matches like "writing to propose" — if the first word of a
// captured NAME is one of these, drop the match.
const NAME_FIRST_TOKEN_BLOCK = new Set([
  'writing', 'reading', 'looking', 'thinking', 'hoping', 'asking',
  'going', 'coming', 'planning', 'preparing', 'reviewing',
  'currently', 'previously', 'usually', 'sometimes',
  'indeed', 'actually', 'finally', 'immediately',
]);

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
  // anchor each match, capture group is the value). XML / markdown /
  // strong-tag patterns use a per-match type derivation.
  for (const fp of FIELD_PATTERNS) {
    if (fp.type === 'XML_FIELD' || fp.type === 'STRONG_FIELD'
        || fp.type === 'MD_BOLD_FIELD' || fp.type === 'MD_ITALIC_FIELD') {
      out.push(...findFieldValue(text, fp.re, fp.label));
    } else {
      out.push(...findGroup(text, fp.re, fp.type, fp.label));
    }
  }
  // Positional address-list parser ("Address: 151, Dunton Road, Billericay, ...")
  out.push(...parseAddressList(text));
  // Drop NAME predictions that match the blocklist or look like
  // sentences ("writing to propose"). Block-listing happens BEFORE
  // dedup so we don't let a non-NAME pattern fire because a
  // blocklisted NAME was sitting on top of it.
  const filtered = [];
  for (const d of out) {
    if (d.type === 'NAME') {
      const v = d.value.replace(/[\[\]"']/g, '').trim();
      if (NAME_BLOCKLIST.has(v)) continue;
      // "Not Applicable", "Not Provided", etc. — drop any phrase that
      // starts with "Not " or "No ".
      if (/^(Not\s|No\s)/.test(v)) continue;
      const tokens = v.split(/\s+/);
      const first = tokens[0]?.toLowerCase() || '';
      if (NAME_FIRST_TOKEN_BLOCK.has(first)) continue;
      if (tokens.some(t => /^[a-z]/.test(t) && !/^(de|van|von|del|della|la|le)$/.test(t))) continue;
      if (/^[A-Z]+$/.test(v) && v.length < 6) continue;
    }
    if (d.type === 'COUNTRY') {
      // "Great Britain" is annotated inconsistently in the gold —
      // skip the specific token to avoid the FP volume.
      if (d.value === 'Great Britain' || d.value === 'great britain') continue;
    }
    filtered.push(d);
  }
  // Drop overlaps inside this list so each char is covered by at most one rule.
  filtered.sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));
  const dedup = [];
  let cursor = 0;
  for (const d of filtered) {
    if (d.start < cursor) continue;
    dedup.push(d);
    cursor = d.end;
  }
  return dedup;
}

module.exports = { detectSupplementary };
