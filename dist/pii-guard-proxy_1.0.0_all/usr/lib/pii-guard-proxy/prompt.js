'use strict';

const readline = require('readline');
const { anonymize } = require('./lib/anonymizer');

// ANSI colors so the prompt is visible against terminal noise
const C = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  green: '\x1b[32m',
  cyan: '\x1b[36m',
  magenta: '\x1b[35m',
};

function printDetections(detections) {
  console.log(`${C.bold}${C.yellow}┌─ PII Guard ─ sensitive data detected ─────────${C.reset}`);
  for (const d of detections) {
    console.log(`${C.yellow}│${C.reset} ${C.red}${d.label}${C.reset}: ${C.dim}${d.value}${C.reset}`);
  }
  console.log(`${C.bold}${C.yellow}└────────────────────────────────────────────────${C.reset}`);
}

function promptUser(text, detections) {
  printDetections(detections);

  if (!process.stdin.isTTY) {
    const fallback = (process.env.PII_GUARD_HEADLESS_ACTION || 'decline').toLowerCase();
    const valid = { decline: 'decline', anonymize: 'anonymize', accept: 'accept', send: 'accept' };
    const action = valid[fallback] || 'decline';
    console.log(`${C.red}[PII Guard] No TTY available — using headless action: ${action}.${C.reset}`);
    return Promise.resolve(action);
  }

  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

    const ask = () => {
      const q = `${C.cyan}[PII Guard]${C.reset} ` +
        `${C.green}(s)${C.reset}end as-is / ` +
        `${C.magenta}(a)${C.reset}nonymize / ` +
        `${C.red}(d)${C.reset}ecline / ` +
        `${C.dim}(p)${C.reset}review anonymized: `;
      rl.question(q, (answer) => {
        const a = (answer || '').trim().toLowerCase();
        if (a === 's' || a === 'send') {
          rl.close();
          resolve('accept');
        } else if (a === 'a' || a === 'anonymize') {
          rl.close();
          resolve('anonymize');
        } else if (a === 'd' || a === 'decline' || a === '') {
          rl.close();
          resolve('decline');
        } else if (a === 'p' || a === 'preview') {
          const result = anonymize(text, detections);
          console.log(`\n${C.dim}--- Anonymized version (will be sent to LLM) ---${C.reset}`);
          console.log(result.text);
          console.log(`${C.dim}--- end preview ---${C.reset}\n`);
          ask();
        } else {
          console.log(`${C.dim}Type s, a, d, or p (empty = decline).${C.reset}`);
          ask();
        }
      });
    };

    ask();
  });
}

module.exports = { promptUser };
