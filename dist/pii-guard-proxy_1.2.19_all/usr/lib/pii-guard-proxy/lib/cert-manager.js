'use strict';

const forge = require('node-forge');
const fs = require('fs');
const path = require('path');
const os = require('os');
const tls = require('tls');

const CA_DIR = process.env.PII_GUARD_CA_DIR || path.join(os.homedir(), '.pii-guard');
const CA_KEY_PATH = path.join(CA_DIR, 'ca-key.pem');
const CA_CERT_PATH = path.join(CA_DIR, 'ca-cert.pem');

let caCert = null;
let caKey = null;
const leafCache = new Map(); // hostname -> SecureContext

function ensureCa() {
  if (caCert && caKey) return;
  if (fs.existsSync(CA_KEY_PATH) && fs.existsSync(CA_CERT_PATH)) {
    caKey = forge.pki.privateKeyFromPem(fs.readFileSync(CA_KEY_PATH, 'utf8'));
    caCert = forge.pki.certificateFromPem(fs.readFileSync(CA_CERT_PATH, 'utf8'));
    return;
  }
  generateCa();
}

function generateCa() {
  if (!fs.existsSync(CA_DIR)) fs.mkdirSync(CA_DIR, { recursive: true, mode: 0o700 });
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01' + Date.now().toString(16);
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 10);
  const attrs = [
    { name: 'commonName', value: 'PII Guard Root CA' },
    { name: 'organizationName', value: 'PII Guard' },
    { name: 'organizationalUnitName', value: 'Local MITM' },
  ];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([
    { name: 'basicConstraints', cA: true, critical: true },
    { name: 'keyUsage', keyCertSign: true, cRLSign: true, critical: true },
    { name: 'subjectKeyIdentifier' },
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());

  fs.writeFileSync(CA_KEY_PATH, forge.pki.privateKeyToPem(keys.privateKey), { mode: 0o600 });
  fs.writeFileSync(CA_CERT_PATH, forge.pki.certificateToPem(cert), { mode: 0o644 });
  caCert = cert;
  caKey = keys.privateKey;
  console.log(`[PII Guard] Generated new CA at ${CA_CERT_PATH}`);
  console.log('[PII Guard] Trust this cert in your browser/OS to enable web-UI interception.');
}

function buildLeafCert(hostname) {
  ensureCa();
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '02' + Date.now().toString(16) + Math.floor(Math.random() * 1e6).toString(16);
  cert.validity.notBefore = new Date();
  cert.validity.notBefore.setHours(cert.validity.notBefore.getHours() - 1);
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
  cert.setSubject([
    { name: 'commonName', value: hostname },
    { name: 'organizationName', value: 'PII Guard' },
  ]);
  cert.setIssuer(caCert.subject.attributes);

  const altNames = [{ type: 2, value: hostname }]; // 2 = DNS
  // Wildcard for one-up parent (e.g. claude.ai → *.claude.ai)
  const parts = hostname.split('.');
  if (parts.length >= 2) {
    altNames.push({ type: 2, value: '*.' + parts.slice(-2).join('.') });
  }

  cert.setExtensions([
    { name: 'basicConstraints', cA: false },
    { name: 'keyUsage', digitalSignature: true, keyEncipherment: true, critical: true },
    { name: 'extKeyUsage', serverAuth: true, clientAuth: true },
    { name: 'subjectAltName', altNames },
  ]);
  cert.sign(caKey, forge.md.sha256.create());

  return {
    cert: forge.pki.certificateToPem(cert),
    key: forge.pki.privateKeyToPem(keys.privateKey),
  };
}

function getSecureContext(hostname) {
  if (leafCache.has(hostname)) return leafCache.get(hostname);
  const { cert, key } = buildLeafCert(hostname);
  const ctx = tls.createSecureContext({ cert, key });
  leafCache.set(hostname, ctx);
  return ctx;
}

function getCaCertPath() { return CA_CERT_PATH; }

module.exports = { ensureCa, getSecureContext, getCaCertPath };
