// closer-click-signer — Autoridad de sello de tiempo (TSA) del ecosistema
// CloserClick. Es un TERCERO de confianza: firma con SU clave un par
// { hash, ts }, donde `hash` es el digest (SHA-256) de un contenido que el
// servidor NUNCA ve. Eso prueba "este contenido exacto existía en el instante
// T (reloj del sellador)", sin revelarle nada al sellador.
//
// Pensado para desplegarse en https://signer.closer.click y ser pineado por las
// apps como autoridad canónica. La verificación es offline: cualquiera con la
// pubkey del sellador valida el sello.
//
// Sin dependencias en runtime: solo módulos nativos de Node (http, crypto, fs).

import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const PORT = parseInt(process.env.PORT, 10) || 4010;
const ALG = 'ECDSA-P256-SHA256';
const VERSION = 1;
const KEY_FILE = process.env.TSA_KEY_FILE || path.join(__dirname, '.tsa-key.json');
// El hash sellado debe ser un SHA-256 (32 bytes) en base64url: el sellador solo
// firma digests de tamaño fijo, nunca contenido arbitrario.
const HASH_BYTES = 32;

// ---- Serialización canónica (idéntica a vault / proxy / proxy-client) -------
function canonicalStringify (v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canonicalStringify).join(',') + ']';
  const ks = Object.keys(v).sort();
  return '{' + ks.map((k) => JSON.stringify(k) + ':' + canonicalStringify(v[k])).join(',') + '}';
}

// ---- base64url ----
function b64urlToBuf (s) {
  if (typeof s !== 'string') return null;
  const norm = s.replace(/-/g, '+').replace(/_/g, '/');
  try { return Buffer.from(norm, 'base64'); } catch { return null; }
}

// ---- Clave del sellador (carga / generación / persistencia) -----------------
function loadOrCreateKey () {
  // 1) Override por variable de entorno (deploy sin estado en disco).
  if (process.env.TSA_PRIVATE_JWK) {
    const privJwk = JSON.parse(process.env.TSA_PRIVATE_JWK);
    return keyFromPrivateJwk(privJwk);
  }
  // 2) Archivo persistente (sobrevive reinicios → los sellos viejos verifican).
  if (fs.existsSync(KEY_FILE)) {
    const privJwk = JSON.parse(fs.readFileSync(KEY_FILE, 'utf8'));
    return keyFromPrivateJwk(privJwk);
  }
  // 3) Primer arranque: generamos y persistimos.
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const privJwk = privateKey.export({ format: 'jwk' });
  fs.writeFileSync(KEY_FILE, JSON.stringify(privJwk), { mode: 0o600 });
  console.log(`[signer] clave nueva generada y guardada en ${KEY_FILE}`);
  return { privateKey, publicKey, publicJwk: publicKey.export({ format: 'jwk' }) };
}

function keyFromPrivateJwk (privJwk) {
  const privateKey = crypto.createPrivateKey({ key: privJwk, format: 'jwk' });
  // Derivamos la pública quitando el componente privado `d`.
  const { d, ...pubJwk } = privJwk;
  const publicKey = crypto.createPublicKey({ key: pubJwk, format: 'jwk' });
  return { privateKey, publicKey, publicJwk: pubJwk };
}

const KEY = loadOrCreateKey();
const PUBKEY_STR = JSON.stringify(KEY.publicJwk);

// ---- Firma del sello --------------------------------------------------------
// Firma ieee-p1363 (r||s, 64 bytes crudos) para que el navegador la verifique
// directo con WebCrypto. El contenido firmado es canonical({ hash, op, ts }).
function signSeal (hash, ts) {
  const payload = { op: 'seal', hash, ts };
  const bytes = Buffer.from(canonicalStringify(payload), 'utf8');
  const sig = crypto.sign('sha256', bytes, { key: KEY.privateKey, dsaEncoding: 'ieee-p1363' });
  return sig.toString('base64');
}

// ---- HTTP -------------------------------------------------------------------
function setCors (res) {
  // Los sellos son públicos y no secretos: CORS abierto para que cualquier app
  // del ecosistema (mundial.closer.click, etc.) pueda pedirlos desde el navegador.
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Max-Age', '86400');
}

function sendJson (res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(body);
}

function pubkeyPayload () {
  return { v: VERSION, alg: ALG, pubkey: PUBKEY_STR, jwk: KEY.publicJwk };
}

function readBody (req, limitBytes, cb) {
  let size = 0;
  const chunks = [];
  let done = false;
  const finish = (err, data) => { if (!done) { done = true; cb(err, data); } };
  req.on('data', (c) => {
    size += c.length;
    if (size > limitBytes) { finish(new Error('payload too large')); req.destroy(); return; }
    chunks.push(c);
  });
  req.on('end', () => finish(null, Buffer.concat(chunks).toString('utf8')));
  req.on('error', (e) => finish(e));
}

function handleSeal (req, res) {
  readBody(req, 4096, (err, raw) => {
    if (err) return sendJson(res, 413, { error: 'cuerpo demasiado grande' });
    let body;
    try { body = JSON.parse(raw || '{}'); } catch { return sendJson(res, 400, { error: 'JSON inválido' }); }
    const hash = body && body.hash;
    const buf = b64urlToBuf(hash);
    if (!hash || typeof hash !== 'string' || !buf || buf.length !== HASH_BYTES) {
      return sendJson(res, 400, { error: `hash inválido: se espera SHA-256 (${HASH_BYTES} bytes) en base64url` });
    }
    const ts = Date.now();
    const signature = signSeal(hash, ts);
    sendJson(res, 200, {
      v: VERSION,
      op: 'seal',
      hash,
      ts,
      alg: ALG,
      signature,
      pubkey: PUBKEY_STR,
    });
  });
}

const server = http.createServer((req, res) => {
  setCors(res);
  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  const url = (req.url || '/').split('?')[0];

  if (req.method === 'GET' && (url === '/' || url === '/health')) {
    return sendJson(res, 200, { ok: true, service: 'closer-click-signer', ...pubkeyPayload() });
  }
  if (req.method === 'GET' && url === '/pubkey') {
    return sendJson(res, 200, pubkeyPayload());
  }
  if (req.method === 'POST' && url === '/seal') {
    return handleSeal(req, res);
  }
  sendJson(res, 404, { error: 'not found' });
});

server.listen(PORT, () => {
  console.log(`[signer] closer-click-signer escuchando en :${PORT}`);
  console.log(`[signer] alg=${ALG} pubkey=${PUBKEY_STR}`);
});

export { server, canonicalStringify, signSeal, pubkeyPayload };
