// @gatoseya/closer-click-signer — cliente de la autoridad de sello de tiempo
// (TSA) del ecosistema CloserClick.
//
// Flujo:
//   1. La app calcula el hash SHA-256 del contenido firmado (p. ej. el blob del
//      pronóstico ya firmado por el vault).  -> sha256Base64url(bytes)
//   2. Pide un sello al sellador.             -> sealHash(hash)
//   3. Guarda el sello junto al contenido.
//   4. Cualquiera verifica luego, offline.    -> verifySeal(seal, { hash })
//
// El sellador es un TERCERO: firma { hash, ts } con SU clave, y por eso el `ts`
// no es falsificable por el autor (que no controla la clave del sellador). El
// sellador nunca ve el contenido, solo su digest.

export const DEFAULT_SIGNER_URL = 'https://signer.closer.click';
export const SEAL_ALG = 'ECDSA-P256-SHA256';

// ---- Serialización canónica (idéntica a vault / proxy / server) -------------
export function canonicalStringify (v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canonicalStringify).join(',') + ']';
  const ks = Object.keys(v).sort();
  return '{' + ks.map((k) => JSON.stringify(k) + ':' + canonicalStringify(v[k])).join(',') + '}';
}

// ---- base64 / base64url -----------------------------------------------------
function bufToB64url (buf) {
  let bin = '';
  const bytes = new Uint8Array(buf);
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64ToBytes (b64) {
  const bin = atob(b64.replace(/-/g, '+').replace(/_/g, '/'));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** SHA-256 de bytes/string, en base64url (formato que espera el sellador). */
export async function sha256Base64url (data) {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return bufToB64url(digest);
}

/** SHA-256 del canonical(obj), en base64url. Útil para sellar objetos. */
export async function sha256OfCanonical (obj) {
  return sha256Base64url(canonicalStringify(obj));
}

// ---- API de red -------------------------------------------------------------

/** Pide al sellador un sello para un hash (SHA-256 en base64url). */
export async function sealHash (hash, { url = DEFAULT_SIGNER_URL, signal } = {}) {
  const res = await fetch(url.replace(/\/$/, '') + '/seal', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ hash }),
    signal,
  });
  if (!res.ok) {
    let msg = `signer respondió ${res.status}`;
    try { const j = await res.json(); if (j && j.error) msg = j.error; } catch { /* */ }
    throw new Error(msg);
  }
  return res.json(); // { v, op, hash, ts, alg, signature, pubkey }
}

/** Calcula el hash del contenido y pide el sello en un paso. */
export async function sealData (data, opts) {
  const hash = await sha256Base64url(data);
  return sealHash(hash, opts);
}

let _pubkeyCache = null;
/** Obtiene (y cachea) la pubkey del sellador. */
export async function getSignerPubkey ({ url = DEFAULT_SIGNER_URL, force = false } = {}) {
  if (_pubkeyCache && !force) return _pubkeyCache;
  const res = await fetch(url.replace(/\/$/, '') + '/pubkey');
  if (!res.ok) throw new Error(`signer /pubkey respondió ${res.status}`);
  const j = await res.json();
  _pubkeyCache = j.pubkey;
  return j.pubkey;
}

// ---- Verificación (offline) -------------------------------------------------

/**
 * Verifica un sello.
 * @param seal  objeto devuelto por sealHash/sealData
 * @param opts.hash       hash esperado del contenido (debe coincidir con seal.hash)
 * @param opts.pubkey     JWK string de la pubkey de confianza del sellador.
 *                        Si se omite, se confía en seal.pubkey (TOFU: pinéala vos).
 * @param opts.maxFutureMs  tolerancia de reloj hacia el futuro (default 5 min)
 * @returns { valid:boolean, ts:number, reason?:string }
 */
export async function verifySeal (seal, { hash, pubkey, maxFutureMs = 5 * 60 * 1000 } = {}) {
  try {
    if (!seal || seal.op !== 'seal' || !seal.signature || !seal.hash || !seal.ts) {
      return { valid: false, ts: 0, reason: 'sello mal formado' };
    }
    if (hash != null && hash !== seal.hash) {
      return { valid: false, ts: seal.ts, reason: 'el hash del sello no coincide con el contenido' };
    }
    if (Date.now() + maxFutureMs < seal.ts) {
      return { valid: false, ts: seal.ts, reason: 'ts del sello en el futuro' };
    }
    const jwkStr = pubkey || seal.pubkey;
    const jwk = typeof jwkStr === 'string' ? JSON.parse(jwkStr) : jwkStr;
    const key = await crypto.subtle.importKey(
      'jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'],
    );
    const bytes = new TextEncoder().encode(
      canonicalStringify({ op: 'seal', hash: seal.hash, ts: seal.ts }),
    );
    const ok = await crypto.subtle.verify(
      { name: 'ECDSA', hash: { name: 'SHA-256' } }, key,
      b64ToBytes(seal.signature), bytes,
    );
    return ok ? { valid: true, ts: seal.ts } : { valid: false, ts: seal.ts, reason: 'firma del sellador inválida' };
  } catch (e) {
    return { valid: false, ts: seal && seal.ts || 0, reason: e instanceof Error ? e.message : String(e) };
  }
}

/**
 * Verifica un sello y además que el ts sea ANTERIOR a una fecha límite (p. ej.
 * el inicio del torneo). Atajo para el caso "pronóstico hecho a tiempo".
 */
export async function verifySealBefore (seal, deadlineMs, opts = {}) {
  const r = await verifySeal(seal, opts);
  if (!r.valid) return r;
  if (r.ts >= deadlineMs) return { valid: false, ts: r.ts, reason: 'sellado después de la fecha límite' };
  return r;
}
