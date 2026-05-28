# closer-click-signer

Autoridad de **sello de tiempo** (TSA, *timestamp authority*) del ecosistema
**CloserClick**. Despliegue canónico: **`https://signer.closer.click`**.

Es solo un **servidor** HTTP: no hay librería cliente, se consume con `fetch`
plano (ver más abajo). Sin dependencias en runtime.

## Qué problema resuelve

Las firmas del vault (`id.closer.click`) prueban **quién** firmó y **qué**, pero
**no cuándo**: el dueño de la clave también controla su reloj, así que puede
antedatar lo que firma. Para casos como un **pronóstico deportivo** eso es
inaceptable: hay que poder probar que el pronóstico existía *antes* del partido.

El sellador es un **tercero de confianza**: firma con SU clave el par
`{ hash, ts }`, donde `hash` es el SHA-256 del contenido. Como el autor no
controla la clave del sellador, no puede falsificar el `ts`.

> **Privacidad:** el sellador solo recibe un **digest** (SHA-256). Nunca ve el
> contenido. Fiel a la filosofía del ecosistema: tu información, en tu servidor.

## Modelo de confianza

`signer.closer.click` es la autoridad **canónica**: las apps pinean su pubkey y
verifican los sellos contra ella. La verificación es **offline** (no requiere
contactar al sellador): basta la pubkey.

## Servidor

Sin dependencias en runtime (solo módulos nativos de Node ≥ 16).

```bash
npm start        # node server.js  (PORT=4010 por defecto)
npm run dev      # con --watch
```

Al primer arranque genera un par ECDSA P-256 y lo guarda en `.tsa-key.json`
(persistente → los sellos viejos siguen verificando tras reinicios). Se puede
inyectar por entorno con `TSA_PRIVATE_JWK`. Ver `.env.example`.

### HTTP API

| Método | Ruta       | Cuerpo / Respuesta |
|--------|------------|--------------------|
| GET    | `/health`  | `{ ok, service, v, alg, pubkey, jwk }` |
| GET    | `/pubkey`  | `{ v, alg, pubkey, jwk }` |
| POST   | `/seal`    | req `{ hash }` · res `{ v, op:"seal", hash, ts, alg, signature, pubkey }` |

- `hash`: SHA-256 (32 bytes) del contenido, en **base64url**.
- `signature`: ECDSA P-256 (r‖s, 64 bytes) en base64, sobre
  `canonicalStringify({ op:"seal", hash, ts })`.
- `ts`: epoch ms del reloj del sellador.
- CORS abierto (los sellos son públicos, no secretos).

## Uso desde el cliente (fetch plano + WebCrypto)

No hay librería: son llamadas HTTP simples. Esta sección es la **fuente de
verdad** del protocolo de verificación — replicala exacta o los sellos no
verificarán.

### Sellar

```js
// hash = SHA-256 del contenido, en base64url (lo que firmás/identificás)
async function sha256Base64url (bytes) {
  const d = await crypto.subtle.digest('SHA-256', bytes)
  return btoa(String.fromCharCode(...new Uint8Array(d)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

const res = await fetch('https://signer.closer.click/seal', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ hash }),
})
const seal = await res.json()   // { v, op:'seal', hash, ts, alg, signature, pubkey }
// guardá `seal` junto al contenido
```

### Verificar (offline)

Lo firmado por el sellador es **exactamente** `canonicalStringify({ op:'seal',
hash, ts })` (claves ordenadas → `{"hash":...,"op":"seal","ts":...}`). La firma
es ECDSA P-256 (r‖s) en base64.

```js
const canon = v => (v === null || typeof v !== 'object') ? JSON.stringify(v)
  : Array.isArray(v) ? '[' + v.map(canon).join(',') + ']'
  : '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}'

async function verifySeal (seal, expectedHash, trustedPubkeyJwkStr) {
  if (seal.op !== 'seal' || seal.hash !== expectedHash) return false
  const jwk = JSON.parse(trustedPubkeyJwkStr)   // PINEÁ esta pubkey en tu app
  const key = await crypto.subtle.importKey('jwk', jwk,
    { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'])
  const bytes = new TextEncoder().encode(canon({ op: 'seal', hash: seal.hash, ts: seal.ts }))
  const sigBin = atob(seal.signature)
  const sig = Uint8Array.from(sigBin, c => c.charCodeAt(0))
  return crypto.subtle.verify({ name: 'ECDSA', hash: { name: 'SHA-256' } }, key, sig, bytes)
}
// "a tiempo": además exigí seal.ts < TOURNAMENT_START
```

> **Pineá la pubkey** del sellador en tu app (obtenida una vez de `/pubkey`). No
> confíes en la `pubkey` que viene dentro del sello para decidir confianza.

## Licencia

MIT
