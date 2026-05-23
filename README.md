# @gatoseya/closer-click-signer

Autoridad de **sello de tiempo** (TSA, *timestamp authority*) del ecosistema
**CloserClick**. Despliegue canónico: **`https://signer.closer.click`**.

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

## Cliente (navegador)

```js
import {
  sealData, sha256Base64url, sealHash,
  verifySeal, verifySealBefore, getSignerPubkey,
} from '@gatoseya/closer-click-signer'

// 1) Sellar el contenido ya firmado por el vault (p. ej. el blob del pronóstico)
const seal = await sealData(signedBlobBytes)   // { hash, ts, signature, pubkey, ... }
//   guardá `seal` junto al contenido

// 2) Verificar más tarde (offline), contra la pubkey pineada del sellador
const trusted = await getSignerPubkey()         // o una pubkey pineada en tu app
const r = await verifySeal(seal, { hash: await sha256Base64url(signedBlobBytes), pubkey: trusted })
//   r.valid === true  →  el contenido existía en r.ts

// 3) Atajo "a tiempo": ¿sellado antes del inicio del torneo?
const ok = await verifySealBefore(seal, TOURNAMENT_START, { hash, pubkey: trusted })
```

### API

- `sha256Base64url(data)` / `sha256OfCanonical(obj)` → digest base64url.
- `sealHash(hash, { url? })` / `sealData(data, { url? })` → `Seal`.
- `getSignerPubkey({ url?, force? })` → JWK string (cacheado).
- `verifySeal(seal, { hash?, pubkey?, maxFutureMs? })` → `{ valid, ts, reason? }`.
- `verifySealBefore(seal, deadlineMs, opts)` → además exige `ts < deadlineMs`.

Si omitís `pubkey` en la verificación se confía en `seal.pubkey` (TOFU): para
seguridad real, **pineá** la pubkey del sellador en tu app.

## Licencia

MIT
