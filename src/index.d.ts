// Tipos de @gatoseya/closer-click-signer

export const DEFAULT_SIGNER_URL: string;
export const SEAL_ALG: string;

/** Sello devuelto por el sellador. */
export interface Seal {
  v: number;
  op: 'seal';
  /** SHA-256 del contenido, en base64url. */
  hash: string;
  /** Instante del sellado (ms epoch, reloj del sellador). */
  ts: number;
  alg: string;
  /** Firma ECDSA P-256 (r||s) del sellador, en base64. */
  signature: string;
  /** JWK string de la pubkey del sellador. */
  pubkey: string;
}

export interface VerifyResult {
  valid: boolean;
  ts: number;
  reason?: string;
}

export function canonicalStringify (v: unknown): string;

export function sha256Base64url (data: string | Uint8Array): Promise<string>;
export function sha256OfCanonical (obj: unknown): Promise<string>;

export function sealHash (hash: string, opts?: { url?: string; signal?: AbortSignal }): Promise<Seal>;
export function sealData (data: string | Uint8Array, opts?: { url?: string; signal?: AbortSignal }): Promise<Seal>;

export function getSignerPubkey (opts?: { url?: string; force?: boolean }): Promise<string>;

export function verifySeal (
  seal: Seal,
  opts?: { hash?: string; pubkey?: string; maxFutureMs?: number },
): Promise<VerifyResult>;

export function verifySealBefore (
  seal: Seal,
  deadlineMs: number,
  opts?: { hash?: string; pubkey?: string; maxFutureMs?: number },
): Promise<VerifyResult>;
