/**
 * JWK handling for DBSC device keys.
 *
 * Only two key shapes exist in DBSC: EC P-256 (for ES256) and RSA with a modulus of
 * at least 2048 bits (for RS256). Everything here normalizes an untrusted JWK down
 * to its public members before any use — a registration JWT that smuggles private
 * members (or extra members that would change the thumbprint) must not poison the
 * stored key or the device identity.
 */

import { base64urlToBytes } from '../internal/base64url.js';
import { bytesToBase64url } from '../internal/base64url.js';
import { MIN_RSA_MODULUS_BITS, type Algorithm } from './constants.js';

/** An untrusted JWK as parsed from a proof header. */
export interface UnknownJwk {
  kty?: unknown;
  crv?: unknown;
  x?: unknown;
  y?: unknown;
  n?: unknown;
  e?: unknown;
  [member: string]: unknown;
}

export type PublicEcJwk = { kty: 'EC'; crv: 'P-256'; x: string; y: string };
export type PublicRsaJwk = { kty: 'RSA'; n: string; e: string };
export type PublicJwk = PublicEcJwk | PublicRsaJwk;

const B64URL_RE = /^[A-Za-z0-9_-]+$/;

const isB64url = (v: unknown): v is string => typeof v === 'string' && v.length > 0 && B64URL_RE.test(v);

/**
 * Normalizes an untrusted JWK to its public members only. Returns null when the key
 * is not an EC P-256 or an RSA (>= 2048 bit) public key in valid base64url encoding.
 * Private members (`d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`, `k`) and any other extra
 * members are dropped, never copied.
 */
export function normalizePublicJwk(jwk: UnknownJwk): PublicJwk | null {
  if (jwk === null || typeof jwk !== 'object') return null;

  if (jwk.kty === 'EC') {
    if (jwk.crv !== 'P-256') return null;
    if (!isB64url(jwk.x) || !isB64url(jwk.y)) return null;
    const x = base64urlToBytes(jwk.x);
    const y = base64urlToBytes(jwk.y);
    if (x === null || y === null || x.length !== 32 || y.length !== 32) return null;
    return { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
  }

  if (jwk.kty === 'RSA') {
    if (!isB64url(jwk.n) || !isB64url(jwk.e)) return null;
    const n = base64urlToBytes(jwk.n);
    const e = base64urlToBytes(jwk.e);
    if (n === null || e === null || e.length === 0) return null;
    // Reject degenerate public exponents. e must be odd and >= 3: with e = 1 a
    // "signature" is just the padded digest, so anyone can forge one; even
    // exponents are not valid RSA. Cap e at 8 bytes to bound verify cost.
    if (e.length > 8) return null;
    const eLast = e[e.length - 1]!;
    if ((eLast & 1) === 0) return null;
    if (e.length === 1 && eLast < 3) return null;
    // Reject weak moduli. Leading zero bytes do not appear in a canonical encoding,
    // but strip them before measuring so a padded modulus cannot fake its size.
    let firstNonZero = 0;
    while (firstNonZero < n.length && n[firstNonZero] === 0) firstNonZero++;
    const modulusBits = (n.length - firstNonZero) * 8;
    if (modulusBits < MIN_RSA_MODULUS_BITS) return null;
    return { kty: 'RSA', n: jwk.n, e: jwk.e };
  }

  return null;
}

/** The only algorithm a key type may sign with. The key pins the algorithm. */
export function algorithmForKey(jwk: PublicJwk): Algorithm {
  return jwk.kty === 'EC' ? 'ES256' : 'RS256';
}

/**
 * RFC 7638 JWK thumbprint, base64url of SHA-256 over the canonical members in
 * lexicographic order: `{crv,kty,x,y}` for EC, `{e,kty,n}` for RSA. This is the
 * stable device-key identity (`kid`).
 */
export async function jwkThumbprint(jwk: PublicJwk): Promise<string> {
  const canonical =
    jwk.kty === 'EC'
      ? `{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}","y":"${jwk.y}"}`
      : `{"e":"${jwk.e}","kty":"${jwk.kty}","n":"${jwk.n}"}`;
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical));
  return bytesToBase64url(new Uint8Array(digest));
}

/** Imports a normalized public JWK as a WebCrypto verification key. */
export async function importVerifyKey(jwk: PublicJwk): Promise<CryptoKey | null> {
  try {
    if (jwk.kty === 'EC') {
      return await crypto.subtle.importKey(
        'jwk',
        { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y },
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['verify'],
      );
    }
    return await crypto.subtle.importKey(
      'jwk',
      { kty: jwk.kty, n: jwk.n, e: jwk.e },
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify'],
    );
  } catch {
    return null;
  }
}
