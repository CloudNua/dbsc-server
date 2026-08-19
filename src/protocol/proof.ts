/**
 * DBSC proof JWT verification.
 *
 * Hard rules, all enforced here:
 * - `typ` must be `dbsc+jwt`; the algorithm must be on the allowlist.
 * - A REGISTRATION proof must carry the device public key in the header `jwk`.
 * - A REFRESH proof must NOT carry a `jwk`; it verifies against the STORED key only.
 *   Accepting a header key on refresh would let any attacker substitute their own.
 * - The key pins the algorithm: an EC key verifies ES256 only, an RSA key RS256 only.
 * - The header key is normalized to public members before any use.
 * - `jti` must match an outstanding challenge (via the caller's verifier).
 * - `aud`, `sub`, `iat`, and `authorization` are validated ONLY when present:
 *   shipping Chrome can send a proof with `jti` and nothing else.
 * - Malformed input is a failed verification, never an exception.
 *
 * The result reports a single failure reason. The reason is for the server's own
 * logs; do not echo it to the client.
 */

import { base64urlToBytes, base64urlToJson } from '../internal/base64url.js';
import { ALGORITHMS, PROOF_TYP, type Algorithm } from './constants.js';
import { algorithmForKey, importVerifyKey, jwkThumbprint, normalizePublicJwk, type PublicJwk, type UnknownJwk } from './jwk.js';

export interface ProofPayload {
  jti: string;
  aud?: string;
  sub?: string;
  iat?: number;
  authorization?: string;
  [claim: string]: unknown;
}

export type VerifyProofOptions = {
  /** Allowed algorithms. Default: ES256 and RS256. */
  algorithms?: readonly Algorithm[];
  /** Returns true when `jti` is an outstanding challenge for this exchange. */
  verifyChallenge: (jti: string) => boolean | Promise<boolean>;
  /** Checked only when the proof carries `aud`. */
  expectedAudience?: string;
  /** Checked only when the proof carries `sub` (the session id on refresh proofs). */
  expectedSub?: string;
  /** Checked only when the proof carries `authorization`. */
  expectedAuthorization?: string;
  /** Tolerated |now - iat| in seconds, when the proof carries `iat`. Default: 300. */
  clockSkewSec?: number;
  /** Clock override for tests. Milliseconds since the epoch. */
  now?: () => number;
} & (
  | { mode: 'registration' }
  | { mode: 'refresh'; storedJwk: PublicJwk }
);

export type ProofFailureReason =
  | 'malformed'
  | 'bad-typ'
  | 'alg-not-allowed'
  | 'jwk-missing'
  | 'jwk-forbidden'
  | 'jwk-invalid'
  | 'alg-key-mismatch'
  | 'no-stored-key'
  | 'bad-signature'
  | 'jti-missing'
  | 'challenge-mismatch'
  | 'aud-mismatch'
  | 'sub-mismatch'
  | 'authorization-mismatch'
  | 'iat-out-of-window';

export type VerifyProofResult =
  | { ok: true; kid: string; jwk: PublicJwk; payload: ProofPayload }
  | { ok: false; reason: ProofFailureReason };

const fail = (reason: ProofFailureReason): VerifyProofResult => ({ ok: false, reason });

/**
 * Upper bound on an acceptable proof, in characters. Real proofs are well under
 * 2 KB (an RS256 proof with a 2048-bit key is ~1.2 KB). The cap keeps attacker
 * input out of base64/JSON work; most servers cap header sizes anyway.
 */
export const MAX_PROOF_LENGTH = 8192;

interface ProofHeader {
  typ?: unknown;
  alg?: unknown;
  jwk?: UnknownJwk;
}

export async function verifyProof(proof: string, opts: VerifyProofOptions): Promise<VerifyProofResult> {
  try {
    if (proof.length > MAX_PROOF_LENGTH) return fail('malformed');
    const parts = proof.split('.');
    if (parts.length !== 3) return fail('malformed');
    const [h, p, s] = parts as [string, string, string];
    if (h === '' || p === '' || s === '') return fail('malformed');

    const header = base64urlToJson<ProofHeader>(h);
    if (header === null || typeof header !== 'object') return fail('malformed');
    if (header.typ !== PROOF_TYP) return fail('bad-typ');

    const allowed = opts.algorithms ?? ALGORITHMS;
    const alg = header.alg;
    if (typeof alg !== 'string' || !(allowed as readonly string[]).includes(alg)) {
      return fail('alg-not-allowed');
    }

    // Resolve the verification key by mode.
    let jwk: PublicJwk;
    if (opts.mode === 'registration') {
      if (header.jwk === undefined) return fail('jwk-missing');
      const normalized = normalizePublicJwk(header.jwk);
      if (normalized === null) return fail('jwk-invalid');
      jwk = normalized;
    } else {
      if (header.jwk !== undefined) return fail('jwk-forbidden');
      const normalized = normalizePublicJwk(opts.storedJwk as UnknownJwk);
      if (normalized === null) return fail('no-stored-key');
      jwk = normalized;
    }

    // The key type pins the algorithm.
    if (algorithmForKey(jwk) !== alg) return fail('alg-key-mismatch');

    const payload = base64urlToJson<ProofPayload>(p);
    if (payload === null || typeof payload !== 'object') return fail('malformed');

    // Signature first: nothing downstream (including single-use challenge
    // consumption) may run on an unauthenticated payload.
    const sig = base64urlToBytes(s);
    if (sig === null || sig.length === 0) return fail('malformed');
    if (jwk.kty === 'EC' && sig.length !== 64) return fail('bad-signature'); // P1363 r||s only
    const key = await importVerifyKey(jwk);
    if (key === null) return fail('jwk-invalid');
    const verifyAlgorithm =
      jwk.kty === 'EC' ? ({ name: 'ECDSA', hash: 'SHA-256' } as const) : ('RSASSA-PKCS1-v1_5' as const);
    const data = new TextEncoder().encode(`${h}.${p}`);
    const valid = await crypto.subtle.verify(verifyAlgorithm, key, sig, data);
    if (!valid) return fail('bad-signature');

    // The challenge is REQUIRED on every proof.
    if (typeof payload.jti !== 'string' || payload.jti === '') return fail('jti-missing');
    if (!(await opts.verifyChallenge(payload.jti))) return fail('challenge-mismatch');

    // Optional claims: validate only when present (Chrome-minimal proofs omit them).
    if (payload.aud !== undefined && opts.expectedAudience !== undefined) {
      if (payload.aud !== opts.expectedAudience) return fail('aud-mismatch');
    }
    if (payload.sub !== undefined && opts.expectedSub !== undefined) {
      if (payload.sub !== opts.expectedSub) return fail('sub-mismatch');
    }
    if (payload.authorization !== undefined && opts.expectedAuthorization !== undefined) {
      if (payload.authorization !== opts.expectedAuthorization) return fail('authorization-mismatch');
    }
    if (payload.iat !== undefined) {
      if (typeof payload.iat !== 'number') return fail('malformed');
      const skew = opts.clockSkewSec ?? 300;
      const nowSec = Math.floor((opts.now ?? Date.now)() / 1000);
      if (Math.abs(nowSec - payload.iat) > skew) return fail('iat-out-of-window');
    }

    return { ok: true, kid: await jwkThumbprint(jwk), jwk, payload };
  } catch {
    // Untrusted input must never turn into an exception for the caller.
    return fail('malformed');
  }
}
