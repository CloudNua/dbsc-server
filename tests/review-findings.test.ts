/** Regression tests for the Phase 2 adversarial-review findings. */
import { describe, expect, it } from 'vitest';
import {
  createHmacChallenger,
  createMemoryConsumedStore,
  withSingleUse,
} from '../src/protocol/challenge.js';
import { getProofHeader, getSessionIdHeader, parseChallengeHeader } from '../src/protocol/headers.js';
import { normalizePublicJwk } from '../src/protocol/jwk.js';
import { MAX_PROOF_LENGTH, verifyProof } from '../src/protocol/proof.js';

const SECRET = 'test-secret-at-least-16-bytes-long';

describe('finding 1: single-use retention must outlive the challenge TTL', () => {
  it('does not re-verify a consumed challenge after 60s when the challenge TTL is longer', async () => {
    let t = 1_000_000_000_000;
    const now = () => t;
    const challenger = withSingleUse(
      createHmacChallenger({ secret: SECRET, ttlSec: 300, now }),
      createMemoryConsumedStore({ now }),
      // Default retention (3600s) — must cover the 300s challenge TTL.
    );
    const challenge = await challenger.issue({ purpose: 'registration' });
    await expect(challenger.verify(challenge, { purpose: 'registration' })).resolves.toBe(true);
    t += 120_000; // Inside the old 60s-retention replay window, challenge still unexpired.
    await expect(challenger.verify(challenge, { purpose: 'registration' })).resolves.toBe(false);
  });
});

describe('finding 2: degenerate RSA public exponents are rejected', () => {
  const n2048 = (() => {
    const bytes = new Uint8Array(256).fill(0xab);
    bytes[0] = 0xc0;
    return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  })();

  it('rejects e = 1, even exponents, and oversized exponents', () => {
    expect(normalizePublicJwk({ kty: 'RSA', n: n2048, e: 'AQ' })).toBeNull(); // e = 1
    expect(normalizePublicJwk({ kty: 'RSA', n: n2048, e: 'Ag' })).toBeNull(); // e = 2
    expect(normalizePublicJwk({ kty: 'RSA', n: n2048, e: 'BA' })).toBeNull(); // e = 4
    const hugeE = btoa(String.fromCharCode(...new Uint8Array(9).fill(1)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
    expect(normalizePublicJwk({ kty: 'RSA', n: n2048, e: hugeE })).toBeNull(); // > 8 bytes
  });

  it('accepts the common exponent 65537', () => {
    expect(normalizePublicJwk({ kty: 'RSA', n: n2048, e: 'AQAB' })).not.toBeNull();
  });
});

describe('finding 3: oversized inputs are rejected cheaply', () => {
  it('rejects a proof over the length cap', async () => {
    const huge = `${'A'.repeat(MAX_PROOF_LENGTH)}.B.C`;
    const result = await verifyProof(huge, { mode: 'registration', verifyChallenge: () => true });
    expect(result).toMatchObject({ ok: false, reason: 'malformed' });
  });

  it('rejects oversized proof and session-id header values', () => {
    const huge = 'A'.repeat(9000);
    expect(getProofHeader(new Headers({ 'Secure-Session-Response': `${huge}.B.C` }))).toBeNull();
    expect(getSessionIdHeader(new Headers({ 'Sec-Secure-Session-Id': 'x'.repeat(2000) }))).toBeNull();
  });
});

describe('finding 4: valueless parameters are treated as absent', () => {
  it('drops an empty session id from the challenge header', () => {
    expect(parseChallengeHeader('"cv";id')).toEqual({ challenge: 'cv' });
    expect(parseChallengeHeader('"cv";id=""')).toEqual({ challenge: 'cv' });
  });
});
