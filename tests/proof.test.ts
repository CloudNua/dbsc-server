import { describe, expect, it } from 'vitest';
import { normalizePublicJwk, type PublicJwk } from '../src/protocol/jwk.js';
import { verifyProof, type VerifyProofOptions } from '../src/protocol/proof.js';
import { generateEs256, generateRs256, mintProof, type KeyPairHandle } from './helpers/mint.js';

const CHALLENGE = 'challenge-value-1';

type CommonOverrides = Partial<Omit<Extract<VerifyProofOptions, { mode: 'registration' }>, 'mode'>>;

function baseOptions(overrides: CommonOverrides = {}): VerifyProofOptions {
  return {
    mode: 'registration',
    verifyChallenge: (jti) => jti === CHALLENGE,
    ...overrides,
  };
}

function refreshOptions(key: KeyPairHandle, overrides: CommonOverrides = {}): VerifyProofOptions {
  return {
    mode: 'refresh',
    storedJwk: normalizePublicJwk(key.publicJwk)!,
    verifyChallenge: (jti) => jti === CHALLENGE,
    ...overrides,
  };
}

describe('verifyProof — happy paths', () => {
  it('accepts a valid ES256 registration proof and returns the normalized key + kid', async () => {
    const key = await generateEs256();
    const proof = await mintProof({ key, payload: { jti: CHALLENGE, aud: 'https://s.example/dbsc/register' } });
    const result = await verifyProof(proof, baseOptions());
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.jwk).toEqual({ kty: 'EC', crv: 'P-256', x: key.publicJwk['x'], y: key.publicJwk['y'] });
    expect(result.kid).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(result.payload.jti).toBe(CHALLENGE);
  });

  it('accepts a valid RS256 registration proof', async () => {
    const key = await generateRs256();
    const proof = await mintProof({ key, payload: { jti: CHALLENGE } });
    const result = await verifyProof(proof, baseOptions());
    expect(result.ok).toBe(true);
  });

  it('accepts a Chrome-minimal proof: jti and nothing else', async () => {
    const key = await generateEs256();
    const proof = await mintProof({ key, payload: { jti: CHALLENGE } });
    const result = await verifyProof(
      proof,
      baseOptions({ expectedAudience: 'https://s.example/dbsc/register', expectedSub: 's-1', clockSkewSec: 1 }),
    );
    // aud, sub, iat are absent — the optional checks must not fire.
    expect(result.ok).toBe(true);
  });

  it('accepts a valid refresh proof verified against the STORED key (no jwk in header)', async () => {
    const key = await generateEs256();
    const proof = await mintProof({ key, includeJwk: false, payload: { jti: CHALLENGE, sub: 's-1' } });
    const result = await verifyProof(proof, refreshOptions(key, { expectedSub: 's-1' }));
    expect(result.ok).toBe(true);
  });

  it('supports an async challenge verifier', async () => {
    const key = await generateEs256();
    const proof = await mintProof({ key, payload: { jti: CHALLENGE } });
    const result = await verifyProof(proof, baseOptions({ verifyChallenge: async (jti) => jti === CHALLENGE }));
    expect(result.ok).toBe(true);
  });
});

describe('verifyProof — optional claims validate only when present', () => {
  it('rejects a wrong aud and accepts a matching one', async () => {
    const key = await generateEs256();
    const proof = await mintProof({ key, payload: { jti: CHALLENGE, aud: 'https://evil.example/x' } });
    expect(
      (await verifyProof(proof, baseOptions({ expectedAudience: 'https://s.example/dbsc/register' }))).ok,
    ).toBe(false);
    const good = await mintProof({ key, payload: { jti: CHALLENGE, aud: 'https://s.example/dbsc/register' } });
    expect(
      (await verifyProof(good, baseOptions({ expectedAudience: 'https://s.example/dbsc/register' }))).ok,
    ).toBe(true);
  });

  it('rejects a wrong sub on refresh', async () => {
    const key = await generateEs256();
    const proof = await mintProof({ key, includeJwk: false, payload: { jti: CHALLENGE, sub: 's-2' } });
    const result = await verifyProof(proof, refreshOptions(key, { expectedSub: 's-1' }));
    expect(result).toMatchObject({ ok: false, reason: 'sub-mismatch' });
  });

  it('rejects an iat outside the skew window and accepts one inside it', async () => {
    const key = await generateEs256();
    const nowSec = 1_700_000_000;
    const now = () => nowSec * 1000;
    const stale = await mintProof({ key, payload: { jti: CHALLENGE, iat: nowSec - 3600 } });
    expect(await verifyProof(stale, baseOptions({ clockSkewSec: 300, now }))).toMatchObject({
      ok: false,
      reason: 'iat-out-of-window',
    });
    const fresh = await mintProof({ key, payload: { jti: CHALLENGE, iat: nowSec - 60 } });
    expect((await verifyProof(fresh, baseOptions({ clockSkewSec: 300, now }))).ok).toBe(true);
  });

  it('validates the authorization claim only when expected and present', async () => {
    const key = await generateEs256();
    const withAuth = await mintProof({ key, payload: { jti: CHALLENGE, authorization: 'auth-1' } });
    expect((await verifyProof(withAuth, baseOptions({ expectedAuthorization: 'auth-1' }))).ok).toBe(true);
    expect(await verifyProof(withAuth, baseOptions({ expectedAuthorization: 'other' }))).toMatchObject({
      ok: false,
      reason: 'authorization-mismatch',
    });
    const without = await mintProof({ key, payload: { jti: CHALLENGE } });
    expect((await verifyProof(without, baseOptions({ expectedAuthorization: 'auth-1' }))).ok).toBe(true);
  });
});

describe('verifyProof — tamper suite', () => {
  it('rejects a wrong typ', async () => {
    const key = await generateEs256();
    const proof = await mintProof({ key, typ: 'JWT', payload: { jti: CHALLENGE } });
    expect(await verifyProof(proof, baseOptions())).toMatchObject({ ok: false, reason: 'bad-typ' });
  });

  it('rejects alg none and HMAC algs', async () => {
    const key = await generateEs256();
    for (const alg of ['none', 'HS256', 'ES384']) {
      const proof = await mintProof({ key, alg, payload: { jti: CHALLENGE } });
      expect(await verifyProof(proof, baseOptions())).toMatchObject({ ok: false, reason: 'alg-not-allowed' });
    }
  });

  it('honors a caller algorithm allowlist', async () => {
    const key = await generateEs256();
    const proof = await mintProof({ key, payload: { jti: CHALLENGE } });
    expect(await verifyProof(proof, baseOptions({ algorithms: ['RS256'] }))).toMatchObject({
      ok: false,
      reason: 'alg-not-allowed',
    });
  });

  it('rejects a registration proof without a jwk', async () => {
    const key = await generateEs256();
    const proof = await mintProof({ key, includeJwk: false, payload: { jti: CHALLENGE } });
    expect(await verifyProof(proof, baseOptions())).toMatchObject({ ok: false, reason: 'jwk-missing' });
  });

  it('rejects a refresh proof that smuggles a jwk (key substitution)', async () => {
    const key = await generateEs256();
    const attacker = await generateEs256();
    // Attacker signs with their own key and presents their own jwk on REFRESH.
    const proof = await mintProof({ key: attacker, payload: { jti: CHALLENGE } });
    expect(await verifyProof(proof, refreshOptions(key))).toMatchObject({ ok: false, reason: 'jwk-forbidden' });
  });

  it('fails closed when the stored key is missing or invalid on refresh', async () => {
    const key = await generateEs256();
    const proof = await mintProof({ key, includeJwk: false, payload: { jti: CHALLENGE } });
    const result = await verifyProof(proof, {
      mode: 'refresh',
      storedJwk: { kty: 'EC', crv: 'P-256', x: '!!!', y: '!!!' } as unknown as PublicJwk,
      verifyChallenge: (jti) => jti === CHALLENGE,
    });
    expect(result).toMatchObject({ ok: false, reason: 'no-stored-key' });
  });

  it('verifies with only public members even when the header jwk carries private ones', async () => {
    const key = await generateEs256();
    const privateJwk = (await crypto.subtle.exportKey('jwk', key.pair.privateKey)) as Record<string, unknown>;
    const proof = await mintProof({ key: { ...key, publicJwk: privateJwk }, payload: { jti: CHALLENGE } });
    const result = await verifyProof(proof, baseOptions());
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(Object.keys(result.jwk)).toEqual(['kty', 'crv', 'x', 'y']);
  });

  it('rejects a mismatched key type and algorithm', async () => {
    const ec = await generateEs256();
    const proof = await mintProof({ key: ec, alg: 'RS256', payload: { jti: CHALLENGE } });
    expect(await verifyProof(proof, baseOptions())).toMatchObject({ ok: false, reason: 'alg-key-mismatch' });
  });

  it('rejects weak keys: P-384 and RSA-1024', async () => {
    const p384 = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, true, ['sign', 'verify']);
    const p384Jwk = (await crypto.subtle.exportKey('jwk', p384.publicKey)) as Record<string, unknown>;
    const proof = await mintProof({
      key: { pair: p384, publicJwk: { ...p384Jwk, crv: 'P-256' } },
      payload: { jti: CHALLENGE },
    });
    expect(await verifyProof(proof, baseOptions())).toMatchObject({ ok: false, reason: 'jwk-invalid' });

    const rsa1024 = await crypto.subtle.generateKey(
      { name: 'RSASSA-PKCS1-v1_5', modulusLength: 1024, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true,
      ['sign', 'verify'],
    );
    const rsaJwk = (await crypto.subtle.exportKey('jwk', rsa1024.publicKey)) as Record<string, unknown>;
    const weak = await mintProof({ key: { pair: rsa1024, publicJwk: rsaJwk }, payload: { jti: CHALLENGE } });
    expect(await verifyProof(weak, baseOptions())).toMatchObject({ ok: false, reason: 'jwk-invalid' });
  });

  it('rejects a tampered payload', async () => {
    const key = await generateEs256();
    const proof = await mintProof({ key, payload: { jti: CHALLENGE } });
    const [h, , s] = proof.split('.') as [string, string, string];
    const forged = btoa(JSON.stringify({ jti: CHALLENGE, admin: true }))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
    expect(await verifyProof(`${h}.${forged}.${s}`, baseOptions())).toMatchObject({
      ok: false,
      reason: 'bad-signature',
    });
  });

  it('rejects a mangled signature and a signature from a different key', async () => {
    const key = await generateEs256();
    const mangled = await mintProof({
      key,
      payload: { jti: CHALLENGE },
      mangleSignature: (sig) => {
        const out = sig.slice();
        out[0]! ^= 0xff;
        return out;
      },
    });
    expect(await verifyProof(mangled, baseOptions())).toMatchObject({ ok: false, reason: 'bad-signature' });

    const other = await generateEs256();
    const crossSigned = await mintProof({ key, payload: { jti: CHALLENGE }, signWith: other.pair.privateKey });
    expect(await verifyProof(crossSigned, baseOptions())).toMatchObject({ ok: false, reason: 'bad-signature' });
  });

  it('rejects an ES256 signature that is not 64 bytes (DER-shaped input)', async () => {
    const key = await generateEs256();
    const padded = await mintProof({
      key,
      payload: { jti: CHALLENGE },
      mangleSignature: (sig) => {
        const out = new Uint8Array(sig.length + 6);
        out.set([0x30, 0x44, 0x02, 0x20, 0x00, 0x00]);
        out.set(sig, 6);
        return out;
      },
    });
    expect(await verifyProof(padded, baseOptions())).toMatchObject({ ok: false, reason: 'bad-signature' });
  });

  it('rejects a wrong or missing challenge', async () => {
    const key = await generateEs256();
    const wrong = await mintProof({ key, payload: { jti: 'stolen-old-challenge' } });
    expect(await verifyProof(wrong, baseOptions())).toMatchObject({ ok: false, reason: 'challenge-mismatch' });
    const missing = await mintProof({ key, payload: {} });
    expect(await verifyProof(missing, baseOptions())).toMatchObject({ ok: false, reason: 'jti-missing' });
  });

  it('returns malformed for structural garbage and never throws', async () => {
    for (const bad of ['', 'a', 'a.b', 'a.b.c.d', '!!.??.$$', 'eyJ.eyJ.c2ln', `${'A'.repeat(10)}.B.C`]) {
      const result = await verifyProof(bad, baseOptions());
      expect(result.ok).toBe(false);
    }
  });
});
