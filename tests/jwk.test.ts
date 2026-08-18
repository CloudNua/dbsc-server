import { describe, expect, it } from 'vitest';
import {
  algorithmForKey,
  importVerifyKey,
  jwkThumbprint,
  normalizePublicJwk,
  type PublicJwk,
} from '../src/protocol/jwk.js';

async function generateEcJwk(): Promise<Record<string, unknown>> {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  return (await crypto.subtle.exportKey('jwk', pair.publicKey)) as Record<string, unknown>;
}

describe('normalizePublicJwk', () => {
  it('normalizes a valid EC P-256 key and drops extra members', async () => {
    const jwk = await generateEcJwk();
    const normalized = normalizePublicJwk({ ...jwk, ext: true, key_ops: ['verify'], kid: 'attacker-chosen' });
    expect(normalized).toEqual({ kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y });
  });

  it('drops private members instead of carrying them', async () => {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const privateJwk = (await crypto.subtle.exportKey('jwk', pair.privateKey)) as Record<string, unknown>;
    expect(privateJwk.d).toBeDefined();
    const normalized = normalizePublicJwk(privateJwk);
    expect(normalized).not.toBeNull();
    expect(Object.keys(normalized!)).toEqual(['kty', 'crv', 'x', 'y']);
  });

  it('rejects non-P-256 curves', async () => {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, true, ['sign', 'verify']);
    const jwk = (await crypto.subtle.exportKey('jwk', pair.publicKey)) as Record<string, unknown>;
    expect(normalizePublicJwk(jwk)).toBeNull();
    expect(normalizePublicJwk({ ...jwk, crv: 'P-256' })).toBeNull(); // lying about the curve: coordinates are 48 bytes
  });

  it('accepts RSA >= 2048 bits and rejects smaller moduli', async () => {
    const pair = await crypto.subtle.generateKey(
      { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true,
      ['sign', 'verify'],
    );
    const jwk = (await crypto.subtle.exportKey('jwk', pair.publicKey)) as Record<string, unknown>;
    expect(normalizePublicJwk(jwk)).toEqual({ kty: 'RSA', n: jwk.n, e: jwk.e });

    const smallN = btoa(String.fromCharCode(...new Uint8Array(128).fill(255)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
    expect(normalizePublicJwk({ kty: 'RSA', n: smallN, e: 'AQAB' })).toBeNull();
  });

  it('rejects malformed and irrelevant keys', () => {
    expect(normalizePublicJwk({})).toBeNull();
    expect(normalizePublicJwk({ kty: 'oct', k: 'AAAA' })).toBeNull();
    expect(normalizePublicJwk({ kty: 'EC', crv: 'P-256', x: 'not base64url!!', y: 'AA' })).toBeNull();
    expect(normalizePublicJwk({ kty: 'RSA', n: '', e: 'AQAB' })).toBeNull();
  });
});

describe('algorithmForKey', () => {
  it('pins EC to ES256 and RSA to RS256', () => {
    expect(algorithmForKey({ kty: 'EC', crv: 'P-256', x: 'a', y: 'b' } as PublicJwk)).toBe('ES256');
    expect(algorithmForKey({ kty: 'RSA', n: 'a', e: 'b' } as PublicJwk)).toBe('RS256');
  });
});

describe('jwkThumbprint', () => {
  it('matches the RFC 7638 example thumbprint', async () => {
    // The RSA key and expected thumbprint from RFC 7638 section 3.1.
    const jwk: PublicJwk = {
      kty: 'RSA',
      n: '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
      e: 'AQAB',
    };
    expect(await jwkThumbprint(jwk)).toBe('NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs');
  });

  it('is stable regardless of extra members in the source', async () => {
    const raw = await generateEcJwk();
    const a = normalizePublicJwk(raw)!;
    const b = normalizePublicJwk({ ...raw, kid: 'x', ext: true })!;
    expect(await jwkThumbprint(a)).toBe(await jwkThumbprint(b));
  });
});

describe('importVerifyKey', () => {
  it('imports normalized keys for verification', async () => {
    const jwk = normalizePublicJwk(await generateEcJwk())!;
    const key = await importVerifyKey(jwk);
    expect(key).not.toBeNull();
    expect(key!.usages).toContain('verify');
  });

  it('returns null on an invalid point instead of throwing', async () => {
    const jwk = normalizePublicJwk(await generateEcJwk())!;
    if (jwk.kty !== 'EC') throw new Error('expected EC');
    const bad = { ...jwk, y: jwk.x }; // x == y is not on the curve (overwhelmingly)
    expect(await importVerifyKey(bad)).toBeNull();
  });
});
