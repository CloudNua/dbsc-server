/**
 * Test helper: mint DBSC proof JWTs, with hooks to tamper with every part.
 * Mirrors what a browser (or an attacker) produces.
 */
import { bytesToBase64url, utf8ToBase64url } from '../../src/internal/base64url.js';

export interface KeyPairHandle {
  pair: CryptoKeyPair;
  publicJwk: Record<string, unknown>;
}

export async function generateEs256(): Promise<KeyPairHandle> {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const publicJwk = (await crypto.subtle.exportKey('jwk', pair.publicKey)) as Record<string, unknown>;
  return { pair, publicJwk };
}

export async function generateRs256(): Promise<KeyPairHandle> {
  const pair = await crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['sign', 'verify'],
  );
  const publicJwk = (await crypto.subtle.exportKey('jwk', pair.publicKey)) as Record<string, unknown>;
  return { pair, publicJwk };
}

export interface MintOptions {
  key: KeyPairHandle;
  alg?: string;
  typ?: string;
  /** Include the public JWK in the header (registration proofs). Default: true. */
  includeJwk?: boolean;
  /** Extra or overriding header members. */
  header?: Record<string, unknown>;
  payload: Record<string, unknown>;
  /** Replace the signature bytes after signing. */
  mangleSignature?: (sig: Uint8Array) => Uint8Array;
  /** Sign with a different private key than the header advertises. */
  signWith?: CryptoKey;
}

export async function mintProof(opts: MintOptions): Promise<string> {
  const isEc = (opts.key.publicJwk['kty'] ?? 'EC') === 'EC';
  const header: Record<string, unknown> = {
    typ: opts.typ ?? 'dbsc+jwt',
    alg: opts.alg ?? (isEc ? 'ES256' : 'RS256'),
    ...(opts.includeJwk === false ? {} : { jwk: opts.key.publicJwk }),
    ...opts.header,
  };
  const h = utf8ToBase64url(JSON.stringify(header));
  const p = utf8ToBase64url(JSON.stringify(opts.payload));
  const signingKey = opts.signWith ?? opts.key.pair.privateKey;
  const algorithm =
    signingKey.algorithm.name === 'ECDSA'
      ? ({ name: 'ECDSA', hash: 'SHA-256' } as const)
      : ('RSASSA-PKCS1-v1_5' as const);
  const sigBuf = await crypto.subtle.sign(algorithm, signingKey, new TextEncoder().encode(`${h}.${p}`));
  let sig: Uint8Array = new Uint8Array(sigBuf);
  if (opts.mangleSignature) sig = opts.mangleSignature(sig);
  return `${h}.${p}.${bytesToBase64url(sig)}`;
}
