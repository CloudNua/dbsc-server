/**
 * Cross-implementation interop: run this package against the vendored
 * dbsc-toolkit native-protocol vectors (see vectors/community/dbsc-toolkit/).
 * dbsc-php validates against the same set, so agreement here means three
 * implementations accept each other's wire output on the native surface.
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { buildChallengeHeader, buildRegistrationHeader } from '../src/protocol/headers.js';
import { jwkThumbprint, type PublicJwk } from '../src/protocol/jwk.js';
import { verifyProof } from '../src/protocol/proof.js';

const load = <T>(file: string): T =>
  JSON.parse(
    readFileSync(new URL(`../vectors/community/dbsc-toolkit/${file}`, import.meta.url), 'utf8'),
  ) as T;

describe('interop: dbsc-toolkit header vectors', () => {
  const vector = load<{
    inputs: { algorithm: string; registrationPath: string; challenge: string; sessionId: string };
    expected: Record<string, string>;
  }>('registration-header.json');

  it('builds a byte-identical Secure-Session-Registration header', () => {
    const value = buildRegistrationHeader({
      algorithms: [vector.inputs.algorithm as 'ES256'],
      path: vector.inputs.registrationPath,
      challenge: vector.inputs.challenge,
    });
    expect(value).toBe(vector.expected['Secure-Session-Registration']);
  });

  it('builds byte-identical Secure-Session-Challenge headers', () => {
    expect(buildChallengeHeader({ challenge: vector.inputs.challenge })).toBe(
      vector.expected['Secure-Session-Challenge (bare)'],
    );
    expect(
      buildChallengeHeader({ challenge: vector.inputs.challenge, sessionId: vector.inputs.sessionId }),
    ).toBe(vector.expected['Secure-Session-Challenge (with id)']);
  });
});

describe('interop: dbsc-toolkit registration vector', () => {
  const vector = load<{
    challenge: string;
    secureSessionResponse: string;
    publicKeyJwk: PublicJwk;
    expectedStoredBoundKey: { jwk: PublicJwk; algorithm: string };
  }>('registration.json');

  it('verifies the registration JWS and stores the same public key', async () => {
    const result = await verifyProof(vector.secureSessionResponse, {
      mode: 'registration',
      verifyChallenge: (jti) => jti === vector.challenge,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.jwk).toEqual(vector.expectedStoredBoundKey.jwk);
    expect(result.kid).toBe(await jwkThumbprint(vector.expectedStoredBoundKey.jwk));
  });
});

describe('interop: dbsc-toolkit refresh vector', () => {
  const vector = load<{
    challenge: string;
    secureSessionResponse: string;
    storedPublicKeyJwk: PublicJwk;
    expectedResult: { verified: boolean; jti: string };
  }>('refresh.json');

  it('verifies the refresh JWS against the stored key', async () => {
    const result = await verifyProof(vector.secureSessionResponse, {
      mode: 'refresh',
      storedJwk: vector.storedPublicKeyJwk,
      verifyChallenge: (jti) => jti === vector.challenge,
    });
    expect(result.ok).toBe(vector.expectedResult.verified);
    if (!result.ok) return;
    expect(result.payload.jti).toBe(vector.expectedResult.jti);
  });
});
