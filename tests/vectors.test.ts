/**
 * Verifies the committed golden vectors in vectors/. These files are the stable
 * cross-implementation reference; this test proves this package agrees with them.
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  getSkippedHeader,
  parseChallengeHeader,
  parseRegistrationHeader,
} from '../src/protocol/headers.js';
import type { PublicJwk } from '../src/protocol/jwk.js';
import { verifyProof } from '../src/protocol/proof.js';
import { buildSessionConfigBody, buildTerminationResponse } from '../src/session-config.js';

const load = <T>(file: string): T =>
  JSON.parse(readFileSync(new URL(`../vectors/${file}`, import.meta.url), 'utf8')) as T;

interface ProofVector {
  name: string;
  mode: 'registration' | 'refresh';
  storedKey?: 'ec' | 'rsa';
  challenge: string;
  jwt: string;
  expected: string;
  expectedSub?: string;
  clockSkewSec?: number;
}

const keys = load<{ ec: { public: PublicJwk }; rsa: { public: PublicJwk } }>('keys.json');
const proofs = load<{ now: number; cases: ProofVector[] }>('proofs.json');

describe('golden vectors: proofs', () => {
  for (const vector of proofs.cases) {
    it(vector.name, async () => {
      const result = await verifyProof(vector.jwt, {
        ...(vector.mode === 'refresh'
          ? { mode: 'refresh', storedJwk: keys[vector.storedKey ?? 'ec'].public }
          : { mode: 'registration' }),
        verifyChallenge: (jti) => jti === vector.challenge,
        ...(vector.expectedSub !== undefined ? { expectedSub: vector.expectedSub } : {}),
        ...(vector.clockSkewSec !== undefined ? { clockSkewSec: vector.clockSkewSec } : {}),
        now: () => proofs.now * 1000,
      });
      if (vector.expected === 'valid') {
        expect(result.ok, `expected valid, got ${result.ok ? 'valid' : (result as { reason: string }).reason}`).toBe(true);
      } else {
        expect(result).toMatchObject({ ok: false, reason: vector.expected });
      }
    });
  }
});

interface HeaderVector {
  name: string;
  value: string;
  parsed: unknown;
}
const headers = load<{ registration: HeaderVector[]; challenge: HeaderVector[]; skipped: HeaderVector[] }>(
  'headers.json',
);

describe('golden vectors: headers', () => {
  for (const vector of headers.registration) {
    it(`registration: ${vector.name}`, () => {
      expect(parseRegistrationHeader(vector.value)).toEqual(vector.parsed);
    });
  }
  for (const vector of headers.challenge) {
    it(`challenge: ${vector.name}`, () => {
      expect(parseChallengeHeader(vector.value)).toEqual(vector.parsed);
    });
  }
  for (const vector of headers.skipped) {
    it(`skipped: ${vector.name}`, () => {
      expect(getSkippedHeader(new Headers({ 'Secure-Session-Skipped': vector.value }))).toEqual(vector.parsed);
    });
  }
});

interface ConfigVector {
  name: string;
  init?: Parameters<typeof buildSessionConfigBody>[0];
  terminate?: string;
  body: unknown;
}
const configs = load<{ cases: ConfigVector[] }>('session-config.json');

describe('golden vectors: session config', () => {
  for (const vector of configs.cases) {
    it(vector.name, async () => {
      if (vector.init !== undefined) {
        expect(buildSessionConfigBody(vector.init)).toEqual(vector.body);
      }
      if (vector.terminate !== undefined) {
        expect(await buildTerminationResponse(vector.terminate).json()).toEqual(vector.body);
      }
    });
  }
});
