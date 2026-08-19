/**
 * Generates the golden-vector suite in vectors/.
 *
 * Run: node scripts/generate-vectors.mjs
 *
 * The vectors are COMMITTED, not regenerated in CI: ES256 signatures are
 * randomized, so each run produces different (equally valid) proof bytes. The
 * committed files are the stable reference; tests/vectors.test.ts verifies them.
 *
 * The key pairs in vectors/keys.json are TEST KEYS. They exist so other
 * implementations can re-sign and cross-check. Never use them for anything real.
 */
import { writeFileSync } from 'node:fs';

const te = new TextEncoder();
const b64u = (bytes) =>
  btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
const b64uJson = (obj) => b64u(te.encode(JSON.stringify(obj)));

async function exportJwk(key) {
  return crypto.subtle.exportKey('jwk', key);
}

async function mint({ privateKey, publicJwk, alg, typ = 'dbsc+jwt', includeJwk = true, payload, tamper }) {
  const header = { typ, alg, ...(includeJwk ? { jwk: publicJwk } : {}) };
  const h = b64uJson(header);
  const p = b64uJson(payload);
  // Sign with the KEY's algorithm, not the JWT alg string — the mismatch vectors
  // (alg-none, alg-key-mismatch) deliberately lie in the header.
  const algorithm =
    privateKey.algorithm.name === 'ECDSA' ? { name: 'ECDSA', hash: 'SHA-256' } : 'RSASSA-PKCS1-v1_5';
  let sig = new Uint8Array(await crypto.subtle.sign(algorithm, privateKey, te.encode(`${h}.${p}`)));
  if (tamper === 'signature') sig[0] ^= 0xff;
  let jwt = `${h}.${p}.${b64u(sig)}`;
  if (tamper === 'payload') {
    jwt = `${h}.${b64uJson({ ...payload, admin: true })}.${b64u(sig)}`;
  }
  return jwt;
}

const CHALLENGE_REG = 'vector-registration-challenge-1';
const CHALLENGE_REFRESH = 'vector-refresh-challenge-1';
const SESSION_ID = 'vector-session-1';
const NOW_SEC = 1755600000; // fixed reference time for iat vectors

const ecPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
const rsaPair = await crypto.subtle.generateKey(
  { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
  true,
  ['sign', 'verify'],
);
const otherEcPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);

const ecPublic = await exportJwk(ecPair.publicKey);
const ecPrivate = await exportJwk(ecPair.privateKey);
const rsaPublic = await exportJwk(rsaPair.publicKey);
const rsaPrivate = await exportJwk(rsaPair.privateKey);
const strip = (jwk) => {
  const { key_ops: _ko, ext: _ext, ...rest } = jwk;
  return rest;
};

const keys = {
  comment: 'TEST KEYS ONLY. Committed so other implementations can cross-check. Never use for anything real.',
  ec: { public: strip(ecPublic), private: strip(ecPrivate) },
  rsa: { public: strip(rsaPublic), private: strip(rsaPrivate) },
};

const ecArgs = { privateKey: ecPair.privateKey, publicJwk: strip(ecPublic), alg: 'ES256' };
const rsaArgs = { privateKey: rsaPair.privateKey, publicJwk: strip(rsaPublic), alg: 'RS256' };

const proofs = {
  comment:
    'DBSC proof JWT verification vectors. mode: registration verifies the header jwk; ' +
    'mode: refresh verifies against storedJwk (keys.<kty>.public). challenge is the expected jti. ' +
    'expected: "valid" or the failure class. Failure NAMES are this package’s; other ' +
    'implementations should map them to their own classes. now = fixed unix seconds for iat checks.',
  now: NOW_SEC,
  cases: [
    {
      name: 'es256-registration-valid',
      mode: 'registration',
      challenge: CHALLENGE_REG,
      jwt: await mint({ ...ecArgs, payload: { jti: CHALLENGE_REG, aud: 'https://server.example/dbsc/register' } }),
      expected: 'valid',
    },
    {
      name: 'es256-registration-minimal-valid',
      comment: 'Chrome-shaped: jti and nothing else',
      mode: 'registration',
      challenge: CHALLENGE_REG,
      jwt: await mint({ ...ecArgs, payload: { jti: CHALLENGE_REG } }),
      expected: 'valid',
    },
    {
      name: 'rs256-registration-valid',
      mode: 'registration',
      challenge: CHALLENGE_REG,
      jwt: await mint({ ...rsaArgs, payload: { jti: CHALLENGE_REG } }),
      expected: 'valid',
    },
    {
      name: 'es256-refresh-valid',
      mode: 'refresh',
      storedKey: 'ec',
      challenge: CHALLENGE_REFRESH,
      jwt: await mint({ ...ecArgs, includeJwk: false, payload: { jti: CHALLENGE_REFRESH, sub: SESSION_ID } }),
      expectedSub: SESSION_ID,
      expected: 'valid',
    },
    {
      name: 'es256-registration-iat-valid',
      mode: 'registration',
      challenge: CHALLENGE_REG,
      jwt: await mint({ ...ecArgs, payload: { jti: CHALLENGE_REG, iat: NOW_SEC - 30 } }),
      expected: 'valid',
    },
    {
      name: 'wrong-typ',
      mode: 'registration',
      challenge: CHALLENGE_REG,
      jwt: await mint({ ...ecArgs, typ: 'JWT', payload: { jti: CHALLENGE_REG } }),
      expected: 'bad-typ',
    },
    {
      name: 'alg-none',
      mode: 'registration',
      challenge: CHALLENGE_REG,
      jwt: await mint({ ...ecArgs, alg: 'none', payload: { jti: CHALLENGE_REG } }),
      expected: 'alg-not-allowed',
    },
    {
      name: 'refresh-smuggled-jwk',
      comment: 'key substitution: refresh proof carries an attacker jwk',
      mode: 'refresh',
      storedKey: 'ec',
      challenge: CHALLENGE_REFRESH,
      jwt: await mint({
        privateKey: otherEcPair.privateKey,
        publicJwk: strip(await exportJwk(otherEcPair.publicKey)),
        alg: 'ES256',
        payload: { jti: CHALLENGE_REFRESH },
      }),
      expected: 'jwk-forbidden',
    },
    {
      name: 'registration-missing-jwk',
      mode: 'registration',
      challenge: CHALLENGE_REG,
      jwt: await mint({ ...ecArgs, includeJwk: false, payload: { jti: CHALLENGE_REG } }),
      expected: 'jwk-missing',
    },
    {
      name: 'alg-key-mismatch',
      mode: 'registration',
      challenge: CHALLENGE_REG,
      jwt: await mint({ ...ecArgs, alg: 'RS256', payload: { jti: CHALLENGE_REG } }),
      expected: 'alg-key-mismatch',
    },
    {
      name: 'tampered-signature',
      mode: 'registration',
      challenge: CHALLENGE_REG,
      jwt: await mint({ ...ecArgs, payload: { jti: CHALLENGE_REG }, tamper: 'signature' }),
      expected: 'bad-signature',
    },
    {
      name: 'tampered-payload',
      mode: 'registration',
      challenge: CHALLENGE_REG,
      jwt: await mint({ ...ecArgs, payload: { jti: CHALLENGE_REG }, tamper: 'payload' }),
      expected: 'bad-signature',
    },
    {
      name: 'wrong-challenge',
      mode: 'registration',
      challenge: CHALLENGE_REG,
      jwt: await mint({ ...ecArgs, payload: { jti: 'an-old-challenge' } }),
      expected: 'challenge-mismatch',
    },
    {
      name: 'stale-iat',
      mode: 'registration',
      challenge: CHALLENGE_REG,
      clockSkewSec: 300,
      jwt: await mint({ ...ecArgs, payload: { jti: CHALLENGE_REG, iat: NOW_SEC - 3600 } }),
      expected: 'iat-out-of-window',
    },
  ],
};

const headers = {
  comment:
    'DBSC header parse vectors. parse=null means the value must be rejected. ' +
    'Names use the second-origin-trial (current) forms.',
  registration: [
    {
      name: 'documented-shape',
      value: '(ES256 RS256);path="/dbsc/register";challenge="cv";authorization="ac"',
      parsed: { algorithms: ['ES256', 'RS256'], path: '/dbsc/register', challenge: 'cv', authorization: 'ac' },
    },
    {
      name: 'unknown-alg-and-federated-params-ignored',
      value: '(ES256 ES512);path="/r";challenge="c";provider_url="https://idp.example"',
      parsed: { algorithms: ['ES256'], path: '/r', challenge: 'c' },
    },
    { name: 'missing-path', value: '(ES256);challenge="c"', parsed: null },
    { name: 'no-known-algs', value: '(ES512);path="/r";challenge="c"', parsed: null },
    { name: 'unterminated-list', value: '(ES256;path="/r";challenge="c"', parsed: null },
  ],
  challenge: [
    { name: 'refresh-challenge', value: '"cv";id="s-1"', parsed: { challenge: 'cv', sessionId: 's-1' } },
    { name: 'registration-challenge', value: '"cv"', parsed: { challenge: 'cv' } },
    { name: 'escaped-string', value: '"a\\"b\\\\c";id="s-1"', parsed: { challenge: 'a"b\\c', sessionId: 's-1' } },
    { name: 'token-not-string', value: 'cv;id="s-1"', parsed: null },
  ],
  skipped: [
    {
      name: 'quota-exceeded',
      value: 'quota_exceeded;session_identifier="123"',
      parsed: { reason: 'quota_exceeded', sessionId: '123' },
    },
    { name: 'unknown-reason-ok', value: 'some_future_reason', parsed: { reason: 'some_future_reason' } },
    { name: 'string-not-token', value: '"unreachable"', parsed: null },
  ],
};

const sessionConfig = {
  comment: 'Session configuration JSON building vectors.',
  cases: [
    {
      name: 'full-shape',
      init: {
        sessionId: 's-1',
        refreshUrl: '/dbsc/refresh',
        scope: {
          includeSite: true,
          specification: [{ type: 'exclude', domain: '*.example.com', path: '/static' }],
        },
        credentials: [{ name: 'session', attributes: 'Path=/; Secure; HttpOnly; SameSite=Lax' }],
      },
      body: {
        session_identifier: 's-1',
        refresh_url: '/dbsc/refresh',
        scope: {
          include_site: true,
          scope_specification: [{ type: 'exclude', domain: '*.example.com', path: '/static' }],
        },
        credentials: [{ type: 'cookie', name: 'session', attributes: 'Path=/; Secure; HttpOnly; SameSite=Lax' }],
      },
    },
    {
      name: 'termination-body',
      terminate: 's-1',
      body: { session_identifier: 's-1', continue: false },
    },
  ],
};

const write = (file, data) => writeFileSync(new URL(`../vectors/${file}`, import.meta.url), `${JSON.stringify(data, null, 2)}\n`);
write('keys.json', keys);
write('proofs.json', proofs);
write('headers.json', headers);
write('session-config.json', sessionConfig);
console.log('vectors written: keys.json, proofs.json, headers.json, session-config.json');
