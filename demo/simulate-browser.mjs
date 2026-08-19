/**
 * Drives the demo server through the full DBSC dance WITHOUT a browser: sign-in,
 * registration proof, and the 403 refresh dance, acting as a DBSC-capable client.
 * Useful as a headless end-to-end check. Real-Chrome testing lives in
 * docs/chrome-testing.md.
 *
 * Run: node demo/server.mjs & node demo/simulate-browser.mjs
 */
const BASE = 'http://localhost:8080';

const te = new TextEncoder();
const b64u = (bytes) =>
  btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
const b64uJson = (obj) => b64u(te.encode(JSON.stringify(obj)));

const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
const publicJwk = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };

async function proof({ includeJwk, payload }) {
  const h = b64uJson({ typ: 'dbsc+jwt', alg: 'ES256', ...(includeJwk ? { jwk: publicJwk } : {}) });
  const p = b64uJson(payload);
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, te.encode(`${h}.${p}`));
  return `${h}.${p}.${b64u(new Uint8Array(sig))}`;
}

const fail = (msg) => {
  console.error(`FAIL: ${msg}`);
  process.exit(1);
};

// 1. Sign in.
const login = await fetch(`${BASE}/login`);
const registration = login.headers.get('secure-session-registration');
if (!registration) fail('no Secure-Session-Registration header on /login');
const challenge = registration.match(/challenge="([^"]+)"/)?.[1];
const path = registration.match(/path="([^"]+)"/)?.[1];
const cookie = login.headers.getSetCookie()[0]?.split(';')[0];
if (!challenge || !path || !cookie) fail('registration header or cookie incomplete');
console.log('1. signed in; registration requested');

// 2. Register the device key.
const register = await fetch(`${BASE}${path}`, {
  method: 'POST',
  headers: {
    cookie,
    'Secure-Session-Response': await proof({ includeJwk: true, payload: { jti: challenge } }),
  },
});
if (register.status !== 200) fail(`registration returned ${register.status}`);
const config = await register.json();
if (!config.session_identifier || config.credentials?.[0]?.name !== 'demo_session') {
  fail('registration config unexpected');
}
console.log(`2. registered dbsc session ${config.session_identifier}`);

// 3. Refresh: first POST gets the 403 challenge.
const sessionId = config.session_identifier;
const first = await fetch(`${BASE}${config.refresh_url}`, {
  method: 'POST',
  headers: { 'Sec-Secure-Session-Id': sessionId },
});
if (first.status !== 403) fail(`expected 403 challenge, got ${first.status}`);
const challengeHeader = first.headers.get('secure-session-challenge');
const refreshChallenge = challengeHeader?.match(/^"([^"]+)"/)?.[1];
if (!refreshChallenge) fail('no refresh challenge issued');
console.log('3. refresh challenged (403)');

// 4. Refresh: retry with the signed proof (no jwk on refresh).
const second = await fetch(`${BASE}${config.refresh_url}`, {
  method: 'POST',
  headers: {
    'Sec-Secure-Session-Id': sessionId,
    'Secure-Session-Response': await proof({
      includeJwk: false,
      payload: { jti: refreshChallenge, sub: sessionId },
    }),
  },
});
if (second.status !== 200) fail(`refresh returned ${second.status}`);
const reminted = second.headers.getSetCookie()[0];
if (!reminted?.startsWith('demo_session=')) fail('refresh did not re-mint the cookie');
console.log('4. refresh verified; cookie re-minted');

// 5. A wrong-key proof must be re-challenged, not accepted.
const attacker = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
const forgedHeader = b64uJson({ typ: 'dbsc+jwt', alg: 'ES256' });
const forgedPayload = b64uJson({ jti: refreshChallenge, sub: sessionId });
const forgedSig = await crypto.subtle.sign(
  { name: 'ECDSA', hash: 'SHA-256' },
  attacker.privateKey,
  te.encode(`${forgedHeader}.${forgedPayload}`),
);
const forged = await fetch(`${BASE}${config.refresh_url}`, {
  method: 'POST',
  headers: {
    'Sec-Secure-Session-Id': sessionId,
    'Secure-Session-Response': `${forgedHeader}.${forgedPayload}.${b64u(new Uint8Array(forgedSig))}`,
  },
});
if (forged.status !== 403) fail(`forged proof: expected 403 re-challenge, got ${forged.status}`);
console.log('5. forged proof re-challenged (403), session intact');

console.log('PASS: full DBSC dance completed against the demo server');
process.exit(0);
