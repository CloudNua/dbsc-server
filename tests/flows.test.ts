/** Full-flow integration: register → refresh (403 dance) → skipped → terminate. */
import { describe, expect, it } from 'vitest';
import { createDbsc, type Dbsc } from '../src/flows.js';
import { parseChallengeHeader, parseRegistrationHeader } from '../src/protocol/headers.js';
import { createMemoryStore, type DbscSessionStore } from '../src/store.js';
import { generateEs256, mintProof, type KeyPairHandle } from './helpers/mint.js';

const SECRET = 'test-secret-at-least-16-bytes-long';
const ORIGIN = 'https://app.example.com';

function makeDbsc(overrides: { store?: DbscSessionStore; now?: () => number } = {}): {
  dbsc: Dbsc;
  store: DbscSessionStore;
} {
  const store = overrides.store ?? createMemoryStore(overrides.now ? { now: overrides.now } : {});
  const dbsc = createDbsc({
    store,
    challenge: { secret: SECRET },
    onWarning: () => {},
    ...(overrides.now ? { now: overrides.now } : {}),
  });
  return { dbsc, store };
}

async function register(dbsc: Dbsc, key: KeyPairHandle, ref?: string) {
  const header = await dbsc.registrationHeader();
  const reg = parseRegistrationHeader(header.value)!;
  const proof = await mintProof({ key, payload: { jti: reg.challenge } });
  const request = new Request(`${ORIGIN}${reg.path}`, {
    method: 'POST',
    headers: { 'Secure-Session-Response': proof },
  });
  return dbsc.handleRegistration(request, ref !== undefined ? { ref } : {});
}

describe('registration flow', () => {
  it('issues a registration header and creates a session from a valid proof', async () => {
    const { dbsc, store } = makeDbsc();
    const header = await dbsc.registrationHeader();
    expect(header.name).toBe('Secure-Session-Registration');
    expect(parseRegistrationHeader(header.value)).toMatchObject({ path: '/dbsc/register' });

    const key = await generateEs256();
    const result = await register(dbsc, key, 'user-42');
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.session.ref).toBe('user-42');
    expect(result.session.kid).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(await store.get(result.session.id)).not.toBeNull();
  });

  it('rejects a proof with a bad challenge and does not create a session', async () => {
    const { dbsc } = makeDbsc();
    const key = await generateEs256();
    const proof = await mintProof({ key, payload: { jti: 'made-up-challenge' } });
    const request = new Request(`${ORIGIN}/dbsc/register`, {
      method: 'POST',
      headers: { 'Secure-Session-Response': proof },
    });
    const result = await dbsc.handleRegistration(request);
    expect(result).toMatchObject({ ok: false, reason: 'challenge-mismatch' });
    if (result.ok) return;
    expect(result.response.status).toBe(400);
  });

  it('rejects a request without a proof', async () => {
    const { dbsc } = makeDbsc();
    const request = new Request(`${ORIGIN}/dbsc/register`, { method: 'POST' });
    const result = await dbsc.handleRegistration(request);
    expect(result).toMatchObject({ ok: false, reason: 'no-proof' });
  });
});

describe('refresh flow (the 403 dance)', () => {
  it('challenges, then verifies the signed challenge against the stored key', async () => {
    const { dbsc } = makeDbsc();
    const key = await generateEs256();
    const reg = await register(dbsc, key);
    if (!reg.ok) throw new Error('registration failed');
    const sessionId = reg.session.id;

    // Step 1: browser hits refresh with only the session id → 403 + challenge.
    const first = await dbsc.handleRefresh(
      new Request(`${ORIGIN}/dbsc/refresh`, {
        method: 'POST',
        headers: { 'Sec-Secure-Session-Id': sessionId },
      }),
    );
    expect(first.kind).toBe('challenge');
    if (first.kind !== 'challenge') return;
    expect(first.response.status).toBe(403);
    const challengeHeader = first.response.headers.get('Secure-Session-Challenge')!;
    const challenge = parseChallengeHeader(challengeHeader)!;
    expect(challenge.sessionId).toBe(sessionId);

    // Step 2: browser retries with the signed proof (no jwk on refresh).
    const proof = await mintProof({
      key,
      includeJwk: false,
      payload: { jti: challenge.challenge, sub: sessionId },
    });
    const second = await dbsc.handleRefresh(
      new Request(`${ORIGIN}/dbsc/refresh`, {
        method: 'POST',
        headers: { 'Sec-Secure-Session-Id': sessionId, 'Secure-Session-Response': proof },
      }),
    );
    expect(second.kind).toBe('verified');
    if (second.kind !== 'verified') return;
    expect(second.session.id).toBe(sessionId);

    // Step 3: the app re-mints the cookie via sessionConfigResponse.
    const response = dbsc.sessionConfigResponse({
      session: second.session,
      scope: { includeSite: false },
      credentials: [{ name: 'session', attributes: 'Path=/; Secure; HttpOnly' }],
      setCookies: ['session=next; Max-Age=600; Path=/; Secure; HttpOnly'],
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as { session_identifier: string; refresh_url: string };
    expect(body.session_identifier).toBe(sessionId);
    expect(body.refresh_url).toBe('/dbsc/refresh');
    expect(response.headers.get('set-cookie')).toContain('session=next');
  });

  it('re-challenges (never terminates) on an invalid proof', async () => {
    const { dbsc, store } = makeDbsc();
    const key = await generateEs256();
    const reg = await register(dbsc, key);
    if (!reg.ok) throw new Error('registration failed');

    const attacker = await generateEs256();
    const forged = await mintProof({
      key: attacker,
      includeJwk: false,
      payload: { jti: 'whatever', sub: reg.session.id },
    });
    const outcome = await dbsc.handleRefresh(
      new Request(`${ORIGIN}/dbsc/refresh`, {
        method: 'POST',
        headers: { 'Sec-Secure-Session-Id': reg.session.id, 'Secure-Session-Response': forged },
      }),
    );
    expect(outcome.kind).toBe('challenge');
    expect(await store.get(reg.session.id)).not.toBeNull(); // session survives
  });

  it('terminates an unknown session with a non-403 4xx and continue:false', async () => {
    const { dbsc } = makeDbsc();
    const outcome = await dbsc.handleRefresh(
      new Request(`${ORIGIN}/dbsc/refresh`, {
        method: 'POST',
        headers: { 'Sec-Secure-Session-Id': 'ghost' },
      }),
    );
    expect(outcome.kind).toBe('terminate');
    if (outcome.kind !== 'terminate') return;
    expect(outcome.response.status).toBe(400);
    expect(await outcome.response.json()).toEqual({ session_identifier: 'ghost', continue: false });
  });

  it('terminates and deletes an expired session', async () => {
    let t = 1_000_000_000_000;
    const now = () => t;
    const { dbsc, store } = makeDbsc({ now });
    const key = await generateEs256();
    const reg = await register(dbsc, key);
    if (!reg.ok) throw new Error('registration failed');

    t = reg.session.expiresAt + 1000;
    const outcome = await dbsc.handleRefresh(
      new Request(`${ORIGIN}/dbsc/refresh`, {
        method: 'POST',
        headers: { 'Sec-Secure-Session-Id': reg.session.id },
      }),
    );
    expect(outcome.kind).toBe('terminate');
    expect(await store.get(reg.session.id)).toBeNull();
  });

  it('returns a plain 400 when no session id is present', async () => {
    const { dbsc } = makeDbsc();
    const outcome = await dbsc.handleRefresh(new Request(`${ORIGIN}/dbsc/refresh`, { method: 'POST' }));
    expect(outcome).toMatchObject({ kind: 'terminate', sessionId: null });
  });
});

describe('proactive challenge, skipped, termination, well-known', () => {
  it('issues a proactive challenge header bound to the session', async () => {
    const { dbsc } = makeDbsc();
    const header = await dbsc.proactiveChallengeHeader('s-9');
    expect(header.name).toBe('Secure-Session-Challenge');
    expect(parseChallengeHeader(header.value)).toMatchObject({ sessionId: 's-9' });
  });

  it('observes the skipped header', () => {
    const { dbsc } = makeDbsc();
    const request = new Request(`${ORIGIN}/app`, {
      headers: { 'Secure-Session-Skipped': 'quota_exceeded;session_identifier="s-1"' },
    });
    expect(dbsc.observeSkipped(request)).toEqual({ reason: 'quota_exceeded', sessionId: 's-1' });
  });

  it('terminate() deletes the session and returns continue:false', async () => {
    const { dbsc, store } = makeDbsc();
    const key = await generateEs256();
    const reg = await register(dbsc, key);
    if (!reg.ok) throw new Error('registration failed');
    const response = await dbsc.terminate(reg.session.id);
    expect(await response.json()).toEqual({ session_identifier: reg.session.id, continue: false });
    expect(await store.get(reg.session.id)).toBeNull();
  });

  it('builds the well-known body', async () => {
    const { dbsc } = makeDbsc();
    const response = dbsc.wellKnownResponse({ registeringOrigins: ['https://app.example.com'] });
    expect(await response.json()).toEqual({ registering_origins: ['https://app.example.com'] });
  });
});

describe('audience checking is opt-in (proxy safety)', () => {
  it('accepts an aud-bearing proof when publicOrigin is unset', async () => {
    const { dbsc } = makeDbsc();
    const header = await dbsc.registrationHeader();
    const reg = parseRegistrationHeader(header.value)!;
    const key = await generateEs256();
    // Signed against the PUBLIC url; the request below arrives on an internal one.
    const proof = await mintProof({
      key,
      payload: { jti: reg.challenge, aud: 'https://app.example.com/dbsc/register' },
    });
    const request = new Request(`http://10.0.0.5:3000${reg.path}`, {
      method: 'POST',
      headers: { 'Secure-Session-Response': proof },
    });
    expect((await dbsc.handleRegistration(request)).ok).toBe(true);
  });

  it('enforces aud against publicOrigin when configured', async () => {
    const store = createMemoryStore();
    const dbsc = createDbsc({
      store,
      challenge: { secret: SECRET },
      publicOrigin: 'https://app.example.com',
      onWarning: () => {},
    });
    const header = await dbsc.registrationHeader();
    const reg = parseRegistrationHeader(header.value)!;
    const key = await generateEs256();
    const good = await mintProof({
      key,
      payload: { jti: reg.challenge, aud: 'https://app.example.com/dbsc/register' },
    });
    const goodResult = await dbsc.handleRegistration(
      new Request(`http://10.0.0.5:3000${reg.path}`, {
        method: 'POST',
        headers: { 'Secure-Session-Response': good },
      }),
    );
    expect(goodResult.ok).toBe(true);

    const header2 = await dbsc.registrationHeader();
    const reg2 = parseRegistrationHeader(header2.value)!;
    const bad = await mintProof({
      key,
      payload: { jti: reg2.challenge, aud: 'https://evil.example.com/dbsc/register' },
    });
    const badResult = await dbsc.handleRegistration(
      new Request(`http://10.0.0.5:3000${reg2.path}`, {
        method: 'POST',
        headers: { 'Secure-Session-Response': bad },
      }),
    );
    expect(badResult).toMatchObject({ ok: false, reason: 'aud-mismatch' });
  });
});
