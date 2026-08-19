/** Regression tests for the pre-release team-review findings (M1-M5, L5, L7). */
import express from 'express';
import type { AddressInfo } from 'node:net';
import { afterAll, describe, expect, it, vi } from 'vitest';
import { dbscExpress } from '../src/adapters/express.js';
import { dbscNest } from '../src/adapters/nestjs.js';
import { createDbsc } from '../src/flows.js';
import { parseChallengeHeader, parseRegistrationHeader } from '../src/protocol/headers.js';
import { createMemoryStore, type DbscSessionStore } from '../src/store.js';
import { makeHandlerConfig } from './helpers/dance.js';
import { generateEs256, mintProof } from './helpers/mint.js';

const SECRET = 'test-secret-at-least-16-bytes-long';

describe('M5: express adapter converts handler failures into 500, never a rejection', () => {
  const servers: Array<{ close(): void }> = [];
  afterAll(() => {
    for (const server of servers) server.close();
  });

  it('returns 500 when the session store rejects', async () => {
    const config = makeHandlerConfig();
    const failingStore: DbscSessionStore = {
      create: () => Promise.reject(new Error('database is down')),
      get: () => Promise.reject(new Error('database is down')),
      delete: () => Promise.reject(new Error('database is down')),
    };
    const dbsc = createDbsc({ store: failingStore, challenge: { secret: SECRET }, onWarning: () => {} });
    const handlers = dbscExpress({ ...config, dbsc });
    const app = express();
    app.post('/dbsc/refresh', (req, res) => void handlers.refresh(req, res));
    const server = app.listen(0);
    servers.push(server);
    const port = (server.address() as AddressInfo).port;

    const response = await fetch(`http://127.0.0.1:${port}/dbsc/refresh`, {
      method: 'POST',
      headers: { 'Sec-Secure-Session-Id': 's-1' },
    });
    // 5xx keeps the browser retrying; a 4xx would end the session; a crash
    // would end the process.
    expect(response.status).toBe(500);
  });
});

describe('M4: nestjs adapter rejects a non-express response object', () => {
  it('throws a clear platform error for a fastify-shaped reply', async () => {
    const config = makeHandlerConfig();
    const handlers = dbscNest(config);
    const fastifyReply = { code: () => {}, header: () => {}, send: () => {} };
    expect(() =>
      // @ts-expect-error deliberately wrong platform object
      handlers.register({ method: 'POST', url: '/dbsc/register', headers: {} }, fastifyReply),
    ).toThrow(/Express platform only/);
  });
});

describe('M1: deployment invariants check once per configuration shape', () => {
  function makeDbsc(checkInvariants: 'once' | 'always' | 'off', onWarning: () => void) {
    return createDbsc({
      store: createMemoryStore(),
      challenge: { secret: SECRET },
      checkInvariants,
      onWarning,
    });
  }
  const badInit = (cookieValue: string) => ({
    sessionId: 's-1',
    scope: { includeSite: false },
    credentials: [{ name: 'session', attributes: 'Path=/; HttpOnly' }],
    // No Max-Age: triggers the cookie-never-expires warning.
    setCookies: [`session=${cookieValue}; Path=/; HttpOnly`],
  });

  it("'once' warns one time even when cookie values differ", () => {
    const onWarning = vi.fn();
    const dbsc = makeDbsc('once', onWarning);
    dbsc.sessionConfigResponse(badInit('value-a'));
    dbsc.sessionConfigResponse(badInit('value-b'));
    expect(onWarning).toHaveBeenCalledTimes(1);
  });

  it("'always' warns every time and 'off' never warns", () => {
    const always = vi.fn();
    const dbscAlways = makeDbsc('always', always);
    dbscAlways.sessionConfigResponse(badInit('a'));
    dbscAlways.sessionConfigResponse(badInit('b'));
    expect(always).toHaveBeenCalledTimes(2);

    const off = vi.fn();
    const dbscOff = makeDbsc('off', off);
    dbscOff.sessionConfigResponse(badInit('a'));
    expect(off).not.toHaveBeenCalled();
  });
});

describe('M2: repeated refreshes verify against the cached key', () => {
  it('completes two sequential refresh dances for one session', async () => {
    const dbsc = createDbsc({ store: createMemoryStore(), challenge: { secret: SECRET }, onWarning: () => {} });
    const header = await dbsc.registrationHeader();
    const reg = parseRegistrationHeader(header.value)!;
    const key = await generateEs256();
    const proof = await mintProof({ key, payload: { jti: reg.challenge } });
    const registered = await dbsc.handleRegistration(
      new Request(`https://app.example.com${reg.path}`, {
        method: 'POST',
        headers: { 'Secure-Session-Response': proof },
      }),
    );
    if (!registered.ok) throw new Error('registration failed');
    const sessionId = registered.session.id;

    for (let round = 0; round < 2; round++) {
      const challenged = await dbsc.handleRefresh(
        new Request('https://app.example.com/dbsc/refresh', {
          method: 'POST',
          headers: { 'Sec-Secure-Session-Id': sessionId },
        }),
      );
      if (challenged.kind !== 'challenge') throw new Error('expected challenge');
      const challenge = parseChallengeHeader(challenged.response.headers.get('Secure-Session-Challenge')!)!;
      const refreshProof = await mintProof({
        key,
        includeJwk: false,
        payload: { jti: challenge.challenge, sub: sessionId },
      });
      const outcome = await dbsc.handleRefresh(
        new Request('https://app.example.com/dbsc/refresh', {
          method: 'POST',
          headers: { 'Sec-Secure-Session-Id': sessionId, 'Secure-Session-Response': refreshProof },
        }),
      );
      expect(outcome.kind).toBe('verified');
    }
  });
});

describe('L5: memory store expiry', () => {
  it('get() returns null for an expired session even between sweeps', async () => {
    let t = 1_000_000_000_000;
    const store = createMemoryStore({ now: () => t });
    await store.create({
      id: 's-1',
      publicJwk: { kty: 'EC', crv: 'P-256', x: 'a', y: 'b' },
      kid: 'k',
      createdAt: t,
      expiresAt: t + 10_000,
    });
    t += 11_000; // inside the 60s sweep throttle window
    expect(await store.get('s-1')).toBeNull();
  });
});
