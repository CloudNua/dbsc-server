/**
 * Adapter test driver: runs the full DBSC dance (register → 403 → refresh)
 * through any `dispatch` function, so every adapter proves the same behavior.
 */
import { expect } from 'vitest';
import { createDbsc, type Dbsc } from '../../src/flows.js';
import type { DbscHandlersConfig } from '../../src/handlers.js';
import { parseChallengeHeader } from '../../src/protocol/headers.js';
import { createMemoryStore } from '../../src/store.js';
import { generateEs256, mintProof } from './mint.js';

export const SECRET = 'test-secret-at-least-16-bytes-long';

export function makeHandlerConfig(): DbscHandlersConfig & { dbsc: Dbsc } {
  const dbsc = createDbsc({ store: createMemoryStore(), challenge: { secret: SECRET }, onWarning: () => {} });
  return {
    dbsc,
    ref: (request) => request.headers.get('x-app-session') ?? undefined,
    bindSession: ({ session }) => ({
      scope: { includeSite: false },
      credentials: [{ name: 'session', attributes: 'Path=/; HttpOnly; SameSite=Lax' }],
      setCookies: [`session=${session.ref ?? 'anon'}; Max-Age=600; Path=/; HttpOnly`],
    }),
  };
}

export interface DanceDispatch {
  (path: '/dbsc/register' | '/dbsc/refresh', headers: Record<string, string>): Promise<Response>;
}

/** Runs the full dance through an adapter and asserts every step. */
export async function runDance(dbsc: Dbsc, dispatch: DanceDispatch): Promise<void> {
  // Registration.
  const registration = await dbsc.registrationHeader();
  const challenge = registration.value.match(/challenge="([^"]+)"/)![1]!;
  const key = await generateEs256();
  const proof = await mintProof({ key, payload: { jti: challenge } });
  const registered = await dispatch('/dbsc/register', {
    'Secure-Session-Response': proof,
    'x-app-session': 'app-1',
  });
  expect(registered.status).toBe(200);
  const config = (await registered.json()) as { session_identifier: string; refresh_url: string };
  expect(config.session_identifier).toBeTruthy();
  expect(registered.headers.getSetCookie().join(';')).toContain('session=app-1');

  // Refresh: no proof → 403 + challenge.
  const sessionId = config.session_identifier;
  const challenged = await dispatch('/dbsc/refresh', { 'Sec-Secure-Session-Id': sessionId });
  expect(challenged.status).toBe(403);
  const refreshChallenge = parseChallengeHeader(challenged.headers.get('Secure-Session-Challenge')!)!;
  expect(refreshChallenge.sessionId).toBe(sessionId);

  // Refresh: signed proof → 200 + re-minted cookie.
  const refreshProof = await mintProof({
    key,
    includeJwk: false,
    payload: { jti: refreshChallenge.challenge, sub: sessionId },
  });
  const refreshed = await dispatch('/dbsc/refresh', {
    'Sec-Secure-Session-Id': sessionId,
    'Secure-Session-Response': refreshProof,
  });
  expect(refreshed.status).toBe(200);
  expect(refreshed.headers.getSetCookie().join(';')).toContain('session=app-1');

  // Unknown session → 400 terminate.
  const terminated = await dispatch('/dbsc/refresh', { 'Sec-Secure-Session-Id': 'ghost' });
  expect(terminated.status).toBe(400);
}
