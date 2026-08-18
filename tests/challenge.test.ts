import { describe, expect, it } from 'vitest';
import {
  createHmacChallenger,
  createMemoryConsumedStore,
  withSingleUse,
} from '../src/protocol/challenge.js';

const SECRET = 'test-secret-at-least-16-bytes-long';

describe('hmac challenger', () => {
  it('issues and verifies a registration challenge', async () => {
    const challenger = createHmacChallenger({ secret: SECRET });
    const challenge = await challenger.issue({ purpose: 'registration' });
    await expect(challenger.verify(challenge, { purpose: 'registration' })).resolves.toBe(true);
  });

  it('issues and verifies a refresh challenge bound to a session', async () => {
    const challenger = createHmacChallenger({ secret: SECRET });
    const challenge = await challenger.issue({ purpose: 'refresh', sessionId: 's-1' });
    await expect(challenger.verify(challenge, { purpose: 'refresh', sessionId: 's-1' })).resolves.toBe(true);
  });

  it('rejects cross-purpose use (domain separation)', async () => {
    const challenger = createHmacChallenger({ secret: SECRET });
    const registration = await challenger.issue({ purpose: 'registration' });
    await expect(challenger.verify(registration, { purpose: 'refresh', sessionId: 's-1' })).resolves.toBe(false);
  });

  it('rejects cross-session use', async () => {
    const challenger = createHmacChallenger({ secret: SECRET });
    const challenge = await challenger.issue({ purpose: 'refresh', sessionId: 's-1' });
    await expect(challenger.verify(challenge, { purpose: 'refresh', sessionId: 's-2' })).resolves.toBe(false);
    await expect(challenger.verify(challenge, { purpose: 'refresh' })).resolves.toBe(false);
  });

  it('rejects an expired challenge', async () => {
    let t = 1_000_000_000_000;
    const challenger = createHmacChallenger({ secret: SECRET, ttlSec: 60, now: () => t });
    const challenge = await challenger.issue({ purpose: 'registration' });
    t += 61_000;
    await expect(challenger.verify(challenge, { purpose: 'registration' })).resolves.toBe(false);
  });

  it('rejects a challenge from a different secret', async () => {
    const a = createHmacChallenger({ secret: SECRET });
    const b = createHmacChallenger({ secret: 'another-secret-16-bytes-min!!' });
    const challenge = await a.issue({ purpose: 'registration' });
    await expect(b.verify(challenge, { purpose: 'registration' })).resolves.toBe(false);
  });

  it('rejects tampered payloads and garbage', async () => {
    const challenger = createHmacChallenger({ secret: SECRET });
    const challenge = await challenger.issue({ purpose: 'registration' });
    const [payload, mac] = challenge.split('.') as [string, string];
    const tamperedPayload = `${payload.slice(0, -2)}AA.${mac}`;
    for (const bad of [tamperedPayload, `${payload}.AAAA`, '', '.', 'a.b.c', 'not-a-challenge']) {
      await expect(challenger.verify(bad, { purpose: 'registration' })).resolves.toBe(false);
    }
  });

  it('requires a sessionId for refresh challenges and a usable secret', async () => {
    const challenger = createHmacChallenger({ secret: SECRET });
    await expect(challenger.issue({ purpose: 'refresh' })).rejects.toThrow();
    expect(() => createHmacChallenger({ secret: 'short' })).toThrow();
    expect(() => createHmacChallenger({ secret: SECRET, ttlSec: 0 })).toThrow();
  });
});

describe('single-use wrapper', () => {
  it('verifies a challenge exactly once', async () => {
    const challenger = withSingleUse(createHmacChallenger({ secret: SECRET }), createMemoryConsumedStore());
    const challenge = await challenger.issue({ purpose: 'registration' });
    await expect(challenger.verify(challenge, { purpose: 'registration' })).resolves.toBe(true);
    await expect(challenger.verify(challenge, { purpose: 'registration' })).resolves.toBe(false);
  });

  it('does not consume a challenge that failed base verification', async () => {
    const store = createMemoryConsumedStore();
    const challenger = withSingleUse(createHmacChallenger({ secret: SECRET }), store);
    const challenge = await challenger.issue({ purpose: 'refresh', sessionId: 's-1' });
    // Wrong session: base verify fails, so the challenge must remain usable.
    await expect(challenger.verify(challenge, { purpose: 'refresh', sessionId: 's-2' })).resolves.toBe(false);
    await expect(challenger.verify(challenge, { purpose: 'refresh', sessionId: 's-1' })).resolves.toBe(true);
  });
});
