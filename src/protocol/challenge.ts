/**
 * Challenge issuance and verification.
 *
 * The default challenger is STATELESS: the challenge value is
 * `base64url(payload) "." base64url(hmac-sha256(payload, secret))`, so any server
 * instance can verify a challenge that any other instance issued, with no shared
 * store. The payload carries an expiry, a purpose ("registration" or "refresh"),
 * an optional session binding, and a random nonce.
 *
 * Domain separation: a registration challenge never verifies as a refresh challenge,
 * and a challenge bound to session A never verifies for session B.
 *
 * The stateless challenger does NOT enforce single use: within the TTL, the same
 * challenge verifies more than once. The TTL is short (default 60 seconds) and a
 * proof replay also has to clear the signature checks, but deployments that want
 * strict single use can wrap any challenger with `withSingleUse()` and a store.
 */

import { base64urlToBytes, bytesToBase64url, utf8ToBase64url, base64urlToJson } from '../internal/base64url.js';

export type ChallengePurpose = 'registration' | 'refresh';

export interface ChallengeContext {
  purpose: ChallengePurpose;
  /** Required when purpose is "refresh": the session the challenge is bound to. */
  sessionId?: string;
}

export interface Challenger {
  issue(ctx: ChallengeContext): Promise<string>;
  /** Returns true when `challenge` is valid, unexpired, and matches `ctx`. */
  verify(challenge: string, ctx: ChallengeContext): Promise<boolean>;
}

export interface HmacChallengerOptions {
  /**
   * The HMAC secret. Give all server instances the same value. Rotating the secret
   * invalidates outstanding challenges, which only forces one extra 403 round trip.
   */
  secret: string | Uint8Array;
  /** Challenge lifetime in seconds. Default: 60. Keep this short. */
  ttlSec?: number;
  /** Clock override for tests. Returns milliseconds since the epoch. */
  now?: () => number;
}

interface ChallengePayload {
  v: 1;
  p: ChallengePurpose;
  s?: string;
  /** Expiry, unix seconds. */
  e: number;
  /** Random nonce, base64url. */
  n: string;
}

const timingSafeEqual = (a: Uint8Array, b: Uint8Array): boolean => {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
};

export function createHmacChallenger(opts: HmacChallengerOptions): Challenger {
  const ttlSec = opts.ttlSec ?? 60;
  if (!Number.isFinite(ttlSec) || ttlSec <= 0) throw new Error('ttlSec must be a positive number');
  const secretBytes = typeof opts.secret === 'string' ? new TextEncoder().encode(opts.secret) : opts.secret;
  if (secretBytes.length < 16) throw new Error('the challenge secret must be at least 16 bytes');
  const now = opts.now ?? Date.now;

  let keyPromise: Promise<CryptoKey> | null = null;
  const key = (): Promise<CryptoKey> =>
    (keyPromise ??= crypto.subtle.importKey(
      'raw',
      secretBytes.slice().buffer as ArrayBuffer,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign', 'verify'],
    ));

  const mac = async (payloadB64: string): Promise<Uint8Array> => {
    const sig = await crypto.subtle.sign('HMAC', await key(), new TextEncoder().encode(payloadB64));
    return new Uint8Array(sig);
  };

  return {
    async issue(ctx: ChallengeContext): Promise<string> {
      if (ctx.purpose === 'refresh' && !ctx.sessionId) {
        throw new Error('a refresh challenge requires a sessionId');
      }
      const nonce = new Uint8Array(16);
      crypto.getRandomValues(nonce);
      const payload: ChallengePayload = {
        v: 1,
        p: ctx.purpose,
        ...(ctx.sessionId !== undefined ? { s: ctx.sessionId } : {}),
        e: Math.floor(now() / 1000) + ttlSec,
        n: bytesToBase64url(nonce),
      };
      const payloadB64 = utf8ToBase64url(JSON.stringify(payload));
      return `${payloadB64}.${bytesToBase64url(await mac(payloadB64))}`;
    },

    async verify(challenge: string, ctx: ChallengeContext): Promise<boolean> {
      const dot = challenge.indexOf('.');
      if (dot <= 0 || dot !== challenge.lastIndexOf('.')) return false;
      const payloadB64 = challenge.slice(0, dot);
      const macBytes = base64urlToBytes(challenge.slice(dot + 1));
      if (macBytes === null) return false;
      if (!timingSafeEqual(macBytes, await mac(payloadB64))) return false;

      const payload = base64urlToJson<ChallengePayload>(payloadB64);
      if (payload === null || payload.v !== 1) return false;
      if (payload.p !== ctx.purpose) return false;
      if ((payload.s ?? null) !== (ctx.sessionId ?? null)) return false;
      if (typeof payload.e !== 'number' || Math.floor(now() / 1000) > payload.e) return false;
      return true;
    },
  };
}

/**
 * Store interface for strict single-use challenges. `consume` must return true the
 * first time it sees a value and false on every later call (atomically, if more than
 * one server instance shares the store). Entries can expire after `ttlSec`.
 */
export interface ChallengeConsumedStore {
  consume(challenge: string, ttlSec: number): Promise<boolean>;
}

/** An in-memory ChallengeConsumedStore for tests, demos, and single-instance servers. */
export function createMemoryConsumedStore(opts: { now?: () => number } = {}): ChallengeConsumedStore {
  const now = opts.now ?? Date.now;
  const seen = new Map<string, number>();
  return {
    async consume(challenge: string, ttlSec: number): Promise<boolean> {
      const t = now();
      for (const [value, expiry] of seen) if (expiry <= t) seen.delete(value);
      if (seen.has(challenge)) return false;
      seen.set(challenge, t + ttlSec * 1000);
      return true;
    },
  };
}

/** Wraps a challenger so every challenge verifies at most once. */
export function withSingleUse(
  challenger: Challenger,
  store: ChallengeConsumedStore,
  opts: { ttlSec?: number } = {},
): Challenger {
  const ttlSec = opts.ttlSec ?? 60;
  return {
    issue: (ctx) => challenger.issue(ctx),
    async verify(challenge, ctx) {
      if (!(await challenger.verify(challenge, ctx))) return false;
      return store.consume(challenge, ttlSec);
    },
  };
}
