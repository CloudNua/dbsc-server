/**
 * The high-level DBSC flows. `createDbsc()` wires the protocol primitives to a
 * session store and returns handlers that mirror the protocol one to one:
 *
 * - `registrationHeader()` — put on the sign-in response.
 * - `handleRegistration(request)` — the registration endpoint. Verifies the proof,
 *   creates the session, returns it. You then mint your cookie and reply with
 *   `sessionConfigResponse()`.
 * - `handleRefresh(request)` — the refresh endpoint state machine: 403 challenge →
 *   proof verification against the stored key → you re-mint the cookie.
 * - `proactiveChallengeHeader()` — pre-cache a challenge on any response.
 * - `terminate()` / `terminationResponse()` — end a session (`continue: false`).
 * - `observeSkipped()` — read the browser's "I skipped refresh" diagnostic.
 * - `wellKnownResponse()` — the `/.well-known/device-bound-sessions` body.
 *
 * Server-side security decisions embedded here:
 * - An invalid or stale proof RE-CHALLENGES (403); it never deletes the session.
 *   Anyone can POST garbage with a guessed session id; unauthenticated input must
 *   not be able to kill a session (denial of service). A stale challenge is also a
 *   benign race in normal operation.
 * - Termination responses (non-403 4xx) are sent only for sessions this server
 *   positively knows are unknown or expired.
 */

import { HEADERS, STATUS, type Algorithm } from './protocol/constants.js';
import {
  createHmacChallenger,
  type Challenger,
} from './protocol/challenge.js';
import {
  buildChallengeHeader,
  buildRegistrationHeader,
  getProofHeader,
  getSessionIdHeader,
  getSkippedHeader,
  type ParsedSkipped,
} from './protocol/headers.js';
import { verifyProof, type ProofFailureReason, type ProofPayload } from './protocol/proof.js';
import type { PublicJwk } from './protocol/jwk.js';
import {
  buildSessionConfigResponse,
  buildTerminationResponse,
  type DeploymentWarning,
  type SessionConfigInit,
} from './session-config.js';
import type { DbscSessionStore, StoredDbscSession } from './store.js';

export interface DbscOptions {
  /** Your session store. See `DbscSessionStore`. */
  store: DbscSessionStore;
  /** HMAC challenge configuration, or a custom `Challenger`. */
  challenge: { secret: string | Uint8Array; ttlSec?: number } | Challenger;
  /** Endpoint paths. Used for header building and refresh_url defaults. */
  paths?: { register?: string; refresh?: string };
  /** DBSC session lifetime in seconds. Default: 30 days. */
  sessionTtlSec?: number;
  /** Allowed proof algorithms. Default: ES256 and RS256. */
  algorithms?: readonly Algorithm[];
  /** Accept legacy `Sec-Session-*` inbound header names. Default: true. */
  acceptLegacyHeaders?: boolean;
  /**
   * The externally visible origin, for example "https://app.example.com". When set,
   * proofs that carry an `aud` claim must point at this origin + the request path.
   * When unset, `aud` is not checked: behind a TLS-terminating proxy the internal
   * request URL (http, internal host) does not match what the browser signed, and a
   * hard check would reject every proof.
   */
  publicOrigin?: string;
  /** Tolerated clock skew for optional `iat` claims, seconds. Default: 300. */
  clockSkewSec?: number;
  /** Receives deployment-invariant warnings. Default: console.warn. */
  onWarning?: (warning: DeploymentWarning) => void;
  /** Session id factory. Default: crypto.randomUUID. */
  generateSessionId?: () => string;
  /** Clock override for tests. Milliseconds since the epoch. */
  now?: () => number;
}

export interface RegistrationSuccess {
  ok: true;
  session: StoredDbscSession;
  payload: ProofPayload;
}
export interface RegistrationFailure {
  ok: false;
  reason: ProofFailureReason | 'no-proof';
  /** A ready 400 response. Send it, or build your own from `reason`. */
  response: Response;
}
export type RegistrationResult = RegistrationSuccess | RegistrationFailure;

/** Like SessionConfigInit, but session id, refresh url, and expiry can come from a session. */
export type SessionConfigResponseInit = Omit<SessionConfigInit, 'sessionId' | 'refreshUrl' | 'now'> & {
  sessionId?: string;
  refreshUrl?: string;
  session?: StoredDbscSession;
};

export type RefreshOutcome =
  /** No/invalid proof: send `response` (403 + Secure-Session-Challenge). */
  | { kind: 'challenge'; sessionId: string; response: Response; reason?: ProofFailureReason }
  /** Proof verified: re-mint the bound cookie and reply with `sessionConfigResponse`. */
  | { kind: 'verified'; session: StoredDbscSession; payload: ProofPayload }
  /** Unknown or expired session: send `response`; the browser ends the session. */
  | { kind: 'terminate'; sessionId: string | null; response: Response };

export interface Dbsc {
  registrationHeader(init?: { path?: string; authorization?: string; algorithms?: readonly Algorithm[] }): Promise<{
    name: string;
    value: string;
  }>;
  handleRegistration(
    request: Request,
    init?: { ref?: string; expectedAuthorization?: string; sessionTtlSec?: number },
  ): Promise<RegistrationResult>;
  handleRefresh(request: Request): Promise<RefreshOutcome>;
  proactiveChallengeHeader(sessionId: string): Promise<{ name: string; value: string }>;
  sessionConfigResponse(init: SessionConfigResponseInit): Response;
  /** Deletes the session and returns the `continue: false` response. */
  terminate(sessionId: string): Promise<Response>;
  observeSkipped(request: Request): ParsedSkipped | null;
  wellKnownResponse(init?: {
    registeringOrigins?: string[];
    relyingOrigins?: string[];
    providerOrigin?: string;
  }): Response;
}

const defaultWarn = (warning: DeploymentWarning): void => {
  console.warn(`dbsc-server: [${warning.code}] ${warning.message}`);
};

export function createDbsc(options: DbscOptions): Dbsc {
  const store = options.store;
  const challenger: Challenger =
    'issue' in options.challenge ? options.challenge : createHmacChallenger({ ...options.challenge, ...(options.now ? { now: options.now } : {}) });
  const registerPath = options.paths?.register ?? '/dbsc/register';
  const refreshPath = options.paths?.refresh ?? '/dbsc/refresh';
  const sessionTtlSec = options.sessionTtlSec ?? 30 * 24 * 3600;
  const headerOpts = { acceptLegacyHeaders: options.acceptLegacyHeaders !== false };
  const onWarning = options.onWarning ?? defaultWarn;
  const generateSessionId = options.generateSessionId ?? (() => crypto.randomUUID());
  const now = options.now ?? Date.now;

  const badRequest = (): Response => new Response(null, { status: 400 });

  /** The `aud` to expect for a request, or undefined when aud checking is off. */
  const expectedAudienceFor = (request: Request): string | undefined => {
    if (options.publicOrigin === undefined) return undefined;
    return new URL(new URL(request.url).pathname, options.publicOrigin).toString();
  };

  return {
    async registrationHeader(init = {}) {
      const challenge = await challenger.issue({ purpose: 'registration' });
      const algorithms = init.algorithms ?? options.algorithms;
      const value = buildRegistrationHeader({
        path: init.path ?? registerPath,
        challenge,
        ...(init.authorization !== undefined ? { authorization: init.authorization } : {}),
        ...(algorithms !== undefined ? { algorithms } : {}),
      });
      return { name: HEADERS.registration, value };
    },

    async handleRegistration(request, init = {}) {
      const proof = getProofHeader(request.headers, headerOpts);
      if (proof === null) return { ok: false, reason: 'no-proof', response: badRequest() };

      const expectedAudience = expectedAudienceFor(request);
      const result = await verifyProof(proof, {
        mode: 'registration',
        ...(options.algorithms !== undefined ? { algorithms: options.algorithms } : {}),
        verifyChallenge: (jti) => challenger.verify(jti, { purpose: 'registration' }),
        ...(expectedAudience !== undefined ? { expectedAudience } : {}),
        ...(init.expectedAuthorization !== undefined
          ? { expectedAuthorization: init.expectedAuthorization }
          : {}),
        ...(options.clockSkewSec !== undefined ? { clockSkewSec: options.clockSkewSec } : {}),
        now,
      });
      if (!result.ok) return { ok: false, reason: result.reason, response: badRequest() };

      const t = now();
      const session: StoredDbscSession = {
        id: generateSessionId(),
        publicJwk: result.jwk,
        kid: result.kid,
        createdAt: t,
        expiresAt: t + (init.sessionTtlSec ?? sessionTtlSec) * 1000,
        ...(init.ref !== undefined ? { ref: init.ref } : {}),
      };
      await store.create(session);
      return { ok: true, session, payload: result.payload };
    },

    async handleRefresh(request) {
      const sessionId = getSessionIdHeader(request.headers, headerOpts);
      if (sessionId === null) {
        // No session identified: nothing to challenge and nothing to terminate by id.
        return { kind: 'terminate', sessionId: null, response: badRequest() };
      }

      const session = await store.get(sessionId);
      if (session === null || session.expiresAt <= now()) {
        if (session !== null) await store.delete(sessionId);
        // Positively known dead: a non-403 4xx tells the browser to end the session.
        return {
          kind: 'terminate',
          sessionId,
          response: buildTerminationResponse(sessionId, { status: 400 }),
        };
      }

      const challengeResponse = async (reason?: ProofFailureReason): Promise<RefreshOutcome> => {
        const challenge = await challenger.issue({ purpose: 'refresh', sessionId });
        const response = new Response(null, {
          status: STATUS.challengeRequired,
          headers: { [HEADERS.challenge]: buildChallengeHeader({ challenge, sessionId }) },
        });
        return { kind: 'challenge', sessionId, response, ...(reason !== undefined ? { reason } : {}) };
      };

      const proof = getProofHeader(request.headers, headerOpts);
      if (proof === null) return challengeResponse();

      const expectedAudience = expectedAudienceFor(request);
      const result = await verifyProof(proof, {
        mode: 'refresh',
        storedJwk: session.publicJwk as PublicJwk,
        ...(options.algorithms !== undefined ? { algorithms: options.algorithms } : {}),
        verifyChallenge: (jti) => challenger.verify(jti, { purpose: 'refresh', sessionId }),
        ...(expectedAudience !== undefined ? { expectedAudience } : {}),
        expectedSub: sessionId,
        ...(options.clockSkewSec !== undefined ? { clockSkewSec: options.clockSkewSec } : {}),
        now,
      });
      if (!result.ok) {
        // Invalid proofs and stale challenges RE-CHALLENGE; they never terminate.
        // Unauthenticated input must not be able to kill a session.
        return challengeResponse(result.reason);
      }

      return { kind: 'verified', session, payload: result.payload };
    },

    async proactiveChallengeHeader(sessionId) {
      const challenge = await challenger.issue({ purpose: 'refresh', sessionId });
      return { name: HEADERS.challenge, value: buildChallengeHeader({ challenge, sessionId }) };
    },

    sessionConfigResponse(init) {
      const sessionExpiresAt = init.sessionExpiresAt ?? init.session?.expiresAt;
      const config: SessionConfigInit = {
        sessionId: init.sessionId ?? init.session?.id ?? '',
        refreshUrl: init.refreshUrl ?? refreshPath,
        scope: init.scope,
        credentials: init.credentials,
        ...(init.setCookies !== undefined ? { setCookies: init.setCookies } : {}),
        ...(sessionExpiresAt !== undefined ? { sessionExpiresAt } : {}),
        now: now(),
        ...(init.status !== undefined ? { status: init.status } : {}),
      };
      if (config.sessionId === '') throw new Error('sessionConfigResponse needs a session or sessionId');
      return buildSessionConfigResponse(config, onWarning);
    },

    async terminate(sessionId) {
      await store.delete(sessionId);
      return buildTerminationResponse(sessionId);
    },

    observeSkipped(request) {
      return getSkippedHeader(request.headers, headerOpts);
    },

    wellKnownResponse(init = {}) {
      const body: Record<string, unknown> = {};
      if (init.registeringOrigins !== undefined) body['registering_origins'] = init.registeringOrigins;
      if (init.relyingOrigins !== undefined) body['relying_origins'] = init.relyingOrigins;
      if (init.providerOrigin !== undefined) body['provider_origin'] = init.providerOrigin;
      return new Response(JSON.stringify(body), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    },
  };
}
