/**
 * Framework-agnostic endpoint handlers: WHATWG Request in, Response out.
 *
 * `createDbscHandlers` turns a `Dbsc` instance plus your cookie-binding logic
 * into two plain functions — `register` and `refresh` — that every adapter
 * (Express, Hono, Next, Elysia) simply routes to. Your app supplies ONE
 * callback, `bindSession`, which says what cookie to mint and what scope to
 * bind. Everything else is protocol.
 */

import type { Dbsc } from './flows.js';
import type { CookieCredential, SessionScopeInit } from './session-config.js';
import type { StoredDbscSession } from './store.js';

export interface SessionBinding {
  scope: SessionScopeInit;
  credentials: CookieCredential[];
  /** The Set-Cookie header values that (re)mint the bound cookie(s). */
  setCookies?: string[];
  refreshUrl?: string;
}

export interface DbscHandlersConfig {
  dbsc: Dbsc;
  /**
   * Called after a proof verifies, on registration and on every refresh.
   * Return the cookie(s) to mint and the scope to declare. Runs with the
   * verified session; use `session.ref` to reach your own session state.
   */
  bindSession: (ctx: {
    session: StoredDbscSession;
    request: Request;
    phase: 'register' | 'refresh';
  }) => SessionBinding | Promise<SessionBinding>;
  /**
   * Resolves your application reference (for example the app session id from a
   * cookie) at registration time. Stored on the session as `ref`.
   */
  ref?: (request: Request) => string | undefined | Promise<string | undefined>;
  /** Expected `authorization` echo for registrations, when you sent one. */
  expectedAuthorization?: (request: Request) => string | undefined;
}

export interface DbscHandlers {
  /** POST handler for the registration endpoint. */
  register(request: Request): Promise<Response>;
  /** POST handler for the refresh endpoint. */
  refresh(request: Request): Promise<Response>;
}

export function createDbscHandlers(config: DbscHandlersConfig): DbscHandlers {
  const { dbsc } = config;

  const configResponse = async (
    session: StoredDbscSession,
    request: Request,
    phase: 'register' | 'refresh',
  ): Promise<Response> => {
    const binding = await config.bindSession({ session, request, phase });
    return dbsc.sessionConfigResponse({
      session,
      scope: binding.scope,
      credentials: binding.credentials,
      ...(binding.setCookies !== undefined ? { setCookies: binding.setCookies } : {}),
      ...(binding.refreshUrl !== undefined ? { refreshUrl: binding.refreshUrl } : {}),
    });
  };

  return {
    async register(request) {
      const ref = await config.ref?.(request);
      const expectedAuthorization = config.expectedAuthorization?.(request);
      const result = await dbsc.handleRegistration(request, {
        ...(ref !== undefined ? { ref } : {}),
        ...(expectedAuthorization !== undefined ? { expectedAuthorization } : {}),
      });
      if (!result.ok) return result.response;
      return configResponse(result.session, request, 'register');
    },

    async refresh(request) {
      const outcome = await dbsc.handleRefresh(request);
      if (outcome.kind !== 'verified') return outcome.response;
      return configResponse(outcome.session, request, 'refresh');
    },
  };
}
