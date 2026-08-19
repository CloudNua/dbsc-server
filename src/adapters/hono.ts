/**
 * dbsc-server/hono — Hono adapter.
 *
 * Hono is WHATWG-native, so the shim is a raw-request unwrap. Typed
 * structurally: this module never imports Hono.
 *
 *   const { register, refresh } = dbscHono({ dbsc, bindSession });
 *   app.post('/dbsc/register', register);
 *   app.post('/dbsc/refresh', refresh);
 */

import { createDbscHandlers, type DbscHandlersConfig } from '../handlers.js';

/** The part of a Hono context this adapter reads. */
export interface HonoContextLike {
  req: { raw: Request };
}

export interface HonoDbscHandlers {
  register(c: HonoContextLike): Promise<Response>;
  refresh(c: HonoContextLike): Promise<Response>;
}

export function dbscHono(config: DbscHandlersConfig): HonoDbscHandlers {
  const handlers = createDbscHandlers(config);
  return {
    register: (c) => handlers.register(c.req.raw),
    refresh: (c) => handlers.refresh(c.req.raw),
  };
}
