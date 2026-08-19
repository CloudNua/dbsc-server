/**
 * dbsc-server/elysia — Elysia adapter (Bun-first, works anywhere Elysia runs).
 *
 * Typed structurally: this module never imports Elysia. The plugin form mounts
 * both endpoints; the handler form gives you the functions to route yourself.
 *
 *   // plugin form
 *   app.use(dbscElysia({ dbsc, bindSession, paths: { register: '/dbsc/register', refresh: '/dbsc/refresh' } }));
 *
 *   // handler form
 *   const { register, refresh } = dbscElysiaHandlers({ dbsc, bindSession });
 *   app.post('/dbsc/register', register).post('/dbsc/refresh', refresh);
 */

import { createDbscHandlers, type DbscHandlersConfig } from '../handlers.js';

/** The part of an Elysia handler context this adapter reads. */
export interface ElysiaContextLike {
  request: Request;
}

/** The part of an Elysia app the plugin form uses. */
export interface ElysiaAppLike {
  post(path: string, handler: (ctx: ElysiaContextLike) => Promise<Response>): unknown;
}

export interface ElysiaDbscHandlers {
  register(ctx: ElysiaContextLike): Promise<Response>;
  refresh(ctx: ElysiaContextLike): Promise<Response>;
}

export function dbscElysiaHandlers(config: DbscHandlersConfig): ElysiaDbscHandlers {
  const handlers = createDbscHandlers(config);
  return {
    register: (ctx) => handlers.register(ctx.request),
    refresh: (ctx) => handlers.refresh(ctx.request),
  };
}

export type ElysiaDbscConfig = DbscHandlersConfig & {
  paths?: { register?: string; refresh?: string };
};

export function dbscElysia(config: ElysiaDbscConfig): <App extends ElysiaAppLike>(app: App) => App {
  const handlers = dbscElysiaHandlers(config);
  const registerPath = config.paths?.register ?? '/dbsc/register';
  const refreshPath = config.paths?.refresh ?? '/dbsc/refresh';
  return (app) => {
    app.post(registerPath, handlers.register);
    app.post(refreshPath, handlers.refresh);
    return app;
  };
}
