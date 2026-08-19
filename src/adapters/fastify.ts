/**
 * dbsc-server/fastify — Fastify adapter.
 *
 * Typed structurally: this module never imports Fastify. Handlers take the
 * Fastify request and reply objects directly.
 *
 *   const { register, refresh } = dbscFastify({ dbsc, bindSession });
 *   app.post('/dbsc/register', register);
 *   app.post('/dbsc/refresh', refresh);
 */

import { createDbscHandlers, type DbscHandlersConfig } from '../handlers.js';
import { toWhatwgRequest, type NodeRequestLike } from '../internal/node-http.js';

/** The parts of a Fastify request this adapter reads. */
export type FastifyRequestLike = NodeRequestLike;

/** The parts of a Fastify reply this adapter writes. */
export interface FastifyReplyLike {
  code(statusCode: number): unknown;
  header(name: string, value: string | string[]): unknown;
  send(payload?: unknown): unknown;
}

export type FastifyDbscConfig = DbscHandlersConfig & {
  /** Base origin for the internal Request URL. Default: "http://localhost". */
  origin?: string;
};

export interface FastifyDbscHandlers {
  register(request: FastifyRequestLike, reply: FastifyReplyLike): Promise<void>;
  refresh(request: FastifyRequestLike, reply: FastifyReplyLike): Promise<void>;
}

async function sendReply(reply: FastifyReplyLike, response: Response): Promise<void> {
  for (const [name, value] of response.headers) {
    if (name !== 'set-cookie') reply.header(name, value);
  }
  const cookies = response.headers.getSetCookie();
  if (cookies.length > 0) reply.header('set-cookie', cookies);
  reply.code(response.status);
  const body = new Uint8Array(await response.arrayBuffer());
  reply.send(body.length > 0 ? body : undefined);
}

export function dbscFastify(config: FastifyDbscConfig): FastifyDbscHandlers {
  const handlers = createDbscHandlers(config);
  const origin = config.origin ?? 'http://localhost';
  return {
    register: async (request, reply) => sendReply(reply, await handlers.register(toWhatwgRequest(request, origin))),
    refresh: async (request, reply) => sendReply(reply, await handlers.refresh(toWhatwgRequest(request, origin))),
  };
}
