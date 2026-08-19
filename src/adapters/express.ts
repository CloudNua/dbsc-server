/**
 * dbsc-server/express — Express (and any node:http-style framework) adapter.
 *
 * Typed structurally: this module never imports Express. It converts the Node
 * request to a WHATWG Request (headers, method, URL — DBSC reads no bodies) and
 * writes the WHATWG Response back.
 *
 *   const { register, refresh } = dbscExpress({ dbsc, bindSession });
 *   app.post('/dbsc/register', register);
 *   app.post('/dbsc/refresh', refresh);
 */

import { createDbscHandlers, type DbscHandlersConfig } from '../handlers.js';

/** The parts of an Express/node:http request this adapter reads. */
export interface NodeRequestLike {
  method?: string;
  url?: string;
  headers: Record<string, string | string[] | undefined>;
}

/** The parts of an Express/node:http response this adapter writes. */
export interface NodeResponseLike {
  statusCode: number;
  setHeader(name: string, value: string | string[]): unknown;
  end(chunk?: unknown): unknown;
}

export type ExpressDbscConfig = DbscHandlersConfig & {
  /**
   * Base origin used to build the internal Request URL. Only the path matters
   * to the protocol handlers; audience checking is governed by the core
   * `publicOrigin` option. Default: "http://localhost".
   */
  origin?: string;
};

export function toWhatwgRequest(req: NodeRequestLike, origin = 'http://localhost'): Request {
  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) {
    if (typeof value === 'string') headers.set(name, value);
    else if (Array.isArray(value)) for (const v of value) headers.append(name, v);
  }
  return new Request(new URL(req.url ?? '/', origin), { method: req.method ?? 'GET', headers });
}

export async function sendWhatwgResponse(res: NodeResponseLike, response: Response): Promise<void> {
  for (const [name, value] of response.headers) {
    if (name !== 'set-cookie') res.setHeader(name, value);
  }
  const cookies = response.headers.getSetCookie();
  if (cookies.length > 0) res.setHeader('set-cookie', cookies);
  res.statusCode = response.status;
  const body = new Uint8Array(await response.arrayBuffer());
  res.end(body.length > 0 ? body : undefined);
}

export interface ExpressDbscHandlers {
  register(req: NodeRequestLike, res: NodeResponseLike): Promise<void>;
  refresh(req: NodeRequestLike, res: NodeResponseLike): Promise<void>;
}

export function dbscExpress(config: ExpressDbscConfig): ExpressDbscHandlers {
  const handlers = createDbscHandlers(config);
  const origin = config.origin ?? 'http://localhost';
  return {
    register: async (req, res) => sendWhatwgResponse(res, await handlers.register(toWhatwgRequest(req, origin))),
    refresh: async (req, res) => sendWhatwgResponse(res, await handlers.refresh(toWhatwgRequest(req, origin))),
  };
}
