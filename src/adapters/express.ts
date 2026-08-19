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
import {
  sendWhatwgResponse,
  toWhatwgRequest,
  type NodeRequestLike,
  type NodeResponseLike,
} from '../internal/node-http.js';

export { sendWhatwgResponse, toWhatwgRequest };
export type { NodeRequestLike, NodeResponseLike };

export type ExpressDbscConfig = DbscHandlersConfig & {
  /**
   * Base origin used to build the internal Request URL. Only the path matters
   * to the protocol handlers; audience checking is governed by the core
   * `publicOrigin` option. Default: "http://localhost".
   */
  origin?: string;
};

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
