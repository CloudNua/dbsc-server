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

  // Express 4 does not catch rejected async handlers, and an unhandled
  // rejection ends the Node process by default. A store outage or a malformed
  // URL must become a 500 (retryable for the browser), never a crash.
  const safely =
    (handle: (request: Request) => Promise<Response>) =>
    async (req: NodeRequestLike, res: NodeResponseLike): Promise<void> => {
      try {
        await sendWhatwgResponse(res, await handle(toWhatwgRequest(req, origin)));
      } catch {
        try {
          res.statusCode = 500;
          res.end();
        } catch {
          // The response is already committed or the socket is gone.
        }
      }
    };

  return {
    register: safely(handlers.register),
    refresh: safely(handlers.refresh),
  };
}
