/**
 * dbsc-server/nestjs — NestJS adapter (Express platform).
 *
 * Typed structurally: this module never imports NestJS. NestJS on the default
 * Express platform hands controllers the Node request and response, so the
 * handlers take those directly. Use passthrough response injection and call
 * the handler; it writes the full response.
 *
 *   @Controller('dbsc')
 *   export class DbscController {
 *     private readonly handlers = dbscNest({ dbsc, bindSession });
 *
 *     @Post('register')
 *     register(@Req() req: Request, @Res() res: Response) {
 *       return this.handlers.register(req, res);
 *     }
 *
 *     @Post('refresh')
 *     refresh(@Req() req: Request, @Res() res: Response) {
 *       return this.handlers.refresh(req, res);
 *     }
 *   }
 *
 * On the Fastify platform, use `dbsc-server/fastify` with `request.raw`
 * equivalents instead; see the recipe.
 */

import type { DbscHandlersConfig } from '../handlers.js';
import { dbscExpress, type ExpressDbscHandlers } from './express.js';

export type NestDbscConfig = DbscHandlersConfig & {
  /** Base origin for the internal Request URL. Default: "http://localhost". */
  origin?: string;
};

export type NestDbscHandlers = ExpressDbscHandlers;

/**
 * EXPRESS PLATFORM ONLY. On the Fastify platform, use `dbsc-server/fastify`
 * inside your controller instead. The handlers verify the response object at
 * runtime and fail with a clear error rather than misbehave on the wrong
 * platform.
 */
export function dbscNest(config: NestDbscConfig): NestDbscHandlers {
  const handlers = dbscExpress(config);
  const guard = (res: unknown): void => {
    const shaped = res as { setHeader?: unknown; end?: unknown };
    if (typeof shaped.setHeader !== 'function' || typeof shaped.end !== 'function') {
      throw new Error(
        'dbsc-server/nestjs supports the NestJS Express platform only. ' +
          'On the Fastify platform, use dbsc-server/fastify in your controller.',
      );
    }
  };
  return {
    register: (req, res) => {
      guard(res);
      return handlers.register(req, res);
    },
    refresh: (req, res) => {
      guard(res);
      return handlers.refresh(req, res);
    },
  };
}
