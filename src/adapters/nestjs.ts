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

export function dbscNest(config: NestDbscConfig): NestDbscHandlers {
  return dbscExpress(config);
}
