/**
 * dbsc-server/next — Next.js App Router route-handler adapter.
 *
 * Next route handlers already receive a WHATWG Request (NextRequest extends
 * Request) and return a Response, so the handlers pass through directly.
 *
 *   // app/dbsc/register/route.ts
 *   export const POST = dbscNext({ dbsc, bindSession }).register;
 *
 *   // app/dbsc/refresh/route.ts
 *   export const POST = dbscNext({ dbsc, bindSession }).refresh;
 *
 * Build ONE shared config module and import it from both route files, so both
 * endpoints use the same `Dbsc` instance and store.
 */

import { createDbscHandlers, type DbscHandlers, type DbscHandlersConfig } from '../handlers.js';

export function dbscNext(config: DbscHandlersConfig): DbscHandlers {
  return createDbscHandlers(config);
}
