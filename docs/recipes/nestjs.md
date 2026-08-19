# NestJS recipe

Import from `dbsc-server/nestjs`. On the default Express platform, NestJS hands
your controller the Node request and response, and the adapter works with those
directly. Use `@Req()` and `@Res()` so the handler controls the full response.

## Controller

```ts
import { Controller, Post, Req, Res } from '@nestjs/common';
import type { Request, Response } from 'express';
import { createDbsc } from 'dbsc-server';
import { dbscNest } from 'dbsc-server/nestjs';
import { myStore } from './dbsc.store';

const dbsc = createDbsc({
  store: myStore,
  challenge: { secret: process.env.DBSC_CHALLENGE_SECRET! },
});

const handlers = dbscNest({
  dbsc,
  ref: (request) => readAppSessionId(request.headers.get('cookie')),
  bindSession: ({ session }) => ({
    scope: { includeSite: false },
    credentials: [{ name: 'session', attributes: 'Path=/; Secure; HttpOnly; SameSite=Lax' }],
    setCookies: [mintAppCookie(session.ref)],
  }),
});

@Controller('dbsc')
export class DbscController {
  @Post('register')
  register(@Req() req: Request, @Res() res: Response): Promise<void> {
    return handlers.register(req, res);
  }

  @Post('refresh')
  refresh(@Req() req: Request, @Res() res: Response): Promise<void> {
    return handlers.refresh(req, res);
  }
}
```

For dependency injection, wrap `dbsc` and `handlers` in a provider instead of
module-level constants. The adapter has no opinion on that.

## Start registration on sign-in

```ts
@Post('login')
async login(@Res({ passthrough: true }) res: Response) {
  // ... your sign-in logic sets the app session cookie ...
  const { name, value } = await dbsc.registrationHeader();
  res.setHeader(name, value);
  return { ok: true };
}
```

## Notes

- Guards and interceptors that require a fresh session cookie must exclude the
  two DBSC endpoints. The refresh endpoint runs exactly when the cookie is
  expired.
- On the Fastify platform, use `dbsc-server/fastify` in the controller with the
  platform request and reply objects instead.
