# Next.js recipe (App Router)

Import from `dbsc-server/next`. Route handlers already use WHATWG Request and
Response, so the handlers plug in directly.

## Shared configuration

Create one module so both route files share the same `Dbsc` instance:

```ts
// lib/dbsc.ts
import { createDbsc } from 'dbsc-server';
import { dbscNext } from 'dbsc-server/next';
import { myStore } from './dbsc-store'; // your DbscSessionStore implementation

export const dbsc = createDbsc({
  store: myStore,
  challenge: { secret: process.env.DBSC_CHALLENGE_SECRET! },
});

export const dbscHandlers = dbscNext({
  dbsc,
  ref: (request) => readAppSessionId(request.headers.get('cookie')),
  bindSession: ({ session }) => ({
    scope: { includeSite: false },
    credentials: [{ name: 'session', attributes: 'Path=/; Secure; HttpOnly; SameSite=Lax' }],
    setCookies: [mintAppCookie(session.ref)],
  }),
});
```

## Route files

```ts
// app/dbsc/register/route.ts
import { dbscHandlers } from '@/lib/dbsc';
export const POST = dbscHandlers.register;
```

```ts
// app/dbsc/refresh/route.ts
import { dbscHandlers } from '@/lib/dbsc';
export const POST = dbscHandlers.refresh;
```

## Start registration on sign-in

In the route or server action that completes sign-in:

```ts
import { dbsc } from '@/lib/dbsc';

const { name, value } = await dbsc.registrationHeader();
response.headers.set(name, value);
```

## Notes

- Session stores must be external (your database). Route handlers can run on
  more than one instance; an in-memory store does not work there.
- With middleware that gates `/api` or cookies, exclude the two DBSC endpoints
  from any check that requires a fresh cookie: the refresh endpoint is exactly
  where the browser goes when the cookie is expired.
