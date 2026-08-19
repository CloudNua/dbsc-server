# Auth.js recipe

Auth.js mints its own session cookie, and your server can mint it again. That
is the one property DBSC needs, so Auth.js pairs well with this package. This
recipe uses Auth.js v5 on Next.js with the database session strategy.

## The idea

1. Keep Auth.js exactly as it is. Its cookie value stays the session token.
2. Bind that cookie with DBSC and re-set it with a SHORT `Max-Age`. The
   browser then refreshes it through DBSC every few minutes.
3. Your Auth.js session lifetime stays long on the server side. Only the
   cookie in the browser becomes short-lived.

## Endpoints

```ts
// lib/dbsc.ts
import { createDbsc } from 'dbsc-server';
import { dbscNext } from 'dbsc-server/next';
import { myStore } from './dbsc-store'; // see the storage recipes

const SESSION_COOKIE = '__Secure-authjs.session-token';

function readSessionToken(cookieHeader: string | null): string | undefined {
  return cookieHeader
    ?.split(';')
    .map((c) => c.trim())
    .find((c) => c.startsWith(`${SESSION_COOKIE}=`))
    ?.split('=')[1];
}

export const dbsc = createDbsc({
  store: myStore,
  challenge: { secret: process.env.DBSC_CHALLENGE_SECRET! },
});

export const dbscHandlers = dbscNext({
  dbsc,
  ref: (request) => readSessionToken(request.headers.get('cookie')),
  bindSession: ({ session }) => ({
    scope: { includeSite: false },
    credentials: [{ name: SESSION_COOKIE, attributes: 'Path=/; Secure; HttpOnly; SameSite=Lax' }],
    setCookies: [
      `${SESSION_COOKIE}=${session.ref}; Max-Age=600; Path=/; Secure; HttpOnly; SameSite=Lax`,
    ],
  }),
});
```

Route the handlers as in the [Next.js recipe](./next.md).

## Start registration after sign-in

Add the header to the first authenticated response. Middleware is a simple
place for it:

```ts
// middleware.ts (add to your existing middleware)
import { dbsc } from '@/lib/dbsc';

if (sessionCookieIsPresent && !dbscAlreadyRegistered) {
  const { name, value } = await dbsc.registrationHeader();
  response.headers.set(name, value);
}
```

Track `dbscAlreadyRegistered` however you like; a small marker cookie set by
`bindSession` works. Sending the header again is safe; browsers that already
registered ignore it.

## Sign-out

When the Auth.js session ends, delete the DBSC session too:

```ts
await dbsc.terminate(dbscSessionId);
```

## Notes

- Exclude `/dbsc/register` and `/dbsc/refresh` from middleware that requires a
  fresh session cookie. The refresh endpoint runs exactly when the cookie is
  expired.
- With the JWT session strategy this pattern still works: the cookie value is
  the JWE, and you re-set the same value with a short `Max-Age`. Keep the JWT
  `maxAge` longer than the cookie `Max-Age`.
- Auth.js rotates the session token in some flows. When the token changes, the
  stored `ref` goes stale and the next refresh re-mints an old cookie. Update
  the DBSC session `ref` on rotation, or key `ref` to your user id and look up
  the current token in `bindSession`.
