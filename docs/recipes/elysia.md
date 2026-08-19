# Elysia recipe

Import from `dbsc-server/elysia`. Use the plugin form to mount both endpoints,
or the handler form to route them yourself.

## Plugin form

```ts
import { Elysia } from 'elysia';
import { createDbsc, createMemoryStore } from 'dbsc-server';
import { dbscElysia } from 'dbsc-server/elysia';

const dbsc = createDbsc({
  store: createMemoryStore(), // replace with your own store in production
  challenge: { secret: process.env.DBSC_CHALLENGE_SECRET! },
});

const app = new Elysia()
  .use(
    dbscElysia({
      dbsc,
      paths: { register: '/dbsc/register', refresh: '/dbsc/refresh' },
      ref: (request) => readAppSessionId(request.headers.get('cookie')),
      bindSession: ({ session }) => ({
        scope: { includeSite: false },
        credentials: [{ name: 'session', attributes: 'Path=/; Secure; HttpOnly; SameSite=Lax' }],
        setCookies: [mintAppCookie(session.ref)],
      }),
    }),
  )
  .listen(3000);
```

## Handler form

```ts
import { dbscElysiaHandlers } from 'dbsc-server/elysia';

const { register, refresh } = dbscElysiaHandlers({ dbsc, ref, bindSession });
app.post('/dbsc/register', register).post('/dbsc/refresh', refresh);
```

## Start registration on sign-in

```ts
app.post('/login', async ({ set }) => {
  // ... your sign-in logic sets the app session cookie ...
  const { name, value } = await dbsc.registrationHeader();
  set.headers[name] = value;
  return { ok: true };
});
```

## Notes

- The core uses Web Crypto only, so it runs the same under Bun and Node.
- `bindSession` runs on registration and on every refresh. Keep the bound
  cookie short-lived (minutes); DBSC refreshes it silently.
