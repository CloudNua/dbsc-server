# Hono recipe

Import from `dbsc-server/hono`. Hono is WHATWG-native, so the adapter is a
direct pass-through of the raw request.

## Wire the endpoints

```ts
import { Hono } from 'hono';
import { createDbsc, createMemoryStore } from 'dbsc-server';
import { dbscHono } from 'dbsc-server/hono';

const dbsc = createDbsc({
  store: createMemoryStore(), // replace with your own store in production
  challenge: { secret: process.env.DBSC_CHALLENGE_SECRET! },
});

const { register, refresh } = dbscHono({
  dbsc,
  ref: (request) => readAppSessionId(request.headers.get('cookie')),
  bindSession: ({ session }) => ({
    scope: { includeSite: false },
    credentials: [{ name: 'session', attributes: 'Path=/; Secure; HttpOnly; SameSite=Lax' }],
    setCookies: [mintAppCookie(session.ref)],
  }),
});

const app = new Hono();
app.post('/dbsc/register', (c) => register(c));
app.post('/dbsc/refresh', (c) => refresh(c));
```

## Start registration on sign-in

```ts
app.post('/login', async (c) => {
  // ... your sign-in logic sets the app session cookie ...
  const { name, value } = await dbsc.registrationHeader();
  c.header(name, value);
  return c.redirect('/');
});
```

## Notes

- `bindSession` runs on registration and on every refresh. Keep the bound
  cookie short-lived (minutes); DBSC refreshes it silently.
- The adapter also works on Cloudflare Workers and Deno, because the core uses
  only Web Crypto and WHATWG types.
