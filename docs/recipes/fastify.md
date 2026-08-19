# Fastify recipe

Import from `dbsc-server/fastify`. The adapter reads the Fastify request and
writes the reply. It never imports Fastify itself.

## Wire the endpoints

```js
import Fastify from 'fastify';
import { createDbsc, createMemoryStore } from 'dbsc-server';
import { dbscFastify } from 'dbsc-server/fastify';

const dbsc = createDbsc({
  store: createMemoryStore(), // replace with your own store in production
  challenge: { secret: process.env.DBSC_CHALLENGE_SECRET },
});

const { register, refresh } = dbscFastify({
  dbsc,
  ref: (request) => readAppSessionId(request.headers.get('cookie')),
  bindSession: ({ session }) => ({
    scope: { includeSite: false },
    credentials: [{ name: 'session', attributes: 'Path=/; Secure; HttpOnly; SameSite=Lax' }],
    setCookies: [mintAppCookie(session.ref)],
  }),
});

const app = Fastify();
app.post('/dbsc/register', register);
app.post('/dbsc/refresh', refresh);
```

## Start registration on sign-in

```js
app.post('/login', async (request, reply) => {
  // ... your sign-in logic sets the app session cookie ...
  const { name, value } = await dbsc.registrationHeader();
  reply.header(name, value);
  return reply.redirect('/');
});
```

## Notes

- `bindSession` runs on registration and on every refresh. Keep the bound
  cookie short-lived (minutes); DBSC refreshes it silently.
- The handlers send the reply themselves. Do not return a payload from the
  route on top of them.
