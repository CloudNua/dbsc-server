# Express recipe

Import from `dbsc-server/express`. The adapter reads the Node request and
writes the Node response. It never imports Express itself, so it also works
with any node:http-style framework.

## Wire the endpoints

```js
import express from 'express';
import { createDbsc, createMemoryStore } from 'dbsc-server';
import { dbscExpress } from 'dbsc-server/express';

const dbsc = createDbsc({
  store: createMemoryStore(), // replace with your own store in production
  challenge: { secret: process.env.DBSC_CHALLENGE_SECRET },
});

const { register, refresh } = dbscExpress({
  dbsc,
  ref: (request) => readAppSessionId(request.headers.get('cookie')),
  bindSession: ({ session }) => ({
    scope: { includeSite: false },
    credentials: [{ name: 'session', attributes: 'Path=/; Secure; HttpOnly; SameSite=Lax' }],
    setCookies: [mintAppCookie(session.ref)], // your short-lived session cookie
  }),
});

const app = express();
app.post('/dbsc/register', register);
app.post('/dbsc/refresh', refresh);
```

## Start registration on sign-in

Add the registration header to your sign-in response:

```js
app.post('/login', async (req, res) => {
  // ... your sign-in logic sets the app session cookie ...
  const { name, value } = await dbsc.registrationHeader();
  res.setHeader(name, value);
  res.redirect('/');
});
```

## Notes

- `bindSession` runs on registration and on every refresh. Return the same
  cookie you use today, with a short `Max-Age` (minutes). The browser refreshes
  the cookie through DBSC when it expires.
- Give all server instances the same `challenge.secret`.
- Behind a proxy, set `publicOrigin` in `createDbsc` if you want strict `aud`
  checking. See the package README.
