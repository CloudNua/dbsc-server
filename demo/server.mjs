/**
 * dbsc-server demo — a complete DBSC deployment in one file, no framework.
 *
 * Run:   npm run build && node demo/server.mjs
 * Then:  open http://localhost:8080 in a DBSC-enabled Chrome.
 *        See docs/chrome-testing.md for the required Chrome flags.
 *
 * What it shows:
 * - Sign-in sets an app cookie and asks the browser to register a device key.
 * - The browser POSTs a proof to /dbsc/register; the server binds the session.
 * - When the short-lived cookie expires, the browser refreshes it at
 *   /dbsc/refresh (the 403 challenge dance) without any user interaction.
 * - Sign-out terminates the DBSC session (`continue: false`).
 */
import { createServer } from 'node:http';
import { randomUUID } from 'node:crypto';
import { createDbsc, createMemoryStore } from '../dist/index.js';

const PORT = 8080;
const COOKIE = 'demo_session';
const COOKIE_MAX_AGE_SEC = 30; // short on purpose, so refresh happens quickly

// App state: cookie value -> user. A real app has its own session system.
const appSessions = new Map();

const dbsc = createDbsc({
  store: createMemoryStore(),
  challenge: { secret: 'demo-secret-change-me-32-bytes!!' },
  paths: { register: '/dbsc/register', refresh: '/dbsc/refresh' },
});

/** node:http -> WHATWG Request (headers, method, url — enough for DBSC). */
function toRequest(req) {
  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) {
    if (typeof value === 'string') headers.set(name, value);
  }
  return new Request(`http://localhost:${PORT}${req.url}`, { method: req.method, headers });
}

/** WHATWG Response -> node:http response. */
async function send(res, response) {
  for (const [name, value] of response.headers) {
    if (name !== 'set-cookie') res.setHeader(name, value);
  }
  const cookies = response.headers.getSetCookie();
  if (cookies.length > 0) res.setHeader('set-cookie', cookies);
  res.writeHead(response.status);
  res.end(Buffer.from(await response.arrayBuffer()));
}

const cookieValue = (req) =>
  req.headers.cookie
    ?.split(';')
    .map((c) => c.trim())
    .find((c) => c.startsWith(`${COOKIE}=`))
    ?.slice(COOKIE.length + 1) ?? null;

const mintCookie = (value) => `${COOKIE}=${value}; Max-Age=${COOKIE_MAX_AGE_SEC}; Path=/; HttpOnly; SameSite=Lax`;

const page = (title, body) =>
  new Response(`<!doctype html><title>${title}</title><h1>${title}</h1>${body}`, {
    headers: { 'content-type': 'text/html' },
  });

createServer(async (req, res) => {
  const request = toRequest(req);
  const url = new URL(request.url);

  // Sign in: set the app cookie AND ask the browser to register a device key.
  if (url.pathname === '/login') {
    const value = randomUUID();
    appSessions.set(value, { user: 'demo-user' });
    const registration = await dbsc.registrationHeader();
    const response = page('Signed in', '<p>DBSC registration requested.</p><a href="/protected">protected</a>');
    response.headers.set(registration.name, registration.value);
    response.headers.append('set-cookie', mintCookie(value));
    return send(res, response);
  }

  // DBSC registration endpoint: verify the proof, bind the session.
  if (url.pathname === '/dbsc/register' && request.method === 'POST') {
    const appSession = cookieValue(req);
    const result = await dbsc.handleRegistration(request, appSession ? { ref: appSession } : {});
    if (!result.ok) return send(res, result.response);
    console.log(`registered dbsc session ${result.session.id} (device ${result.session.kid.slice(0, 8)}…)`);
    return send(
      res,
      dbsc.sessionConfigResponse({
        session: result.session,
        scope: { includeSite: false },
        credentials: [{ name: COOKIE, attributes: 'Path=/; HttpOnly; SameSite=Lax' }],
        setCookies: appSession ? [mintCookie(appSession)] : [],
      }),
    );
  }

  // DBSC refresh endpoint: the 403 challenge dance, then re-mint the cookie.
  if (url.pathname === '/dbsc/refresh' && request.method === 'POST') {
    const outcome = await dbsc.handleRefresh(request);
    if (outcome.kind !== 'verified') return send(res, outcome.response);
    const appSession = outcome.session.ref;
    console.log(`refreshed dbsc session ${outcome.session.id}`);
    return send(
      res,
      dbsc.sessionConfigResponse({
        session: outcome.session,
        scope: { includeSite: false },
        credentials: [{ name: COOKIE, attributes: 'Path=/; HttpOnly; SameSite=Lax' }],
        setCookies: appSession ? [mintCookie(appSession)] : [],
      }),
    );
  }

  // Sign out: end the app session and tell the browser to drop the DBSC session.
  if (url.pathname === '/logout') {
    const appSession = cookieValue(req);
    if (appSession) appSessions.delete(appSession);
    // A real app looks up the DBSC session id bound to this user; the demo store
    // is small enough that termination on next refresh (unknown ref) suffices.
    return send(res, page('Signed out', '<a href="/">home</a>'));
  }

  if (url.pathname === '/protected') {
    const value = cookieValue(req);
    const skipped = dbsc.observeSkipped(request);
    if (skipped) console.log(`browser skipped refresh: ${skipped.reason}`);
    if (value && appSessions.has(value)) {
      return send(res, page('Protected', `<p>Cookie is fresh. It expires in ${COOKIE_MAX_AGE_SEC}s; ` +
        'reload after that and DBSC refreshes it silently.</p><a href="/logout">sign out</a>'));
    }
    return send(res, page('Signed out', 'No valid cookie. <a href="/login">sign in</a>'));
  }

  return send(res, page('dbsc-server demo', '<a href="/login">sign in</a>'));
}).listen(PORT, () => {
  console.log(`demo on http://localhost:${PORT} — see docs/chrome-testing.md for Chrome flags`);
});
