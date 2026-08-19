# Test with real Chrome

> Last validated: 2026-08-19, Chrome on Linux with software keys. Registration
> and repeated silent refresh both worked against the demo server.

You do not need a TPM to test DBSC. Chrome can use software keys for manual
testing. This page shows how to run the demo against a real Chrome.

## 1. Set the Chrome flags

Open `chrome://flags` and set these three flags. Then restart Chrome.

| Flag | Value | Why |
|---|---|---|
| `#enable-standard-device-bound-session-credentials` | **Enabled - For developers** | Turns DBSC on. The developer mode also skips refresh quotas and origin-trial checks, and it allows plain HTTP on localhost. |
| `#enable-standard-device-bound-session-persistence` | Enabled | Keeps sessions across restarts. |
| `#enable-bound-session-credentials-software-keys-for-manual-testing` | Enabled | Uses software keys instead of the TPM. Required on macOS and Linux. Software keys sign ES256 only. |

## 2. Run the demo

```sh
npm run build
node demo/server.mjs
```

Open `http://localhost:8080` and click **sign in**.

## 3. What you can observe

1. The sign-in response carries `Secure-Session-Registration`. Chrome generates
   a key and POSTs a proof to `/dbsc/register`. The server log prints the new
   session id.
2. Open `/protected`. The cookie is fresh for 30 seconds.
3. Wait 30 seconds and reload `/protected`. Chrome defers the request, runs the
   403 challenge dance at `/dbsc/refresh`, gets a new cookie, and then sends
   your request. You stay signed in without any code in the page. The server
   log prints the refresh.

## 4. Debugging

Chrome has no DevTools panel for DBSC yet. Use these instead:

- `chrome://net-export`: record a network log, then load it in
  `https://netlog-viewer.appspot.com`. Search for `device_bound` events.
- `chrome://histograms/#Net.DeviceBoundSessions`: counters for registration,
  refresh, and errors.
- The demo server log: it prints registration, refresh, and skip events.

## 5. Known behavior notes

- Chrome sends minimal proof payloads: expect `jti` and little else. Do not
  require `aud`, `sub`, or `iat` in a proof.
- Chrome is not fully spec-compliant yet. When Chrome and the W3C draft
  disagree, validate against what Chrome actually sends and file the
  difference upstream.
- A `Secure-Session-Skipped` header on a normal request means the browser could
  not refresh (quota, TPM pressure, or repeated errors) and sent the request
  anyway. Serve it like a normal expired-cookie request.
