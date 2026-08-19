# Browser support

Snapshot date: 2026-08. Check the linked sources for movement; this area
changes quickly.

| Browser | Status |
|---|---|
| Chrome on Windows | Shipping and on by default (TPM-backed). Google enables it for Google accounts at scale. |
| Chrome on macOS | Rolling out gradually (Secure Enclave). Off by default during the staged rollout. |
| Chrome on Linux, ChromeOS, Android | Not yet. Manual testing works with the software-key flag; see [Chrome testing](./chrome-testing.md). |
| Microsoft Edge | Ships the same web platform capability. |
| Firefox | Mozilla has published a negative position. Do not expect support. |
| Safari | No commitment. WebKit has open questions on the design. |

Roughly 6 in 10 Windows machines expose a usable TPM. Chrome falls back to
normal cookies on machines without one. Google has announced an intent to
explore software keys for devices without secure hardware.

## Design for progressive enhancement

DBSC is an extra lock, not a gate. Follow these rules and every browser keeps
working:

1. Send `Secure-Session-Registration` to every browser after sign-in. A
   browser without DBSC ignores the header. Never require a registration to
   complete sign-in.
2. Keep your existing session security unchanged for browsers that do not
   register. A non-DBSC browser must never be worse off than before.
3. Decide your cookie lifetime per session, after you know whether the
   session is bound. A common pattern: short-lived cookies for DBSC sessions,
   your current lifetime for the rest.
4. Detection is server-side. There is no JavaScript API to test for DBSC in
   the page. You know a browser supports DBSC when its registration proof
   arrives at your endpoint.

## Sources

- Chrome status and documentation: https://developer.chrome.com/docs/web-platform/device-bound-session-credentials
- W3C draft: https://w3c.github.io/webappsec-dbsc/
- Mozilla position: https://github.com/mozilla/standards-positions/issues/912
- WebKit discussion: https://github.com/WebKit/standards-positions/issues/281
