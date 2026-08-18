# dbsc-server

A server-side toolkit for Device Bound Session Credentials (DBSC).

> **Status: in development.** This package is not ready for use. Do not install it yet.

## What DBSC does

DBSC is a web standard from the W3C WebAppSec working group. The browser creates a
private key in secure hardware on the device. The key cannot leave the device. The
browser signs a server challenge with this key at short intervals. The server checks the
signature and issues a fresh, short-lived session cookie.

If an attacker steals the cookie, the cookie expires in minutes. The attacker cannot
refresh it on a different device, because the attacker does not have the device key.
This defeats session theft by infostealer malware.

## What this package does

`dbsc-server` implements the server side of the DBSC protocol:

- It builds and parses the DBSC protocol headers.
- It issues and validates registration and refresh challenges.
- It validates the signed proofs from the browser.
- It tells your application when to issue a new session cookie.

You keep control of your sessions and your cookies. The package has no runtime
dependencies. It runs on Node.js, Bun, and Deno.

## Install

Not published yet.

## Documentation

Not written yet. See [SECURITY.md](./SECURITY.md) for the security policy and
[CONTRIBUTING.md](./CONTRIBUTING.md) for the contribution policy.

## License

[MIT](./LICENSE)
