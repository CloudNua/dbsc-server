# Security model

This page states what DBSC protects, what it does not protect, and the
security decisions inside this package. Read it before you deploy.

## What DBSC gives you

DBSC binds a session cookie to a device key that lives in secure hardware.
The key cannot leave the device. The result:

- A stolen cookie expires in minutes and cannot be refreshed from another
  device. This defeats the common infostealer attack: steal the browser
  profile, replay the session elsewhere.
- The protection covers the whole session, with no user interaction and no
  page JavaScript.

## What DBSC does not give you

- **A compromised device stays compromised.** Malware that is present at
  sign-in can bind the session to a key the attacker controls, or drive the
  real browser directly. DBSC raises the cost of exfiltration; it does not
  clean the endpoint.
- **XSS still acts in place.** Script running on your origin can call your API
  with the fresh cookie. DBSC stops cookie exfiltration, not in-page abuse.
  Keep your content security policy strict.
- **Only Chromium browsers today.** Treat DBSC as progressive enhancement.
  See [browser support](./browser-support.md). A browser without DBSC keeps
  your current cookie security, never less.

## Decisions in this package

| Decision | Reason |
|---|---|
| Refresh proofs verify against the STORED key only. A refresh proof that carries its own key is rejected. | Accepting a key from the request would let any attacker substitute their own key. |
| Invalid proofs get a new challenge (403). They never terminate the session. | Anyone can POST garbage with a guessed session id. Unauthenticated input must not be able to kill a session. Termination responses go only to sessions the server positively knows are unknown or expired. |
| The signature is verified before the challenge is consumed. | Garbage proofs must not burn single-use challenges. |
| The key type pins the algorithm. ES256 signatures must be exactly 64 bytes. RSA keys need an odd exponent of at least 3 and a modulus of at least 2048 bits. | This closes algorithm-confusion and degenerate-key attacks. |
| Registration keys are reduced to their public members before storage and before the RFC 7638 thumbprint. | A smuggled private member or extra member must not change the stored key or the device identity. |
| `aud`, `sub`, and `iat` are validated only when the proof carries them. | Shipping Chrome sends minimal proofs. Requiring optional claims would reject real browsers. Set `publicOrigin` to enforce `aud` when your deployment allows it. |
| Malformed input never throws. A bad proof is a failed verification with a reason for your logs. | Attacker input must not become an exception path. Do not echo failure reasons to clients. |
| Challenges are HMAC-signed, purpose-bound, session-bound, and short-lived. Optional strict single use is available. | A registration challenge cannot be replayed as a refresh challenge, and challenges cannot cross sessions. |
| Proof and header inputs have length caps. | Oversized attacker input is rejected before any parsing work. |

## Deployment rules

1. **Keep the bound cookie short-lived.** Minutes, not days. The browser only
   refreshes when the cookie expires. The package warns when your
   configuration breaks this rule; see [gotchas](./gotchas.md).
2. **Give every server instance the same challenge secret.** Rotation
   invalidates outstanding challenges and costs one extra 403 round trip.
3. **Return 5xx from the refresh endpoint on transient server errors.** A 4xx
   other than 403 tells the browser to end the session permanently.
4. **Watch `Secure-Session-Skipped`.** It tells you the browser could not
   refresh. Serve those requests like normal expired-cookie requests, and log
   them.
5. **Use an external session store in production.** The in-memory store is for
   tests and demos.

## Audit status

This package has not had a third-party security audit. The verifier has an
adversarial test suite, the package cross-validates against two independent
implementations, and it is validated against real Chrome. Read the code; it is
small on purpose.
