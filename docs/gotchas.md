# Protocol gotchas

DBSC has several failure modes that look green and do nothing, plus normal
behavior that looks like an error. This page lists them. The package detects
the configuration mistakes at runtime and reports them through `onWarning`.
By default each distinct configuration shape is checked once per process; set
`checkInvariants: 'always'` while debugging, or `'off'` to disable.

## Deployments that silently do nothing

### The bound cookie never expires

The browser refreshes only when the bound cookie is missing or expired. A
bound cookie without `Max-Age` or `Expires`, or with a lifetime as long as the
session, never triggers a refresh. Everything looks healthy and DBSC never
runs. Give the bound cookie a lifetime of minutes.
Warning code: `cookie-never-expires`.

### Expiry inside the credential attributes

The `credentials[].attributes` string describes the cookie for matching.
Expiry there does not affect matching, and it has broken registration in
Chrome. Put `Max-Age` on the real `Set-Cookie` header only.
Warning code: `credential-attributes-expiry`.

### A `__Host-` cookie with a site-wide scope

A `__Host-` cookie exists on one host only. With `include_site: true`, requests
to subdomains defer and wait for a cookie that can never exist there. Use
`includeSite: false` with `__Host-` cookies. Warning codes:
`host-prefix-scope`, `host-prefix-attributes`.

## Normal behavior that looks wrong

### 403 responses in your logs

The refresh flow is a 403 challenge followed by a 200. Pairs of 403 and 200 on
the refresh endpoint are the protocol working, not an attack. Alert on 403s
without a following 200, not on 403s.

### Challenge mismatches

Challenges are short-lived, and refreshes can race. A stale challenge is
benign: the server issues a fresh challenge and the browser retries. This
package re-challenges automatically.

### Requests without a fresh cookie

`Secure-Session-Skipped` on a request means the browser could not refresh
(quota, key pressure, or repeated errors) and sent the request anyway. Handle
it like a normal expired-cookie request. Log it.

## Mistakes that break sessions

### Redirects on the DBSC endpoints

Do not redirect the registration or refresh endpoints. Chrome has deadlocked
on redirected refresh flows. Serve both endpoints directly over HTTPS on the
final host.

### 4xx on transient errors

Any refresh response with a 4xx status other than 403 tells the browser to end
the session permanently. If your database is briefly down, return a 5xx: the
browser backs off and retries. Return 4xx only when the session is positively
unknown or expired.

### Middleware in front of the refresh endpoint

The browser calls the refresh endpoint exactly when the bound cookie is
expired. Auth middleware that rejects requests without a fresh cookie must
exclude the DBSC endpoints, or refresh can never succeed.

### Proxies that eat the headers

Confirm your proxy forwards `Secure-Session-Registration`,
`Secure-Session-Challenge`, `Secure-Session-Response`,
`Sec-Secure-Session-Id`, and `Secure-Session-Skipped` in both directions, and
that it does not turn the 403 challenge into an error page.

## History that trips people

The protocol renamed every header between the first and second Chrome origin
trials: `Sec-Session-*` became `Secure-Session-*`, except the session id
header, which is `Sec-Secure-Session-Id`. The challenge status changed from
401 to 403. Many tutorials still show the old forms. This package emits the
current names and accepts the legacy names on inbound requests.

Chrome also sends minimal proof payloads: often `jti` and nothing else. Do not
require `aud`, `sub`, or `iat` in proofs. This package validates them only
when they are present.
