# Security policy

## Report a vulnerability

Do not open a public issue for a security problem.

Send a report to <security@cloudnua.com>. Include the steps to reproduce the
problem and the version that you tested.

You get an acknowledgement within 72 hours. You get a status update at least
every 14 days until the problem is resolved. We credit reporters in the
release notes unless you ask us not to.

## Supported versions

| Version | Supported |
|---|---|
| Latest release | Yes |
| Older releases | No. Upgrade to the latest release. |

## Scope

The protocol implementation in this package is in scope: proof verification,
challenge handling, header parsing, and the refresh state machine. Your
application code, your session store implementation, and the DBSC protocol
design itself are out of scope.

## Audit status

This package has not had a third-party security audit. See the
[security model](./docs/security-model.md) for the design decisions and the
testing that backs them.
