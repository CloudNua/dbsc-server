# Interoperability

This package cross-checks its wire output against other open-source DBSC
implementations. This page records the current results.

## Shared vectors

Two other implementations publish or consume a shared set of native-protocol
test vectors:

- [dbsc-toolkit](https://github.com/SulimanAbdulrazzaq/dbsc-toolkit) publishes
  the vectors in its `spec/vectors/` directory.
- [dbsc-php](https://github.com/report-uri/dbsc-php) validates against the same
  set.

This package vendors the native-protocol vectors in
[`vectors/community/dbsc-toolkit/`](../vectors/community/dbsc-toolkit/) and runs
them in `tests/interop.test.ts` on every build.

## Results (checked 2026-08-19, source commit `df1c83e`)

| Vector | Result |
|---|---|
| `registration-header.json` | Pass. This package builds byte-identical `Secure-Session-Registration` and `Secure-Session-Challenge` header strings. |
| `registration.json` | Pass. The registration JWS verifies, and this package stores the same public key and RFC 7638 thumbprint. |
| `refresh.json` | Pass. The refresh JWS verifies against the stored key with no `jwk` in the header. |

The other vector files in the source repository pin layers this package does not
implement (a WebCrypto polyfill for non-DBSC browsers, per-request proofs, and
DPoP). They do not apply here.

## Our vectors

This package publishes its own vector suite in [`vectors/`](../vectors/). Other
implementations are welcome to use it. See `vectors/*.json`; each file carries a
`comment` field that explains its format. The key pairs in `vectors/keys.json`
are test keys and must never be used for anything real.
