# Community vectors: dbsc-toolkit

These three files are copies of the native-protocol test vectors from
[dbsc-toolkit](https://github.com/SulimanAbdulrazzaq/dbsc-toolkit)
(`spec/vectors/`, commit `df1c83ef9b9f92b28ff80842a2316957b1fb2c60`, 2026-06-23).
License: Apache-2.0 (see the source repository).

`tests/interop.test.ts` runs this package against them. The
[dbsc-php](https://github.com/report-uri/dbsc-php) implementation validates
against the same set, so agreement here gives three-way interoperability on the
native protocol surface.

The source repository has more vector files. They pin non-standard layers of
dbsc-toolkit (a WebCrypto polyfill, per-request proofs, and DPoP). This package
does not implement those layers, so those vectors do not apply.
