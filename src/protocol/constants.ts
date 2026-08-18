/**
 * The DBSC protocol constants, in one data-driven table.
 *
 * The protocol renamed every header between the first and second Chrome origin trials
 * (`Sec-Session-*` became `Secure-Session-*`, except the session-id header, which kept
 * the forbidden-header `Sec-` prefix as `Sec-Secure-Session-Id`). The challenge status
 * code changed from 401 to 403 at the same time. This module isolates every name and
 * code so a future rename is a data change, not a code change.
 *
 * Spec: W3C editor's draft, https://w3c.github.io/webappsec-dbsc/
 */

/** The spec revision this package tracks. Update when re-validating against the draft. */
export const SPEC_TRACKING = {
  editorsDraft: 'https://w3c.github.io/webappsec-dbsc/',
  lastValidated: '2026-08-19',
} as const;

/** Current header names (second origin trial onward; what GA Chrome ships). */
export const HEADERS = {
  /** Server → browser: start a session registration. */
  registration: 'Secure-Session-Registration',
  /** Server → browser: deliver a challenge (with the 403 dance or proactively). */
  challenge: 'Secure-Session-Challenge',
  /** Browser → server: the signed proof JWT. */
  response: 'Secure-Session-Response',
  /** Browser → server: the session the browser is refreshing. Note the `Sec-` prefix. */
  sessionId: 'Sec-Secure-Session-Id',
  /** Browser → server: the browser skipped a refresh; the reason and session follow. */
  skipped: 'Secure-Session-Skipped',
} as const;

/**
 * First-origin-trial header names. Most tutorials still show these. The compat mode
 * accepts them on inbound requests; the package never emits them.
 */
export const LEGACY_HEADERS = {
  registration: 'Sec-Session-Registration',
  challenge: 'Sec-Session-Challenge',
  response: 'Sec-Session-Response',
  sessionId: 'Sec-Session-Id',
  skipped: 'Sec-Session-Skipped',
} as const;

export const STATUS = {
  /** Refresh endpoint: "present a proof for this challenge". Was 401 in the first OT. */
  challengeRequired: 403,
  /** Registration and refresh success. */
  ok: 200,
} as const;

/** JWT `typ` for DBSC proofs. */
export const PROOF_TYP = 'dbsc+jwt';

/** Signature algorithms the spec defines. `none` (unbound sessions) is not supported. */
export const ALGORITHMS = ['ES256', 'RS256'] as const;
export type Algorithm = (typeof ALGORITHMS)[number];

/** Minimum RSA modulus size in bits for RS256 keys. */
export const MIN_RSA_MODULUS_BITS = 2048;

/** The site-scoped well-known path for cross-origin and federated registrations. */
export const WELL_KNOWN_PATH = '/.well-known/device-bound-sessions';

/** Reasons the browser sends in the skipped header. Servers must tolerate unknown ones. */
export const SKIP_REASONS = ['unreachable', 'server_error', 'quota_exceeded'] as const;
export type SkipReason = (typeof SKIP_REASONS)[number] | (string & {});
