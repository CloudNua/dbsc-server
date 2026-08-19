/**
 * Build and parse the five DBSC headers.
 *
 * Servers EMIT the current header names only. Servers ACCEPT the legacy
 * first-origin-trial names on inbound requests when `acceptLegacyHeaders` is on,
 * because old clients and old write-ups still use them.
 *
 * All parse functions return null on malformed input. Header values are
 * attacker-controlled; a bad header is "no header".
 */

import { ALGORITHMS, HEADERS, LEGACY_HEADERS, type Algorithm, type SkipReason } from './constants.js';
import {
  parseItem,
  parseList,
  serializeStringItem,
  serializeTokenInnerList,
  type SfParams,
} from './structured-fields.js';

// ---------------------------------------------------------------------------
// Secure-Session-Registration (server → browser)
// ---------------------------------------------------------------------------

export interface RegistrationHeaderInit {
  /** Allowed proof algorithms, strongest first. Default: ES256 then RS256. */
  algorithms?: readonly Algorithm[];
  /** Registration endpoint path. Resolved by the browser against the response URL. */
  path: string;
  /** The registration challenge the proof JWT must echo in `jti`. */
  challenge: string;
  /** Optional bearer value that links the registration to the sign-in. */
  authorization?: string;
}

/** Builds the `Secure-Session-Registration` header value. */
export function buildRegistrationHeader(init: RegistrationHeaderInit): string {
  const algorithms = init.algorithms ?? ALGORITHMS;
  if (algorithms.length === 0) throw new Error('at least one algorithm is required');
  const params: SfParams = { path: init.path, challenge: init.challenge };
  if (init.authorization !== undefined) params['authorization'] = init.authorization;
  return serializeTokenInnerList(algorithms, params);
}

export interface ParsedRegistration {
  algorithms: Algorithm[];
  path: string;
  challenge: string;
  authorization?: string;
}

/**
 * Parses a `Secure-Session-Registration` value. Servers do not normally consume this
 * header; the parser exists for tests, tooling, and golden vectors. Unknown algorithms
 * and unknown parameters (for example the federated `provider_*` set) are ignored.
 */
export function parseRegistrationHeader(value: string): ParsedRegistration | null {
  const list = parseList(value);
  if (list === null || list.length !== 1) return null;
  const member = list[0];
  if (!member || member.kind !== 'inner-list') return null;
  const algorithms = member.items
    .filter((i) => i.type === 'token')
    .map((i) => i.value)
    .filter((v): v is Algorithm => (ALGORITHMS as readonly string[]).includes(v));
  const path = member.params['path'];
  const challenge = member.params['challenge'];
  if (algorithms.length === 0 || path === undefined || challenge === undefined) return null;
  const parsed: ParsedRegistration = { algorithms, path, challenge };
  if (member.params['authorization'] !== undefined) parsed.authorization = member.params['authorization'];
  return parsed;
}

// ---------------------------------------------------------------------------
// Secure-Session-Challenge (server → browser)
// ---------------------------------------------------------------------------

export interface ChallengeHeaderInit {
  challenge: string;
  /** The session the challenge belongs to. Omitted on registration challenges. */
  sessionId?: string;
}

/** Builds the `Secure-Session-Challenge` header value: `"challenge";id="session"`. */
export function buildChallengeHeader(init: ChallengeHeaderInit): string {
  const params: SfParams = {};
  if (init.sessionId !== undefined) params['id'] = init.sessionId;
  return serializeStringItem(init.challenge, params);
}

export interface ParsedChallenge {
  challenge: string;
  sessionId?: string;
}

/** Parses a `Secure-Session-Challenge` value (single item or list; first item wins). */
export function parseChallengeHeader(value: string): ParsedChallenge | null {
  const list = parseList(value);
  if (list === null || list.length === 0) return null;
  const member = list[0];
  if (!member || member.kind !== 'item' || member.item.type !== 'string') return null;
  const parsed: ParsedChallenge = { challenge: member.item.value };
  // A valueless `;id` parameter parses as '' — treat empty as absent.
  if (member.params['id']) parsed.sessionId = member.params['id'];
  return parsed;
}

// ---------------------------------------------------------------------------
// Inbound headers (browser → server)
// ---------------------------------------------------------------------------

export interface InboundHeaderOptions {
  /** Also accept the legacy `Sec-Session-*` names. Default: true. */
  acceptLegacyHeaders?: boolean;
}

function readHeader(
  headers: Headers,
  current: string,
  legacy: string,
  opts: InboundHeaderOptions,
): string | null {
  const value = headers.get(current);
  if (value !== null) return value;
  if (opts.acceptLegacyHeaders !== false) return headers.get(legacy);
  return null;
}

/** Upper bound on inbound header values this module will look at. */
const MAX_HEADER_VALUE_LENGTH = 8192;
const MAX_SESSION_ID_LENGTH = 1024;

/** Reads the proof JWT from `Secure-Session-Response` (or the legacy name). */
export function getProofHeader(headers: Headers, opts: InboundHeaderOptions = {}): string | null {
  const value = readHeader(headers, HEADERS.response, LEGACY_HEADERS.response, opts);
  if (value === null || value.length > MAX_HEADER_VALUE_LENGTH) return null;
  const trimmed = value.trim();
  // A compact JWS: three non-empty base64url sections.
  return /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(trimmed) ? trimmed : null;
}

/** Reads the session id from `Sec-Secure-Session-Id` (or the legacy name). */
export function getSessionIdHeader(headers: Headers, opts: InboundHeaderOptions = {}): string | null {
  const value = readHeader(headers, HEADERS.sessionId, LEGACY_HEADERS.sessionId, opts);
  if (value === null || value.length > MAX_SESSION_ID_LENGTH) return null;
  // Chrome sends the raw identifier. Tolerate an sf-string form as well.
  const trimmed = value.trim();
  if (trimmed === '') return null;
  if (trimmed.startsWith('"')) {
    const item = parseItem(trimmed);
    if (item === null || item.kind !== 'item' || item.item.type !== 'string') return null;
    return item.item.value;
  }
  return trimmed;
}

export interface ParsedSkipped {
  reason: SkipReason;
  sessionId?: string;
}

/**
 * Parses `Secure-Session-Skipped`: the browser refused or failed to refresh and sent
 * the request without a fresh bound credential. Servers must tolerate this. Unknown
 * reasons parse fine; the reason set is expected to grow.
 */
export function getSkippedHeader(headers: Headers, opts: InboundHeaderOptions = {}): ParsedSkipped | null {
  const value = readHeader(headers, HEADERS.skipped, LEGACY_HEADERS.skipped, opts);
  if (value === null) return null;
  const item = parseItem(value.trim());
  if (item === null || item.kind !== 'item' || item.item.type !== 'token') return null;
  const parsed: ParsedSkipped = { reason: item.item.value };
  const sessionId = item.params['session_identifier'] || item.params['id'];
  if (sessionId) parsed.sessionId = sessionId;
  return parsed;
}
