import { describe, expect, it } from 'vitest';
import {
  buildChallengeHeader,
  buildRegistrationHeader,
  getProofHeader,
  getSessionIdHeader,
  getSkippedHeader,
  parseChallengeHeader,
  parseRegistrationHeader,
} from '../src/protocol/headers.js';
import { parseItem, parseList } from '../src/protocol/structured-fields.js';

describe('structured fields (RFC 8941 subset)', () => {
  it('parses an inner list of tokens with parameters', () => {
    const list = parseList('(ES256 RS256);path="/dbsc/register";challenge="cv"');
    expect(list).toHaveLength(1);
    expect(list![0]).toMatchObject({
      kind: 'inner-list',
      items: [
        { type: 'token', value: 'ES256' },
        { type: 'token', value: 'RS256' },
      ],
      params: { path: '/dbsc/register', challenge: 'cv' },
    });
  });

  it('parses escaped characters inside sf-strings', () => {
    const item = parseItem('"a\\"b\\\\c"');
    expect(item).toMatchObject({ kind: 'item', item: { type: 'string', value: 'a"b\\c' } });
  });

  it('returns null for malformed input instead of throwing', () => {
    for (const bad of ['(ES256', '"unterminated', '"bad\\x"', 'tok;=v', '(a),', ',', '"a"trailing']) {
      expect(parseList(bad) === null || parseItem(bad) === null).toBe(true);
    }
  });

  it('rejects non-ASCII when serializing strings', () => {
    expect(() => buildChallengeHeader({ challenge: 'café' })).toThrow();
  });
});

describe('Secure-Session-Registration', () => {
  it('builds the documented shape', () => {
    const value = buildRegistrationHeader({
      path: '/dbsc/register',
      challenge: 'cv',
      authorization: 'ac',
    });
    expect(value).toBe('(ES256 RS256);path="/dbsc/register";challenge="cv";authorization="ac"');
  });

  it('round-trips through the parser', () => {
    const value = buildRegistrationHeader({ algorithms: ['ES256'], path: '/r', challenge: 'c1' });
    expect(parseRegistrationHeader(value)).toEqual({
      algorithms: ['ES256'],
      path: '/r',
      challenge: 'c1',
    });
  });

  it('ignores unknown algorithms and federated parameters when parsing', () => {
    const parsed = parseRegistrationHeader(
      '(ES256 ES512);path="/r";challenge="c";provider_url="https://idp.example"',
    );
    expect(parsed).toEqual({ algorithms: ['ES256'], path: '/r', challenge: 'c' });
  });

  it('requires at least one algorithm and the path/challenge parameters', () => {
    expect(() => buildRegistrationHeader({ algorithms: [], path: '/r', challenge: 'c' })).toThrow();
    expect(parseRegistrationHeader('(ES512);path="/r";challenge="c"')).toBeNull();
    expect(parseRegistrationHeader('(ES256);challenge="c"')).toBeNull();
    expect(parseRegistrationHeader('(ES256);path="/r"')).toBeNull();
  });
});

describe('Secure-Session-Challenge', () => {
  it('builds and round-trips with a session id', () => {
    const value = buildChallengeHeader({ challenge: 'cv', sessionId: 's-1' });
    expect(value).toBe('"cv";id="s-1"');
    expect(parseChallengeHeader(value)).toEqual({ challenge: 'cv', sessionId: 's-1' });
  });

  it('builds a registration challenge without a session id', () => {
    expect(parseChallengeHeader(buildChallengeHeader({ challenge: 'cv' }))).toEqual({
      challenge: 'cv',
    });
  });
});

describe('inbound headers', () => {
  const jwt = 'eyJh.eyJq.c2ln';

  it('reads the proof from the current header name', () => {
    const headers = new Headers({ 'Secure-Session-Response': jwt });
    expect(getProofHeader(headers)).toBe(jwt);
  });

  it('reads the proof from the legacy header name by default', () => {
    const headers = new Headers({ 'Sec-Session-Response': jwt });
    expect(getProofHeader(headers)).toBe(jwt);
  });

  it('ignores legacy names when compat is off', () => {
    const headers = new Headers({ 'Sec-Session-Response': jwt });
    expect(getProofHeader(headers, { acceptLegacyHeaders: false })).toBeNull();
  });

  it('rejects a proof that is not compact-JWS shaped', () => {
    for (const bad of ['not a jwt', 'a.b', 'a.b.c.d', '..', 'a.b.$$$']) {
      expect(getProofHeader(new Headers({ 'Secure-Session-Response': bad }))).toBeNull();
    }
  });

  it('reads the session id from current and legacy names, raw or sf-string', () => {
    expect(getSessionIdHeader(new Headers({ 'Sec-Secure-Session-Id': 's-1' }))).toBe('s-1');
    expect(getSessionIdHeader(new Headers({ 'Sec-Session-Id': 's-1' }))).toBe('s-1');
    expect(getSessionIdHeader(new Headers({ 'Sec-Secure-Session-Id': '"s-1"' }))).toBe('s-1');
    expect(getSessionIdHeader(new Headers())).toBeNull();
  });

  it('parses the skipped header with known and unknown reasons', () => {
    expect(
      getSkippedHeader(new Headers({ 'Secure-Session-Skipped': 'quota_exceeded;session_identifier="123"' })),
    ).toEqual({ reason: 'quota_exceeded', sessionId: '123' });
    expect(getSkippedHeader(new Headers({ 'Secure-Session-Skipped': 'some_future_reason' }))).toEqual({
      reason: 'some_future_reason',
    });
    expect(getSkippedHeader(new Headers({ 'Secure-Session-Skipped': '"not-a-token"' }))).toBeNull();
  });
});
