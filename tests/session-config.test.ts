import { describe, expect, it } from 'vitest';
import {
  buildSessionConfigBody,
  buildTerminationResponse,
  checkDeploymentInvariants,
  type SessionConfigInit,
} from '../src/session-config.js';

const base: SessionConfigInit = {
  sessionId: 's-1',
  refreshUrl: '/dbsc/refresh',
  scope: { includeSite: false },
  credentials: [{ name: 'session', attributes: 'Path=/; Secure; HttpOnly; SameSite=Lax' }],
  setCookies: ['session=abc; Max-Age=600; Path=/; Secure; HttpOnly; SameSite=Lax'],
  sessionExpiresAt: Date.now() + 30 * 24 * 3600 * 1000,
};

describe('buildSessionConfigBody', () => {
  it('builds the wire shape', () => {
    const body = buildSessionConfigBody({
      ...base,
      scope: {
        includeSite: true,
        specification: [{ type: 'exclude', domain: '*.example.com', path: '/static' }],
      },
    });
    expect(body).toEqual({
      session_identifier: 's-1',
      refresh_url: '/dbsc/refresh',
      scope: {
        include_site: true,
        scope_specification: [{ type: 'exclude', domain: '*.example.com', path: '/static' }],
      },
      credentials: [{ type: 'cookie', name: 'session', attributes: 'Path=/; Secure; HttpOnly; SameSite=Lax' }],
    });
  });
});

describe('deployment invariants', () => {
  it('passes a healthy configuration silently', () => {
    expect(checkDeploymentInvariants(base)).toEqual([]);
  });

  it('W1: warns when the bound cookie has no expiry', () => {
    const warnings = checkDeploymentInvariants({
      ...base,
      setCookies: ['session=abc; Path=/; Secure; HttpOnly'],
    });
    expect(warnings.map((w) => w.code)).toEqual(['cookie-never-expires']);
  });

  it('W1: warns when the cookie lifetime reaches past the session expiry', () => {
    const warnings = checkDeploymentInvariants({
      ...base,
      sessionExpiresAt: Date.now() + 60_000,
      setCookies: ['session=abc; Max-Age=600; Path=/; Secure'],
    });
    expect(warnings.map((w) => w.code)).toEqual(['cookie-never-expires']);
  });

  it('W2: warns when credential attributes carry expiry', () => {
    const warnings = checkDeploymentInvariants({
      ...base,
      credentials: [{ name: 'session', attributes: 'Max-Age=600; Path=/; Secure' }],
    });
    expect(warnings.map((w) => w.code)).toEqual(['credential-attributes-expiry']);
  });

  it('W3: warns on a __Host- cookie with include_site', () => {
    const warnings = checkDeploymentInvariants({
      ...base,
      scope: { includeSite: true },
      credentials: [{ name: '__Host-session', attributes: 'Path=/; Secure' }],
      setCookies: ['__Host-session=abc; Max-Age=600; Path=/; Secure'],
    });
    expect(warnings.map((w) => w.code)).toContain('host-prefix-scope');
  });

  it('W4: warns on a __Host- cookie that breaks the prefix rules', () => {
    const warnings = checkDeploymentInvariants({
      ...base,
      credentials: [{ name: '__Host-session', attributes: 'Path=/; Secure' }],
      setCookies: ['__Host-session=abc; Max-Age=600; Path=/api; Secure'],
    });
    expect(warnings.map((w) => w.code)).toContain('host-prefix-attributes');
  });

  it('ignores set-cookies that are not bound credentials', () => {
    const warnings = checkDeploymentInvariants({
      ...base,
      setCookies: [...base.setCookies!, 'analytics=1; Path=/'],
    });
    expect(warnings).toEqual([]);
  });
});

describe('buildTerminationResponse', () => {
  it('builds the continue:false body', async () => {
    const response = buildTerminationResponse('s-1');
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ session_identifier: 's-1', continue: false });
  });
});
