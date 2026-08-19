/**
 * Builds the DBSC session configuration JSON — the body of successful
 * registration and refresh responses — plus the termination body, and checks the
 * deployment invariants that produce silently-broken DBSC setups:
 *
 * - W1 `cookie-never-expires`: the bound Set-Cookie has no Max-Age/Expires, or one
 *   at least as long as the session. The browser only refreshes when the bound
 *   cookie is missing or expired, so such a deployment LOOKS green and never
 *   exercises DBSC.
 * - W2 `credential-attributes-expiry`: the `credentials[].attributes` string
 *   contains Max-Age/Expires. Expiry there does not affect credential matching and
 *   has broken registration in Chrome. Put expiry on the real Set-Cookie only.
 * - W3 `host-prefix-scope`: a `__Host-` cookie with `include_site: true`. The
 *   cookie is host-only; the session scope says whole site. Subdomain requests
 *   defer on a cookie that can never exist there.
 * - W4 `host-prefix-attributes`: a `__Host-` cookie whose attributes break the
 *   prefix rules (needs Secure, Path=/, no Domain) — the browser rejects it.
 */

export interface CookieCredential {
  /** The bound cookie's name. */
  name: string;
  /** Set-Cookie-style attributes WITHOUT a value or expiry, e.g. "Path=/; Secure; HttpOnly; SameSite=Lax". */
  attributes: string;
}

export interface SessionScopeInit {
  /** Bind the whole site (registrable domain) or the origin only. Required by spec. */
  includeSite: boolean;
  /** Origin override; defaults browser-side to the registration origin. */
  origin?: string;
  /** Path/domain rules. Later rules win. The refresh endpoint is always excluded. */
  specification?: Array<{ type: 'include' | 'exclude'; domain: string; path: string }>;
}

export interface SessionConfigInit {
  sessionId: string;
  refreshUrl: string;
  scope: SessionScopeInit;
  credentials: CookieCredential[];
  /** The actual Set-Cookie header values to send with this response. */
  setCookies?: string[];
  /** Session end-of-life (epoch ms). Used only for invariant checks. */
  sessionExpiresAt?: number;
  /** Reference time for invariant checks (epoch ms). Default: Date.now(). */
  now?: number;
  status?: number;
}

export interface DeploymentWarning {
  code: 'cookie-never-expires' | 'credential-attributes-expiry' | 'host-prefix-scope' | 'host-prefix-attributes';
  message: string;
}

/** Parsed Set-Cookie internals — just enough for the invariant checks. */
interface ParsedSetCookie {
  name: string;
  attrs: Map<string, string>;
}

function parseSetCookie(value: string): ParsedSetCookie | null {
  const parts = value.split(';');
  const first = parts[0];
  if (first === undefined) return null;
  const eq = first.indexOf('=');
  if (eq <= 0) return null;
  const name = first.slice(0, eq).trim();
  const attrs = new Map<string, string>();
  for (const part of parts.slice(1)) {
    const aeq = part.indexOf('=');
    const key = (aeq === -1 ? part : part.slice(0, aeq)).trim().toLowerCase();
    const val = aeq === -1 ? '' : part.slice(aeq + 1).trim();
    if (key !== '') attrs.set(key, val);
  }
  return { name, attrs };
}

function attributeStringHasExpiry(attributes: string): boolean {
  return /(?:^|;)\s*(?:max-age|expires)\s*=/i.test(attributes);
}

/** Checks the deployment invariants. Returns warnings; never throws. */
export function checkDeploymentInvariants(init: SessionConfigInit): DeploymentWarning[] {
  const warnings: DeploymentWarning[] = [];
  const now = init.now ?? Date.now();

  for (const credential of init.credentials) {
    if (attributeStringHasExpiry(credential.attributes)) {
      warnings.push({
        code: 'credential-attributes-expiry',
        message:
          `credential "${credential.name}": remove Max-Age/Expires from credentials[].attributes; ` +
          'expiry there does not affect matching and has broken registration in Chrome. ' +
          'Put expiry on the Set-Cookie header instead.',
      });
    }
    if (credential.name.startsWith('__Host-') && init.scope.includeSite) {
      warnings.push({
        code: 'host-prefix-scope',
        message:
          `credential "${credential.name}": a __Host- cookie is host-only but the session scope has ` +
          'include_site true. Subdomain requests will defer on a cookie that cannot exist there. ' +
          'Use include_site false, or drop the __Host- prefix.',
      });
    }
  }

  for (const setCookie of init.setCookies ?? []) {
    const parsed = parseSetCookie(setCookie);
    if (parsed === null) continue;
    const bound = init.credentials.find((c) => c.name === parsed.name);
    if (bound === undefined) continue;

    const maxAge = parsed.attrs.get('max-age');
    const expires = parsed.attrs.get('expires');
    let cookieLifetimeMs: number | null = null;
    if (maxAge !== undefined && /^-?\d+$/.test(maxAge)) {
      cookieLifetimeMs = Number(maxAge) * 1000;
    } else if (expires !== undefined) {
      const t = Date.parse(expires);
      if (!Number.isNaN(t)) cookieLifetimeMs = t - now;
    }

    if (cookieLifetimeMs === null) {
      warnings.push({
        code: 'cookie-never-expires',
        message:
          `bound cookie "${parsed.name}": no Max-Age or Expires. The browser refreshes only when the ` +
          'bound cookie expires, so this deployment never exercises DBSC. Give the cookie a short ' +
          'lifetime (minutes).',
      });
    } else if (init.sessionExpiresAt !== undefined && now + cookieLifetimeMs >= init.sessionExpiresAt) {
      warnings.push({
        code: 'cookie-never-expires',
        message:
          `bound cookie "${parsed.name}": its lifetime reaches past the session expiry, so no refresh ` +
          'will ever happen inside this session. Use a cookie lifetime much shorter than the session.',
      });
    }

    if (parsed.name.startsWith('__Host-')) {
      const hasSecure = parsed.attrs.has('secure');
      const pathIsRoot = parsed.attrs.get('path') === '/';
      const hasDomain = parsed.attrs.has('domain');
      if (!hasSecure || !pathIsRoot || hasDomain) {
        warnings.push({
          code: 'host-prefix-attributes',
          message:
            `bound cookie "${parsed.name}": __Host- requires Secure, Path=/, and no Domain attribute; ` +
            'the browser rejects it otherwise.',
        });
      }
    }
  }

  return warnings;
}

/** The wire shape of the session configuration JSON. */
export interface SessionConfigBody {
  session_identifier: string;
  refresh_url: string;
  scope: {
    origin?: string;
    include_site: boolean;
    scope_specification?: Array<{ type: 'include' | 'exclude'; domain: string; path: string }>;
  };
  credentials: Array<{ type: 'cookie'; name: string; attributes: string }>;
}

export function buildSessionConfigBody(init: SessionConfigInit): SessionConfigBody {
  const scope: SessionConfigBody['scope'] = { include_site: init.scope.includeSite };
  if (init.scope.origin !== undefined) scope.origin = init.scope.origin;
  if (init.scope.specification !== undefined && init.scope.specification.length > 0) {
    scope.scope_specification = init.scope.specification;
  }
  return {
    session_identifier: init.sessionId,
    refresh_url: init.refreshUrl,
    scope,
    credentials: init.credentials.map((c) => ({ type: 'cookie', name: c.name, attributes: c.attributes })),
  };
}

/** Builds the registration/refresh success Response: config JSON + Set-Cookie headers. */
export function buildSessionConfigResponse(
  init: SessionConfigInit,
  onWarning?: (warning: DeploymentWarning) => void,
): Response {
  if (onWarning) for (const warning of checkDeploymentInvariants(init)) onWarning(warning);
  const headers = new Headers({ 'content-type': 'application/json' });
  for (const setCookie of init.setCookies ?? []) headers.append('set-cookie', setCookie);
  return new Response(JSON.stringify(buildSessionConfigBody(init)), {
    status: init.status ?? 200,
    headers,
  });
}

/** Builds the termination body: `{"session_identifier": id, "continue": false}`. */
export function buildTerminationResponse(sessionId: string, opts: { status?: number } = {}): Response {
  return new Response(JSON.stringify({ session_identifier: sessionId, continue: false }), {
    status: opts.status ?? 200,
    headers: { 'content-type': 'application/json' },
  });
}
