/**
 * A minimal RFC 8941 (Structured Field Values) subset — exactly the shapes the DBSC
 * headers use, nothing more:
 *
 * - Items: token, string. Parameters on items and inner lists (string values only in
 *   serialization; tokens tolerated when parsing).
 * - Lists whose members are items or inner lists of tokens.
 *
 * Parsing never throws. Every parse function returns null on malformed input, because
 * header values are attacker-controlled.
 */

export type SfBareValue = { type: 'token' | 'string'; value: string };
export type SfParams = Record<string, string>;
export type SfMember =
  | { kind: 'item'; item: SfBareValue; params: SfParams }
  | { kind: 'inner-list'; items: SfBareValue[]; params: SfParams };

const TOKEN_RE = /^[A-Za-z*][A-Za-z0-9:/!#$%&'*+\-.^_`|~]*$/;
const KEY_RE = /^[a-z*][a-z0-9_\-.*]*$/;

export function serializeString(value: string): string {
  // RFC 8941: strings are printable ASCII only.
  // eslint-disable-next-line no-control-regex
  if (/[^\x20-\x7e]/.test(value)) throw new Error('sf-string must be printable ASCII');
  return `"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

export function serializeToken(value: string): string {
  if (!TOKEN_RE.test(value)) throw new Error(`invalid sf-token: ${value}`);
  return value;
}

export function serializeParams(params: SfParams): string {
  let out = '';
  for (const [key, value] of Object.entries(params)) {
    if (!KEY_RE.test(key)) throw new Error(`invalid sf-param key: ${key}`);
    out += `;${key}=${serializeString(value)}`;
  }
  return out;
}

/** Serializes an inner list of tokens with parameters: `(a b);k="v"`. */
export function serializeTokenInnerList(tokens: readonly string[], params: SfParams = {}): string {
  return `(${tokens.map(serializeToken).join(' ')})${serializeParams(params)}`;
}

/** Serializes a string item with parameters: `"v";k="v2"`. */
export function serializeStringItem(value: string, params: SfParams = {}): string {
  return `${serializeString(value)}${serializeParams(params)}`;
}

/** Serializes a token item with parameters: `tok;k="v"`. */
export function serializeTokenItem(value: string, params: SfParams = {}): string {
  return `${serializeToken(value)}${serializeParams(params)}`;
}

class Parser {
  private i = 0;
  constructor(private readonly s: string) {}

  private peek(): string {
    return this.s[this.i] ?? '';
  }
  eof(): boolean {
    return this.i >= this.s.length;
  }
  skipSp(): void {
    while (this.peek() === ' ') this.i++;
  }
  skipOws(): void {
    while (this.peek() === ' ' || this.peek() === '\t') this.i++;
  }
  expect(ch: string): boolean {
    if (this.peek() !== ch) return false;
    this.i++;
    return true;
  }

  parseBare(): SfBareValue | null {
    const ch = this.peek();
    if (ch === '"') return this.parseString();
    if (/[A-Za-z*]/.test(ch)) return this.parseToken();
    return null;
  }

  parseString(): SfBareValue | null {
    if (!this.expect('"')) return null;
    let out = '';
    while (!this.eof()) {
      const ch = this.s[this.i++]!;
      if (ch === '\\') {
        const next = this.s[this.i++];
        if (next !== '\\' && next !== '"') return null;
        out += next;
      } else if (ch === '"') {
        return { type: 'string', value: out };
      } else if (/[\x20-\x7e]/.test(ch)) {
        out += ch;
      } else {
        return null;
      }
    }
    return null; // unterminated
  }

  parseToken(): SfBareValue | null {
    const rest = this.s.slice(this.i);
    const m = rest.match(/^[A-Za-z*][A-Za-z0-9:/!#$%&'*+\-.^_`|~]*/);
    if (!m) return null;
    this.i += m[0].length;
    return { type: 'token', value: m[0] };
  }

  parseParams(): SfParams | null {
    const params: SfParams = {};
    while (this.peek() === ';') {
      this.i++;
      this.skipSp();
      const key = this.s.slice(this.i).match(/^[a-z*][a-z0-9_\-.*]*/);
      if (!key) return null;
      this.i += key[0].length;
      if (this.expect('=')) {
        const value = this.parseBare();
        if (value === null) return null;
        params[key[0]] = value.value;
      } else {
        params[key[0]] = ''; // boolean true parameter; DBSC does not use these today
      }
    }
    return params;
  }

  parseInnerList(): SfMember | null {
    if (!this.expect('(')) return null;
    const items: SfBareValue[] = [];
    for (;;) {
      this.skipSp();
      if (this.expect(')')) break;
      const item = this.parseBare();
      if (item === null) return null;
      // DBSC inner lists carry no per-item parameters; skip any to stay tolerant.
      const p = this.parseParams();
      if (p === null) return null;
      items.push(item);
    }
    const params = this.parseParams();
    if (params === null) return null;
    return { kind: 'inner-list', items, params };
  }

  parseMember(): SfMember | null {
    if (this.peek() === '(') return this.parseInnerList();
    const item = this.parseBare();
    if (item === null) return null;
    const params = this.parseParams();
    if (params === null) return null;
    return { kind: 'item', item, params };
  }

  parseList(): SfMember[] | null {
    const members: SfMember[] = [];
    this.skipOws();
    if (this.eof()) return members;
    for (;;) {
      const member = this.parseMember();
      if (member === null) return null;
      members.push(member);
      this.skipOws();
      if (this.eof()) return members;
      if (!this.expect(',')) return null;
      this.skipOws();
      if (this.eof()) return null; // trailing comma
    }
  }
}

/** Parses an SF list (members: items or inner lists). Returns null when malformed. */
export function parseList(value: string): SfMember[] | null {
  return new Parser(value).parseList();
}

/** Parses a single SF item with parameters. Returns null when malformed. */
export function parseItem(value: string): SfMember | null {
  const parser = new Parser(value);
  parser.skipOws();
  const member = parser.parseMember();
  if (member === null) return null;
  parser.skipOws();
  // Reject trailing garbage.
  return parser.eof() ? member : null;
}
