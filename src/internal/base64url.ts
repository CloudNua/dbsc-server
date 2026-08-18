/** Base64url helpers. No padding on encode; padding tolerated on decode. */

export function bytesToBase64url(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Decodes base64url to bytes. Returns null on malformed input instead of throwing:
 * proof material is attacker-controlled, and "bad input = no proof" is the contract.
 * Copies into a fresh ArrayBuffer so the result is a valid BufferSource for
 * crypto.subtle in every runtime.
 */
export function base64urlToBytes(s: string): Uint8Array<ArrayBuffer> | null {
  if (!/^[A-Za-z0-9_-]*={0,2}$/.test(s)) return null;
  try {
    const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

export function utf8ToBase64url(s: string): string {
  return bytesToBase64url(new TextEncoder().encode(s));
}

/** Decodes base64url and parses the result as JSON. Returns null on any failure. */
export function base64urlToJson<T>(s: string): T | null {
  const bytes = base64urlToBytes(s);
  if (bytes === null) return null;
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as T;
  } catch {
    return null;
  }
}
