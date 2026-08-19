/**
 * Node-style HTTP bridge shared by the Express, Fastify, and NestJS adapters:
 * convert a Node request to a WHATWG Request (headers, method, URL; DBSC reads
 * no bodies) and write a WHATWG Response back to a Node response.
 */

/** The parts of a Node-style request the adapters read. */
export interface NodeRequestLike {
  method?: string;
  url?: string;
  headers: Record<string, string | string[] | undefined>;
}

/** The parts of a Node-style response the adapters write. */
export interface NodeResponseLike {
  statusCode: number;
  setHeader(name: string, value: string | string[]): unknown;
  end(chunk?: unknown): unknown;
}

export function toWhatwgRequest(req: NodeRequestLike, origin = 'http://localhost'): Request {
  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) {
    if (typeof value === 'string') headers.set(name, value);
    else if (Array.isArray(value)) for (const v of value) headers.append(name, v);
  }
  return new Request(new URL(req.url ?? '/', origin), { method: req.method ?? 'GET', headers });
}

export async function sendWhatwgResponse(res: NodeResponseLike, response: Response): Promise<void> {
  for (const [name, value] of response.headers) {
    if (name !== 'set-cookie') res.setHeader(name, value);
  }
  const cookies = response.headers.getSetCookie();
  if (cookies.length > 0) res.setHeader('set-cookie', cookies);
  res.statusCode = response.status;
  const body = new Uint8Array(await response.arrayBuffer());
  res.end(body.length > 0 ? body : undefined);
}
