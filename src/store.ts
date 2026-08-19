/**
 * The session store interface — the ONE thing a consumer implements.
 *
 * The store maps a DBSC session id to the registered device public key plus
 * lifetimes. It holds no cookie contents and no application session state; keep
 * your own session data wherever it lives today and use `ref` to link the two.
 *
 * This package ships only `createMemoryStore`, for tests, demos, and
 * single-instance servers. Production deployments implement this interface over
 * their own database. The documentation contains copy-paste recipes; shipped and
 * maintained storage adapters are a deliberate non-goal.
 */

import type { PublicJwk } from './protocol/jwk.js';

export interface StoredDbscSession {
  /** The session identifier the browser echoes in `Sec-Secure-Session-Id`. */
  id: string;
  /** The registered device public key (public members only). */
  publicJwk: PublicJwk;
  /** RFC 7638 thumbprint of `publicJwk` — the stable device-key identity. */
  kid: string;
  /** Milliseconds since the epoch. */
  createdAt: number;
  /** Session end-of-life, milliseconds since the epoch. After this, refresh terminates. */
  expiresAt: number;
  /** Opaque application reference (for example your user id). Never parsed. */
  ref?: string;
}

export interface DbscSessionStore {
  /** Persists a new session. Must reject or overwrite atomically on id collision. */
  create(session: StoredDbscSession): Promise<void>;
  /** Returns the session or null. Returning an expired session is fine; flows check. */
  get(id: string): Promise<StoredDbscSession | null>;
  /** Applies a partial update to an existing session. Unknown id: no-op. */
  update(id: string, patch: Partial<Pick<StoredDbscSession, 'expiresAt' | 'ref'>>): Promise<void>;
  /** Deletes the session. Unknown id: no-op. */
  delete(id: string): Promise<void>;
}

/** In-memory store for tests, demos, and single-instance servers. Not durable. */
export function createMemoryStore(opts: { now?: () => number } = {}): DbscSessionStore {
  const now = opts.now ?? Date.now;
  const sessions = new Map<string, StoredDbscSession>();

  const sweep = (): void => {
    const t = now();
    for (const [id, session] of sessions) if (session.expiresAt <= t) sessions.delete(id);
  };

  return {
    async create(session) {
      sweep();
      sessions.set(session.id, { ...session });
    },
    async get(id) {
      sweep();
      const session = sessions.get(id);
      return session ? { ...session } : null;
    },
    async update(id, patch) {
      const session = sessions.get(id);
      if (session) sessions.set(id, { ...session, ...patch });
    },
    async delete(id) {
      sessions.delete(id);
    },
  };
}
