# Storage recipes

The package ships only an in-memory store, for tests and demos. In production
you implement the four-method `DbscSessionStore` interface over your own
database. These examples are code to copy and adapt, not shipped modules.

The store holds no secrets: session ids, public keys, and timestamps only.
Standard database hygiene is enough.

## Postgres with Drizzle

```ts
import { pgTable, text, jsonb, bigint } from 'drizzle-orm/pg-core';
import { eq } from 'drizzle-orm';
import type { DbscSessionStore, StoredDbscSession } from 'dbsc-server';

export const dbscSessions = pgTable('dbsc_sessions', {
  id: text('id').primaryKey(),
  publicJwk: jsonb('public_jwk').notNull(),
  kid: text('kid').notNull(),
  createdAt: bigint('created_at', { mode: 'number' }).notNull(),
  expiresAt: bigint('expires_at', { mode: 'number' }).notNull(),
  ref: text('ref'),
});

export function drizzleDbscStore(db: YourDrizzleDb): DbscSessionStore {
  return {
    async create(session) {
      await db.insert(dbscSessions).values({ ...session, ref: session.ref ?? null });
    },
    async get(id) {
      const rows = await db.select().from(dbscSessions).where(eq(dbscSessions.id, id)).limit(1);
      const row = rows[0];
      if (!row) return null;
      return {
        id: row.id,
        publicJwk: row.publicJwk as StoredDbscSession['publicJwk'],
        kid: row.kid,
        createdAt: row.createdAt,
        expiresAt: row.expiresAt,
        ...(row.ref ? { ref: row.ref } : {}),
      };
    },
    async update(id, patch) {
      await db.update(dbscSessions).set(patch).where(eq(dbscSessions.id, id));
    },
    async delete(id) {
      await db.delete(dbscSessions).where(eq(dbscSessions.id, id));
    },
  };
}
```

Add a periodic cleanup job for expired rows:
`DELETE FROM dbsc_sessions WHERE expires_at < (extract(epoch from now()) * 1000);`

## Redis

```ts
import type { DbscSessionStore, StoredDbscSession } from 'dbsc-server';

export function redisDbscStore(redis: YourRedisClient): DbscSessionStore {
  const key = (id: string) => `dbsc:session:${id}`;
  const ttl = (session: { expiresAt: number }) =>
    Math.max(1, Math.ceil((session.expiresAt - Date.now()) / 1000));

  return {
    async create(session) {
      await redis.set(key(session.id), JSON.stringify(session), { EX: ttl(session) });
    },
    async get(id) {
      const value = await redis.get(key(id));
      return value ? (JSON.parse(value) as StoredDbscSession) : null;
    },
    async update(id, patch) {
      const value = await redis.get(key(id));
      if (!value) return;
      const session = { ...(JSON.parse(value) as StoredDbscSession), ...patch };
      await redis.set(key(id), JSON.stringify(session), { EX: ttl(session) });
    },
    async delete(id) {
      await redis.del(key(id));
    },
  };
}
```

## Single-use challenges

For strict single-use challenges across instances, implement
`ChallengeConsumedStore` with an atomic operation:

```ts
import type { ChallengeConsumedStore } from 'dbsc-server';

export function redisConsumedStore(redis: YourRedisClient): ChallengeConsumedStore {
  return {
    async consume(challenge, ttlSec) {
      // SET NX returns null when the key already exists: consumed once only.
      const result = await redis.set(`dbsc:used:${challenge}`, '1', { NX: true, EX: ttlSec });
      return result !== null;
    },
  };
}
```

Keep the consumed-store TTL at least as long as the challenge TTL. A store
that forgets sooner re-opens the challenge for replay.
