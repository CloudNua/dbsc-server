/**
 * Adapter integration tests: the SAME full dance runs through every adapter —
 * real Hono (app.request), real Express (listening server), real Elysia
 * (app.handle), and the Next pass-through contract.
 */
import express from 'express';
import { Hono } from 'hono';
import { Elysia } from 'elysia';
import type { AddressInfo } from 'node:net';
import { afterAll, describe, it } from 'vitest';
import { dbscExpress } from '../src/adapters/express.js';
import { dbscHono } from '../src/adapters/hono.js';
import { dbscNext } from '../src/adapters/next.js';
import { dbscElysia } from '../src/adapters/elysia.js';
import { makeHandlerConfig, runDance } from './helpers/dance.js';

describe('hono adapter', () => {
  it('runs the full dance through a real Hono app', async () => {
    const config = makeHandlerConfig();
    const handlers = dbscHono(config);
    const app = new Hono();
    app.post('/dbsc/register', (c) => handlers.register(c));
    app.post('/dbsc/refresh', (c) => handlers.refresh(c));
    await runDance(config.dbsc, async (path, headers) => app.request(path, { method: 'POST', headers }));
  });
});

describe('express adapter', () => {
  const servers: Array<{ close(): void }> = [];
  afterAll(() => {
    for (const server of servers) server.close();
  });

  it('runs the full dance through a real listening Express app', async () => {
    const config = makeHandlerConfig();
    const handlers = dbscExpress(config);
    const app = express();
    app.post('/dbsc/register', (req, res) => void handlers.register(req, res));
    app.post('/dbsc/refresh', (req, res) => void handlers.refresh(req, res));
    const server = app.listen(0);
    servers.push(server);
    const port = (server.address() as AddressInfo).port;
    await runDance(config.dbsc, (path, headers) =>
      fetch(`http://127.0.0.1:${port}${path}`, { method: 'POST', headers }),
    );
  });
});

describe('next adapter', () => {
  it('runs the full dance through the route-handler contract (Request in, Response out)', async () => {
    const config = makeHandlerConfig();
    const handlers = dbscNext(config);
    await runDance(config.dbsc, (path, headers) => {
      const request = new Request(`http://localhost${path}`, { method: 'POST', headers });
      return path === '/dbsc/register' ? handlers.register(request) : handlers.refresh(request);
    });
  });
});

describe('elysia adapter', () => {
  it('runs the full dance through a real Elysia app (plugin form)', async () => {
    const config = makeHandlerConfig();
    const app = dbscElysia(config)(new Elysia());
    await runDance(config.dbsc, (path, headers) =>
      app.handle(new Request(`http://localhost${path}`, { method: 'POST', headers })),
    );
  });
});
