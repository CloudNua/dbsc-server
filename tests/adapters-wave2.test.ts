/**
 * Wave-2 adapter integration tests: the same full dance runs through a real
 * Fastify app (inject) and a real NestJS app on the Express platform
 * (listening server).
 */
import 'reflect-metadata';
import Fastify from 'fastify';
import { Controller, Module, Post, Req, Res } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import type { INestApplication } from '@nestjs/common';
import { afterAll, describe, it } from 'vitest';
import { dbscFastify } from '../src/adapters/fastify.js';
import { dbscNest, type NestDbscHandlers } from '../src/adapters/nestjs.js';
import type { NodeRequestLike, NodeResponseLike } from '../src/adapters/express.js';
import { makeHandlerConfig, runDance } from './helpers/dance.js';

describe('fastify adapter', () => {
  it('runs the full dance through a real Fastify app via inject', async () => {
    const config = makeHandlerConfig();
    const handlers = dbscFastify(config);
    const app = Fastify();
    app.post('/dbsc/register', (request, reply) => handlers.register(request, reply));
    app.post('/dbsc/refresh', (request, reply) => handlers.refresh(request, reply));

    await runDance(config.dbsc, async (path, headers) => {
      const res = await app.inject({ method: 'POST', url: path, headers });
      const h = new Headers();
      for (const [name, value] of Object.entries(res.headers)) {
        if (Array.isArray(value)) for (const v of value) h.append(name, String(v));
        else if (value !== undefined) h.set(name, String(value));
      }
      const body = res.rawPayload.length > 0 ? new Uint8Array(res.rawPayload) : null;
      return new Response(body, { status: res.statusCode, headers: h });
    });
  });
});

describe('nestjs adapter', () => {
  let app: INestApplication | null = null;
  afterAll(async () => {
    await app?.close();
  });

  it('runs the full dance through a real NestJS app (express platform)', async () => {
    const config = makeHandlerConfig();
    const handlers: NestDbscHandlers = dbscNest(config);

    @Controller('dbsc')
    class DbscController {
      @Post('register')
      register(@Req() req: NodeRequestLike, @Res() res: NodeResponseLike): Promise<void> {
        return handlers.register(req, res);
      }

      @Post('refresh')
      refresh(@Req() req: NodeRequestLike, @Res() res: NodeResponseLike): Promise<void> {
        return handlers.refresh(req, res);
      }
    }

    @Module({ controllers: [DbscController] })
    class AppModule {}

    app = await NestFactory.create(AppModule, { logger: false });
    await app.listen(0);
    const url = await app.getUrl();
    const base = url.replace('[::1]', '127.0.0.1');

    await runDance(config.dbsc, (path, headers) => fetch(`${base}${path}`, { method: 'POST', headers }));
  });
});
