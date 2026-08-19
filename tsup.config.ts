import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    express: 'src/adapters/express.ts',
    hono: 'src/adapters/hono.ts',
    next: 'src/adapters/next.ts',
    elysia: 'src/adapters/elysia.ts',
    fastify: 'src/adapters/fastify.ts',
    nestjs: 'src/adapters/nestjs.ts',
  },
  format: ['esm'],
  dts: true,
  clean: true,
  target: 'node20',
  sourcemap: true,
});
