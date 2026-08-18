import { describe, expect, it } from 'vitest';
import { PACKAGE_NAME } from '../src/index.js';

describe('package scaffold', () => {
  it('exposes the package name', () => {
    expect(PACKAGE_NAME).toBe('dbsc-server');
  });

  it('has WebCrypto available in the test runtime', () => {
    expect(globalThis.crypto?.subtle).toBeDefined();
  });
});
