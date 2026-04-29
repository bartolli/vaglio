import { describe, expect, it } from 'vitest';

describe('vaglio', () => {
  it('module loads', async () => {
    const mod = await import('./index.js');
    expect(mod).toBeDefined();
  });
});
