/**
 * Subpath self-import smoke test — closes the gap flagged in the M4 docs primer
 * ("tests miss the gap because all imports are relative; package-name imports
 * are never exercised").
 *
 * Imports vaglio via its own package name (Node self-reference) so the
 * package.json#exports map is the resolution path. Runs against the BUILT
 * artifact in dist/. Excluded from the default `pnpm test` suite via
 * vitest.config.ts; invoked separately by `pnpm test:exports` after `pnpm build`.
 *
 * Verifies:
 *   1. Exports map declarations resolve at runtime.
 *   2. Re-exported symbols are present on the resolved module objects.
 *   3. Internal helpers (redactCore, redactSilent, findHoldbackCutoff,
 *      stripAnsiEscapes, etc.) are NOT reachable through the subpath surface
 *      — these are deliberately gated to prevent partial-defense misuse.
 */
import { describe, expect, it } from 'vitest';

describe('vaglio root exports', () => {
  it('resolves the root subpath', async () => {
    const root = await import('vaglio');
    expect(typeof root.sanitize).toBe('function');
    expect(typeof root.sanitizeDetailed).toBe('function');
    expect(typeof root.policy).toBe('function');
    expect(root.DEFAULT_POLICY).toBeDefined();
  });
});

describe('vaglio/unicode subpath', () => {
  it('exposes the composed pipeline + low-level helpers', async () => {
    const mod = await import('vaglio/unicode');
    expect(typeof mod.stripUnicode).toBe('function');
    expect(typeof mod.stripUnicodeDetailed).toBe('function');
    expect(typeof mod.normalizeNFKC).toBe('function');
    expect(typeof mod.capCombiningMarks).toBe('function');
  });

  it('does NOT expose internal granular strippers (deferred to v0.2)', async () => {
    const mod = (await import('vaglio/unicode')) as Record<string, unknown>;
    // Granular variants per spec-api §1 (post-amendment) ship in v0.2.
    // Defenders must not be able to ship strict subsets of the composed pipeline
    // and lose the load-bearing pipeline order.
    expect(mod.stripAnsiEscapes).toBeUndefined();
    expect(mod.stripOrphanedSurrogates).toBeUndefined();
    expect(mod.stripBidi).toBeUndefined();
    expect(mod.stripZeroWidth).toBeUndefined();
  });

  it('subpath stripUnicode and root stripUnicode are the same function', async () => {
    const sub = await import('vaglio/unicode');
    const root = await import('vaglio');
    expect(sub.stripUnicode).toBe(root.stripUnicode);
    expect(sub.stripUnicodeDetailed).toBe(root.stripUnicodeDetailed);
  });
});

describe('vaglio/credentials subpath', () => {
  it('exposes redact + redactDetailed + DEFAULT_CREDENTIAL_PATTERNS', async () => {
    const mod = await import('vaglio/credentials');
    expect(typeof mod.redact).toBe('function');
    expect(typeof mod.redactDetailed).toBe('function');
    expect(Array.isArray(mod.DEFAULT_CREDENTIAL_PATTERNS)).toBe(true);
    expect(mod.DEFAULT_CREDENTIAL_PATTERNS.length).toBeGreaterThan(0);
  });

  it('does NOT expose internal cross-module plumbing', async () => {
    const mod = (await import('vaglio/credentials')) as Record<string, unknown>;
    // These are internal helpers whose contracts are not v0.1-frozen.
    // Exposing them would lock the v0.2 refactor surface.
    expect(mod.redactCore).toBeUndefined();
    expect(mod.redactSilent).toBeUndefined();
    expect(mod.findHoldbackCutoff).toBeUndefined();
  });

  it('subpath redact and root redact are the same function', async () => {
    const sub = await import('vaglio/credentials');
    const root = await import('vaglio');
    expect(sub.redact).toBe(root.redact);
    expect(sub.redactDetailed).toBe(root.redactDetailed);
  });
});

describe('vaglio/tags subpath', () => {
  it('exposes stripTags + stripTagsDetailed + DEFAULT_REASONING_TAGS', async () => {
    const mod = await import('vaglio/tags');
    expect(typeof mod.stripTags).toBe('function');
    expect(typeof mod.stripTagsDetailed).toBe('function');
    expect(Array.isArray(mod.DEFAULT_REASONING_TAGS)).toBe(true);
  });

  it('subpath stripTags and root stripTags are the same function', async () => {
    const sub = await import('vaglio/tags');
    const root = await import('vaglio');
    expect(sub.stripTags).toBe(root.stripTags);
    expect(sub.stripTagsDetailed).toBe(root.stripTagsDetailed);
  });
});

describe('subpath functional smoke (defense surface intact)', () => {
  it('vaglio/unicode stripUnicode strips zero-width via subpath', async () => {
    const { stripUnicode } = await import('vaglio/unicode');
    const zwsp = '​';
    const out = stripUnicode(`hel${zwsp}lo`);
    expect(out).toBe('hello');
  });

  it('vaglio/credentials redact via subpath', async () => {
    const { redact } = await import('vaglio/credentials');
    const out = redact(
      'sk-ant-api03-deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefAA'
    );
    expect(out).toContain('<credential>');
  });

  it('vaglio/tags stripTags via subpath', async () => {
    const { stripTags } = await import('vaglio/tags');
    const out = stripTags('keep<internal>drop</internal>this');
    expect(out).toBe('keepthis');
  });
});
