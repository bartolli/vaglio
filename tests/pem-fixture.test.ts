import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { DEFAULT_CREDENTIAL_PATTERNS, redact } from '../src/credentials.js';

const FIXTURE_PATH = fileURLToPath(new URL('./fixtures/real-pem-rsa-4096.txt', import.meta.url));
const REAL_PEM = readFileSync(FIXTURE_PATH, 'utf8').trim();

describe('real RSA-4096 PEM fixture', () => {
  it('fixture is a well-formed PRIVATE KEY block', () => {
    expect(REAL_PEM).toMatch(/^-----BEGIN [A-Z ]*PRIVATE KEY-----/);
    expect(REAL_PEM).toMatch(/-----END [A-Z ]*PRIVATE KEY-----$/);
  });

  it('fixture length is what triggered the maxMatchLength bump (sanity anchor)', () => {
    // RSA-4096 PKCS#8 PEM measures ~3272 bytes; 3272 ± 32 covers minor format/newline
    // variation. The original spec value of 3072 was insufficient — that's the wake-up
    // surfaced by this fixture and the reason maxMatchLength is 4096.
    expect(REAL_PEM.length).toBeGreaterThanOrEqual(3000);
    expect(REAL_PEM.length).toBeLessThanOrEqual(3400);
  });

  it('PEM length fits within DEFAULT pem-private-key.maxMatchLength (with margin)', () => {
    // The bound must accommodate the real PEM with breathing room. If this
    // assertion fails, a real RSA-4096 PEM will bypass streaming redaction in M3
    // (the sliding-window buffer derives bufferLimit from maxMatchLength).
    const bound =
      DEFAULT_CREDENTIAL_PATTERNS.find((p) => p.ruleId === 'pem-private-key')?.maxMatchLength ?? 0;
    expect(bound).toBeGreaterThan(0);
    expect(REAL_PEM.length).toBeLessThan(bound);
  });

  it('redact replaces the entire real PEM block in surrounding context', () => {
    const wrapped = `config:\n${REAL_PEM}\nrest`;
    expect(redact(wrapped)).toBe('config:\n<credential>\nrest');
  });

  it('redact replaces the real PEM block when it is the entire input', () => {
    expect(redact(REAL_PEM)).toBe('<credential>');
  });

  it('redact replaces back-to-back real PEM blocks without spanning the boundary (lazy match)', () => {
    // Two real-sized PEM blocks adjacent. Lazy `[\s\S]*?` must terminate at the
    // first `-----END ... PRIVATE KEY-----`, not consume across into the second.
    const two = `${REAL_PEM}\nseparator\n${REAL_PEM}`;
    expect(redact(two)).toBe('<credential>\nseparator\n<credential>');
  });
});
