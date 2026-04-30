/**
 * M3.6 — fast-check property suites for the streaming surface.
 *
 * Three property surfaces, one file:
 *
 *   - **Boundary fuzz (checkbox 1).** 1k iterations of carrier+credential
 *     embeddings split at every chunk boundary. Asserts streaming output
 *     equals batch output (which is the strict superset of "100% redaction":
 *     if batch redacts, stream must redact identically; if a chunk boundary
 *     lands inside the credential, the placeholder still appears in the
 *     stream output and the original credential bytes do not leak).
 *
 *   - **Stream ≡ batch invariance (checkbox 2).** For arbitrary input and
 *     arbitrary chunking (bounded below `bufferLimit`), the streaming
 *     output equals the batch output for both `redact` and `sanitize`.
 *     The trailing-edge ZWJ holdback (Slice E.2 v0.1 contract) gets a
 *     dedicated property over emoji-ZWJ ligature inputs split at every
 *     codepoint-aligned boundary.
 *
 *   - **Telemetry kinds + `onFinding` invariants (checkbox 3).** Every
 *     `Finding.kind` (`unicode-strip`, `credential`, `stream-diagnostic`)
 *     emits at least once; every emitted finding is frozen; `onFinding`
 *     fires once per finding present in `sanitizeDetailed`'s merged
 *     result; `stream-canceled` fires only on consumer-initiated cancel,
 *     not on source-thrown errors (M3.5b source-error semantics).
 *
 * Chunking note: all chunk-boundary arbitraries operate on **codepoint
 * arrays** (`[...s]`) rather than UTF-16 indices. Splitting between UTF-16
 * units of a surrogate pair would manufacture orphan surrogates that
 * `stripOrphanedSurrogates` legitimately strips — making stream and
 * batch diverge for a reason that's a test artifact, not a contract bug.
 */

import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import {
  type CredentialFinding,
  type Finding,
  redact,
  redactIterable,
  sanitize,
  sanitizeDetailed,
  sanitizeIterable
} from '../src/index.js';

// ─────────────────────────────────────────────────────────────────────────────
// Streaming helpers
// ─────────────────────────────────────────────────────────────────────────────

async function streamRedact(
  chunks: ReadonlyArray<string>,
  onFinding?: (f: Finding) => void
): Promise<string> {
  let out = '';
  const opts = onFinding !== undefined ? { onFinding } : undefined;
  for await (const c of redactIterable(chunks, opts)) out += c;
  return out;
}

async function streamSanitize(
  chunks: ReadonlyArray<string>,
  onFinding?: (f: Finding) => void
): Promise<string> {
  let out = '';
  const opts = onFinding !== undefined ? { onFinding } : undefined;
  for await (const c of sanitizeIterable(chunks, opts)) out += c;
  return out;
}

/**
 * Split a codepoint array at the given boundaries (deduped, sorted, clamped
 * to interior positions). Returns string chunks suitable for the streaming
 * adapters. Empty resulting chunks are preserved (the engine treats them as
 * no-ops, but we want to exercise that path too).
 */
function chunkAtCodepoints(
  cps: ReadonlyArray<string>,
  boundaries: ReadonlyArray<number>
): string[] {
  if (cps.length === 0) return [''];
  const sorted = Array.from(new Set(boundaries))
    .map((b) => Math.max(0, Math.min(cps.length, b)))
    .sort((a, b) => a - b)
    .filter((b) => b > 0 && b < cps.length);
  const chunks: string[] = [];
  let prev = 0;
  for (const b of sorted) {
    chunks.push(cps.slice(prev, b).join(''));
    prev = b;
  }
  chunks.push(cps.slice(prev).join(''));
  return chunks;
}

// ─────────────────────────────────────────────────────────────────────────────
// Carrier + credential arbitraries (boundary-fuzz block)
// ─────────────────────────────────────────────────────────────────────────────

// Carrier alphabet: lowercase letters + space + a few non-word punctuation.
// Excludes digits, _, -, [, <, > so the carrier alone never matches a builtin
// credential or tag-block pattern by accident. The bookend space around an
// embedded credential satisfies `\b` for the long-hex pattern.
const CARRIER_CHARS = 'abcdefghijklmnopqrstuvwxyz .,!?\n';
const carrierString = fc
  .array(fc.constantFrom(...CARRIER_CHARS), { maxLength: 200 })
  .map((arr) => arr.join(''));

const AWS_BODY = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
const HEX_BODY = '0123456789abcdef';
const ALNUM = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
const ALNUM_HYPHEN = `${ALNUM}-`;
const ALNUM_UNDER_HYPHEN = `${ALNUM}_-`;
const JWT_BODY = `${ALNUM}._-`;

const awsKey = fc
  .tuple(
    fc.constantFrom('AKIA', 'ASIA'),
    fc.array(fc.constantFrom(...AWS_BODY), { minLength: 16, maxLength: 16 })
  )
  .map(([prefix, body]) => `${prefix}${body.join('')}`);

const anthropicToken = fc
  .array(fc.constantFrom(...ALNUM_UNDER_HYPHEN), { minLength: 20, maxLength: 60 })
  .map((arr) => `sk-ant-${arr.join('')}`);

const githubPat = fc
  .array(fc.constantFrom(...ALNUM), { minLength: 36, maxLength: 36 })
  .map((arr) => `ghp_${arr.join('')}`);

const slackToken = fc
  .tuple(
    fc.constantFrom('xoxb-', 'xoxp-'),
    fc.array(fc.constantFrom(...ALNUM_HYPHEN), { minLength: 20, maxLength: 60 })
  )
  .map(([prefix, body]) => `${prefix}${body.join('')}`);

const stripeKey = fc
  .array(fc.constantFrom(...ALNUM), { minLength: 20, maxLength: 60 })
  .map((arr) => `rk_live_${arr.join('')}`);

const jwtToken = fc
  .array(fc.constantFrom(...JWT_BODY), { minLength: 50, maxLength: 100 })
  .map((arr) => `Bearer eyJ${arr.join('')}`);

const longHex = fc
  .array(fc.constantFrom(...HEX_BODY), { minLength: 64, maxLength: 96 })
  .map((arr) => arr.join(''));

// PEM is excluded from the boundary-fuzz arbitrary by design: its
// `maxMatchLength` is 4096 and the default `bufferLimit` is 4160, so a
// carrier of any nontrivial size pushes total input past `bufferLimit` and
// triggers slide-emit. That doesn't violate any contract — it just means
// stream output legitimately differs from the batch path. PEM is covered
// in `tests/pem-fixture.test.ts` (real RSA-4096 fixture) and
// `tests/stream-redact.test.ts` (PEM split mid-body).
const credentialArb = fc.oneof(
  awsKey,
  anthropicToken,
  githubPat,
  slackToken,
  stripeKey,
  jwtToken,
  longHex
);

interface FuzzCase {
  input: string;
  cred: string;
  /** Codepoint indices (interior to `input`) where chunks are cut. */
  boundaries: number[];
}

/**
 * Embed a credential between two carrier strings with whitespace bookends
 * (so `\b`-anchored patterns match) and supply a guaranteed boundary inside
 * the credential plus a few random extra boundaries.
 */
const fuzzCase: fc.Arbitrary<FuzzCase> = fc
  .tuple(
    carrierString,
    credentialArb,
    carrierString,
    fc.nat(),
    fc.array(fc.nat(), { maxLength: 4 })
  )
  .map(([before, cred, after, splitOffset, extras]) => {
    const input = `${before} ${cred} ${after}`;
    const credStart = before.length + 1;
    const inCredBoundary = credStart + (splitOffset % cred.length);
    return { input, cred, boundaries: [inCredBoundary, ...extras] };
  });

// ─────────────────────────────────────────────────────────────────────────────
// Block A — boundary fuzz (M3.6 checkbox 1)
// ─────────────────────────────────────────────────────────────────────────────

describe('properties — credential boundary fuzz (M3.6 checkbox 1)', () => {
  it('1000 iterations: stream redact equals batch redact across credential chunk splits', async () => {
    await fc.assert(
      fc.asyncProperty(fuzzCase, async ({ input, cred, boundaries }) => {
        const cps = [...input];
        const chunks = chunkAtCodepoints(cps, boundaries);
        const stream = await streamRedact(chunks);
        const batch = redact(input);
        expect(stream).toBe(batch);
        // Strict redaction claim: the credential is gone from the stream output
        // AND the placeholder is present. Strict equivalence above already
        // implies these (since batch always redacts the embedded cred), but
        // pinning them separately makes the security contract explicit.
        expect(batch.includes('<credential>')).toBe(true);
        expect(stream.includes('<credential>')).toBe(true);
        expect(stream.includes(cred)).toBe(false);
      }),
      { numRuns: 1000 }
    );
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Partial-prefix + oversized-match contract pins (per advisor pass on M3.6)
// ─────────────────────────────────────────────────────────────────────────────

describe('properties — option-B holdback contract pins', () => {
  it("partial pattern prefix split mid-prefix: 'Bearer eyJ' + body still redacts", async () => {
    // The buffer must exceed K (default 4160) so the engine actually commits
    // bytes downstream on push 1 — otherwise no holdback decision is exercised
    // and the pin doesn't distinguish B1's K-char evaluation holdback from a
    // hypothetical "end-of-buffer-only" holdback. Pad with 5000 unmatched
    // chars before "Bearer eyJ" so push 1 commits leading bytes; the partial
    // prefix straddles the chunk boundary and must be retained, not leaked.
    const padding = 'x'.repeat(5000);
    const body = 'a'.repeat(60);
    const input = `${padding} Bearer eyJa${body} suffix`;
    // Split codepoint position: after "Bearer eyJ" but before the body's
    // first char (5000 + 1 + 10 = 5011). Push 1 includes everything up to
    // and including "eyJ"; push 2 has the body. End-of-buffer-only holdback
    // would commit "Bearer eyJ" in push 1 (no match yet), leak it downstream,
    // and miss the JWT entirely. K-char holdback retains the trailing K
    // bytes (which include "Bearer eyJ"), so the JWT match completes when
    // push 2 brings the body.
    const cps = [...input];
    const splitAt = padding.length + 1 + 'Bearer eyJ'.length;
    const chunks = chunkAtCodepoints(cps, [splitAt]);
    const stream = await streamRedact(chunks);
    const batch = redact(input);
    expect(stream).toBe(batch);
    expect(batch.includes('<credential>')).toBe(true);
    expect(stream.includes('<credential>')).toBe(true);
    expect(stream.includes(`Bearer eyJa${body}`)).toBe(false);
    expect(stream.includes('Bearer eyJ')).toBe(false);
  });

  it('oversized credential (length > 2K) degrades with overflow warning, no full-cred leak', async () => {
    // bufferLimit defaults to 4160 (PEM 4096 + 64). A 9000-char hex string
    // matches `\b[0-9a-f]{64,}\b` greedy at one match of length 9000;
    // shrunk effCutoff would give heldTailLen = 9000 > 2*K = 8320, triggering
    // the degrade path. Leading region commits as a partial-match; held tail
    // commits at next push (or flush). Net: the original full-9000-char
    // string is not a contiguous substring of the output, and the placeholder
    // appears at least once. Overflow warning fires with `degraded` semantics.
    const oversize = '0'.repeat(9000);
    const input = ` ${oversize} `;
    const findings: Finding[] = [];
    const out = await streamRedact([input], (f) => findings.push(f));
    const overflow = findings.find(
      (f) => f.kind === 'stream-diagnostic' && f.ruleId === 'buffer-overflow-warning'
    );
    expect(overflow).toBeDefined();
    // Placeholder appears at least once.
    expect(out.includes('<credential>')).toBe(true);
    // The full original cred isn't a contiguous substring of the output.
    expect(out.includes(oversize)).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Block B — stream ≡ batch invariance (M3.6 checkbox 2)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * `fc.string({ unit: 'grapheme-composite' })` covers astral-plane code points
 * via valid surrogate pairs (no orphan surrogates), so codepoint-aligned
 * chunking via `[...s]` is safe. Bound input length below `bufferLimit`
 * (default 4160) to keep slide-emit out of the picture for these
 * generic-input properties — the boundary-fuzz block above already
 * exercises holdback semantics under credential pressure.
 */
const arbInput = fc.string({ unit: 'grapheme-composite', maxLength: 1500 });
const arbBoundaries = fc.array(fc.nat(), { maxLength: 12 });

describe('properties — stream ≡ batch invariance (M3.6 checkbox 2)', () => {
  it('redactIterable equals redact for arbitrary input + chunking', async () => {
    await fc.assert(
      fc.asyncProperty(arbInput, arbBoundaries, async (input, rawBoundaries) => {
        const cps = [...input];
        const boundaries = cps.length === 0 ? [] : rawBoundaries.map((n) => n % cps.length);
        const chunks = chunkAtCodepoints(cps, boundaries);
        const stream = await streamRedact(chunks);
        expect(stream).toBe(redact(input));
      }),
      { numRuns: 300 }
    );
  });

  it('sanitizeIterable equals sanitize for arbitrary input + chunking', async () => {
    await fc.assert(
      fc.asyncProperty(arbInput, arbBoundaries, async (input, rawBoundaries) => {
        const cps = [...input];
        const boundaries = cps.length === 0 ? [] : rawBoundaries.map((n) => n % cps.length);
        const chunks = chunkAtCodepoints(cps, boundaries);
        const stream = await streamSanitize(chunks);
        expect(stream).toBe(sanitize(input));
      }),
      { numRuns: 300 }
    );
  });

  /**
   * ZWJ-emoji ligature stress: pin the trailing-edge ZWJ holdback (Slice E.2
   * v0.1 contract). Generate sequences of {emoji, ZWJ, ASCII, ZWSP, fullwidth
   * digit, combining mark}, split at every codepoint-aligned boundary, and
   * verify stream ≡ batch sanitize. The trailing-edge ZWJ holdback ensures
   * the chunk-boundary case `<emoji><ZWJ>|<emoji>` doesn't strip the ZWJ as
   * orphan in stream while batch keeps it as a ligature joiner.
   */
  // (telemetry block follows — keep ordering: ZWJ stress → telemetry)
  it('sanitizeIterable equals sanitize for ZWJ-shape inputs at every boundary', async () => {
    const ligaturePart = fc.constantFrom(
      '\u{1F468}', // 👨
      '\u{1F469}', // 👩
      '\u{1F466}', // 👦
      '\u{1F467}', // 👧
      '‍', // ZWJ
      '​', // ZWSP
      '️', // VS-16 (BMP)
      'a',
      'B',
      ' ',
      '\u{FF11}', // fullwidth 1 (NFKC → 1)
      '́', // combining acute
      '\u{E0001}', // tag-block (astral; strip-set member)
      '\u{E0102}', // supplementary VS (astral; strip-set member)
      '\u{F0001}' // supplementary PUA (astral; strip-set member)
    );
    await fc.assert(
      fc.asyncProperty(
        fc.array(ligaturePart, { maxLength: 200 }),
        arbBoundaries,
        async (cps, rawBoundaries) => {
          const input = cps.join('');
          const boundaries = cps.length === 0 ? [] : rawBoundaries.map((n) => n % cps.length);
          const chunks = chunkAtCodepoints(cps, boundaries);
          const stream = await streamSanitize(chunks);
          expect(stream).toBe(sanitize(input));
        }
      ),
      { numRuns: 300 }
    );
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Block C — telemetry kinds + onFinding invariants (M3.6 checkbox 3)
// ─────────────────────────────────────────────────────────────────────────────

describe('properties — telemetry kinds + onFinding invariants (M3.6 checkbox 3)', () => {
  it('every Finding.kind emits at least once across constructed inputs', async () => {
    const collected: Finding[] = [];

    // Constructed input that should fire all three kinds across two streams.
    // Inputs combine: ZWSP (unicode-strip, kind: unicode-strip), an AWS access
    // key (credential, kind: credential), and an oversized hex run that
    // triggers degraded overflow (stream-diagnostic, kind: stream-diagnostic).
    const zwspAndKey = '​ start AKIAIOSFODNN7EXAMPLE end';
    const oversizeHex = ` ${'0'.repeat(9000)} `;

    await streamSanitize([zwspAndKey], (f) => collected.push(f));
    await streamRedact([oversizeHex], (f) => collected.push(f));

    const kinds = new Set(collected.map((f) => f.kind));
    expect(kinds.has('unicode-strip')).toBe(true);
    expect(kinds.has('credential')).toBe(true);
    expect(kinds.has('stream-diagnostic')).toBe(true);
  });

  it('every emitted finding is frozen', async () => {
    const findings: Finding[] = [];
    await streamSanitize([`​<internal>x</internal> AKIAIOSFODNN7EXAMPLE`], (f) => findings.push(f));
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(Object.isFrozen(f)).toBe(true);
    }
  });

  it('source-thrown error: no stream-canceled finding (M3.5b source-error semantics)', async () => {
    const findings: Finding[] = [];
    const erroringSource = (async function* () {
      yield 'hello ';
      throw new Error('source boom');
    })();

    let thrown: unknown;
    try {
      for await (const _ of redactIterable(erroringSource, {
        onFinding: (f) => findings.push(f)
      })) {
        // consume
      }
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(Error);
    expect((thrown as Error).message).toBe('source boom');
    const cancelFinding = findings.find(
      (f) => f.kind === 'stream-diagnostic' && f.ruleId === 'stream-canceled'
    );
    expect(cancelFinding).toBeUndefined();
  });

  it('consumer-initiated break: stream-canceled finding fires', async () => {
    const findings: Finding[] = [];
    // Chunks large enough to push the buffer past `K` (default 4160), so
    // `push()` yields downstream and the consumer-for-await loop body runs.
    // Without yielding, the consumer can't break mid-stream — it would just
    // hit the natural end-of-iterator boundary and finally would run with
    // `consumerAborted = false` (no stream-canceled finding).
    const cleanSource = (async function* () {
      yield 'a'.repeat(5000);
      yield 'b'.repeat(5000);
      yield 'c'.repeat(5000);
    })();

    let count = 0;
    for await (const _ of redactIterable(cleanSource, {
      onFinding: (f) => findings.push(f)
    })) {
      count++;
      if (count >= 1) break;
    }
    const cancelFinding = findings.find(
      (f) => f.kind === 'stream-diagnostic' && f.ruleId === 'stream-canceled'
    );
    expect(cancelFinding).toBeDefined();
  });

  it('sanitizeDetailed: onFinding callback observes the same findings as the result, in order', () => {
    const callbackFindings: Finding[] = [];
    const result = sanitizeDetailed(`​<internal>secret</internal> AKIAIOSFODNN7EXAMPLE`, {
      onFinding: (f) => callbackFindings.push(f)
    });
    // onFinding observes the merged stream; same as result.findings.
    expect(callbackFindings.length).toBe(result.findings.length);
    expect(callbackFindings).toEqual([...result.findings]);
  });

  it('credential findings carry placeholder + offset; arbitrary credential inputs', async () => {
    await fc.assert(
      fc.asyncProperty(fuzzCase, async ({ input, boundaries }) => {
        const cps = [...input];
        const chunks = chunkAtCodepoints(cps, boundaries);
        const findings: Finding[] = [];
        const out = await streamRedact(chunks, (f) => findings.push(f));
        const credFindings = findings.filter(
          (f): f is CredentialFinding => f.kind === 'credential'
        );
        expect(credFindings.length).toBeGreaterThan(0);
        for (const f of credFindings) {
          expect(typeof f.placeholder).toBe('string');
          expect(f.placeholder.length).toBeGreaterThan(0);
          expect(typeof f.offset).toBe('number');
          expect(f.offset).toBeGreaterThanOrEqual(0);
          expect(f.offset).toBeLessThanOrEqual(out.length);
          expect(f.length).toBeGreaterThan(0);
          expect(['low', 'medium', 'high', 'critical']).toContain(f.severity);
          expect(['stripped', 'redacted', 'replaced']).toContain(f.action);
        }
      }),
      { numRuns: 100 }
    );
  });
});
