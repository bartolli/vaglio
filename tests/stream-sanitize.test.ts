import { describe, expect, it } from 'vitest';
import type {
  CredentialFinding,
  Finding,
  StreamDiagnosticFinding,
  UnicodeStripFinding
} from '../src/findings.js';
import type { SanitizeOptions } from '../src/policy.js';
import { policy } from '../src/policy.js';
import { sanitize } from '../src/sanitize.js';
import { createSanitizeStream, sanitizeIterable } from '../src/stream-sanitize.js';

// ─────────────────────────────────────────────────────────────────────────────
// Adapter helpers
// ─────────────────────────────────────────────────────────────────────────────

async function consumeStream(
  chunks: ReadonlyArray<string>,
  stream: TransformStream<string, string>
): Promise<string> {
  const writer = stream.writable.getWriter();
  const reader = stream.readable.getReader();
  const writePromise = (async () => {
    for (const c of chunks) await writer.write(c);
    await writer.close();
  })();
  let collected = '';
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    collected += value;
  }
  await writePromise;
  return collected;
}

async function consumeIter(
  src: Iterable<string> | AsyncIterable<string>,
  options?: SanitizeOptions
): Promise<string> {
  let collected = '';
  for await (const c of sanitizeIterable(src, options)) collected += c;
  return collected;
}

// ─────────────────────────────────────────────────────────────────────────────
// Batch 1 — engine smoke
// ─────────────────────────────────────────────────────────────────────────────

describe('createSanitizeStream — engine smoke', () => {
  it('passes clean ASCII through unchanged (single chunk)', async () => {
    const out = await consumeStream(['plain prose with no threats'], createSanitizeStream());
    expect(out).toBe('plain prose with no threats');
  });

  it('runs the full pipeline in a single chunk (zwsp + tag + credential)', async () => {
    const input = '​<internal>secret</internal> key=AKIAIOSFODNN7EXAMPLE rest';
    const out = await consumeStream([input], createSanitizeStream());
    expect(out).toBe(' key=<credential> rest');
  });

  it('empty input + close → empty output', async () => {
    const out = await consumeStream([], createSanitizeStream());
    expect(out).toBe('');
  });

  it('empty chunks are no-ops', async () => {
    const out = await consumeStream(['', 'AKIAIOSFODNN7EXAMPLE', ''], createSanitizeStream());
    expect(out).toBe('<credential>');
  });
});

describe('sanitizeIterable — engine smoke', () => {
  it('passes clean ASCII through unchanged', async () => {
    const out = await consumeIter(['plain prose with no threats']);
    expect(out).toBe('plain prose with no threats');
  });

  it('strips a reasoning tag split into many small chunks', async () => {
    const input = '<internal>secret thoughts</internal>after';
    const carriers = input.split(''); // one codepoint per chunk
    const out = await consumeIter(carriers);
    expect(out).toBe('after');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Batch 2 — cross-chunk pipeline composition
// ─────────────────────────────────────────────────────────────────────────────

describe('createSanitizeStream — cross-chunk pipeline', () => {
  it('zwsp-laced credential split across chunks: stripUnicode glues the credential, then redact fires', async () => {
    // Chunk 1 ends with the ZWSP between AWS-key chars; chunk 2 carries the rest.
    // After stripUnicode joins the buffer, the credential is whole and redact matches.
    const findings: Finding[] = [];
    const out = await consumeStream(
      ['prefix AKIA​', 'IOSFODNN7EXAMPLE suffix'],
      createSanitizeStream({ onFinding: (f) => findings.push(f) })
    );
    expect(out).toBe('prefix <credential> suffix');

    const zwsp = findings.find(
      (f) => f.kind === 'unicode-strip' && f.charClass.includes('U+200B')
    ) as UnicodeStripFinding | undefined;
    expect(zwsp).toBeDefined();

    const cred = findings.find((f) => f.kind === 'credential' && f.ruleId === 'aws-access-key') as
      | CredentialFinding
      | undefined;
    expect(cred).toBeDefined();
  });

  it('fullwidth tag brackets cross chunks: NFKC folds, then stripTags strips', async () => {
    // U+FF1C / U+FF1E are fullwidth `<` / `>`; NFKC folds them to ASCII <,>.
    // Split the open bracket across chunks → only the buffered union normalizes
    // and stripTags can match the resulting <internal>...</internal> block.
    const out = await consumeStream(
      ['head ＜inter', 'nal＞secret＜/internal＞ tail'],
      createSanitizeStream()
    );
    expect(out).toBe('head  tail');
  });

  it('reasoning-tag block split mid-content: buffered close completes the block', async () => {
    const findings: Finding[] = [];
    const out = await consumeStream(
      ['<internal>secret', ' more text</internal>after'],
      createSanitizeStream({ onFinding: (f) => findings.push(f) })
    );
    expect(out).toBe('after');

    const tag = findings.find((f) => f.kind === 'unicode-strip' && f.ruleId === 'reasoning-tag') as
      | UnicodeStripFinding
      | undefined;
    expect(tag).toBeDefined();
    expect(tag?.charClass).toBe('internal');
  });

  it('credential straddling a chunk boundary inside a closed reasoning tag is removed by tag-strip alone', async () => {
    // The block fully closes within the buffer → stripTags removes the whole
    // block, including the credential, before redact runs. Defense-in-depth
    // not needed here, but still: no credential leaks.
    const out = await consumeStream(
      ['<internal>token=AKIAIOSFO', 'DNN7EXAMPLE</internal>tail'],
      createSanitizeStream()
    );
    expect(out).toBe('tail');
  });
});

describe('createSanitizeStream — reasoning-tag-block overflow', () => {
  it('oversized open tag never closes within bufferLimit: filler slides downstream and overflow fires', async () => {
    // Open <internal>, then 6000 chars of inert filler, no close. bufferLimit
    // is 4160 by default; the buffer fills with the unclosed block content,
    // slides the oldest bytes downstream, and overflow fires.
    const findings: Finding[] = [];
    const filler = 'x'.repeat(6000);
    const out = await consumeStream(
      [`<internal>${filler}`],
      createSanitizeStream({ onFinding: (f) => findings.push(f) })
    );

    // Tag never closed → strip never fires → all bytes leak through verbatim
    // (slide-emit during push + flush at end). The semantic guarantee for
    // v0.1 is the overflow warning, not buffered suppression.
    expect(out).toBe(`<internal>${filler}`);

    const overflow = findings.find(
      (f) => f.kind === 'stream-diagnostic' && f.ruleId === 'buffer-overflow-warning'
    );
    expect(overflow).toBeDefined();

    const tag = findings.find((f) => f.kind === 'unicode-strip' && f.ruleId === 'reasoning-tag');
    expect(tag).toBeUndefined();
  });

  it('oversized open tag with a credential inside: credential still redacts at the redact stage (defense-in-depth)', async () => {
    // The block doesn't close within bufferLimit, so stripTags can't remove
    // the credential. But redact runs against the same buffer and matches
    // the credential independently → it still gets <credential>.
    const findings: Finding[] = [];
    const filler = 'x'.repeat(3000);
    const out = await consumeStream(
      [`<internal>${filler}AKIAIOSFODNN7EXAMPLE${filler}`],
      createSanitizeStream({ onFinding: (f) => findings.push(f) })
    );

    expect(out).toContain('<credential>');
    expect(out).not.toContain('AKIAIOSFODNN7EXAMPLE');

    const cred = findings.find((f) => f.kind === 'credential' && f.ruleId === 'aws-access-key');
    expect(cred).toBeDefined();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Batch 3 — cancel + overflow contract (mirrors E.1)
// ─────────────────────────────────────────────────────────────────────────────

describe('createSanitizeStream — cancel', () => {
  it('readable.cancel(reason) fires stream-canceled finding carrying the reason', async () => {
    const findings: Finding[] = [];
    const stream = createSanitizeStream({ onFinding: (f) => findings.push(f) });

    const writer = stream.writable.getWriter();
    const reader = stream.readable.getReader();
    void writer.write('partial <inter').catch(() => {});

    await reader.cancel('user navigated away');

    const finding = findings.find(
      (f) => f.kind === 'stream-diagnostic' && f.ruleId === 'stream-canceled'
    ) as StreamDiagnosticFinding | undefined;
    expect(finding).toBeDefined();
    expect(finding?.message).toContain('user navigated away');

    writer.releaseLock();
  });

  it('cancel discards a buffered partial tag block; no reasoning-tag finding fires', async () => {
    const findings: Finding[] = [];
    const stream = createSanitizeStream({ onFinding: (f) => findings.push(f) });
    const writer = stream.writable.getWriter();
    const reader = stream.readable.getReader();

    // Big enough to definitely run transform; ends mid-block (no </internal>).
    const partial = `<internal>${'x'.repeat(5000)}`;
    const w = writer.write(partial);
    const r = await reader.read();
    expect(r.done).toBe(false);
    await w;

    await reader.cancel('partial-block test');

    const tag = findings.find((f) => f.kind === 'unicode-strip' && f.ruleId === 'reasoning-tag');
    expect(tag).toBeUndefined();

    const canceled = findings.find(
      (f) => f.kind === 'stream-diagnostic' && f.ruleId === 'stream-canceled'
    );
    expect(canceled).toBeDefined();

    writer.releaseLock();
  });
});

describe('sanitizeIterable — cancel via consumer break', () => {
  it('consumer break mid-stream emits stream-canceled finding', async () => {
    const findings: Finding[] = [];
    const big = 'x'.repeat(6000);
    async function* source(): AsyncIterable<string> {
      yield big;
      yield 'never reached';
    }
    const collected: string[] = [];
    for await (const c of sanitizeIterable(source(), { onFinding: (f) => findings.push(f) })) {
      collected.push(c);
      if (collected.length === 1) break;
    }
    const cancel = findings.find(
      (f) => f.kind === 'stream-diagnostic' && f.ruleId === 'stream-canceled'
    );
    expect(cancel).toBeDefined();
  });

  it('source error rethrows; no stream-canceled finding fires', async () => {
    const findings: Finding[] = [];
    async function* badSource(): AsyncIterable<string> {
      yield 'plain text ';
      throw new Error('source kaboom');
    }
    await expect(consumeIter(badSource(), { onFinding: (f) => findings.push(f) })).rejects.toThrow(
      'source kaboom'
    );
    const canceled = findings.find(
      (f) => f.kind === 'stream-diagnostic' && f.ruleId === 'stream-canceled'
    );
    expect(canceled).toBeUndefined();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Batch 4 — overflow warning (extends E.1 trigger to substantive findings)
// ─────────────────────────────────────────────────────────────────────────────

describe('createSanitizeStream — buffer overflow warning', () => {
  it('fires when slide-emit happens with no substantive findings (no strips, no creds, no tags)', async () => {
    const findings: Finding[] = [];
    const filler = 'x'.repeat(6000);
    await consumeStream([filler], createSanitizeStream({ onFinding: (f) => findings.push(f) }));
    const overflow = findings.find(
      (f) => f.kind === 'stream-diagnostic' && f.ruleId === 'buffer-overflow-warning'
    ) as StreamDiagnosticFinding | undefined;
    expect(overflow).toBeDefined();
    expect(overflow?.severity).toBe('low');
    expect(overflow?.message).toContain('consumedBytes=');
  });

  it('suppressed when a credential matched in the same push (substantive activity)', async () => {
    const findings: Finding[] = [];
    const padded = `${'x'.repeat(3000)}AKIAIOSFODNN7EXAMPLE${'y'.repeat(3000)}`;
    await consumeStream([padded], createSanitizeStream({ onFinding: (f) => findings.push(f) }));
    const overflow = findings.find(
      (f) => f.kind === 'stream-diagnostic' && f.ruleId === 'buffer-overflow-warning'
    );
    expect(overflow).toBeUndefined();
  });

  it('suppressed when a unicode-strip happened in the same push (substantive activity)', async () => {
    const findings: Finding[] = [];
    // 6000 unmatched chars, but stuff a single ZWSP in there → unicode-strip
    // fires → overflow suppressed even though slide-emit happens.
    const padded = `${'x'.repeat(3000)}​${'y'.repeat(3000)}`;
    await consumeStream([padded], createSanitizeStream({ onFinding: (f) => findings.push(f) }));
    const overflow = findings.find(
      (f) => f.kind === 'stream-diagnostic' && f.ruleId === 'buffer-overflow-warning'
    );
    expect(overflow).toBeUndefined();

    const strip = findings.find((f) => f.kind === 'unicode-strip');
    expect(strip).toBeDefined();
  });

  it('does not fire for steady-state below bufferLimit', async () => {
    const findings: Finding[] = [];
    const chunks = Array.from({ length: 50 }, () => 'small ');
    await consumeStream(chunks, createSanitizeStream({ onFinding: (f) => findings.push(f) }));
    const overflow = findings.find(
      (f) => f.kind === 'stream-diagnostic' && f.ruleId === 'buffer-overflow-warning'
    );
    expect(overflow).toBeUndefined();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Batch 5 — finding offset frame (v0.1 contract pin)
//
// Streaming + composed pipeline: `Finding.offset = stage_local_offset +
// consumedBytes`. The stage_local_offset inherits Slice D's cross-stage frame
// (each stage's offset is in input-to-that-stage). Pinned here so the v0.1
// contract is regression-protected.
// ─────────────────────────────────────────────────────────────────────────────

describe('createSanitizeStream — finding offset frame (v0.1)', () => {
  it('single-chunk credential offset matches the post-prior-stages position', async () => {
    // No unicode strips, no tags → redact's input == buffer == input, so
    // the credential offset is the literal position in the chunk.
    const findings: Finding[] = [];
    const input = 'prefix AKIAIOSFODNN7EXAMPLE suffix';
    await consumeStream([input], createSanitizeStream({ onFinding: (f) => findings.push(f) }));
    const cred = findings.find((f) => f.kind === 'credential' && f.ruleId === 'aws-access-key') as
      | CredentialFinding
      | undefined;
    expect(cred).toBeDefined();
    expect(cred?.offset).toBe(7);
  });

  it('credential straddling a chunk boundary carries an absolute offset (consumedBytes added)', async () => {
    // 5000 chars of inert filler → slide-emit 5000 - 4160 = 840 chars (since
    // the pipeline is a no-op on filler, processed.length = buffer.length).
    // Chunk 2 = AWS key. After unicode + tags pass through, redact matches
    // at buffer index 4160. baseOffset = consumedBytes-at-call = 840.
    // finding.offset = 840 + 4160 = 5000.
    const findings: Finding[] = [];
    const filler = 'x'.repeat(5000);
    const cred = 'AKIAIOSFODNN7EXAMPLE';
    await consumeStream(
      [filler, cred],
      createSanitizeStream({ onFinding: (f) => findings.push(f) })
    );

    const found = findings.find((f) => f.kind === 'credential' && f.ruleId === 'aws-access-key') as
      | CredentialFinding
      | undefined;
    expect(found).toBeDefined();
    expect(found?.offset).toBe(5000);
  });

  it('cross-stage AND cross-push: both stripUnicode and stripTags findings carry the same baseOffset shift', async () => {
    // Push 1: 5000 unmatched filler → slide-emit 840 chars; consumedBytes = 840.
    // Buffer retains the trailing 4160 filler chars.
    // Push 2 chunk = ZWSP + `<internal>x</internal>` appended → buffer = 4183.
    // ZWSP is at stripUnicode-input offset 4160 (after the filler tail);
    // after strip, the tag block sits at stripTags-input offset 4160.
    // Both findings shift by baseOffset = consumedBytes-at-call = 840 →
    // absolute offset = 4160 + 840 = 5000 for both stages.
    const findings: Finding[] = [];
    const filler = 'x'.repeat(5000);
    await consumeStream(
      [filler, '​<internal>x</internal>'],
      createSanitizeStream({ onFinding: (f) => findings.push(f) })
    );

    const zwsp = findings.find(
      (f) => f.kind === 'unicode-strip' && f.charClass.includes('U+200B')
    ) as UnicodeStripFinding | undefined;
    const tag = findings.find((f) => f.kind === 'unicode-strip' && f.ruleId === 'reasoning-tag') as
      | UnicodeStripFinding
      | undefined;

    expect(zwsp).toBeDefined();
    expect(tag).toBeDefined();
    // Same baseOffset shift applied to both stages on this push.
    expect(zwsp?.offset).toBe(5000);
    expect(tag?.offset).toBe(5000);
  });

  it('cross-stage offset frame: zwsp at 0 followed by tag at 1 (post-strip frame), reasoning-tag offset is 0', async () => {
    // ZWSP at offset 0 in pre-NFKC buffer (Slice A frame).
    // After stripUnicode the buffer is "<internal>x</internal>" → tag block
    // starts at offset 0 in the stripTags-input frame (Slice C frame).
    // Both findings emit with consumedBytes=0 baseOffset (no prior emit).
    const findings: Finding[] = [];
    await consumeStream(
      ['​<internal>x</internal>'],
      createSanitizeStream({ onFinding: (f) => findings.push(f) })
    );

    const zwsp = findings.find(
      (f) => f.kind === 'unicode-strip' && f.charClass.includes('U+200B')
    ) as UnicodeStripFinding | undefined;
    expect(zwsp?.offset).toBe(0);

    const tag = findings.find((f) => f.kind === 'unicode-strip' && f.ruleId === 'reasoning-tag') as
      | UnicodeStripFinding
      | undefined;
    expect(tag?.offset).toBe(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Batch 6 — custom policy plumbing
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// Batch 7 — trailing-edge ZWJ holdback (stream/batch equivalence)
//
// stripNonEmojiZwj checks the codepoint after each ZWJ to decide if it sits
// in a legitimate emoji ligature. Without holdback, a chunk boundary right
// after a ZWJ would have the ZWJ stripped as orphan because the after-codepoint
// is undefined at evaluation time — making the streaming output diverge from
// the batch output for the same concatenated input. That divergence is
// adversary-controllable (chunk size is often outside the consumer's hands)
// so it's a contract bug, not a cosmetic ligature break. Pinned here.
// ─────────────────────────────────────────────────────────────────────────────

describe('createSanitizeStream — trailing-edge ZWJ holdback', () => {
  it('legitimate emoji-ZWJ-emoji ligature split mid-ZWJ preserves the ZWJ', async () => {
    // U+1F468 man + U+200D ZWJ + U+1F469 woman. Split between ZWJ and the
    // start of the second emoji's surrogate pair.
    const findings: Finding[] = [];
    const out = await consumeStream(
      ['\u{1F468}‍', '\u{1F469}'],
      createSanitizeStream({ onFinding: (f) => findings.push(f) })
    );
    expect(out).toBe('\u{1F468}‍\u{1F469}');

    // No ZWJ stripping should fire — the ligature is legitimate.
    const zwjStrip = findings.find(
      (f) => f.kind === 'unicode-strip' && f.charClass.includes('U+200D')
    );
    expect(zwjStrip).toBeUndefined();
  });

  it('adversarial trailing ZWJ next to non-emoji still strips on next push', async () => {
    // chunk 1 ends `hello<ZWJ>`; chunk 2 = `world`. ZWJ has non-emoji on
    // both sides on next push → strip. Holdback only defers the decision;
    // it doesn't preserve adversarial ZWJs.
    const out = await consumeStream(['hello‍', 'world'], createSanitizeStream());
    expect(out).toBe('helloworld');
  });

  it('trailing ZWJ on flush (source exhausted) is stripped as orphan', async () => {
    // Source ends with `<emoji><ZWJ>` and no further data ever arrives.
    // Flush evaluates without holdback — the deferred ZWJ has no future
    // partner so the orphan-strip is correct.
    const out = await consumeStream(['hello\u{1F468}‍'], createSanitizeStream());
    expect(out).toBe('hello\u{1F468}');
  });

  it('stream output equals batch output at every codepoint-aligned split of an emoji-ZWJ-emoji ligature', async () => {
    // Property pin for the stream/batch equivalence contract under
    // adversary-controlled chunking. Splits at codepoint boundaries only
    // (mid-surrogate splits would test orphan-surrogate handling — a
    // separate concern).
    const input = '\u{1F468}‍\u{1F469}';
    const batchOut = sanitize(input);
    const codepointSplits = [2, 3]; // after first emoji (2 units), after ZWJ (1 unit)
    for (const i of codepointSplits) {
      const streamOut = await consumeStream(
        [input.slice(0, i), input.slice(i)],
        createSanitizeStream()
      );
      expect(streamOut, `split at codepoint boundary ${i}`).toBe(batchOut);
    }
  });
});

describe('createSanitizeStream — custom policy', () => {
  it('user-supplied credential pattern via policy() builder redacts in stream', async () => {
    const customPolicy = policy()
      .addCredentialPattern(/myorg-[A-Z0-9]{12}/g, {
        ruleId: 'myorg-key',
        placeholder: '<myorg>'
      })
      .build();
    const out = await consumeStream(
      ['hello myorg-ABCDEF123456 world'],
      createSanitizeStream({ policy: customPolicy })
    );
    expect(out).toBe('hello <myorg> world');
  });

  it('user-supplied reasoning tag via policy() builder strips in stream', async () => {
    const customPolicy = policy().addReasoningTag('thinking').build();
    const out = await consumeStream(
      ['a<thinking>plan', ' more</thinking>b'],
      createSanitizeStream({ policy: customPolicy })
    );
    expect(out).toBe('ab');
  });
});
