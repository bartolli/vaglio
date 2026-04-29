import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import type { CredentialFinding, Finding, StreamDiagnosticFinding } from '../src/findings.js';
import type { SanitizeOptions } from '../src/policy.js';
import { policy } from '../src/policy.js';
import { createRedactStream, redactIterable } from '../src/stream-redact.js';

// ─────────────────────────────────────────────────────────────────────────────
// Adapter helpers — keep tests focused on engine behavior, not WHATWG plumbing.
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
  for await (const c of redactIterable(src, options)) collected += c;
  return collected;
}

// ─────────────────────────────────────────────────────────────────────────────
// Batch 1 — engine smoke (single-chunk happy paths, flush, double-flush, empty)
// ─────────────────────────────────────────────────────────────────────────────

describe('createRedactStream — engine smoke', () => {
  it('passes clean ASCII through unchanged (single chunk)', async () => {
    const out = await consumeStream(['plain prose with no threats'], createRedactStream());
    expect(out).toBe('plain prose with no threats');
  });

  it('redacts a credential in a single chunk', async () => {
    const out = await consumeStream(['key=AKIAIOSFODNN7EXAMPLE rest'], createRedactStream());
    expect(out).toBe('key=<credential> rest');
  });

  it('empty input + close → empty output (flush on empty buffer is benign)', async () => {
    const out = await consumeStream([], createRedactStream());
    expect(out).toBe('');
  });

  it('empty chunks are no-ops', async () => {
    const out = await consumeStream(['', 'AKIAIOSFODNN7EXAMPLE', ''], createRedactStream());
    expect(out).toBe('<credential>');
  });

  it('redacts back-to-back AWS keys without spanning the boundary (lazy-match invariant)', async () => {
    const back2back = 'AKIAIOSFODNN7EXAMPLEAKIAIOSFODNN7EXAMPLE';
    const out = await consumeStream([back2back], createRedactStream());
    expect(out).toBe('<credential><credential>');
  });
});

describe('redactIterable — engine smoke', () => {
  it('passes clean ASCII through unchanged', async () => {
    const out = await consumeIter(['plain prose with no threats']);
    expect(out).toBe('plain prose with no threats');
  });

  it('redacts a credential split into many small chunks (sub-credential chunks)', async () => {
    // Default policy contains aws-access-key matching /(?:AKIA|ASIA)[0-9A-Z]{16}/g.
    // Splitting into 1-char chunks must still redact — the buffer aggregates.
    const cred = 'AKIAIOSFODNN7EXAMPLE';
    const carriers = [`prefix `, ...cred.split(''), ` suffix`];
    const out = await consumeIter(carriers);
    expect(out).toBe('prefix <credential> suffix');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Batch 2 — cross-chunk redaction, custom policies, PEM, source-error
// ─────────────────────────────────────────────────────────────────────────────

describe('createRedactStream — cross-chunk redaction', () => {
  it('credential split at every internal boundary still redacts', async () => {
    const cred = 'AKIAIOSFODNN7EXAMPLE';
    for (let i = 1; i < cred.length; i++) {
      const out = await consumeStream([cred.slice(0, i), cred.slice(i)], createRedactStream());
      expect(out, `boundary ${i}`).toBe('<credential>');
    }
  });

  it('credential split with carrier prefix/suffix preserved verbatim', async () => {
    const out = await consumeStream(
      ['prefix AKIAIOSFO', 'DNN7EXAMPLE suffix'],
      createRedactStream()
    );
    expect(out).toBe('prefix <credential> suffix');
  });

  it('back-to-back AWS keys each split across the seam redact independently', async () => {
    const cred = 'AKIAIOSFODNN7EXAMPLE';
    const out = await consumeStream(
      [`${cred.slice(0, 10)}`, `${cred.slice(10)}${cred.slice(0, 10)}`, `${cred.slice(10)}`],
      createRedactStream()
    );
    expect(out).toBe('<credential><credential>');
  });

  it('synthetic PEM block split mid-body still redacts (covers default bufferLimit 4160)', async () => {
    const pem = [
      '-----BEGIN RSA PRIVATE KEY-----',
      'MIIEowIBAAKCAQEAvLxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
      'MIIEowIBAAKCAQEAvLyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy',
      '-----END RSA PRIVATE KEY-----'
    ].join('\n');
    const mid = Math.floor(pem.length / 2);
    const out = await consumeStream([pem.slice(0, mid), pem.slice(mid)], createRedactStream());
    expect(out).toBe('<credential>');
  });

  it('real RSA-4096 PEM fixture split mid-body still redacts (3272-byte PEM in 4160-byte window)', async () => {
    const fixturePath = fileURLToPath(new URL('./fixtures/real-pem-rsa-4096.txt', import.meta.url));
    const realPem = readFileSync(fixturePath, 'utf8').trim();
    const wrapped = `prefix\n${realPem}\nsuffix`;
    const mid = Math.floor(wrapped.length / 2);
    const out = await consumeStream(
      [wrapped.slice(0, mid), wrapped.slice(mid)],
      createRedactStream()
    );
    expect(out).toBe('prefix\n<credential>\nsuffix');
  });
});

describe('createRedactStream — custom policy', () => {
  it('user-supplied credential pattern via policy() builder redacts in stream', async () => {
    const customPolicy = policy()
      .addCredentialPattern(/myorg-[A-Z0-9]{12}/g, {
        ruleId: 'myorg-key',
        placeholder: '<myorg>'
      })
      .build();
    const out = await consumeStream(
      ['hello myorg-ABCDEF123456 world'],
      createRedactStream({ policy: customPolicy })
    );
    expect(out).toBe('hello <myorg> world');
  });

  it('non-global user RegExp is coerced to global at registration; cross-chunk still redacts', async () => {
    const customPolicy = policy()
      // Deliberately non-global; PolicyBuilder.addCredentialPattern coerces.
      .addCredentialPattern(/secret-[a-z]{8}/, { ruleId: 'secret-key' })
      .build();
    const out = await consumeStream(
      ['head secret-', 'abcdefgh tail'],
      createRedactStream({ policy: customPolicy })
    );
    expect(out).toBe('head <credential> tail');
  });
});

describe('redactIterable — source-error propagation', () => {
  it('rethrows when source iterable errors; no stream-canceled finding fires', async () => {
    const findings: Finding[] = [];
    async function* badSource(): AsyncIterable<string> {
      yield 'plain text ';
      throw new Error('source kaboom');
    }
    const seen = (...args: unknown[]) => findings.push(...(args as Finding[]));
    await expect(consumeIter(badSource(), { onFinding: (f) => seen(f) })).rejects.toThrow(
      'source kaboom'
    );
    const canceled = findings.find(
      (f) => f.kind === 'stream-diagnostic' && f.ruleId === 'stream-canceled'
    );
    expect(canceled).toBeUndefined();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Batch 3 — cancel paths + overflow warning
// ─────────────────────────────────────────────────────────────────────────────

describe('createRedactStream — cancel', () => {
  it('readable.cancel(reason) fires stream-canceled finding carrying the reason', async () => {
    const findings: Finding[] = [];
    const stream = createRedactStream({ onFinding: (f) => findings.push(f) });

    // Pump one chunk through, then cancel the readable side via its reader.
    // Reading the chunk first lets the writer.write() promise settle without
    // our depending on internal queueing semantics.
    const writer = stream.writable.getWriter();
    const reader = stream.readable.getReader();
    void writer.write('partial credentials AKI').catch(() => {});

    await reader.cancel('user navigated away');

    const finding = findings.find(
      (f) => f.kind === 'stream-diagnostic' && f.ruleId === 'stream-canceled'
    ) as StreamDiagnosticFinding | undefined;
    expect(finding).toBeDefined();
    expect(finding?.message).toContain('user navigated away');
    expect(finding?.severity).toBe('low');

    // Release locks so the writer doesn't keep the stream alive past the test.
    writer.releaseLock();
  });

  it('writable.abort(reason) also fires stream-canceled finding', async () => {
    const findings: Finding[] = [];
    const stream = createRedactStream({ onFinding: (f) => findings.push(f) });
    const writer = stream.writable.getWriter();
    const reader = stream.readable.getReader();

    void writer.write('hello AKI').catch(() => {});
    await writer.abort('shutting down');
    // Drain the reader so it doesn't hold the readable side open.
    await reader.cancel().catch(() => {});

    const finding = findings.find(
      (f) => f.kind === 'stream-diagnostic' && f.ruleId === 'stream-canceled'
    ) as StreamDiagnosticFinding | undefined;
    expect(finding).toBeDefined();
    expect(finding?.message).toContain('shutting down');
  });

  it('cancel without onFinding is benign (no error path)', async () => {
    // Smoke: cancel releases buffer + sets canceled flag; no onFinding means
    // no finding emit, but no throw either.
    const stream = createRedactStream();
    const writer = stream.writable.getWriter();
    const reader = stream.readable.getReader();
    void writer.write('partial AKIAIOSFOD').catch(() => {});
    await reader.cancel('done');
    writer.releaseLock();
  });

  it('cancel discards a buffered partial credential (spec §7 partial-state contract)', async () => {
    // Push a chunk that ends with a partial AWS key — 'AKIA' + 6 chars, short
    // of the full 16-char suffix. Drain the slide-emit so transform DEFINITELY
    // ran and the partial sits in the engine's retained tail. Then cancel and
    // verify (a) no credential finding fires (partial discarded, not lazily
    // matched), (b) stream-canceled finding fires.
    const findings: Finding[] = [];
    const stream = createRedactStream({ onFinding: (f) => findings.push(f) });
    const writer = stream.writable.getWriter();
    const reader = stream.readable.getReader();

    const chunkWithPartial = `${'x'.repeat(5000)}AKIAIOSFOD`;
    const w = writer.write(chunkWithPartial);
    const r = await reader.read();
    expect(r.done).toBe(false);
    await w;

    await reader.cancel('partial-discard test');

    const cred = findings.find((f) => f.kind === 'credential' && f.ruleId === 'aws-access-key');
    expect(cred).toBeUndefined();

    const canceled = findings.find(
      (f) => f.kind === 'stream-diagnostic' && f.ruleId === 'stream-canceled'
    );
    expect(canceled).toBeDefined();

    writer.releaseLock();
  });
});

describe('redactIterable — cancel via consumer break', () => {
  it('consumer break mid-stream emits stream-canceled finding', async () => {
    const findings: Finding[] = [];
    // Use a chunk large enough to force slide-emit so the consumer actually
    // sees a yield to break on; small chunks accumulate silently below
    // bufferLimit and the consumer never enters the loop body.
    const big = 'x'.repeat(6000);
    async function* source(): AsyncIterable<string> {
      yield big;
      yield 'never reached';
    }
    const collected: string[] = [];
    for await (const c of redactIterable(source(), { onFinding: (f) => findings.push(f) })) {
      collected.push(c);
      if (collected.length === 1) break;
    }
    const cancel = findings.find(
      (f) => f.kind === 'stream-diagnostic' && f.ruleId === 'stream-canceled'
    );
    expect(cancel).toBeDefined();
  });

  it('full iteration to natural completion emits NO stream-canceled finding', async () => {
    const findings: Finding[] = [];
    async function* source(): AsyncIterable<string> {
      yield 'one ';
      yield 'two';
    }
    const out = await consumeIter(source(), { onFinding: (f) => findings.push(f) });
    expect(out).toBe('one two');
    const cancel = findings.find(
      (f) => f.kind === 'stream-diagnostic' && f.ruleId === 'stream-canceled'
    );
    expect(cancel).toBeUndefined();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Batch 4 — streaming offset frame (v0.1 contract pin)
//
// The contract: `Finding.offset = consumedBytes + matchOffsetInBuffer`, where
// `consumedBytes` is the count of post-redaction characters this engine has
// already emitted, and `matchOffsetInBuffer` is `m.index` in the
// post-prior-pattern buffer at the time of the match. Slice B's
// post-prior-pattern frame extended with an absolute origin per emit history.
// Captured here as a regression pin — v0.2 may refine to fully stable
// cross-pipeline offsets.
// ─────────────────────────────────────────────────────────────────────────────

describe('createRedactStream — finding offset frame (v0.1)', () => {
  it('single-chunk credential offset equals the batch offset (no slide)', async () => {
    const findings: Finding[] = [];
    const input = 'prefix AKIAIOSFODNN7EXAMPLE suffix';
    await consumeStream([input], createRedactStream({ onFinding: (f) => findings.push(f) }));
    const cred = findings.find((f) => f.kind === 'credential' && f.ruleId === 'aws-access-key') as
      | CredentialFinding
      | undefined;
    expect(cred).toBeDefined();
    expect(cred?.offset).toBe(7);
    expect(cred?.length).toBe(20);
  });

  it('credential straddling a chunk boundary carries an absolute offset', async () => {
    // Setup: chunk1 = 5000 unmatched filler → slide-emit 840 chars, retain 4160.
    // chunk2 = AWS key (20 chars). Buffer becomes 4180; match at buffer index 4160.
    // baseOffset = consumedBytes = 840 → finding.offset = 840 + 4160 = 5000.
    //
    // Filler is 'x' (not in [0-9a-f]) so the default long-hex pattern
    // /\b[0-9a-f]{64,}\b/g doesn't redact it; otherwise the first chunk
    // would collapse to "<credential>" and the offset frame would shift.
    const findings: Finding[] = [];
    const filler = 'x'.repeat(5000);
    const cred = 'AKIAIOSFODNN7EXAMPLE';
    await consumeStream([filler, cred], createRedactStream({ onFinding: (f) => findings.push(f) }));

    const found = findings.find((f) => f.kind === 'credential' && f.ruleId === 'aws-access-key') as
      | CredentialFinding
      | undefined;
    expect(found).toBeDefined();
    expect(found?.offset).toBe(5000);
    expect(found?.length).toBe(20);
  });

  it('two credentials in different pushes get independent monotonic offsets', async () => {
    const findings: Finding[] = [];
    const filler = 'x'.repeat(5000);
    const cred = 'AKIAIOSFODNN7EXAMPLE';
    await consumeStream(
      [`${filler}${cred}`, `${filler}${cred}`],
      createRedactStream({ onFinding: (f) => findings.push(f) })
    );
    const creds = findings.filter(
      (f): f is CredentialFinding => f.kind === 'credential' && f.ruleId === 'aws-access-key'
    );
    expect(creds.length).toBe(2);
    expect(creds[0]?.offset).toBe(5000);
    // Second match must be monotonically after the first; exact value depends
    // on placeholder length and slide accounting, so just pin the invariant.
    expect(creds[1]?.offset).toBeGreaterThan(creds[0]?.offset ?? 0);
  });
});

describe('createRedactStream — buffer overflow warning', () => {
  it('fires when a push slides bytes downstream without matching any credential', async () => {
    const findings: Finding[] = [];
    // 6000 chars of unmatched filler, single chunk → buffer >> bufferLimit (4160),
    // zero credentials. Slide-emit fires the warning.
    const filler = 'x'.repeat(6000);
    await consumeStream([filler], createRedactStream({ onFinding: (f) => findings.push(f) }));
    const overflow = findings.find(
      (f) => f.kind === 'stream-diagnostic' && f.ruleId === 'buffer-overflow-warning'
    ) as StreamDiagnosticFinding | undefined;
    expect(overflow).toBeDefined();
    expect(overflow?.severity).toBe('low');
    expect(overflow?.message).toContain('consumedBytes=');
  });

  it('suppressed when a credential matched in the same push (silent steady-state)', async () => {
    const findings: Finding[] = [];
    // Push a long chunk that contains a credential; the slide-emit DOES happen
    // (chunk > bufferLimit) but a credential match in the same push suppresses
    // the warning.
    const padded = `${'x'.repeat(3000)}AKIAIOSFODNN7EXAMPLE${'y'.repeat(3000)}`;
    await consumeStream([padded], createRedactStream({ onFinding: (f) => findings.push(f) }));
    const overflow = findings.find(
      (f) => f.kind === 'stream-diagnostic' && f.ruleId === 'buffer-overflow-warning'
    );
    expect(overflow).toBeUndefined();
    // Sanity: the credential WAS redacted and emitted.
    const cred = findings.find((f) => f.kind === 'credential' && f.ruleId === 'aws-access-key');
    expect(cred).toBeDefined();
  });

  it('does not fire for steady-state below bufferLimit', async () => {
    const findings: Finding[] = [];
    // Many small chunks, total well under bufferLimit. No slide ever happens.
    const chunks = Array.from({ length: 50 }, () => 'small ');
    await consumeStream(chunks, createRedactStream({ onFinding: (f) => findings.push(f) }));
    const overflow = findings.find(
      (f) => f.kind === 'stream-diagnostic' && f.ruleId === 'buffer-overflow-warning'
    );
    expect(overflow).toBeUndefined();
  });
});
