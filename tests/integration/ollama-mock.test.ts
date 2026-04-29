/**
 * M3.5b Group 1 — mock-fetch SDK-glue tests.
 *
 * Wires `new Ollama({ host, fetch: mockFetch })` into `sanitizeIterable`
 * via the bridge. Coverage limited to what the SDK adds beyond a raw
 * `AsyncIterable<string>`. Chunk-boundary property invariants belong to
 * M3.6 fast-check (vaglio sees codepoint-aligned strings either way; the
 * SDK doesn't add coverage there).
 */

import { Ollama } from 'ollama';
import { describe, expect, it } from 'vitest';
import { VaglioStreamCanceledError } from '../../src/errors.js';
import type { Finding } from '../../src/findings.js';
import { sanitizeIterable } from '../../src/stream-sanitize.js';
import { bridgeOllamaChatStream } from '../helpers/ollama-bridge.js';
import { mockFetchFromChunks, ndjsonLine, rechunkBytes } from '../helpers/ollama-mock-fetch.js';

// ─────────────────────────────────────────────────────────────────────────────
// Test fixture builders
// ─────────────────────────────────────────────────────────────────────────────

interface ChatLineArgs {
  content?: string;
  thinking?: string;
  done?: boolean;
}

/** Build one NDJSON line shaped like `ollama-js`'s `ChatResponse`. */
function chatLine(args: ChatLineArgs): Uint8Array {
  const message: Record<string, unknown> = {
    role: 'assistant',
    content: args.content ?? ''
  };
  if (args.thinking !== undefined) message.thinking = args.thinking;
  return ndjsonLine({
    model: 'mock',
    created_at: '2026-04-29T00:00:00.000Z',
    message,
    done: args.done ?? false,
    done_reason: args.done ? 'stop' : '',
    total_duration: 0,
    load_duration: 0,
    prompt_eval_count: 0,
    prompt_eval_duration: 0,
    eval_count: 0,
    eval_duration: 0
  });
}

function makeClient(chunks: ReadonlyArray<Uint8Array>): Ollama {
  return new Ollama({ host: 'http://mock', fetch: mockFetchFromChunks(chunks) });
}

async function chatStream(client: Ollama) {
  return client.chat({
    model: 'mock',
    messages: [{ role: 'user', content: 'hi' }],
    stream: true
  });
}

async function consume(it: AsyncIterable<string>): Promise<string> {
  let out = '';
  for await (const chunk of it) out += chunk;
  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Batch 1 — bridge / done / thinking / heartbeat
// ─────────────────────────────────────────────────────────────────────────────

describe('M3.5b — ollama bridge / done / thinking / heartbeat', () => {
  it('bridges content from successive responses; done:true terminates cleanly', async () => {
    const client = makeClient([
      chatLine({ content: 'Hello, ' }),
      chatLine({ content: 'world' }),
      chatLine({ content: '!', done: true })
    ]);
    const stream = await chatStream(client);
    const out = await consume(sanitizeIterable(bridgeOllamaChatStream(stream)));
    expect(out).toBe('Hello, world!');
  });

  it('emits thinking before content for think:true responses', async () => {
    const client = makeClient([
      chatLine({ thinking: 'Reasoning step.', content: '' }),
      chatLine({ thinking: '', content: 'Answer: 42' }),
      chatLine({ done: true })
    ]);
    const stream = await chatStream(client);
    const out = await consume(sanitizeIterable(bridgeOllamaChatStream(stream)));
    expect(out).toBe('Reasoning step.Answer: 42');
  });

  it('empty content chunks (model heartbeat) are no-ops for the engine', async () => {
    const client = makeClient([
      chatLine({ content: '' }),
      chatLine({ content: 'A' }),
      chatLine({ content: '' }),
      chatLine({ content: 'B', done: true })
    ]);
    const stream = await chatStream(client);
    const out = await consume(sanitizeIterable(bridgeOllamaChatStream(stream)));
    expect(out).toBe('AB');
  });

  it('NDJSON line split mid-byte across transport chunks reassembles correctly', async () => {
    const lines = [
      chatLine({ content: 'foo-payload' }),
      chatLine({ content: '-bar-payload', done: true })
    ];
    const chunked = rechunkBytes(lines, 30);
    expect(chunked.length).toBeGreaterThan(2);
    const client = new Ollama({
      host: 'http://mock',
      fetch: mockFetchFromChunks(chunked)
    });
    const stream = await chatStream(client);
    const out = await consume(sanitizeIterable(bridgeOllamaChatStream(stream)));
    expect(out).toBe('foo-payload-bar-payload');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Batch 2 — source error / cancel / cross-chunk credential
//
// Source-error semantics (M3.5b spec correction): an SDK- or
// upstream-source-thrown error mid-stream propagates as-is. Only
// user-initiated cancel produces `VaglioStreamCanceledError`.
// `client.abort()` from vaglio's POV is a source-side event; the
// AbortError raised by the underlying fetch propagates as-is.
// ─────────────────────────────────────────────────────────────────────────────

describe('M3.5b — source error / cancel / cross-chunk credential', () => {
  it('NDJSON {"error":"..."} line propagates as plain Error from sanitizeIterable', async () => {
    const client = makeClient([
      chatLine({ content: 'before' }),
      ndjsonLine({ error: 'model not found' })
    ]);
    const stream = await chatStream(client);
    let caught: unknown;
    try {
      for await (const _ of sanitizeIterable(bridgeOllamaChatStream(stream))) {
        // drain
      }
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(Error);
    expect(caught).not.toBeInstanceOf(VaglioStreamCanceledError);
    expect((caught as Error).message).toBe('model not found');
  });

  it('client.abort() mid-stream propagates AbortError as-is (not VaglioStreamCanceledError)', async () => {
    // Default bufferLimit is 4160 (PEM 4096 + slack), so small content chunks
    // accumulate in the engine without sliding downstream — the consumer's
    // for-await won't yield anything before flush. The contract under test
    // is the rejection path, not the per-chunk yield, so we race abort
    // against the source via `chunkDelayMs` and assert what propagates.
    const client = new Ollama({
      host: 'http://mock',
      fetch: mockFetchFromChunks(
        [
          chatLine({ content: 'first' }),
          chatLine({ content: 'second' }),
          chatLine({ content: 'third', done: true })
        ],
        { chunkDelayMs: 20 }
      )
    });
    const stream = await chatStream(client);
    const consumer = (async (): Promise<unknown> => {
      try {
        for await (const _ of sanitizeIterable(bridgeOllamaChatStream(stream))) {
          // drain
        }
        return null;
      } catch (err) {
        return err;
      }
    })();
    // Let the consumer attach to the stream and start the first pull.
    await new Promise<void>((r) => setTimeout(r, 5));
    client.abort();
    const caught = await consumer;
    expect(caught).toBeInstanceOf(Error);
    expect(caught).not.toBeInstanceOf(VaglioStreamCanceledError);
    expect((caught as Error).name).toBe('AbortError');
  });

  it('credential split across two response messages redacts (bridge feeds the engine)', async () => {
    const client = makeClient([
      chatLine({ content: 'key=AKIAIOSF' }),
      chatLine({ content: 'ODNN7EXAMPLE rest', done: true })
    ]);
    const stream = await chatStream(client);
    const out = await consume(sanitizeIterable(bridgeOllamaChatStream(stream)));
    expect(out).toBe('key=<credential> rest');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Batch 3 — bridge `wrapThinkingTag` option (deterministic via mock)
//
// The smoke suite exercises the wrap path against a real thinking model, but
// gates on `OLLAMA_HOST` so default `pnpm test` doesn't hit it. These two
// cases pin the open / close / tail-close branches deterministically so a
// regression in the wrap state machine is caught without a daemon running.
// ─────────────────────────────────────────────────────────────────────────────

describe('M3.5b — bridge wrapThinkingTag option', () => {
  it('wraps a thinking phase end-to-end so sanitize strips it (open + close)', async () => {
    const client = makeClient([
      chatLine({ thinking: 'reasoning step 1; ', content: '' }),
      chatLine({ thinking: 'reasoning step 2.', content: '' }),
      chatLine({ content: 'final answer.', done: true })
    ]);
    const stream = await chatStream(client);
    const findings: Finding[] = [];
    let out = '';
    for await (const safe of sanitizeIterable(
      bridgeOllamaChatStream(stream, { wrapThinkingTag: 'internal' }),
      { onFinding: (f) => findings.push(f) }
    )) {
      out += safe;
    }
    expect(out).toBe('final answer.');
    expect(out).not.toContain('<internal>');
    expect(out).not.toContain('reasoning step');
    expect(findings.some((f) => f.kind === 'unicode-strip' && f.ruleId === 'reasoning-tag')).toBe(
      true
    );
  });

  it('emits the close tag on tail when stream ends mid-thinking (no content phase)', async () => {
    // Model emitted only thinking before `done: true`. Without the tail-close
    // branch the bridge would leave the buffer with an unclosed <internal>,
    // and the stripper would not match the (open-but-unclosed) block.
    const client = makeClient([
      chatLine({ thinking: 'incomplete reasoning', content: '' }),
      chatLine({ content: '', done: true })
    ]);
    const stream = await chatStream(client);
    const findings: Finding[] = [];
    let out = '';
    for await (const safe of sanitizeIterable(
      bridgeOllamaChatStream(stream, { wrapThinkingTag: 'internal' }),
      { onFinding: (f) => findings.push(f) }
    )) {
      out += safe;
    }
    expect(out).toBe('');
    expect(findings.some((f) => f.kind === 'unicode-strip' && f.ruleId === 'reasoning-tag')).toBe(
      true
    );
  });
});
