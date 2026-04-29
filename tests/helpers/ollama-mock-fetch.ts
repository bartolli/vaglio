/**
 * Test-only helper: build a `fetch`-shaped function whose `Response.body`
 * is a `ReadableStream<Uint8Array>` emitting NDJSON, with caller control
 * over chunk boundaries.
 *
 * Used to drive `new Ollama({ host, fetch })` in deterministic mock-based
 * SDK-glue tests (Group 1 of M3.5b). NOT exported from `src/index.ts`.
 *
 * Abort propagation mirrors the WHATWG fetch semantics ollama-js relies
 * on: when the consumer's `AbortController` aborts (typically via
 * `client.abort()`), pending and subsequent reads on the response body
 * reject with an `AbortError`. The mock wires `signal.addEventListener`
 * in `start()` so the rejection surfaces on the very next `read()`,
 * not only on the next pull.
 */

import type { Fetch } from 'ollama';

/** Encode an object as one NDJSON line (object + "\n"). */
export function ndjsonLine(obj: unknown): Uint8Array {
  return new TextEncoder().encode(`${JSON.stringify(obj)}\n`);
}

/**
 * Concatenate `parts`, then re-chunk into byte slices of `chunkSize` each
 * (the last slice may be shorter). Useful for splitting an NDJSON document
 * at arbitrary mid-line byte boundaries.
 */
export function rechunkBytes(parts: ReadonlyArray<Uint8Array>, chunkSize: number): Uint8Array[] {
  if (chunkSize <= 0) throw new Error('chunkSize must be > 0');
  const total = parts.reduce((n, p) => n + p.byteLength, 0);
  const merged = new Uint8Array(total);
  let pos = 0;
  for (const p of parts) {
    merged.set(p, pos);
    pos += p.byteLength;
  }
  const out: Uint8Array[] = [];
  for (let i = 0; i < merged.byteLength; i += chunkSize) {
    out.push(merged.slice(i, i + chunkSize));
  }
  return out;
}

function makeAbortError(reason: unknown): Error {
  if (reason instanceof Error) return reason;
  const message = typeof reason === 'string' ? reason : 'aborted';
  return new DOMException(message, 'AbortError');
}

export interface MockFetchOptions {
  /**
   * Delay (in ms) between successive chunk emissions. Default 0 (drains
   * synchronously). Set a small positive value when the test needs to
   * race `client.abort()` against an in-flight pull — without it the
   * stream may exhaust before the abort scheduling has a chance to fire.
   */
  chunkDelayMs?: number;
}

/**
 * Build a `fetch` that streams the supplied byte chunks as the response
 * body. Chunks are pulled one at a time, so consumers can interleave
 * `client.abort()` between yields and observe prompt cancellation.
 *
 * The fetch ignores `input` and `init.body` — it's a one-shot mock
 * intended for SDK-glue tests, not a general HTTP simulator.
 */
export function mockFetchFromChunks(
  chunks: ReadonlyArray<Uint8Array>,
  options?: MockFetchOptions
): Fetch {
  const delayMs = options?.chunkDelayMs ?? 0;
  return async (_input, init) => {
    const signal = (init?.signal ?? undefined) as AbortSignal | undefined;
    let i = 0;
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        if (signal?.aborted) {
          controller.error(makeAbortError(signal.reason));
          return;
        }
        signal?.addEventListener(
          'abort',
          () => {
            controller.error(makeAbortError(signal.reason));
          },
          { once: true }
        );
      },
      async pull(controller) {
        if (delayMs > 0) await new Promise<void>((r) => setTimeout(r, delayMs));
        if (signal?.aborted) {
          controller.error(makeAbortError(signal.reason));
          return;
        }
        if (i >= chunks.length) {
          controller.close();
          return;
        }
        const next = chunks[i++];
        if (next === undefined) {
          controller.close();
          return;
        }
        controller.enqueue(next);
      }
    });
    return new Response(stream, {
      status: 200,
      headers: { 'Content-Type': 'application/x-ndjson' }
    });
  };
}
