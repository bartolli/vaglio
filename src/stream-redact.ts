/**
 * Streaming credential redaction for Vaglio v0.1 — M3.5 Slice E.1.
 *
 * Two surfaces over one engine:
 *   - `createRedactStream(options?)` — `TransformStream<string, string>` per spec-api §1, §7.
 *   - `redactIterable(source, options?)` — `AsyncIterable<string>` per spec-api §1, §7.
 *
 * Both wrap `RedactStreamEngine`, an internal sliding-window buffer that
 * keeps the trailing `policy.bufferLimit` characters so a credential
 * straddling a chunk boundary still matches once its tail arrives. Each
 * push runs every credential pattern (matchAll, sequential) against the
 * full buffer; per-pattern findings carry absolute offsets via the
 * `baseOffset` parameter on `redactCore`.
 *
 * v0.1 contract notes (capture in M3 wiki resync):
 *
 *   - **Streaming offset frame.** `Finding.offset = consumedBytes + matchOffset`,
 *     where `consumedBytes` is the count of characters already emitted
 *     downstream by this engine instance (post-redaction), and `matchOffset`
 *     is the match's index in the current buffer. The post-prior-pattern
 *     frame from Slice B carries through unchanged; streaming just adds
 *     the absolute origin per emit history.
 *
 *   - **Overflow trigger.** A `buffer-overflow-warning` finding fires only
 *     when a push slides bytes downstream AND zero `CredentialFinding`s
 *     were emitted in that same push. This is the meaningful "your stream
 *     is churning bytes downstream without matching anything" signal.
 *     Pure "every slide-emit" would be noise; pure "buffer still > limit
 *     after slide" never fires under the slide-to-bufferLimit algorithm.
 *
 *   - **No identity contract for streaming.** spec-api §7 explicitly
 *     disclaims per-chunk reference equality. Callers needing identity
 *     should use the batch surface.
 *
 *   - **`push()` after `flush()`** throws a generic `Error` ("flush already
 *     called"). `VaglioStreamCanceledError` is reserved for the cancel
 *     path per its spec-api §8 docstring.
 *
 *   - **`push()` / `flush()` after `cancel()`** throws
 *     `VaglioStreamCanceledError`, carrying the cancel reason. The async
 *     iterator's `next()` on a canceled engine throws the same.
 *
 *   - **Empty chunks** are no-ops.
 *
 *   - **Source error vs consumer cancel (async-iter).** If the source
 *     iterable throws, the generator rethrows (spec §7 fail-fast); no
 *     `stream-canceled` finding fires. If the consumer breaks the loop
 *     (or otherwise calls `return()` on the generator), the finally
 *     block runs `engine.cancel(undefined)` and the finding fires (when
 *     `onFinding` is subscribed).
 */

import { type EmitContext, redactCore, redactSilent } from './credentials.js';
import { VaglioStreamCanceledError } from './errors.js';
import type { Finding, Severity, StreamDiagnosticFinding } from './findings.js';
import { DEFAULT_POLICY, type Policy, type SanitizeOptions } from './policy.js';

const FINDING_RULE_VERSION = 1;

/** Default severity for the two stream-diagnostic ruleIds (spec-api §6 table). */
const DEFAULT_DIAGNOSTIC_SEVERITY: Severity = 'low';

function diagnosticSeverity(policy: Policy, ruleId: string): Severity {
  return policy.severityOverrides[ruleId] ?? DEFAULT_DIAGNOSTIC_SEVERITY;
}

function makeOverflowFinding(policy: Policy, consumedBytes: number): StreamDiagnosticFinding {
  return Object.freeze({
    kind: 'stream-diagnostic' as const,
    ruleId: 'buffer-overflow-warning',
    ruleVersion: FINDING_RULE_VERSION,
    severity: diagnosticSeverity(policy, 'buffer-overflow-warning'),
    message: `buffer overflow at consumedBytes=${consumedBytes}`
  });
}

function makeCanceledFinding(policy: Policy, reason: unknown): StreamDiagnosticFinding {
  let message = 'stream canceled';
  if (reason !== undefined) {
    if (typeof reason === 'string') {
      message = `stream canceled: ${reason}`;
    } else if (reason instanceof Error) {
      message = `stream canceled: ${reason.message}`;
    } else {
      message = `stream canceled: ${String(reason)}`;
    }
  }
  return Object.freeze({
    kind: 'stream-diagnostic' as const,
    ruleId: 'stream-canceled',
    ruleVersion: FINDING_RULE_VERSION,
    severity: diagnosticSeverity(policy, 'stream-canceled'),
    message
  });
}

/**
 * Per-call state for one streaming-redact instance. Adapter-agnostic;
 * the TransformStream and the async-iter generator both drive the same
 * engine. `bufferLimit` is snapshotted at construction so an unrelated
 * `Policy` mutation (impossible — frozen) or replacement cannot change
 * the in-flight engine's buffer behavior.
 */
class RedactStreamEngine {
  readonly #policy: Policy;
  readonly #onFinding: ((f: Finding) => void) | undefined;
  readonly #bufferLimit: number;
  #buffer = '';
  #consumedBytes = 0;
  #flushed = false;
  #canceled = false;
  #cancelReason: unknown = undefined;

  constructor(options: SanitizeOptions | undefined) {
    this.#policy = options?.policy ?? DEFAULT_POLICY;
    this.#onFinding = options?.onFinding;
    this.#bufferLimit = this.#policy.bufferLimit;
  }

  push(chunk: string): string {
    if (this.#canceled) throw new VaglioStreamCanceledError(this.#cancelReason);
    if (this.#flushed) throw new Error('Vaglio: push() called after flush()');
    if (chunk.length === 0) return '';

    this.#buffer += chunk;
    return this.#processAndSlide();
  }

  flush(): string {
    if (this.#canceled) throw new VaglioStreamCanceledError(this.#cancelReason);
    if (this.#flushed) return '';
    this.#flushed = true;

    const buf = this.#buffer;
    this.#buffer = '';
    if (buf.length === 0) return '';

    let processed: string;
    if (this.#onFinding !== undefined) {
      const ctx: EmitContext = {
        findings: null,
        onFinding: this.#onFinding,
        policy: this.#policy
      };
      processed = redactCore(buf, ctx, this.#consumedBytes);
    } else {
      processed = redactSilent(buf, this.#policy);
    }

    this.#consumedBytes += processed.length;
    return processed;
  }

  cancel(reason: unknown): void {
    if (this.#canceled || this.#flushed) return;
    this.#canceled = true;
    this.#cancelReason = reason;
    this.#buffer = '';
    if (this.#onFinding !== undefined) {
      this.#onFinding(makeCanceledFinding(this.#policy, reason));
    }
  }

  #processAndSlide(): string {
    let credentialMatchCount = 0;
    let processed: string;

    if (this.#onFinding !== undefined) {
      const userOnFinding = this.#onFinding;
      const wrappedOnFinding: (f: Finding) => void = (f) => {
        if (f.kind === 'credential') credentialMatchCount++;
        userOnFinding(f);
      };
      const ctx: EmitContext = {
        findings: null,
        onFinding: wrappedOnFinding,
        policy: this.#policy
      };
      processed = redactCore(this.#buffer, ctx, this.#consumedBytes);
    } else {
      processed = redactSilent(this.#buffer, this.#policy);
    }

    if (processed.length > this.#bufferLimit) {
      const emitLen = processed.length - this.#bufferLimit;
      const emitted = processed.slice(0, emitLen);
      this.#buffer = processed.slice(emitLen);

      // Slide-emit happened without any credential matching this push: meaningful
      // overflow signal per the M3.5 advisor pass.
      if (this.#onFinding !== undefined && credentialMatchCount === 0) {
        this.#onFinding(makeOverflowFinding(this.#policy, this.#consumedBytes));
      }

      this.#consumedBytes += emitLen;
      return emitted;
    }

    this.#buffer = processed;
    return '';
  }
}

/**
 * Web Streams factory. Returns a fresh `TransformStream<string, string>`
 * with per-call internal state. Cancel via `readable.cancel(reason)` or
 * `writable.abort(reason)` — both wire through the transformer's `cancel`
 * callback per the WHATWG Streams contract.
 *
 * @example
 *   await fetch(url)
 *     .then(r => r.body!)
 *     .pipeThrough(new TextDecoderStream())
 *     .pipeThrough(createRedactStream({ onFinding: emitMetric }))
 *     .pipeTo(modelInputSink);
 */
export function createRedactStream(options?: SanitizeOptions): TransformStream<string, string> {
  const engine = new RedactStreamEngine(options);

  return new TransformStream<string, string>({
    transform(chunk, controller) {
      try {
        const out = engine.push(chunk);
        if (out.length > 0) controller.enqueue(out);
      } catch (err) {
        controller.error(err);
      }
    },
    flush(controller) {
      try {
        const out = engine.flush();
        if (out.length > 0) controller.enqueue(out);
      } catch (err) {
        controller.error(err);
      }
    },
    cancel(reason) {
      engine.cancel(reason);
    }
  });
}

/**
 * Async-iter adapter. Pulls chunks from `source`, streams redacted chunks
 * out, and finalizes the buffer on source exhaustion. Consumer `break` /
 * `return()` on the resulting iterator runs the finally block, which
 * cancels the engine and (if `onFinding` is subscribed) emits a
 * `stream-canceled` finding. Source errors propagate without a cancel
 * finding (spec §7 fail-fast vs consumer-initiated cancel).
 *
 * @example
 *   for await (const safe of redactIterable(modelStream(), { onFinding: log })) {
 *     yield safe;
 *   }
 */
export async function* redactIterable(
  source: AsyncIterable<string> | Iterable<string>,
  options?: SanitizeOptions
): AsyncIterable<string> {
  const engine = new RedactStreamEngine(options);
  let consumerAborted = true;

  try {
    for await (const chunk of source) {
      const out = engine.push(chunk);
      if (out.length > 0) yield out;
    }
    const tail = engine.flush();
    if (tail.length > 0) yield tail;
    consumerAborted = false;
  } catch (err) {
    consumerAborted = false;
    throw err;
  } finally {
    if (consumerAborted) engine.cancel(undefined);
  }
}
