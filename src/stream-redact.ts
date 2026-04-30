/**
 * Streaming credential redaction for Vaglio v0.1 — M3.5 Slice E.1,
 * extended in M3.6 with option-B holdback.
 *
 * Two surfaces over one engine:
 *   - `createRedactStream(options?)` — `TransformStream<string, string>` per spec-api §1, §7.
 *   - `redactIterable(source, options?)` — `AsyncIterable<string>` per spec-api §1, §7.
 *
 * Both wrap `RedactStreamEngine`, an internal buffer that retains the
 * trailing K = `policy.bufferLimit` characters from regex evaluation per
 * push. Each push runs `findHoldbackCutoff` to determine the safe leading
 * region (shrinks for crossing matches), then `redactCore` on that region
 * only; the held tail is preserved verbatim until the next push. Findings
 * carry absolute offsets via the `baseOffset` parameter on `redactCore`.
 *
 * v0.1 contract notes (capture in M3 wiki resync):
 *
 *   - **Option-B holdback.** Each push retains the trailing K chars from
 *     regex evaluation (K = `bufferLimit`). Closes two stream/batch
 *     divergences for greedy `{N,}` patterns: (a) early-match at end-of-
 *     buffer (greedy stops when the buffer ends and commits less than the
 *     full match would on concatenated input); (b) partial-prefix
 *     straddle (e.g. `Bearer eyJ` arrives before its `{50,}` body).
 *     `findHoldbackCutoff` shrinks the cutoff to the start of any match
 *     crossing the K boundary so the entire match lands in the held tail.
 *     Flush has no holdback (source exhausted; greedy matches in the tail
 *     are final and any partial-prefix has no future continuation).
 *
 *   - **Single-oversized-match degrade.** If a crossing match shrinks the
 *     held tail past `2 * K`, the engine reverts to the no-holdback
 *     cutoff for that push and emits `buffer-overflow-warning`. This is
 *     the documented "redaction trumps fidelity" carve-out: the leading
 *     half of an oversized match commits as a partial-match-leak under
 *     early-match semantics, but the stream makes progress and downstream
 *     consumers don't stall.
 *
 *   - **K = `bufferLimit` latency contract.** Default policy K = 4160
 *     (PEM `maxMatchLength` 4096 + 64 slack). Token-streaming consumers
 *     who don't need PEM redaction can shrink K to 320 via
 *     `policy().removeCredentialPattern('pem-private-key').build()`.
 *
 *   - **Streaming offset frame.** `Finding.offset = consumedBytes + matchOffset`,
 *     where `consumedBytes` is the count of characters already emitted
 *     downstream by this engine instance (post-redaction), and `matchOffset`
 *     is the match's index in the leading region. The post-prior-pattern
 *     frame from Slice B carries through unchanged.
 *
 *   - **Overflow trigger.** `buffer-overflow-warning` fires under one of
 *     two conditions: (i) a `degraded` push (held tail > `2 * K`) —
 *     always fires regardless of pending findings; (ii) slide-emit
 *     happens with no credential matched in this push AND no credential
 *     held in the tail (`anyMatch === false` from `findHoldbackCutoff`).
 *     `anyMatch` suppresses (ii) when a credential is held for the next
 *     push (the buffer is doing useful work).
 *
 *   - **Streaming always uses `redactCore`.** The silent-path optimization
 *     in `redactSilent` (per-pattern `String.prototype.replace`) cannot
 *     honor the holdback cutoff, so streaming pushes through `redactCore`
 *     regardless of whether `onFinding` is subscribed.
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

import { type EmitContext, findHoldbackCutoff, redactCore } from './credentials.js';
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

    // Flush has no holdback — source is exhausted, so any greedy match in the
    // tail is final and any partial-prefix has no future continuation.
    const ctx: EmitContext = {
      findings: null,
      onFinding: this.#onFinding,
      policy: this.#policy
    };
    const processed = redactCore(buf, ctx, this.#consumedBytes);
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
    if (this.#buffer.length === 0) return '';

    const K = this.#bufferLimit;

    // While the buffer fits inside the holdback region, nothing is committable
    // yet — partial-prefix and greedy-extension concerns dominate. Wait for
    // more chunks (or for `flush()` to release the buffer eagerly).
    if (this.#buffer.length <= K) return '';

    // Phase 1: determine the effective cutoff. Initial cutoff is `length - K`;
    // any pattern match that crosses the cutoff shrinks it to the match's
    // start so the entire match lands in the held tail. `anyMatch` reports
    // whether any pattern matched anywhere in the buffer — used below to
    // suppress the no-progress overflow signal when a credential is held in
    // the tail (the buffer IS doing useful work).
    const { cutoff: cutoffInitial, anyMatch } = findHoldbackCutoff(
      this.#buffer,
      this.#policy.credentials.patterns,
      K
    );
    let effCutoff = cutoffInitial;

    // Single-oversized-match degrade. If a crossing match shrinks `effCutoff`
    // so far that the held tail would exceed `2 * K`, we can't keep waiting:
    // the buffer is past `2 * K` already and would unboundedly grow on the
    // next push. Force progress by reverting to the no-holdback cutoff and
    // emit a `buffer-overflow-warning`. This is the documented "redaction
    // trumps fidelity" carve-out — the leading half of the oversized match
    // commits as partial-match-leak under early-match semantics, but the
    // stream makes progress and downstream consumers don't stall.
    let degraded = false;
    const heldTailLen = this.#buffer.length - effCutoff;
    if (heldTailLen > 2 * K) {
      effCutoff = this.#buffer.length - K;
      degraded = true;
    } else if (effCutoff <= 0) {
      // Held tail has not yet hit the degrade threshold. Wait for more chunks.
      return '';
    }

    // Phase 2: redactCore on the leading region only. The held tail is
    // retained verbatim for the next push.
    const leading = this.#buffer.slice(0, effCutoff);

    let credentialMatchCount = 0;
    let committed: string;
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
      committed = redactCore(leading, ctx, this.#consumedBytes);
    } else {
      const ctx: EmitContext = {
        findings: null,
        onFinding: undefined,
        policy: this.#policy
      };
      committed = redactCore(leading, ctx, this.#consumedBytes);
    }

    this.#buffer = this.#buffer.slice(effCutoff);
    this.#consumedBytes += committed.length;

    // Overflow trigger: two paths under one ruleId.
    //   (i)  `degraded`: a single match larger than `2 * K` forced partial-
    //        match leak. Always fires regardless of pending matches because
    //        the leak itself is the signal.
    //   (ii) Slide-emit without progress: the push committed bytes
    //        downstream but no credential matched anywhere in the buffer
    //        (`anyMatch === false` — neither in the leading region nor
    //        held in the tail). Suppressed when `anyMatch === true` so a
    //        credential held for the next push doesn't fire a false-positive.
    if (this.#onFinding !== undefined && committed.length > 0) {
      if (degraded || (credentialMatchCount === 0 && !anyMatch)) {
        this.#onFinding(makeOverflowFinding(this.#policy, this.#consumedBytes));
      }
    }

    return committed;
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
