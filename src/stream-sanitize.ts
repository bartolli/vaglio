/**
 * Streaming composed sanitization for Vaglio v0.1 — M3.5 Slice E.2.
 *
 * Two surfaces over one engine:
 *   - `createSanitizeStream(options?)` — `TransformStream<string, string>` per spec-api §1, §7.
 *   - `sanitizeIterable(source, options?)` — `AsyncIterable<string>` per spec-api §1, §7.
 *
 * Both wrap `SanitizeStreamEngine`, a single-buffer adapter that layers the
 * Slice D pipeline (`stripUnicode → stripTags → redact`) over E.1's sliding
 * window. Per push: append chunk, run all three stages against the full
 * buffer in pipeline order, slide-emit if the result exceeds `bufferLimit`.
 *
 * **Single-buffer architecture (per the M3.5 plan).** One buffer per call;
 * every stage runs against it. Chained `pipeThrough` of per-stage streams
 * was rejected as v0.1 architecture — multiplies memory and breaks per-call
 * ownership of cancel/overflow semantics.
 *
 * v0.1 contract notes (capture in M3 wiki resync):
 *
 *   - **Pipeline idempotency.** Each stage is idempotent on its own output:
 *     NFKC-of-NFKC is NFKC, the strip-set regex consumes its targets,
 *     ZWJ/VS context-checks pass over already-stripped sequences, mark-cap
 *     re-runs leave capped sequences in place, default placeholders don't
 *     match credential patterns, tag stripping consumes complete blocks.
 *     This is what makes "re-run all three stages on every push" safe —
 *     prior pushes' transformations don't re-emit findings.
 *
 *   - **Cross-chunk + cross-stage offset frame.** `Finding.offset =
 *     stage_local_offset + consumedBytes`. The `stage_local_offset` is
 *     the Slice D cross-stage frame: each stage's offset is in the input
 *     to that stage (post-prior-stages within the push). `consumedBytes`
 *     is the count of post-pipeline characters already emitted downstream
 *     by this engine. Mirrors E.1's offset frame; just adds two more
 *     stages to the post-prior-stages part.
 *
 *   - **Overflow trigger (extends E.1's rule).** A `buffer-overflow-warning`
 *     finding fires when slide-emit happens AND zero substantive findings
 *     (credential or unicode-strip) emit in that same push. "Substantive"
 *     = the pipeline sanitized something this push. Stream-diagnostic
 *     findings (cancel) don't count toward suppression. Same shape as
 *     E.1's "zero credential findings" rule, generalized to the composed
 *     surface where the strip stages also count as productive work.
 *
 *   - **Tag-block overflow leaks reasoning context (v0.1 limitation).**
 *     If `<internal>` opens but never closes within `bufferLimit`, the
 *     unmatched content slides downstream as the buffer fills. Credentials
 *     inside still redact at the redact stage — defense in depth — but the
 *     reasoning text itself reaches the model. `buffer-overflow-warning`
 *     fires in this case (no substantive findings until the close arrives).
 *     v0.1 reuses the existing `bufferLimit`; no new
 *     `Policy.reasoningTags.maxBlockBytes` slot. v0.2 candidate.
 *
 *   - **Trailing-edge ZWJ holdback.** `stripNonEmojiZwj` checks the
 *     codepoint AFTER each ZWJ to decide whether it sits inside a
 *     legitimate emoji ligature. At a chunk boundary the after-codepoint
 *     is unknown, so naïvely running the pipeline would strip a trailing
 *     ZWJ that's waiting for its emoji partner in the next push — making
 *     the streaming output diverge from the batch output for the same
 *     concatenated input. The engine holds back a single trailing U+200D
 *     codepoint from the per-push pipeline run and reattaches it to the
 *     buffer afterwards. Next push concatenates new data and re-evaluates
 *     with full context. Flush runs without holdback (source exhausted →
 *     trailing ZWJ has no future partner and is correctly treated as
 *     orphan). Detection is BMP-only: U+200D occupies a single UTF-16
 *     code unit, so `endsWith('‍')` is sufficient.
 *
 *   - **`push()` after `flush()`** throws a generic `Error`.
 *     `VaglioStreamCanceledError` is reserved for the cancel path.
 *
 *   - **`push()` / `flush()` after `cancel()`** throws
 *     `VaglioStreamCanceledError`, carrying the cancel reason.
 *
 *   - **Empty chunks** are no-ops.
 *
 *   - **Source error vs consumer cancel (async-iter).** Same shape as E.1:
 *     source errors propagate without a `stream-canceled` finding;
 *     consumer break / `return()` runs the finally block which cancels
 *     the engine and (if `onFinding` is subscribed) emits the finding.
 */

import { redact } from './credentials.js';
import { VaglioStreamCanceledError } from './errors.js';
import type {
  CredentialFinding,
  Finding,
  Severity,
  StreamDiagnosticFinding,
  UnicodeStripFinding
} from './findings.js';
import { DEFAULT_POLICY, type Policy, type SanitizeOptions } from './policy.js';
import { stripTags } from './tags.js';
import { stripUnicode } from './unicode.js';

const FINDING_RULE_VERSION = 1;

/** Default severity for stream-diagnostic ruleIds (spec-api §6 table). */
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
 * Produce a copy of `f` with `delta` added to its offset, when the kind
 * carries one. `stream-diagnostic` findings have no offset and pass through.
 * Findings are frozen, so we spread + freeze a new object.
 */
function shiftOffset(f: Finding, delta: number): Finding {
  if (delta === 0) return f;
  if (f.kind === 'unicode-strip') {
    const shifted: UnicodeStripFinding = { ...f, offset: f.offset + delta };
    return Object.freeze(shifted);
  }
  if (f.kind === 'credential') {
    const shifted: CredentialFinding = { ...f, offset: f.offset + delta };
    return Object.freeze(shifted);
  }
  return f;
}

/**
 * Per-call state for one streaming-sanitize instance. Adapter-agnostic;
 * the TransformStream and the async-iter generator both drive the same
 * engine. `bufferLimit` is snapshotted at construction.
 *
 * Plumbing (cancel / flushed / canceled-throw / empty-chunk / reflush
 * no-op) is intentionally duplicated with `RedactStreamEngine` — the two
 * engines diverge only in the per-push process function, and a shared
 * base class would be premature for v0.1's two-engine surface.
 */
class SanitizeStreamEngine {
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

    const processed = this.#runPipeline(buf, /*forSlide*/ false);
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

  /**
   * Run all three stages against `buf`. The closure captures
   * `consumedBytes` at call entry so emitted findings carry the absolute
   * origin from THIS push's emit history (subsequent updates to
   * `consumedBytes` after the call don't reach already-emitted findings).
   *
   * `forSlide` is informational: in the slide-emit path the caller checks
   * the substantive-finding tally (via the `findingTally` returned out of
   * band by the wrapper) to decide whether to fire an overflow warning.
   */
  #runPipeline(buf: string, forSlide: boolean): string {
    if (this.#onFinding !== undefined) {
      const baseOffset = this.#consumedBytes;
      const userOnFinding = this.#onFinding;
      const wrapped: (f: Finding) => void = (f) => {
        if (forSlide && (f.kind === 'credential' || f.kind === 'unicode-strip')) {
          this.#substantiveTally++;
        }
        userOnFinding(shiftOffset(f, baseOffset));
      };
      const stageOptions: SanitizeOptions = {
        policy: this.#policy,
        onFinding: wrapped
      };
      let out = stripUnicode(buf, stageOptions);
      out = stripTags(out, stageOptions);
      out = redact(out, stageOptions);
      return out;
    }

    const stageOptions: SanitizeOptions = { policy: this.#policy };
    let out = stripUnicode(buf, stageOptions);
    out = stripTags(out, stageOptions);
    out = redact(out, stageOptions);
    return out;
  }

  /** Tally for the current push's substantive findings; reset per slide call. */
  #substantiveTally = 0;

  #processAndSlide(): string {
    this.#substantiveTally = 0;

    // Trailing-edge ZWJ holdback. Defer a trailing U+200D codepoint until
    // the next push provides its after-context — without this, a push that
    // ends mid-emoji-ligature would have its ZWJ stripped as orphan, which
    // would make the streaming output diverge from the batch output for
    // the same concatenated input (an adversary-controllable contract
    // violation, not just a cosmetic ligature break). The deferred ZWJ
    // does not flow through the pipeline this push and is reattached to
    // the buffer afterwards; it never reaches the slide-emit calculation.
    let processBuf = this.#buffer;
    let deferred = '';
    if (this.#buffer.endsWith('‍')) {
      deferred = '‍';
      processBuf = this.#buffer.slice(0, -1);
    }

    const processed = this.#runPipeline(processBuf, /*forSlide*/ true);

    if (processed.length > this.#bufferLimit) {
      const emitLen = processed.length - this.#bufferLimit;
      const emitted = processed.slice(0, emitLen);
      this.#buffer = processed.slice(emitLen) + deferred;

      // Slide-emit happened without any substantive sanitization in this push:
      // meaningful "stream churning bytes downstream untouched" signal.
      if (this.#onFinding !== undefined && this.#substantiveTally === 0) {
        this.#onFinding(makeOverflowFinding(this.#policy, this.#consumedBytes));
      }

      this.#consumedBytes += emitLen;
      return emitted;
    }

    this.#buffer = processed + deferred;
    return '';
  }
}

/**
 * Web Streams factory. Returns a fresh `TransformStream<string, string>`
 * with per-call internal state. Cancel via `readable.cancel(reason)` or
 * `writable.abort(reason)`.
 *
 * @example
 *   await fetch(url)
 *     .then(r => r.body!)
 *     .pipeThrough(new TextDecoderStream())
 *     .pipeThrough(createSanitizeStream({ onFinding: emitMetric }))
 *     .pipeTo(modelInputSink);
 */
export function createSanitizeStream(options?: SanitizeOptions): TransformStream<string, string> {
  const engine = new SanitizeStreamEngine(options);

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
 * Async-iter adapter. Pulls chunks from `source`, streams sanitized chunks
 * out, finalizes the buffer on source exhaustion. Consumer `break` /
 * `return()` runs the finally block, which cancels the engine and (if
 * `onFinding` is subscribed) emits a `stream-canceled` finding.
 *
 * @example
 *   for await (const safe of sanitizeIterable(modelStream(), { onFinding: log })) {
 *     yield safe;
 *   }
 */
export async function* sanitizeIterable(
  source: AsyncIterable<string> | Iterable<string>,
  options?: SanitizeOptions
): AsyncIterable<string> {
  const engine = new SanitizeStreamEngine(options);
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
