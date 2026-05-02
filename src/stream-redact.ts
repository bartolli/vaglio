/**
 * Streaming credential redaction. Two adapters (`createRedactStream` /
 * `redactIterable`) over one `RedactStreamEngine`.
 *
 * **Option-B holdback.** Each push retains trailing K = `policy.bufferLimit`
 * chars from regex evaluation. `findHoldbackCutoff` shrinks the cutoff to the
 * start of any match crossing K so the whole match lands in the held tail.
 * Closes two stream/batch divergences for greedy `{N,}` patterns:
 *   - early-match at end-of-buffer (greedy stops at buffer end, commits less
 *     than the full match would on concatenated input);
 *   - partial-prefix straddle (e.g. `Bearer eyJ` arrives before its `{50,}` body).
 * Flush has no holdback (source exhausted ⇒ tail matches are final).
 *
 * **Single-oversized-match degrade.** Crossing match shrinks held tail past
 * `2 * K` ⇒ engine reverts to no-holdback cutoff and emits
 * `buffer-overflow-warning`. "Redaction trumps fidelity" — partial-match leak
 * accepted to keep stream from stalling.
 *
 * **K latency.** Default 4160 (PEM 4096 + 64). Token-streaming consumers who
 * don't need PEM ⇒ `policy().removeCredentialPattern('pem-private-key')` ⇒ K = 320.
 *
 * **Offset frame.** `Finding.offset = consumedBytes + matchOffset` where
 * `consumedBytes` is post-redaction bytes already emitted by this engine.
 *
 * **Overflow trigger** (one ruleId, two paths):
 *   (i) `degraded` ⇒ always fires regardless of pending findings;
 *   (ii) slide-emit + no credential matched in this push AND none held in tail.
 * `anyMatch` from `findHoldbackCutoff` suppresses (ii) when a credential is
 * held for the next push.
 *
 * Streaming always uses `redactCore` (the `redactSilent` per-pattern
 * `replace` optimization can't honor the holdback cutoff).
 */

import { type EmitContext, findHoldbackCutoff, redactCore } from './credentials.js';
import { VaglioStreamCanceledError } from './errors.js';
import type { Finding, Severity, StreamDiagnosticFinding } from './findings.js';
import { DEFAULT_POLICY, type Policy, type SanitizeOptions } from './policy.js';

const FINDING_RULE_VERSION = 1;
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

/** `bufferLimit` snapshotted at construction — forward-compat insurance against in-flight policy replacement. */
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

    // Buffer ≤ K ⇒ nothing committable yet (partial-prefix / greedy concerns).
    if (this.#buffer.length <= K) return '';

    // Phase 1: cutoff = length - K; crossing matches shrink it. `anyMatch` ⇒
    // a credential is held in the tail; suppresses no-progress overflow.
    const { cutoff: cutoffInitial, anyMatch } = findHoldbackCutoff(
      this.#buffer,
      this.#policy.credentials.patterns,
      K
    );
    let effCutoff = cutoffInitial;

    // Held tail > 2*K ⇒ degrade to no-holdback (single oversized match would
    // grow buffer unboundedly on next push). Partial-match leak accepted.
    let degraded = false;
    const heldTailLen = this.#buffer.length - effCutoff;
    if (heldTailLen > 2 * K) {
      effCutoff = this.#buffer.length - K;
      degraded = true;
    } else if (effCutoff <= 0) {
      return '';
    }

    // Phase 2: redactCore on leading region; held tail kept verbatim.
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

    if (this.#onFinding !== undefined && committed.length > 0) {
      if (degraded || (credentialMatchCount === 0 && !anyMatch)) {
        this.#onFinding(makeOverflowFinding(this.#policy, this.#consumedBytes));
      }
    }

    return committed;
  }
}

/**
 * Cancel via `readable.cancel(reason)` or `writable.abort(reason)`.
 * @example
 *   await fetch(url).then(r => r.body!)
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
 * Source errors propagate as-is; consumer break/return() ⇒ finally runs
 * `engine.cancel(undefined)` ⇒ emits `stream-canceled` finding when subscribed.
 * @example
 *   for await (const safe of redactIterable(modelStream(), { onFinding: log })) yield safe;
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
