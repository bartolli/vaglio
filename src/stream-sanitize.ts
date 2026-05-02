/**
 * Streaming composed sanitization. Two adapters over one
 * `SanitizeStreamEngine` that layers the batch pipeline
 * (`stripUnicode → stripTags → redact`) with two holdback regions per push:
 * trailing-peel (ZWJ-context after-context shield) and redact-stage K-char
 * (greedy `{N,}` credential shield).
 *
 * **Single-buffer architecture.** One buffer per call; every stage runs
 * against it. Chained `pipeThrough` of per-stage streams rejected at v0.1 —
 * multiplies memory and breaks per-call ownership of cancel/overflow.
 *
 * **Pipeline idempotency** (`pipeline(pipeline(x)) === pipeline(x)`) is
 * load-bearing for streaming. M3.6 closed two idempotency gaps:
 *   - final NFKC after strip stages re-canonicalizes sequences exposed by
 *     stripping intervening blockers;
 *   - VS-context moved before ZWJ-context so ZWJ doesn't accept a VS-16 as
 *     before-context that the subsequent VS check would orphan-strip.
 *
 * **Trailing-peel holdback** (generalizes the M3.5 trailing-ZWJ holdback).
 * ZWJ-context needs the codepoint AFTER each ZWJ; at a chunk boundary that
 * is unknown. Naïve `endsWith('ZWJ')` misses an attack: trailing codepoints
 * the pipeline later removes (zero-width, bidi, fillers, BMP VS, astral
 * ranges: tag-block, supplementary VS, supplementary PUA) can expose a
 * previously-interior ZWJ to orphan-strip ⇒ stream/batch divergence. Engine
 * peels any trailing run of these codepoints and defers the peeled region
 * when a ZWJ is among them. Peel set MUST mirror strip-set categories in
 * `src/unicode.ts` ⇒ new categories there add an entry in `isTrailingPeelable` here.
 *
 * **Redact-stage holdback (option B).** Same as `stream-redact.ts`. K =
 * `policy.bufferLimit` (default 4160). Single-oversized-match degrade ⇒
 * `buffer-overflow-warning`.
 *
 * **Offset frame.** `Finding.offset = stage_local_offset + consumedBytes`.
 * `stage_local_offset` is the batch cross-stage frame (post-prior-stages
 * within this push); `consumedBytes` is post-pipeline bytes already emitted.
 *
 * **Overflow trigger.** Same shape as `stream-redact`, except substantive =
 * `credential` ∪ `unicode-strip` (covers strip-set + reasoning-tag findings).
 *
 * **Tag-block overflow leaks reasoning context** (v0.1 limitation). Unclosed
 * `<internal>` past `bufferLimit` ⇒ unmatched content slides downstream;
 * credentials inside still redact (defense in depth). v0.2 candidate:
 * dedicated `Policy.reasoningTags.maxBlockBytes`.
 */

import { type EmitContext, findHoldbackCutoff, redact, redactCore } from './credentials.js';
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
const DEFAULT_DIAGNOSTIC_SEVERITY: Severity = 'low';

function diagnosticSeverity(policy: Policy, ruleId: string): Severity {
  return policy.severityOverrides[ruleId] ?? DEFAULT_DIAGNOSTIC_SEVERITY;
}

/**
 * Superset of the strip-set: over-peel is harmless (re-evaluated next push),
 * under-peel exposes trailing ZWJ ⇒ stream/batch divergence under
 * adversary-controlled chunking.
 */
function isTrailingPeelable(ch: string): boolean {
  // MUST mirror `src/unicode.ts` CATEGORY_SOURCES (BMP) + astral entries.
  // New strip-set category there ⇒ add an entry here, or attacker can place
  // an unpeeled codepoint between ZWJ and the next emoji in a different chunk.
  const cp = ch.codePointAt(0);
  if (cp === undefined) return false;
  if (cp <= 0x001f) return true;
  if (cp >= 0x007f && cp <= 0x009f) return true;
  if (cp === 0x00ad) return true;
  if (cp === 0x115f || cp === 0x1160) return true;
  if (cp >= 0x180b && cp <= 0x180f) return true;
  if (cp >= 0x200b && cp <= 0x200d) return true;
  if (cp >= 0x202a && cp <= 0x202e) return true;
  if (cp >= 0x2060 && cp <= 0x2064) return true;
  if (cp >= 0x2066 && cp <= 0x2069) return true;
  if (cp >= 0xfe00 && cp <= 0xfe0f) return true;
  if (cp === 0xfeff) return true;
  if (cp >= 0xfff9 && cp <= 0xfffc) return true;
  // Astral peelables — same risk class as BMP. tags-block, supplementary
  // variation selectors, and supplementary PUA are all in the strip set.
  if (cp >= 0xe0001 && cp <= 0xe007f) return true;
  if (cp >= 0xe0100 && cp <= 0xe01ef) return true;
  if (cp >= 0xf0000 && cp <= 0xffffd) return true;
  if (cp >= 0x100000 && cp <= 0x10fffd) return true;
  return false;
}

function findTrailingZwjDeferral(buffer: string): { processBuf: string; deferred: string } {
  if (buffer.length === 0) return { processBuf: buffer, deferred: '' };
  const cps = [...buffer];
  let peelEnd = cps.length;
  let hasZwj = false;
  while (peelEnd > 0) {
    const ch = cps[peelEnd - 1] as string;
    if (isTrailingPeelable(ch)) {
      if (ch === '‍') hasZwj = true;
      peelEnd--;
    } else {
      break;
    }
  }
  if (peelEnd === cps.length || !hasZwj) return { processBuf: buffer, deferred: '' };
  let pos = 0;
  for (let j = 0; j < peelEnd; j++) pos += (cps[j] as string).length;
  return { processBuf: buffer.slice(0, pos), deferred: buffer.slice(pos) };
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

/** Findings are frozen ⇒ spread + freeze a new object. `stream-diagnostic` has no offset. */
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
 * Plumbing duplicated with `RedactStreamEngine` — the two diverge only in
 * the per-push process function; a shared base is premature for v0.1.
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

    const processed = this.#runPipelineEager(buf);
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

  /** Flush: source exhausted ⇒ no redact-stage holdback; greedy matches in tail are final. */
  #runPipelineEager(buf: string): string {
    if (this.#onFinding !== undefined) {
      const baseOffset = this.#consumedBytes;
      const userOnFinding = this.#onFinding;
      const wrapped: (f: Finding) => void = (f) => {
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

  /**
   * `stripUnicode`/`stripTags` run against the full buffer (no greedy /
   * partial-prefix concerns); redact applies the K holdback so a straddling
   * credential stays in the held tail until next push (or flush).
   */
  #runPipelineWithHoldback(
    buf: string,
    K: number
  ): {
    committed: string;
    retain: string;
    degraded: boolean;
    substantive: boolean;
    credentialPending: boolean;
  } {
    const baseOffset = this.#consumedBytes;
    const userOnFinding = this.#onFinding;
    let substantive = false;

    const stripWrapped: ((f: Finding) => void) | undefined =
      userOnFinding !== undefined
        ? (f) => {
            if (f.kind === 'unicode-strip') substantive = true;
            userOnFinding(shiftOffset(f, baseOffset));
          }
        : undefined;
    const stripStageOptions: SanitizeOptions =
      stripWrapped !== undefined
        ? { policy: this.#policy, onFinding: stripWrapped }
        : { policy: this.#policy };

    let out = stripUnicode(buf, stripStageOptions);
    out = stripTags(out, stripStageOptions);

    if (out.length <= K) {
      return {
        committed: '',
        retain: out,
        degraded: false,
        substantive,
        credentialPending: false
      };
    }

    const { cutoff: cutoffInitial, anyMatch } = findHoldbackCutoff(
      out,
      this.#policy.credentials.patterns,
      K
    );
    let effCutoff = cutoffInitial;

    let degraded = false;
    const heldTailLen = out.length - effCutoff;
    if (heldTailLen > 2 * K) {
      effCutoff = out.length - K;
      degraded = true;
    } else if (effCutoff <= 0) {
      return {
        committed: '',
        retain: out,
        degraded: false,
        substantive,
        credentialPending: anyMatch
      };
    }

    const leading = out.slice(0, effCutoff);
    const heldTail = out.slice(effCutoff);

    const redactWrapped: ((f: Finding) => void) | undefined =
      userOnFinding !== undefined
        ? (f) => {
            if (f.kind === 'credential') substantive = true;
            userOnFinding(shiftOffset(f, baseOffset));
          }
        : undefined;
    const ctx: EmitContext = {
      findings: null,
      onFinding: redactWrapped,
      policy: this.#policy
    };
    const committed = redactCore(leading, ctx, baseOffset);

    return { committed, retain: heldTail, degraded, substantive, credentialPending: anyMatch };
  }

  #processAndSlide(): string {
    if (this.#buffer.length === 0) return '';

    // Trailing-peel: see file header for the algorithm + attack rationale.
    const { processBuf, deferred } = findTrailingZwjDeferral(this.#buffer);

    const K = this.#bufferLimit;
    const { committed, retain, degraded, substantive, credentialPending } =
      this.#runPipelineWithHoldback(processBuf, K);

    this.#buffer = retain + deferred;

    if (committed.length === 0) return '';

    this.#consumedBytes += committed.length;

    if (this.#onFinding !== undefined) {
      if (degraded || (!substantive && !credentialPending)) {
        this.#onFinding(makeOverflowFinding(this.#policy, this.#consumedBytes));
      }
    }

    return committed;
  }
}

/**
 * @example
 *   await fetch(url).then(r => r.body!)
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
 * Source errors propagate as-is; consumer break/return() ⇒ finally cancels
 * engine ⇒ emits `stream-canceled` finding when subscribed.
 * @example
 *   for await (const safe of sanitizeIterable(modelStream(), { onFinding: log })) yield safe;
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
