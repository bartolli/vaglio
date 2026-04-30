/**
 * Streaming composed sanitization for Vaglio v0.1 — M3.5 Slice E.2,
 * extended in M3.6 with option-B holdback at the redact stage.
 *
 * Two surfaces over one engine:
 *   - `createSanitizeStream(options?)` — `TransformStream<string, string>` per spec-api §1, §7.
 *   - `sanitizeIterable(source, options?)` — `AsyncIterable<string>` per spec-api §1, §7.
 *
 * Both wrap `SanitizeStreamEngine`, a single-buffer adapter that layers
 * the Slice D pipeline (`stripUnicode → stripTags → redact`) with two
 * holdback regions per push: a trailing-peel region (shielding the ZWJ-
 * context check from chunk-boundary after-context unknowns) and the
 * redact-stage K-char holdback (shielding greedy `{N,}` credential
 * patterns from early commits).
 *
 * **Single-buffer architecture (per the M3.5 plan).** One buffer per call;
 * every stage runs against it. Chained `pipeThrough` of per-stage streams
 * was rejected as v0.1 architecture — multiplies memory and breaks per-call
 * ownership of cancel/overflow semantics.
 *
 * v0.1 contract notes (capture in M3 wiki resync):
 *
 *   - **Pipeline idempotency.** `pipeline(pipeline(x)) === pipeline(x)`
 *     is load-bearing for streaming: the engine's per-call buffer holds
 *     post-pipeline state across pushes, so re-running the pipeline on
 *     buffer + new chunk must not produce different output than running
 *     it once on the concatenated raw input. M3.6 closed two idempotency
 *     gaps to make this hold: (1) a final NFKC pass after the strip
 *     stages, so codepoints exposed by stripping intervening blockers
 *     (e.g. `a + ZWSP + ́` → `a + ́` after ZWSP strip) re-canonicalize
 *     to NFKC; (2) VS-context strip moved before ZWJ-context strip, so
 *     the ZWJ check doesn't accept a VS-16 as before-context that the
 *     subsequent VS check would orphan-strip.
 *
 *   - **Trailing-peel holdback (generalizes the M3.5 trailing-ZWJ
 *     holdback).** The ZWJ-context check needs the codepoint AFTER each
 *     ZWJ to decide preserve-vs-strip; at a chunk boundary the after is
 *     unknown. A naïve `endsWith('‍')` check misses an attack: trailing
 *     codepoints the strip-set or context strippers later remove
 *     (zero-width, bidi, fillers, BMP variation selectors, **astral
 *     ranges**: tag-block U+E0001–U+E007F, supplementary VS, supplementary
 *     PUA) can expose a previously-interior ZWJ to the orphan-strip rule
 *     once peeled — making streaming output diverge from batch for the
 *     same concatenated input. The engine peels any trailing run of these
 *     codepoints and, when a ZWJ is among them, defers the entire peeled
 *     region to the next push. Flush runs without holdback (source
 *     exhausted → trailing ZWJ has no future partner and is correctly
 *     treated as orphan). The peel set mirrors the strip-set categories
 *     in `src/unicode.ts`; new categories there must add a corresponding
 *     entry in `isTrailingPeelable` here.
 *
 *   - **Redact-stage holdback (option B).** At the redact stage the engine
 *     retains the trailing K = `bufferLimit` characters from regex
 *     evaluation; only the leading region commits. Closes two
 *     stream/batch divergences for greedy `{N,}` patterns: (a) early-match
 *     at end-of-buffer (e.g. `\b[0-9a-f]{64,}\b` greedy-stops at buffer
 *     end and commits 64 chars when the full input would have matched 68);
 *     (b) partial-prefix straddle (e.g. `Bearer eyJ` arrives in chunk 1
 *     before the body satisfies `{50,}`). A crossing match shrinks the
 *     cutoff so the entire match lands in the held tail; if the held tail
 *     would exceed `2 * K` (single oversized match), the engine degrades
 *     to no-holdback for that push and emits a `buffer-overflow-warning`
 *     ("redaction trumps fidelity" — partial-match leak accepted to keep
 *     the stream from stalling). Flush has no holdback.
 *
 *   - **K = `bufferLimit` latency contract.** Default policy K = 4160
 *     (PEM `maxMatchLength` 4096 + 64 slack). Token-streaming consumers
 *     who don't need PEM redaction can shrink K to 320 via
 *     `policy().removeCredentialPattern('pem-private-key').build()`.
 *
 *   - **Cross-chunk + cross-stage offset frame.** `Finding.offset =
 *     stage_local_offset + consumedBytes`. The `stage_local_offset` is
 *     the Slice D cross-stage frame: each stage's offset is in the input
 *     to that stage (post-prior-stages within the push). `consumedBytes`
 *     is the count of post-pipeline characters already emitted downstream
 *     by this engine. Mirrors E.1's offset frame; just adds two more
 *     stages to the post-prior-stages part.
 *
 *   - **Overflow trigger.** `buffer-overflow-warning` fires under one of
 *     two conditions: (i) the redact-stage held tail would exceed
 *     `2 * K`, forcing the engine to degrade to no-holdback for that push
 *     — always fires regardless of pending findings; (ii) slide-emit
 *     happens with zero substantive findings (`unicode-strip` ∪
 *     `credential`) AND no credential is held in the tail — meaningful
 *     "stream churning bytes downstream without sanitizing" signal (e.g.
 *     unclosed `<internal>` tag-block leak). `credentialPending` from
 *     `findHoldbackCutoff` suppresses (ii) when a credential is held for
 *     the next push.
 *
 *   - **Tag-block overflow leaks reasoning context (v0.1 limitation).**
 *     If `<internal>` opens but never closes within `bufferLimit`, the
 *     unmatched content slides downstream as the buffer fills. Credentials
 *     inside still redact at the redact stage — defense in depth — but the
 *     reasoning text itself reaches the model. `buffer-overflow-warning`
 *     fires per (ii) above. v0.1 reuses the existing `bufferLimit`; no
 *     new `Policy.reasoningTags.maxBlockBytes` slot. v0.2 candidate.
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

/** Default severity for stream-diagnostic ruleIds (spec-api §6 table). */
const DEFAULT_DIAGNOSTIC_SEVERITY: Severity = 'low';

function diagnosticSeverity(policy: Policy, ruleId: string): Severity {
  return policy.severityOverrides[ruleId] ?? DEFAULT_DIAGNOSTIC_SEVERITY;
}

/**
 * Codepoints the sanitize pipeline might remove (strip-set, ANSI/control
 * fast paths, bidi, fillers, BMP variation selectors, zero-width including
 * ZWJ). Used by the trailing-edge holdback to detect "ZWJ exposed by
 * later stages" — peeling these from the trailing edge and deferring when
 * a ZWJ is among them ensures the ZWJ-context strip evaluates with full
 * after-context across chunk boundaries. NB: this is intentionally a
 * superset of the actual strip set; over-peeling at the trailing edge is
 * harmless (those codepoints will be re-evaluated next push), under-peeling
 * is the bug we're fixing.
 */
function isTrailingPeelable(ch: string): boolean {
  // Mirror of the unicode strip-set categories in `src/unicode.ts`
  // CATEGORY_SOURCES (BMP) plus the astral entries that are otherwise
  // invisible to UTF-16 indexing. Every new entry to a strip-set category
  // needs a corresponding entry here; missing astral ranges produce the
  // same "expose-trailing-ZWJ" divergence as missing BMP ranges (e.g. an
  // attacker placing a tag-block codepoint between ZWJ and the next emoji
  // in a different chunk).
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

  /**
   * Flush-time pipeline: run all three stages eagerly. No redact-stage
   * holdback because the source is exhausted and any greedy match in the
   * tail is final.
   */
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
   * Per-push pipeline with redact-stage holdback. Runs `stripUnicode` and
   * `stripTags` against the full buffer (these stages have no
   * greedy-extension or partial-prefix concerns), then applies the
   * holdback cutoff at the redact stage so a credential that straddles
   * the chunk boundary stays in the held tail until the next push (or
   * until flush) provides the rest. Returns the committed leading slice
   * (post-pipeline) and the held tail (post-stripUnicode + post-stripTags
   * + verbatim credentials within the held region).
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

    // Trailing-edge holdback for context-dependent stages. The ZWJ-context
    // strip needs the codepoint AFTER each ZWJ to decide preserve-vs-strip;
    // at a chunk boundary the after-context is unknown, so the engine must
    // defer any trailing ZWJ. The naive `endsWith('‍')` check misses
    // an attack: trailing zero-width chars (e.g. ZWSP) get removed by the
    // strip-set first, exposing a now-trailing ZWJ that the ZWJ-context
    // check then strips as orphan — making streaming diverge from batch
    // for the same concatenated input. The fix is to peel any trailing
    // codepoints the pipeline could remove (zero-width in the strip-set,
    // bidi controls, fillers, BMP variation selectors, ZWJ itself, etc.)
    // and defer the entire peeled region whenever a ZWJ is among the
    // peeled codepoints. The next push concatenates new data and re-runs
    // with full context. Flush has no holdback (source exhausted → an
    // orphan ZWJ is correct).
    const { processBuf, deferred } = findTrailingZwjDeferral(this.#buffer);

    const K = this.#bufferLimit;
    const { committed, retain, degraded, substantive, credentialPending } =
      this.#runPipelineWithHoldback(processBuf, K);

    this.#buffer = retain + deferred;

    if (committed.length === 0) return '';

    this.#consumedBytes += committed.length;

    // Overflow trigger: same two-path shape as RedactStreamEngine.
    //   (i)  `degraded`: single match exceeded `2 * K`; fired regardless of
    //        pending findings.
    //   (ii) Slide-emit + no substantive findings AND no credential held in
    //        the tail: stream churned bytes downstream without sanitizing
    //        (e.g. tag-block leak when `<internal>` opens but never closes
    //        within bufferLimit). `credentialPending` suppresses the
    //        false-positive when a credential is held for the next push.
    if (this.#onFinding !== undefined) {
      if (degraded || (!substantive && !credentialPending)) {
        this.#onFinding(makeOverflowFinding(this.#policy, this.#consumedBytes));
      }
    }

    return committed;
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
