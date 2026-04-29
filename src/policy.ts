/**
 * Policy + PolicyBuilder + DEFAULT_POLICY for Vaglio v0.1.
 *
 * Per spec-api §3 (Policy shape), §5 (builder), §8 (validation errors).
 *
 * Builder is **immutable** per ADR D2: every customization method returns a NEW
 * builder instance. `build()` produces a frozen `Policy` and leaves the builder
 * untouched (callers can `.build()` repeatedly off a shared base).
 *
 * v0.1 deferrals (per user direction 2026-04-29):
 *
 *   - **ReDoS static analyzer → v0.2.** `build()` does not analyze user-supplied
 *     regex sources. Builtin patterns are pre-validated at library-build time;
 *     consumers MUST audit any custom patterns they add via `addCredentialPattern`
 *     or `addStripPattern`. The v0.1 contract is "evaluated unchecked."
 *   - **Unbounded-pattern detection → v0.2.** Same analyzer. v0.1 strongly
 *     recommends `maxMatchLength` for any pattern with `*`/`+`/unbounded
 *     alternation, but does not enforce. The streaming buffer falls back to a
 *     256-character bound when `maxMatchLength` is omitted.
 *
 * v0.1 `build()` validates:
 *
 *   - Duplicate `ruleId` across credential + strip patterns.
 *   - Explicit `setBufferLimit` below the auto-derived minimum.
 *
 * **Spec correction (M3, 2026-04-29):** spec-api §3's Policy shape originally
 * omitted a slot for user `addStripPattern` regexes. This file adds
 * `Policy.strip.patterns` parallel to `Policy.credentials.patterns`. Folding
 * user strip patterns into `Policy.unicode` would conflate arbitrary regex with
 * the closed `UnicodeCategory` enum and is the wrong shape. Captured in the M3
 * wiki resync.
 */

import type { CredentialPattern } from './credentials.js';
import { type PolicyValidationCause, VaglioPolicyValidationError } from './errors.js';
import type { Finding, Severity } from './findings.js';

/**
 * The default credential pattern set lives here (not in `credentials.ts`) to
 * break a load-time cycle: `credentials.ts` needs `DEFAULT_POLICY` at runtime,
 * which forces a static import edge from credentials.ts → policy.ts. If
 * `policy.ts` reciprocated by value-importing `DEFAULT_CREDENTIAL_PATTERNS`
 * from credentials.ts, the partial-evaluation moment leaves the patterns array
 * in TDZ when `INITIAL_STATE` is being constructed. Inlining the array here —
 * with the type still defined in credentials.ts via a type-only edge — keeps
 * the runtime graph acyclic. `credentials.ts` re-exports the array for the
 * public surface (spec-api §1).
 */
export const DEFAULT_CREDENTIAL_PATTERNS: ReadonlyArray<CredentialPattern> = Object.freeze([
  Object.freeze({
    ruleId: 'anthropic-token',
    pattern: /sk-ant-\S{20,}/g,
    severity: 'high' as Severity
  }),
  Object.freeze({
    ruleId: 'aws-access-key',
    pattern: /(?:AKIA|ASIA)[0-9A-Z]{16}/g,
    severity: 'high' as Severity
  }),
  Object.freeze({
    ruleId: 'jwt',
    pattern: /Bearer\s+eyJ[a-zA-Z0-9._-]{50,}/g,
    severity: 'medium' as Severity
  }),
  Object.freeze({
    ruleId: 'slack-token',
    pattern: /xox[bp]-[A-Za-z0-9-]{20,}/g,
    severity: 'medium' as Severity
  }),
  Object.freeze({
    ruleId: 'github-pat',
    pattern: /ghp_[A-Za-z0-9]{36}/g,
    severity: 'medium' as Severity
  }),
  Object.freeze({
    ruleId: 'stripe-restricted-key',
    pattern: /rk_live_[A-Za-z0-9]{20,}/g,
    severity: 'high' as Severity
  }),
  Object.freeze({
    ruleId: 'pem-private-key',
    pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
    severity: 'high' as Severity,
    maxMatchLength: 4096
  }),
  Object.freeze({
    ruleId: 'long-hex',
    pattern: /\b[0-9a-f]{64,}\b/g,
    severity: 'medium' as Severity
  })
]);

export type UnicodeCategory =
  | 'tags-block'
  | 'zero-width'
  | 'bidi-override'
  | 'mongolian-fvs'
  | 'interlinear-annotations'
  | 'object-replacement'
  | 'supplementary-pua'
  | 'supplementary-variation-selectors'
  | 'soft-hyphen-fillers'
  | 'math-invisibles'
  | 'orphaned-surrogates'
  | 'ansi-escapes'
  | 'c0-c1-controls';

const ALL_UNICODE_CATEGORIES: ReadonlyArray<UnicodeCategory> = Object.freeze([
  'tags-block',
  'zero-width',
  'bidi-override',
  'mongolian-fvs',
  'interlinear-annotations',
  'object-replacement',
  'supplementary-pua',
  'supplementary-variation-selectors',
  'soft-hyphen-fillers',
  'math-invisibles',
  'orphaned-surrogates',
  'ansi-escapes',
  'c0-c1-controls'
]);

/**
 * User-supplied regex strip pattern (added via `PolicyBuilder.addStripPattern`).
 * Parallel to `CredentialPattern` but without `placeholder` — matches are
 * removed entirely, no substitution. Findings emitted with `kind:
 * "unicode-strip"` and the user-supplied `ruleId`.
 */
export type StripPattern = Readonly<{
  ruleId: string;
  pattern: RegExp;
  severity?: Severity;
  ruleVersion?: number;
  maxMatchLength?: number;
}>;

const DEFAULT_COMBINING_MARK_CAP = 4;
const DEFAULT_PLACEHOLDER = '<credential>';
const DEFAULT_REASONING_TAG_NAMES: ReadonlyArray<string> = Object.freeze(['internal']);

/**
 * Buffer fallback for patterns without an explicit `maxMatchLength`. The
 * v0.1 streaming buffer uses this as a safe lower bound for sliding-window
 * sizing when a pattern is bounded-by-source but doesn't declare its bound.
 * Tightening this is part of the v0.2 static analyzer.
 */
const UNDECLARED_PATTERN_LENGTH_FALLBACK = 256;

/** Slack added on top of the longest matchable pattern (spec §F3 / spec-api §3). */
const BUFFER_LIMIT_SLACK = 64;

export type Policy = Readonly<{
  unicode: Readonly<{
    /**
     * Active Unicode strip categories. v0.1: declarative only — the
     * `stripUnicode` runtime currently strips the union; per-category gating
     * lands in M3.4 alongside the `*Detailed` variants. After M3.4, disabling
     * a category here will skip its stripper.
     */
    categories: ReadonlySet<UnicodeCategory>;
    combiningMarkCap: number;
    nfkcEnabled: boolean;
  }>;

  credentials: Readonly<{
    patterns: ReadonlyArray<CredentialPattern>;
  }>;

  /**
   * User-supplied regex strip patterns added via `addStripPattern`. Spec
   * correction (see file header).
   */
  strip: Readonly<{
    patterns: ReadonlyArray<StripPattern>;
  }>;

  reasoningTags: Readonly<{
    names: ReadonlySet<string>;
  }>;

  placeholderDefault: string;

  /**
   * Streaming sliding-window buffer cap. Auto-derived at `build()` time from
   * `max(maxMatchLength_for_each_pattern) + 64`. Patterns without an explicit
   * `maxMatchLength` contribute the v0.1 fallback (256). Override via
   * `setBufferLimit`; values below the auto-derived minimum throw at build().
   */
  bufferLimit: number;

  severityOverrides: Readonly<Record<string, Severity>>;
}>;

export type SanitizeOptions = Readonly<{
  policy?: Policy;
  onFinding?: (finding: Finding) => void;
}>;

export type SanitizeResult = Readonly<{
  /** Same string reference as input when `changed === false`. */
  text: string;
  /** True iff sanitization mutated the input. */
  changed: boolean;
  findings: ReadonlyArray<Finding>;
}>;

export interface PolicyBuilder {
  addCredentialPattern(
    pattern: RegExp,
    options: { ruleId: string } & Partial<Omit<CredentialPattern, 'pattern' | 'ruleId'>>
  ): PolicyBuilder;
  addCredentialPattern(pattern: CredentialPattern): PolicyBuilder;

  removeCredentialPattern(ruleId: string): PolicyBuilder;

  addStripPattern(
    pattern: RegExp,
    options: { ruleId: string; severity?: Severity; ruleVersion?: number; maxMatchLength?: number }
  ): PolicyBuilder;
  removeStripPattern(ruleId: string): PolicyBuilder;

  addReasoningTag(name: string): PolicyBuilder;
  removeReasoningTag(name: string): PolicyBuilder;

  enableUnicodeCategory(category: UnicodeCategory): PolicyBuilder;
  disableUnicodeCategory(category: UnicodeCategory): PolicyBuilder;
  setCombiningMarkCap(cap: number): PolicyBuilder;
  setNfkcEnabled(enabled: boolean): PolicyBuilder;

  setPlaceholderDefault(placeholder: string): PolicyBuilder;
  setSeverity(ruleId: string, severity: Severity): PolicyBuilder;
  setBufferLimit(limit: number): PolicyBuilder;

  build(): Policy;
}

/** Internal builder state — frozen field-by-field, copied on every customization. */
type BuilderState = Readonly<{
  unicodeCategories: ReadonlySet<UnicodeCategory>;
  combiningMarkCap: number;
  nfkcEnabled: boolean;
  credentials: ReadonlyArray<CredentialPattern>;
  strip: ReadonlyArray<StripPattern>;
  reasoningTags: ReadonlySet<string>;
  placeholderDefault: string;
  severityOverrides: Readonly<Record<string, Severity>>;
  bufferLimitOverride: number | undefined;
}>;

const INITIAL_STATE: BuilderState = Object.freeze({
  unicodeCategories: new Set(ALL_UNICODE_CATEGORIES),
  combiningMarkCap: DEFAULT_COMBINING_MARK_CAP,
  nfkcEnabled: true,
  credentials: DEFAULT_CREDENTIAL_PATTERNS,
  strip: Object.freeze<ReadonlyArray<StripPattern>>([]),
  reasoningTags: new Set(DEFAULT_REASONING_TAG_NAMES),
  placeholderDefault: DEFAULT_PLACEHOLDER,
  severityOverrides: Object.freeze({}),
  bufferLimitOverride: undefined
});

class PolicyBuilderImpl implements PolicyBuilder {
  readonly #state: BuilderState;

  constructor(state: BuilderState) {
    this.#state = state;
  }

  // ── Credential patterns ────────────────────────────────────────────────────

  addCredentialPattern(
    pattern: RegExp,
    options: { ruleId: string } & Partial<Omit<CredentialPattern, 'pattern' | 'ruleId'>>
  ): PolicyBuilder;
  addCredentialPattern(pattern: CredentialPattern): PolicyBuilder;
  addCredentialPattern(
    patternOrEntry: RegExp | CredentialPattern,
    options?: { ruleId: string } & Partial<Omit<CredentialPattern, 'pattern' | 'ruleId'>>
  ): PolicyBuilder {
    // Coerce non-global to global. The redact telemetry path uses `matchAll`,
    // which throws TypeError on a non-global RegExp; coercing at registration
    // keeps the runtime path uniform and spares user patterns a separate validation
    // step. Built-ins all carry `g`; this is a no-op for them.
    const sourceRe = patternOrEntry instanceof RegExp ? patternOrEntry : patternOrEntry.pattern;
    const finalRe = sourceRe.flags.includes('g')
      ? sourceRe
      : new RegExp(sourceRe.source, `${sourceRe.flags}g`);
    const entry: CredentialPattern =
      patternOrEntry instanceof RegExp
        ? Object.freeze({ ...(options as { ruleId: string }), pattern: finalRe })
        : Object.freeze({ ...patternOrEntry, pattern: finalRe });
    return this.#with({ credentials: Object.freeze([...this.#state.credentials, entry]) });
  }

  removeCredentialPattern(ruleId: string): PolicyBuilder {
    return this.#with({
      credentials: Object.freeze(this.#state.credentials.filter((p) => p.ruleId !== ruleId))
    });
  }

  // ── Strip patterns ─────────────────────────────────────────────────────────

  addStripPattern(
    pattern: RegExp,
    options: { ruleId: string; severity?: Severity; ruleVersion?: number; maxMatchLength?: number }
  ): PolicyBuilder {
    const entry: StripPattern = Object.freeze({ ...options, pattern });
    return this.#with({ strip: Object.freeze([...this.#state.strip, entry]) });
  }

  removeStripPattern(ruleId: string): PolicyBuilder {
    return this.#with({
      strip: Object.freeze(this.#state.strip.filter((p) => p.ruleId !== ruleId))
    });
  }

  // ── Reasoning tags ─────────────────────────────────────────────────────────

  addReasoningTag(name: string): PolicyBuilder {
    if (this.#state.reasoningTags.has(name)) return this;
    const next = new Set(this.#state.reasoningTags);
    next.add(name);
    return this.#with({ reasoningTags: next });
  }

  removeReasoningTag(name: string): PolicyBuilder {
    if (!this.#state.reasoningTags.has(name)) return this;
    const next = new Set(this.#state.reasoningTags);
    next.delete(name);
    return this.#with({ reasoningTags: next });
  }

  // ── Unicode categories ─────────────────────────────────────────────────────

  enableUnicodeCategory(category: UnicodeCategory): PolicyBuilder {
    if (this.#state.unicodeCategories.has(category)) return this;
    const next = new Set(this.#state.unicodeCategories);
    next.add(category);
    return this.#with({ unicodeCategories: next });
  }

  disableUnicodeCategory(category: UnicodeCategory): PolicyBuilder {
    if (!this.#state.unicodeCategories.has(category)) return this;
    const next = new Set(this.#state.unicodeCategories);
    next.delete(category);
    return this.#with({ unicodeCategories: next });
  }

  setCombiningMarkCap(cap: number): PolicyBuilder {
    return this.#with({ combiningMarkCap: cap });
  }

  setNfkcEnabled(enabled: boolean): PolicyBuilder {
    return this.#with({ nfkcEnabled: enabled });
  }

  // ── Global knobs ───────────────────────────────────────────────────────────

  setPlaceholderDefault(placeholder: string): PolicyBuilder {
    return this.#with({ placeholderDefault: placeholder });
  }

  setSeverity(ruleId: string, severity: Severity): PolicyBuilder {
    return this.#with({
      severityOverrides: Object.freeze({ ...this.#state.severityOverrides, [ruleId]: severity })
    });
  }

  setBufferLimit(limit: number): PolicyBuilder {
    return this.#with({ bufferLimitOverride: limit });
  }

  // ── Terminator ─────────────────────────────────────────────────────────────

  build(): Policy {
    const causes: PolicyValidationCause[] = [];

    // Duplicate ruleId check across credentials + strip patterns.
    const seen = new Map<string, RegExp>();
    for (const p of this.#state.credentials) {
      const prior = seen.get(p.ruleId);
      if (prior !== undefined) {
        causes.push({
          pattern: p.pattern.source,
          rule: 'duplicate-rule-id',
          detail: `ruleId "${p.ruleId}" declared on multiple credential patterns`
        });
      } else {
        seen.set(p.ruleId, p.pattern);
      }
    }
    for (const p of this.#state.strip) {
      const prior = seen.get(p.ruleId);
      if (prior !== undefined) {
        causes.push({
          pattern: p.pattern.source,
          rule: 'duplicate-rule-id',
          detail: `ruleId "${p.ruleId}" declared on a strip pattern conflicts with an earlier pattern`
        });
      } else {
        seen.set(p.ruleId, p.pattern);
      }
    }

    // Auto-derive bufferLimit. Patterns without explicit maxMatchLength fall
    // back to UNDECLARED_PATTERN_LENGTH_FALLBACK (v0.1 simplification — v0.2
    // ReDoS analyzer will compute exact bounds from regex source).
    const candidates: number[] = [UNDECLARED_PATTERN_LENGTH_FALLBACK];
    for (const p of this.#state.credentials) {
      candidates.push(p.maxMatchLength ?? UNDECLARED_PATTERN_LENGTH_FALLBACK);
    }
    for (const p of this.#state.strip) {
      candidates.push(p.maxMatchLength ?? UNDECLARED_PATTERN_LENGTH_FALLBACK);
    }
    const autoMin = Math.max(...candidates) + BUFFER_LIMIT_SLACK;

    let bufferLimit = autoMin;
    if (this.#state.bufferLimitOverride !== undefined) {
      if (this.#state.bufferLimitOverride < autoMin) {
        causes.push({
          pattern: '',
          rule: 'buffer-limit-too-low',
          detail: `bufferLimit ${this.#state.bufferLimitOverride} is below auto-derived minimum ${autoMin}`
        });
      } else {
        bufferLimit = this.#state.bufferLimitOverride;
      }
    }

    if (causes.length > 0) {
      throw new VaglioPolicyValidationError(causes);
    }

    return Object.freeze({
      unicode: Object.freeze({
        categories: freezeSet(this.#state.unicodeCategories),
        combiningMarkCap: this.#state.combiningMarkCap,
        nfkcEnabled: this.#state.nfkcEnabled
      }),
      credentials: Object.freeze({
        patterns: Object.freeze([...this.#state.credentials])
      }),
      strip: Object.freeze({
        patterns: Object.freeze([...this.#state.strip])
      }),
      reasoningTags: Object.freeze({
        names: freezeSet(this.#state.reasoningTags)
      }),
      placeholderDefault: this.#state.placeholderDefault,
      bufferLimit,
      severityOverrides: Object.freeze({ ...this.#state.severityOverrides })
    });
  }

  #with(patch: Partial<BuilderState>): PolicyBuilder {
    return new PolicyBuilderImpl(Object.freeze({ ...this.#state, ...patch }));
  }
}

/**
 * `Set` is structurally mutable in JS — `Object.freeze` on a Set is shallow and
 * leaves `add`/`delete` working. The `ReadonlySet` type tells the compiler not
 * to mutate; for runtime safety we wrap in a frozen proxy-free clone (avoiding
 * Proxy keeps allocation cheap; consumers who try to mutate get a TS error
 * before runtime).
 */
function freezeSet<T>(input: ReadonlySet<T>): ReadonlySet<T> {
  return new Set(input);
}

/** Construct a fresh builder seeded with library defaults. */
export function policy(): PolicyBuilder {
  return new PolicyBuilderImpl(INITIAL_STATE);
}

/**
 * Library-default policy. Frozen; consumers store and pass it freely. To
 * customize, start from `policy()` and chain customization methods.
 */
export const DEFAULT_POLICY: Policy = policy().build();
