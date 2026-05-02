/**
 * v0.1 `build()` validates duplicate `ruleId` (across credential + strip
 * patterns) and `setBufferLimit` floor only. ReDoS analysis and
 * unbounded-pattern detection are deferred to v0.2 ⇒ consumers MUST audit
 * any custom patterns added via `addCredentialPattern` / `addStripPattern`.
 * Patterns without explicit `maxMatchLength` contribute a 256-char fallback
 * to `bufferLimit` auto-derivation.
 */

import type { CredentialPattern } from './credentials.js';
import { type PolicyValidationCause, VaglioPolicyValidationError } from './errors.js';
import type { Finding, Severity } from './findings.js';

/**
 * Lives here, not in credentials.ts, to break the credentials.ts → policy.ts
 * → credentials.ts load-time cycle (TDZ on `INITIAL_STATE` construction). Type
 * stays in credentials.ts via a type-only edge; credentials.ts re-exports the
 * array for the public surface.
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
    severity: 'medium' as Severity,
    maxMatchLength: 4096
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

/** Matches are removed entirely (no placeholder substitution). Emits `unicode-strip` findings. */
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

/** Conservative bound for patterns without explicit `maxMatchLength`. v0.2 analyzer will tighten. */
const UNDECLARED_PATTERN_LENGTH_FALLBACK = 256;

const BUFFER_LIMIT_SLACK = 64;

export type Policy = Readonly<{
  unicode: Readonly<{
    categories: ReadonlySet<UnicodeCategory>;
    combiningMarkCap: number;
    nfkcEnabled: boolean;
  }>;

  credentials: Readonly<{
    patterns: ReadonlyArray<CredentialPattern>;
  }>;

  strip: Readonly<{
    patterns: ReadonlyArray<StripPattern>;
  }>;

  reasoningTags: Readonly<{
    names: ReadonlySet<string>;
  }>;

  placeholderDefault: string;

  /** Auto-derived: `max(maxMatchLength) + 64`. Override via `setBufferLimit`; below auto-min throws. */
  bufferLimit: number;

  severityOverrides: Readonly<Record<string, Severity>>;
}>;

export type SanitizeOptions = Readonly<{
  policy?: Policy;
  onFinding?: (finding: Finding) => void;
}>;

export type SanitizeResult = Readonly<{
  /** Same reference as input when `changed === false`. */
  text: string;
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

/** Frozen, copied on every customization (immutable builder per ADR D2). */
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
    // Coerce to /g — `matchAll` throws on non-global. Built-ins already carry `g`; no-op for them.
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

/** `Object.freeze` on a Set is shallow ⇒ clone defensively. `ReadonlySet` blocks compile-time mutation. */
function freezeSet<T>(input: ReadonlySet<T>): ReadonlySet<T> {
  return new Set(input);
}

export function policy(): PolicyBuilder {
  return new PolicyBuilderImpl(INITIAL_STATE);
}

/** Frozen library defaults. Customize via `policy().<methods>.build()`. */
export const DEFAULT_POLICY: Policy = policy().build();
