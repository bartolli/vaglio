/**
 * Reasoning-tag stripping for Vaglio v0.1.
 *
 * Lifted from `~/Projects/sotto/src/message-io.ts` lines 147-149 per the
 * extraction inventory; reshaped in M3.4 Slice C to the spec-api §1 surface
 * (`stripTags(text, options?)` + `stripTagsDetailed`).
 *
 * Reads `policy.reasoningTags.names` for the active tag-name set (default:
 * `{'internal'}` per `DEFAULT_POLICY`). Removes `<name>...</name>` blocks
 * with a multi-line lazy match; legitimate Unicode and unbalanced tags are
 * preserved per spec-requirements §F1 / §F6.
 *
 * Load-bearing detail (preserved): `[\s\S]*?` lazy multi-line. Greedy or
 * single-line variants over-match across multiple tag pairs.
 *
 * v0.1 simplifications (Slice C, captured for M3 wiki resync):
 *   - `Finding.ruleId = 'reasoning-tag'` for every reasoning-tag strip; per-tag
 *     identity carried in `charClass`. spec-api §6 ruleId comment enum should
 *     gain `"reasoning-tag"`.
 *   - `Finding.charClass = name` overloads §6's "Unicode block name or hex
 *     codepoint range" semantics with the tag literal. Acceptable for v0.1;
 *     a cleaner shape (e.g. a tag-block kind) is a v0.2 concern.
 *   - Cross-name offset frame: when multiple tag names iterate sequentially,
 *     each name's findings reference the text AS PROCESSED BY PRIOR NAMES in
 *     this stage. Same shape as Slice A's post-NFKC frame and Slice B's
 *     cross-pattern frame.
 *
 * Divergences from origin:
 *   - Sotto's trailing `.trim()` is dropped — Vaglio is format-agnostic
 *     (spec-requirements §F6); leading/trailing whitespace is the consumer's
 *     concern.
 *   - Per-tag iteration with one regex per name (rather than alternation +
 *     backreference) preserves balance by construction and gives the telemetry
 *     path a per-name finding without group inspection.
 */

import type { Finding, Severity, UnicodeStripFinding } from './findings.js';
import {
  DEFAULT_POLICY,
  type Policy,
  type SanitizeOptions,
  type SanitizeResult
} from './policy.js';

/**
 * Default tag-name set for the public surface (spec-api §1, `vaglio/tags`
 * subpath). Mirrors `DEFAULT_POLICY.reasoningTags.names`; the runtime reads
 * from the policy, this constant is informational for consumers who want the
 * default literal without constructing a policy.
 */
export const DEFAULT_REASONING_TAGS: ReadonlyArray<string> = Object.freeze(['internal']);

/** Stable rule identifier for reasoning-tag findings. */
const REASONING_TAG_RULE_ID = 'reasoning-tag';

/** Default severity per the v0.1 finding emit (spec-api §6 has no row for `reasoning-tag`; medium is consistent with non-`tags-block` strip findings). */
const REASONING_TAG_DEFAULT_SEVERITY: Severity = 'medium';

/** Schema version for forensic stability of v0.1 findings (spec-api §6). */
const FINDING_RULE_VERSION = 1;

/** Regex metacharacters that need escaping when interpolating a tag name. */
const REGEX_META = /[.*+?^${}()|[\]\\]/g;

function escapeRegex(s: string): string {
  return s.replace(REGEX_META, '\\$&');
}

/**
 * Build the lazy multi-line regex for a given tag name. The `[\s\S]*?` body
 * is load-bearing (greedy or single-line variants over-match). Always global
 * — both the silent `.replace()` and the telemetry `matchAll` require it.
 */
function tagRegex(name: string): RegExp {
  const escaped = escapeRegex(name);
  return new RegExp(`<${escaped}>[\\s\\S]*?</${escaped}>`, 'g');
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal emission machinery (mirrors src/unicode.ts / src/credentials.ts)
// ─────────────────────────────────────────────────────────────────────────────

type EmitContext = Readonly<{
  findings: Finding[] | null;
  onFinding: ((f: Finding) => void) | undefined;
  policy: Policy;
}>;

function shouldEmit(ctx: EmitContext): boolean {
  return ctx.findings !== null || ctx.onFinding !== undefined;
}

function emit(ctx: EmitContext, finding: Finding): void {
  if (ctx.findings !== null) ctx.findings.push(finding);
  ctx.onFinding?.(finding);
}

function effectiveSeverity(policy: Policy): Severity {
  return policy.severityOverrides[REASONING_TAG_RULE_ID] ?? REASONING_TAG_DEFAULT_SEVERITY;
}

function makeReasoningTagFinding(
  offset: number,
  length: number,
  name: string,
  severity: Severity
): UnicodeStripFinding {
  // `count = length` per spec-api §6 ("consecutive characters removed"). One
  // tag block is one match → characters removed equals the block span.
  // Consumers grouping by `ruleId` get a row count from `findings.length`.
  return Object.freeze({
    kind: 'unicode-strip' as const,
    ruleId: REASONING_TAG_RULE_ID,
    ruleVersion: FINDING_RULE_VERSION,
    action: 'stripped' as const,
    offset,
    length,
    charClass: name,
    count: length,
    severity
  });
}

function makeContext(options: SanitizeOptions | undefined, detailed: boolean): EmitContext {
  return {
    findings: detailed ? [] : null,
    onFinding: options?.onFinding,
    policy: options?.policy ?? DEFAULT_POLICY
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Pipeline
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Silent fast path: per-name global `.replace()`. The `!text.includes('<')`
 * gate up front keeps clean inputs identity-preserved by reference (no
 * `.replace()` call, no allocation).
 */
function stripTagsSilent(text: string, policy: Policy): string {
  const names = policy.reasoningTags.names;
  if (names.size === 0) return text;
  if (!text.includes('<')) return text;

  let result = text;
  for (const name of names) {
    result = result.replace(tagRegex(name), '');
  }
  return result;
}

/**
 * Telemetry path: per-name `matchAll`, rebuild the output by slicing around
 * each match site, emit one `UnicodeStripFinding` per stripped block. Each
 * finding's `offset` is in the text AS PROCESSED BY PRIOR NAMES in this
 * stage — v0.1 simplification documented in the file header.
 */
function stripTagsWithFindings(text: string, ctx: EmitContext): string {
  const names = ctx.policy.reasoningTags.names;
  if (names.size === 0) return text;
  if (!text.includes('<')) return text;

  const severity = effectiveSeverity(ctx.policy);

  let result = text;
  for (const name of names) {
    const re = tagRegex(name);

    let out = '';
    let lastEnd = 0;
    let any = false;

    for (const m of result.matchAll(re)) {
      any = true;
      const start = m.index ?? 0;
      const end = start + m[0].length;
      out += result.slice(lastEnd, start);
      lastEnd = end;
      emit(ctx, makeReasoningTagFinding(start, end - start, name, severity));
    }

    if (any) {
      out += result.slice(lastEnd);
      result = out;
    }
  }
  return result;
}

function runStripTags(text: string, ctx: EmitContext): string {
  return shouldEmit(ctx) ? stripTagsWithFindings(text, ctx) : stripTagsSilent(text, ctx.policy);
}

/**
 * Strip `<name>...</name>` blocks (multi-line, lazy) for every name in
 * `policy.reasoningTags.names`. Returns the input string by reference if
 * nothing matched (spec-api §2).
 *
 * @example
 *   stripTags('before<internal>secret</internal>after')
 *   // → 'beforeafter'
 *
 *   const customPolicy = policy().addReasoningTag('thinking').build();
 *   stripTags('a<thinking>plan</thinking>b', { policy: customPolicy })
 *   // → 'ab'
 */
export function stripTags(text: string, options?: SanitizeOptions): string {
  return runStripTags(text, makeContext(options, /*detailed*/ false));
}

/**
 * Detailed variant per spec-api §1, §2. Returns a frozen `SanitizeResult`;
 * `result.text === text` (same reference) when `result.changed === false`.
 *
 * @example
 *   const r = stripTagsDetailed('a<internal>secret</internal>b');
 *   // r.changed === true, r.findings[0].kind === 'unicode-strip',
 *   // r.findings[0].ruleId === 'reasoning-tag', r.findings[0].charClass === 'internal'
 */
export function stripTagsDetailed(text: string, options?: SanitizeOptions): SanitizeResult {
  const ctx = makeContext(options, /*detailed*/ true);
  const out = runStripTags(text, ctx);
  const changed = out !== text;
  return Object.freeze({
    text: changed ? out : text,
    changed,
    findings: Object.freeze([...(ctx.findings ?? [])])
  });
}
