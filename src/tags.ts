/**
 * Reasoning-tag stripping. Per-tag iteration with one regex per name (not
 * alternation + backreference) preserves balance by construction and yields
 * a per-name finding without group inspection. `[\s\S]*?` lazy multi-line is
 * load-bearing — greedy or single-line over-match across tag pairs.
 *
 * v0.1 finding shape: `ruleId: 'reasoning-tag'` (per-tag identity in
 * `charClass`); cross-name offset frame is post-prior-name within this stage.
 */

import type { Finding, Severity, UnicodeStripFinding } from './findings.js';
import {
  DEFAULT_POLICY,
  type Policy,
  type SanitizeOptions,
  type SanitizeResult
} from './policy.js';

/** Mirrors `DEFAULT_POLICY.reasoningTags.names`; informational for consumers who don't construct a policy. */
export const DEFAULT_REASONING_TAGS: ReadonlyArray<string> = Object.freeze(['internal']);

const REASONING_TAG_RULE_ID = 'reasoning-tag';
const REASONING_TAG_DEFAULT_SEVERITY: Severity = 'medium';
const FINDING_RULE_VERSION = 1;
const REGEX_META = /[.*+?^${}()|[\]\\]/g;

function escapeRegex(s: string): string {
  return s.replace(REGEX_META, '\\$&');
}

/** Always global — both the silent `.replace()` and the telemetry `matchAll` require it. */
function tagRegex(name: string): RegExp {
  const escaped = escapeRegex(name);
  return new RegExp(`<${escaped}>[\\s\\S]*?</${escaped}>`, 'g');
}

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
  // count = length: one tag block is one match ⇒ chars removed = block span.
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

/** `!text.includes('<')` gate ⇒ clean inputs return by reference, no `.replace()`, no allocation. */
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
 * @example
 *   stripTags('before<internal>secret</internal>after')   // → 'beforeafter'
 *   stripTags('a<thinking>plan</thinking>b', { policy: policy().addReasoningTag('thinking').build() })  // → 'ab'
 */
export function stripTags(text: string, options?: SanitizeOptions): string {
  return runStripTags(text, makeContext(options, /*detailed*/ false));
}

/** Frozen `SanitizeResult`; `result.text === text` (same ref) when `changed === false`. */
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
