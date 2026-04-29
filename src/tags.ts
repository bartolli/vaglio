/**
 * Reasoning-tag stripping for Vaglio v0.1.
 *
 * Lifted from `~/Projects/sotto/src/message-io.ts` lines 147-149 per the
 * extraction inventory, generalized from a hardcoded `<internal>` to a
 * configurable tag-name list (spec-requirements §F1, spec-api §3 reasoningTags).
 *
 * Load-bearing detail (preserved): `[\s\S]*?` lazy multi-line. Greedy or
 * single-line variants over-match across multiple tag pairs.
 *
 * Divergences from origin:
 *   - Sotto's trailing `.trim()` is dropped — Vaglio is format-agnostic
 *     (spec-requirements §F6); leading/trailing whitespace is the consumer's
 *     concern.
 *   - Per-tag iteration with one regex per name (rather than alternation +
 *     backreference) preserves balance by construction and gives M3 a clean
 *     hook for per-name findings.
 */

/** Default tag-name set per spec-requirements §F1. */
export const DEFAULT_REASONING_TAGS: ReadonlyArray<string> = Object.freeze(['internal']);

/** Regex metacharacters that need escaping inside a generated character/literal regex. */
const REGEX_META = /[.*+?^${}()|[\]\\]/g;

function escapeRegex(s: string): string {
  return s.replace(REGEX_META, '\\$&');
}

/**
 * Strip `<name>...</name>` blocks (multi-line, lazy) for the given tag name(s).
 *
 * @param text  Input string.
 * @param names Tag name (single) or list of names. Defaults to `DEFAULT_REASONING_TAGS`.
 *
 * @example
 *   stripTags('before<internal>secret</internal>after')      // 'beforeafter'
 *   stripTags('a<x>1</x>b<y>2</y>c', ['x', 'y'])             // 'abc'
 *   stripTags('a<x>1</x>b', 'x')                             // 'ab'
 */
export function stripTags(
  text: string,
  names: string | ReadonlyArray<string> = DEFAULT_REASONING_TAGS
): string {
  const list = typeof names === 'string' ? [names] : names;
  if (list.length === 0) return text;
  // Fast path: no `<` means no tag block can exist. Skip the regex passes and
  // return the input by reference (preserves identity per spec-api §2).
  if (!text.includes('<')) return text;

  let result = text;
  for (const name of list) {
    const escaped = escapeRegex(name);
    const re = new RegExp(`<${escaped}>[\\s\\S]*?</${escaped}>`, 'g');
    result = result.replace(re, '');
  }
  return result;
}
