/**
 * `@bartolli/vaglio/tags` subpath — selective re-export per spec-api §1.
 *
 * Treeshaking entry point for consumers who want only reasoning-tag stripping.
 */

export type {
  Finding,
  UnicodeStripFinding
} from './findings.js';
export type {
  Policy,
  SanitizeOptions,
  SanitizeResult
} from './policy.js';
export {
  DEFAULT_REASONING_TAGS,
  stripTags,
  stripTagsDetailed
} from './tags.js';
