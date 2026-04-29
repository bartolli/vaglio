/**
 * Test-only helper: project an `ollama-js` chat stream onto an
 * `AsyncIterable<string>` that vaglio's `sanitizeIterable` accepts.
 *
 * v0.1 decision (per plan-v0 M3.5b): when a `ChatResponse.message` carries
 * both `thinking` and `content`, yield them as separate strings in that
 * order — matches the model's emission phase order under `think: true`.
 * Downstream sanitization sees a single concatenated stream either way;
 * separate yields stay lossless and avoid masking phase boundaries from
 * the engine's chunk-aware logic.
 *
 * Optional `wrapThinkingTag` wraps the contiguous thinking phase in
 * `<{tag}>...</{tag}>` so downstream reasoning-tag stripping (e.g. vaglio's
 * `stripTags` with `policy.reasoningTags.names = ['internal']`) consumes
 * the whole block. This is the deterministic real-world pattern: when a
 * consumer enables `think: true`, they typically want vaglio to strip the
 * leaked reasoning before it reaches the user — wrapping makes that a
 * single configuration line instead of a prompt-engineering exercise.
 *
 * NOT exported from `src/index.ts` — vaglio's scope (per
 * adr-scope-and-naming) is sanitization, not SDK adapters. Lives under
 * `tests/helpers/` so any consumer can copy it as a recipe.
 */

import type { ChatResponse } from 'ollama';

export interface BridgeOptions {
  /**
   * If set, wrap each contiguous thinking phase in `<{tag}>...</{tag}>`
   * before yielding. Open emits when the first non-empty `thinking` of a
   * phase arrives; close emits when the first non-empty `content` after
   * the phase arrives, OR on stream tail if the source ends mid-thinking.
   *
   * Default undefined → thinking yielded inline as plain text (v0.1
   * baseline; users wanting separation write their own bridge).
   */
  wrapThinkingTag?: string;
}

export async function* bridgeOllamaChatStream(
  source: AsyncIterable<ChatResponse>,
  options?: BridgeOptions
): AsyncIterable<string> {
  const wrapTag = options?.wrapThinkingTag;
  let inThinking = false;
  for await (const r of source) {
    const thinking = r.message.thinking;
    if (thinking !== undefined && thinking.length > 0) {
      if (wrapTag !== undefined && !inThinking) {
        yield `<${wrapTag}>`;
        inThinking = true;
      }
      yield thinking;
    }
    const content = r.message.content;
    if (content.length > 0) {
      if (wrapTag !== undefined && inThinking) {
        yield `</${wrapTag}>`;
        inThinking = false;
      }
      yield content;
    }
  }
  if (wrapTag !== undefined && inThinking) {
    yield `</${wrapTag}>`;
  }
}
