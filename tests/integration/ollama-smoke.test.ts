/**
 * M3.5b Group 2 — real-Ollama smoke tests.
 *
 * Opt-in: skipped unless `OLLAMA_HOST` is set. Run via `pnpm test:smoke`
 * after starting an Ollama daemon and pulling the model.
 *
 * Configuration:
 *   - OLLAMA_HOST              required; gates the suite (e.g. http://127.0.0.1:11434)
 *   - OLLAMA_MODEL             default 'llama3.2:1b' (~1.3 GB) — used by the
 *                              long-generation, credential, and cancel cases
 *   - OLLAMA_THINKING_MODEL    optional; gates the reasoning-tag case via
 *                              `it.skipIf`. Must be a thinking-capable model
 *                              (e.g. 'qwen3.5:latest'). The case sets
 *                              `think: true` and uses the bridge's
 *                              `wrapThinkingTag: 'internal'` option so
 *                              vaglio's reasoning-tag stripper fires
 *                              deterministically on real model output.
 *   - OLLAMA_SMOKE_TIMEOUT_MS  default 60000
 *   - OLLAMA_SMOKE_DEBUG       '1' enables raw-content / raw-thinking /
 *                              sanitized-output / findings logging
 *
 * Verifies the integration along axes that mock-fetch can't:
 *   - long real generation flows through `sanitizeIterable` to completion;
 *   - a planted credential in the model's output redacts and emits a finding;
 *   - thinking-mode reasoning is stripped end-to-end (gated by THINKING_MODEL);
 *   - mid-stream `client.abort()` propagates the SDK's `AbortError` as-is,
 *     NOT `VaglioStreamCanceledError` (per the M3.5b source-error semantics:
 *     SDK-thrown errors propagate unchanged; only user-initiated cancel of
 *     vaglio's own surface produces VSCE).
 *
 * The credential prompt uses `temperature: 0` + literal-echo instruction;
 * small models occasionally rephrase. If the model fails to comply, treat
 * it as a model-fitness signal rather than a vaglio bug.
 */

import type { ChatResponse } from 'ollama';
import { Ollama } from 'ollama';
import { describe, expect, it } from 'vitest';
import { VaglioStreamCanceledError } from '../../src/errors.js';
import type { Finding } from '../../src/findings.js';
import { sanitizeIterable } from '../../src/stream-sanitize.js';
import { bridgeOllamaChatStream } from '../helpers/ollama-bridge.js';

// Default to empty string so the `host` field types as `string`. The
// `skipIf(!OLLAMA_HOST)` gate keeps the suite a no-op without the env var.
const OLLAMA_HOST = process.env.OLLAMA_HOST ?? '';
const OLLAMA_MODEL = process.env.OLLAMA_MODEL ?? 'llama3.2:1b';
// Empty default keeps `model: OLLAMA_THINKING_MODEL` typing as `string`;
// `it.skipIf(!OLLAMA_THINKING_MODEL)` makes the case a no-op when unset.
const OLLAMA_THINKING_MODEL = process.env.OLLAMA_THINKING_MODEL ?? '';
const TIMEOUT_MS = Number(process.env.OLLAMA_SMOKE_TIMEOUT_MS ?? '60000');
const DEBUG = process.env.OLLAMA_SMOKE_DEBUG === '1';

/** Tee the SDK's chat stream so the test can capture raw content + thinking. */
function teeChatStream(
  source: AsyncIterable<ChatResponse>,
  rawContent: string[],
  rawThinking: string[]
): AsyncIterable<ChatResponse> {
  return (async function* () {
    for await (const r of source) {
      if (r.message.content.length > 0) rawContent.push(r.message.content);
      const t = r.message.thinking;
      if (t !== undefined && t.length > 0) rawThinking.push(t);
      yield r;
    }
  })();
}

function debugDump(
  label: string,
  raw: { content: string; thinking: string },
  sanitized: string,
  findings: ReadonlyArray<Finding>
): void {
  if (!DEBUG) return;
  console.log(`\n[smoke:${label}] raw.content    = ${JSON.stringify(raw.content)}`);
  console.log(`[smoke:${label}] raw.thinking   = ${JSON.stringify(raw.thinking)}`);
  console.log(`[smoke:${label}] sanitized.out  = ${JSON.stringify(sanitized)}`);
  console.log(`[smoke:${label}] findings.count = ${findings.length}`);
  for (const f of findings) {
    console.log(`[smoke:${label}] finding        = ${JSON.stringify(f)}`);
  }
}

describe.skipIf(!OLLAMA_HOST)('M3.5b — real-Ollama smoke', () => {
  it('long generation flows through sanitizeIterable to completion', {
    timeout: TIMEOUT_MS
  }, async () => {
    const client = new Ollama({ host: OLLAMA_HOST });
    const stream = await client.chat({
      model: OLLAMA_MODEL,
      messages: [{ role: 'user', content: 'Write a 200-word essay about sandwiches.' }],
      stream: true,
      options: { temperature: 0 }
    });
    let out = '';
    for await (const safe of sanitizeIterable(bridgeOllamaChatStream(stream))) {
      out += safe;
    }
    expect(out.length).toBeGreaterThan(0);
  });

  it('redacts a credential when the model echoes one', { timeout: TIMEOUT_MS }, async () => {
    const client = new Ollama({ host: OLLAMA_HOST });
    const stream = await client.chat({
      model: OLLAMA_MODEL,
      messages: [
        {
          role: 'user',
          content:
            'Repeat exactly the following text and nothing else: My token is AKIAIOSFODNN7EXAMPLE'
        }
      ],
      stream: true,
      options: { temperature: 0 }
    });
    const rawContent: string[] = [];
    const rawThinking: string[] = [];
    const findings: Finding[] = [];
    let out = '';
    for await (const safe of sanitizeIterable(
      bridgeOllamaChatStream(teeChatStream(stream, rawContent, rawThinking)),
      { onFinding: (f) => findings.push(f) }
    )) {
      out += safe;
    }
    debugDump(
      'credential',
      { content: rawContent.join(''), thinking: rawThinking.join('') },
      out,
      findings
    );
    expect(out).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(out).toContain('<credential>');
    expect(findings.some((f) => f.kind === 'credential')).toBe(true);
  });

  it.skipIf(!OLLAMA_THINKING_MODEL)(
    'strips a thinking-mode reasoning block via the bridge wrap option',
    { timeout: TIMEOUT_MS },
    async () => {
      // The deterministic real-world pattern: a thinking-capable model
      // (qwen3.5, deepseek-r1, etc.) emits reasoning tokens via
      // `message.thinking`. The bridge wraps the contiguous thinking phase
      // in `<internal>...</internal>` so vaglio's reasoning-tag stripper
      // (which defaults to `['internal']`) consumes the whole block.
      // Avoids prompt-engineering brittleness — works regardless of how
      // the model phrases its reasoning, and doesn't trip RLHF refusal on
      // the prompt side (small chat-tuned models refuse on prompts that
      // reference 'internal' / 'hidden reasoning' literally).
      const client = new Ollama({ host: OLLAMA_HOST });
      const stream = await client.chat({
        model: OLLAMA_THINKING_MODEL,
        messages: [{ role: 'user', content: 'What is 2 plus 2? Answer in one short sentence.' }],
        stream: true,
        think: true,
        options: { temperature: 0 }
      });
      const rawContent: string[] = [];
      const rawThinking: string[] = [];
      const findings: Finding[] = [];
      let out = '';
      for await (const safe of sanitizeIterable(
        bridgeOllamaChatStream(teeChatStream(stream, rawContent, rawThinking), {
          wrapThinkingTag: 'internal'
        }),
        { onFinding: (f) => findings.push(f) }
      )) {
        out += safe;
      }
      debugDump(
        'reasoning-tag',
        { content: rawContent.join(''), thinking: rawThinking.join('') },
        out,
        findings
      );
      // Sanity: model actually emitted thinking. Without this the rest of
      // the assertions would pass vacuously on a model that ignored think:true.
      expect(rawThinking.length).toBeGreaterThan(0);
      // The wrapped <internal>...</internal> block is consumed by the stripper;
      // neither the open/close tags nor any thinking-phase deltas survive.
      expect(out).not.toContain('<internal>');
      expect(out).not.toContain('</internal>');
      // The model's actual answer (post-thinking content phase) passes through.
      expect(out.length).toBeGreaterThan(0);
      // At least one reasoning-tag finding fires.
      expect(findings.some((f) => f.kind === 'unicode-strip' && f.ruleId === 'reasoning-tag')).toBe(
        true
      );
    }
  );

  it('client.abort() mid-stream propagates AbortError as-is (not VaglioStreamCanceledError)', {
    timeout: TIMEOUT_MS
  }, async () => {
    const client = new Ollama({ host: OLLAMA_HOST });
    const stream = await client.chat({
      model: OLLAMA_MODEL,
      messages: [{ role: 'user', content: 'Write a 1000-word essay about sandwiches.' }],
      stream: true,
      options: { temperature: 0 }
    });
    const findings: Finding[] = [];
    const consumer = (async (): Promise<unknown> => {
      try {
        for await (const _ of sanitizeIterable(bridgeOllamaChatStream(stream), {
          onFinding: (f) => findings.push(f)
        })) {
          // drain
        }
        return null;
      } catch (err) {
        return err;
      }
    })();
    await new Promise<void>((r) => setTimeout(r, 500));
    client.abort();
    const caught = await consumer;
    expect(caught).toBeInstanceOf(Error);
    expect(caught).not.toBeInstanceOf(VaglioStreamCanceledError);
    expect((caught as Error).name).toBe('AbortError');
    // Source-error semantics: vaglio's engine is NOT canceled when the
    // SDK throws AbortError, so no stream-canceled finding emits. (VSCE
    // + stream-canceled finding emit only on user-initiated cancel of
    // vaglio's own surface — not driven by this test.)
    expect(
      findings.some((f) => f.kind === 'stream-diagnostic' && f.ruleId === 'stream-canceled')
    ).toBe(false);
  });
});
