/**
 * Dedicated vitest config for the subpath self-import smoke test.
 *
 * Runs against the BUILT artifact in dist/ via package.json#exports
 * self-reference. Default `pnpm test` excludes tests/exports/** because
 * dist may not exist during the dev test loop. CI invokes this after
 * `pnpm build` via `pnpm test:exports`.
 */
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['tests/exports/**/*.test.ts']
  }
});
