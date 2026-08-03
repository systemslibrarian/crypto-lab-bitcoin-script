import { defineConfig, configDefaults } from 'vitest/config';

export default defineConfig({
  base: '/crypto-lab-bitcoin-script/',
  test: {
    // `e2e/` belongs to Playwright (`npm run test:a11y`). Vitest cannot execute
    // a Playwright spec at all — it throws "Playwright Test did not expect
    // test() to be called here" during collection — so `npm test` reported a
    // failed suite containing zero runnable tests. Excluding the directory
    // removes a collection error, not coverage: those specs still run, and
    // still gate the deploy, under the runner that can actually run them.
    exclude: [...configDefaults.exclude, 'e2e/**'],
  },
});
