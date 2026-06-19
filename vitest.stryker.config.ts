import { defineConfig } from 'vitest/config';

// Config used only by Stryker mutation runs. It excludes the seeded property
// fuzzer (test/invariants.test.ts): under per-test mutation instrumentation it
// would be re-executed for every mutant (400 models × matrix), which is
// prohibitively slow and adds no mutation signal the deterministic suites don't
// already provide. The fuzzer still runs in the normal `vitest` / CI suite.
export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    testTimeout: 30000,
    include: ['test/**/*.{test,spec}.ts'],
    exclude: ['test/invariants.test.ts', 'node_modules/**']
  }
});
