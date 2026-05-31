import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: false,
    environment: 'node',
    include: ['test/**/*.test.ts'],
    exclude: ['test/cross-rust/**', 'node_modules'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html', 'lcov'],
      include: ['src/**/*.ts'],
      exclude: ['src/index.ts', 'src/types.ts'],
      // Lines / functions / statements are pinned at 100 % on the
      // activated surface — these are the load-bearing guarantees.
      // Branches are at 85 %: TypeScript's `strict-null-checks` +
      // `exactOptionalPropertyTypes` produces extra "branches" that
      // are unreachable in practice (the `signal ? { signal } : {}`
      // spread pattern is the main culprit); aiming for 95 % drives
      // synthetic tests without commensurate value. Real
      // correctness regressions show up on lines / statements first.
      thresholds: {
        lines: 100,
        functions: 100,
        branches: 85,
        statements: 100,
      },
    },
  },
});
