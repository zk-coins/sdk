// ESLint flat config (ESLint 10 — flat config is the only supported
// format). Ported 1:1 from the previous `.eslintrc.cjs`:
//
//   eslint:recommended
//   + @typescript-eslint/recommended
//   + @typescript-eslint/recommended-requiring-type-checking
//   + prettier (turns off stylistic rules Prettier owns)
//
// plus the SDK's rule overrides (no-floating-promises, consistent-type-
// imports, require-await off, no-console) and the same ignore set.
//
// Type-aware linting (the `recommendedTypeChecked` ruleset) needs the
// TypeScript program; `projectService: true` lets typescript-eslint
// discover the nearest `tsconfig.json` per file (replacing the old
// `parserOptions.project: './tsconfig.json'`).

import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import prettier from 'eslint-config-prettier/flat';
import globals from 'globals';

export default tseslint.config(
  {
    // Standalone ignores object — replaces the old `ignorePatterns`.
    // `*.config.{ts,cjs}` and the lockfile-adjacent build artefacts stay
    // out of the lint surface exactly as before.
    ignores: [
      'dist/',
      'node_modules/',
      'coverage/',
      'test/cross-rust/shim/',
      '*.config.ts',
      '*.config.cjs',
      'eslint.config.js',
      // Plain CommonJS build script, not part of the typed SDK program
      // (no tsconfig entry). Matches the pre-flat-config behaviour where
      // ESLint 8 only linted `.ts`/`.js` source under src/ + test/.
      'scripts/',
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  {
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: {
        ...globals.node,
        ...globals.browser,
      },
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
      '@typescript-eslint/consistent-type-imports': ['error', { prefer: 'type-imports' }],
      '@typescript-eslint/no-floating-promises': 'error',
      '@typescript-eslint/no-misused-promises': 'error',
      // The SDK keeps every cryptographic primitive `async` even when
      // the underlying library is synchronous. This is a load-bearing
      // compat decision: the prior @zkcoins/wasm API was async (because
      // WASM init was async), and every consumer call site uses
      // `await`. Switching to sync would break the drop-in migration
      // story. See README.md §"Why pure TypeScript" + the function-
      // level doc-comments in src/derivation.ts.
      '@typescript-eslint/require-await': 'off',
      'no-console': ['warn', { allow: ['warn', 'error'] }],
    },
  },
  // Prettier last so it wins over any stylistic rule the rulesets enable.
  prettier,
);
