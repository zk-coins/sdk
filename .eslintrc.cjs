/** @type {import('eslint').Linter.Config} */
module.exports = {
  root: true,
  env: {
    node: true,
    browser: true,
    es2022: true,
  },
  parser: '@typescript-eslint/parser',
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: 'module',
    project: './tsconfig.json',
  },
  plugins: ['@typescript-eslint'],
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended',
    'plugin:@typescript-eslint/recommended-requiring-type-checking',
    'prettier',
  ],
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
  ignorePatterns: [
    'dist/',
    'node_modules/',
    'coverage/',
    'test/cross-rust/shim/',
    '*.config.ts',
    '*.config.cjs',
    '.eslintrc.cjs',
  ],
};
