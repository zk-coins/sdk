/**
 * Package version, kept in sync with `package.json#version` by
 * `scripts/sync-version.cjs` (runs automatically as part of
 * `npm version <patch|minor|major>` via the `version` lifecycle
 * hook). Do not hand-edit — the matching drift-sentinel test in
 * `test/version.test.ts` will fail on CI if this constant ever
 * diverges from `package.json`.
 */
export const VERSION = '0.3.0';
