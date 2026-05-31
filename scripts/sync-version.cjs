#!/usr/bin/env node
/**
 * Sync `src/version.ts` from `package.json#version`.
 *
 * Run automatically by `npm version <patch|minor|major>` via the
 * `version` lifecycle hook in `package.json`. Keeps the typed
 * `VERSION` constant in step with the canonical version field so
 * consumers reading `pkg.version` and consumers reading
 * `import { VERSION } from '@zkcoins/sdk'` never see a mismatch.
 *
 * Hand-editing `src/version.ts` directly is still possible (e.g.
 * for hotfix experiments) but is caught loud by
 * `test/version.test.ts`, which asserts the constant matches
 * `package.json#version` on every CI run.
 *
 * CommonJS on purpose: avoids ESM/TS bootstrapping in a script
 * called from the npm CLI before any build step has run.
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');

const repoRoot = path.resolve(__dirname, '..');
const pkgPath = path.join(repoRoot, 'package.json');
const versionFilePath = path.join(repoRoot, 'src', 'version.ts');

const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
const { version } = pkg;
if (typeof version !== 'string' || version.length === 0) {
  console.error(`sync-version: package.json#version is not a non-empty string (got ${version})`);
  process.exit(1);
}

const body = `/**
 * Package version, kept in sync with \`package.json#version\` by
 * \`scripts/sync-version.cjs\` (runs automatically as part of
 * \`npm version <patch|minor|major>\` via the \`version\` lifecycle
 * hook). Do not hand-edit — the matching drift-sentinel test in
 * \`test/version.test.ts\` will fail on CI if this constant ever
 * diverges from \`package.json\`.
 */
export const VERSION = '${version}';
`;

fs.writeFileSync(versionFilePath, body);
console.log(`sync-version: src/version.ts updated → ${version}`);
