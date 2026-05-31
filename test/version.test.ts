import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { VERSION } from '../src/version.js';

const here = fileURLToPath(new URL('.', import.meta.url));

describe('VERSION', () => {
  it('matches package.json#version (drift sentinel)', () => {
    const pkgPath = resolve(here, '..', 'package.json');
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf8')) as { version: string };
    expect(VERSION).toBe(pkg.version);
  });

  it('is a semver-shaped string', () => {
    expect(VERSION).toMatch(/^\d+\.\d+\.\d+(-[\w.]+)?$/);
  });
});
