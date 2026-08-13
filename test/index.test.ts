/**
 * Public barrel surface (`src/index.ts`).
 *
 * Guards against a schema/type being declared in `schemas.ts` but never
 * re-exported from the package root — a `type`-only export still
 * type-checks, so a missing *value* (runtime) export of a Zod schema is
 * invisible to `tsc` and only bites a consumer at runtime. This caught
 * `TxDetailSchema` missing from the value-export block.
 */

import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

import * as sdk from '../src/index.js';
import * as v1index from '../src/v1/index.js';

function namedExports(source: string): Array<{
  typeOnlyBlock: boolean;
  modulePath: string;
  entries: Array<{ name: string; typeOnly: boolean }>;
}> {
  const blocks: Array<{
    typeOnlyBlock: boolean;
    modulePath: string;
    entries: Array<{ name: string; typeOnly: boolean }>;
  }> = [];
  const pattern = /export\s+(type\s+)?\{([\s\S]*?)\}\s+from\s+['"]([^'"]+)['"];/g;
  for (const match of source.matchAll(pattern)) {
    const typeOnlyBlock = match[1] !== undefined;
    const entries = match[2]!
      .split(',')
      .map((entry) => entry.trim())
      .filter((entry) => entry.length > 0)
      .map((entry) => {
        const typeOnly = typeOnlyBlock || entry.startsWith('type ');
        const withoutType = entry.replace(/^type\s+/, '');
        const name = withoutType.split(/\s+as\s+/)[0]!;
        return { name, typeOnly };
      });
    blocks.push({ typeOnlyBlock, modulePath: match[3]!, entries });
  }
  return blocks;
}

describe('package barrel exports', () => {
  it('re-exports the history + tx-detail Zod schemas as runtime values', () => {
    for (const name of ['TxItemSchema', 'HistoryResponseSchema', 'TxDetailSchema'] as const) {
      expect(sdk[name], `${name} must be exported from the package root`).toBeDefined();
      // Zod schemas are parseable objects with a `.parse` method.
      expect(typeof sdk[name].parse).toBe('function');
    }
  });

  it('exposes getTransaction on ZkCoinsClient', () => {
    const client = new sdk.ZkCoinsClient({ apiUrl: 'http://node.test' });
    expect(typeof client.getTransaction).toBe('function');
  });

  it('re-exports the v1 transition-signing surface as runtime values', () => {
    for (const name of [
      'mStateBytes',
      'serializeProofData',
      'hashProofData',
      'signTransition',
      'verify',
      'commVerify',
      'aggregateSig',
      'aggregateVerify',
      'deriveSpendKey',
      'freshNpkRand',
      'refuseOrSignTransition',
      'chanBindForHost',
      'ZkCoinsV1Client',
    ] as const) {
      expect(sdk[name], `${name} must be exported from the package root`).toBeDefined();
      expect(typeof sdk[name]).toBe('function');
    }
  });

  it('re-exports every v1 runtime value from the package root', () => {
    for (const name of Object.keys(v1index)) {
      expect(
        (sdk as Record<string, unknown>)[name],
        `${name} must be exported from the package root`,
      ).toBeDefined();
    }
  });

  it('re-exports every v1 named type from the package root', () => {
    const v1Source = readFileSync(new URL('../src/v1/index.ts', import.meta.url), 'utf8');
    const rootSource = readFileSync(new URL('../src/index.ts', import.meta.url), 'utf8');
    const v1Types = namedExports(v1Source)
      .flatMap((block) => block.entries)
      .filter((entry) => entry.typeOnly)
      .map((entry) => entry.name);
    const rootV1Types = new Set(
      namedExports(rootSource)
        .filter((block) => block.typeOnlyBlock && block.modulePath === './v1/index.js')
        .flatMap((block) => block.entries)
        .map((entry) => entry.name),
    );

    for (const name of v1Types) {
      expect(rootV1Types.has(name), `${name} type must be exported from the package root`).toBe(
        true,
      );
    }
  });

  it('does not export the fixture-nonce signer (test-vector only; scalar leak if public)', () => {
    // Deterministic k' does not bind m_SC — must never ship on the package root.
    expect(Object.prototype.hasOwnProperty.call(sdk, 'signTransitionWithFixtureNonce')).toBe(false);
    expect((sdk as Record<string, unknown>).signTransitionWithFixtureNonce).toBeUndefined();
  });

  it('does not export internal sign-trace / redraw-budget helpers', () => {
    for (const name of ['signTransitionTrace', 'runWithRedrawBudget', 'SignTrace'] as const) {
      expect(Object.prototype.hasOwnProperty.call(sdk, name)).toBe(false);
      expect((sdk as Record<string, unknown>)[name]).toBeUndefined();
      expect(Object.prototype.hasOwnProperty.call(v1index, name)).toBe(false);
      expect((v1index as Record<string, unknown>)[name]).toBeUndefined();
    }
  });
});
