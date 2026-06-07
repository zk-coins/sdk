/**
 * Public barrel surface (`src/index.ts`).
 *
 * Guards against a schema/type being declared in `schemas.ts` but never
 * re-exported from the package root — a `type`-only export still
 * type-checks, so a missing *value* (runtime) export of a Zod schema is
 * invisible to `tsc` and only bites a consumer at runtime. This caught
 * `TxDetailSchema` missing from the value-export block.
 */

import { describe, expect, it } from 'vitest';

import * as sdk from '../src/index.js';

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
});
