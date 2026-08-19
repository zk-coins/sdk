/**
 * NIP-01 helpers — escape table, serialize guards, verify/sign fail-closed paths.
 *
 * Complements the positive pin coverage in delivery.test.ts with every
 * remaining classical escape and every shape/guard refusal.
 */

import { describe, expect, it } from 'vitest';
import { hexToBytes } from '@noble/hashes/utils.js';
import { schnorr } from '@noble/curves/secp256k1.js';

import {
  computeNip01EventId,
  encodeHexLower,
  escapeNip01String,
  serializeNip01IdPreimage,
  signNip01Event,
  verifyNip01Event,
} from '../../src/v1/index.js';

const OP_SECRET = hexToBytes('6516c985b442d51f1e91760c9327a593ddcb7fe06b363aa5b2b8547cc61d7395');

/** BIP-340 invalid public key (not on the curve) — same probe as rejection-paths. */
const OFF_CURVE_XONLY = hexToBytes(
  'eefdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34',
);

/**
 * 32-byte x-only with x ≥ secp256k1 field prime p (all 0xFF).
 * Valid length; invalid point. noble `schnorr.verify` returns false for this.
 */
const X_GE_P_XONLY = new Uint8Array(32).fill(0xff);

describe('escapeNip01String classical short escapes', () => {
  it('escapes quote, backslash, CR, backspace, and form-feed', () => {
    expect(escapeNip01String('a"b')).toBe('"a\\"b"');
    expect(escapeNip01String('a\\b')).toBe('"a\\\\b"');
    expect(escapeNip01String('a\rb')).toBe('"a\\rb"');
    expect(escapeNip01String('a\u0008b')).toBe('"a\\bb"');
    expect(escapeNip01String('a\u000Cb')).toBe('"a\\fb"');
  });
});

describe('serializeNip01IdPreimage guards', () => {
  it('rejects wrong-length pubkey and non-integer createdAt/kind', () => {
    const pk = new Uint8Array(32);
    expect(() =>
      serializeNip01IdPreimage({
        pubkey: new Uint8Array(16),
        createdAt: 1,
        kind: 0,
        tags: [],
        content: '',
      }),
    ).toThrow(/pubkey must be 32 bytes, got 16/);
    expect(() =>
      serializeNip01IdPreimage({
        pubkey: pk,
        createdAt: -1,
        kind: 0,
        tags: [],
        content: '',
      }),
    ).toThrow(/created_at must be a non-negative integer/);
    expect(() =>
      serializeNip01IdPreimage({
        pubkey: pk,
        createdAt: 1.5,
        kind: 0,
        tags: [],
        content: '',
      }),
    ).toThrow(/created_at must be a non-negative integer/);
    expect(() =>
      serializeNip01IdPreimage({
        pubkey: pk,
        createdAt: 1,
        kind: -1,
        tags: [],
        content: '',
      }),
    ).toThrow(/kind must be a non-negative integer/);
    expect(() =>
      serializeNip01IdPreimage({
        pubkey: pk,
        createdAt: 1,
        kind: 0.5,
        tags: [],
        content: '',
      }),
    ).toThrow(/kind must be a non-negative integer/);
  });
});

describe('verifyNip01Event fail-closed paths', () => {
  it('rejects non-object, bad tags, non-string content, bad created_at/kind', () => {
    expect(() => verifyNip01Event(null as never)).toThrow(/expected object/);
    expect(() => verifyNip01Event(undefined as never)).toThrow(/expected object/);

    const good = signNip01Event({
      secretKey: OP_SECRET,
      createdAt: 42,
      kind: 0,
      tags: [],
      content: '{}',
    });

    expect(() => verifyNip01Event({ ...good, tags: 'x' as never })).toThrow(
      /tags must be an array/,
    );
    expect(() => verifyNip01Event({ ...good, content: 1 as never })).toThrow(
      /content must be a string/,
    );
    expect(() => verifyNip01Event({ ...good, created_at: -1 })).toThrow(
      /created_at must be a non-negative integer/,
    );
    expect(() => verifyNip01Event({ ...good, created_at: 1.25 })).toThrow(
      /created_at must be a non-negative integer/,
    );
    expect(() => verifyNip01Event({ ...good, kind: -3 })).toThrow(
      /kind must be a non-negative integer/,
    );
    expect(() => verifyNip01Event({ ...good, kind: 0.1 })).toThrow(
      /kind must be a non-negative integer/,
    );
    expect(() => verifyNip01Event({ ...good, tags: [['ok'], [1 as never]] })).toThrow(
      /each tag must be an array of strings/,
    );
    expect(() => verifyNip01Event({ ...good, tags: ['not-array' as never] })).toThrow(
      /each tag must be an array of strings/,
    );
  });

  it('accepts an event with non-empty tags (copy arm)', () => {
    const event = signNip01Event({
      secretKey: OP_SECRET,
      createdAt: 99,
      kind: 0,
      tags: [
        ['e', 'aa'.repeat(32)],
        ['p', 'bb'.repeat(32), 'relay'],
      ],
      content: '{"n":1}',
    });
    expect(() => verifyNip01Event(event)).not.toThrow();
    expect(event.tags).toEqual([
      ['e', 'aa'.repeat(32)],
      ['p', 'bb'.repeat(32), 'relay'],
    ]);
  });

  it('rejects a forged signature under a valid event id', () => {
    const event = signNip01Event({
      secretKey: OP_SECRET,
      createdAt: 7,
      kind: 0,
      tags: [],
      content: '{}',
    });
    const forged = { ...event, sig: '00'.repeat(64) };
    expect(() => verifyNip01Event(forged)).toThrow(/BIP-340 signature verification failed/);
  });

  it('rejects verification when pubkey is off-curve (verify returns false)', () => {
    // Recompute id under the off-curve bytes so the id-match arm passes and
    // BIP-340 is the gate that fails closed via `false`.
    const id = computeNip01EventId({
      pubkey: OFF_CURVE_XONLY,
      createdAt: 1,
      kind: 0,
      tags: [],
      content: '',
    });
    const event = {
      id: encodeHexLower(id),
      pubkey: encodeHexLower(OFF_CURVE_XONLY),
      created_at: 1,
      kind: 0,
      tags: [] as string[][],
      content: '',
      sig: '22'.repeat(64),
    };
    expect(() => verifyNip01Event(event)).toThrow(/BIP-340 signature verification failed/);
  });

  it('rejects verification when author pubkey x ≥ p (32×0xFF)', () => {
    // 32-byte length is accepted by decodeHexExact; only the curve point is invalid.
    // noble returns false → unified signature-failed error.
    const id = computeNip01EventId({
      pubkey: X_GE_P_XONLY,
      createdAt: 1,
      kind: 0,
      tags: [],
      content: '',
    });
    const event = {
      id: encodeHexLower(id),
      pubkey: encodeHexLower(X_GE_P_XONLY),
      created_at: 1,
      kind: 0,
      tags: [] as string[][],
      content: '',
      sig: '22'.repeat(64),
    };
    expect(() => verifyNip01Event(event)).toThrow(
      /verifyNip01Event: BIP-340 signature verification failed/,
    );
  });
});

describe('signNip01Event guards', () => {
  it('rejects a non-32-byte secretKey', () => {
    expect(() =>
      signNip01Event({
        secretKey: new Uint8Array(16),
        createdAt: 1,
        kind: 0,
        tags: [],
        content: '',
      }),
    ).toThrow(/secretKey must be 32 bytes, got 16/);
    expect(() =>
      signNip01Event({
        secretKey: null as never,
        createdAt: 1,
        kind: 0,
        tags: [],
        content: '',
      }),
    ).toThrow(/secretKey must be 32 bytes, got invalid/);
  });

  it('copies tag rows into the returned event', () => {
    const tags: string[][] = [['t', 'x']];
    const event = signNip01Event({
      secretKey: OP_SECRET,
      createdAt: 1,
      kind: 0,
      tags,
      content: '',
    });
    tags[0]![1] = 'mutated';
    expect(event.tags[0]![1]).toBe('x');
    // Public key matches noble for this secret.
    expect(event.pubkey).toBe(encodeHexLower(schnorr.getPublicKey(OP_SECRET)));
  });
});
