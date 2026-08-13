/**
 * Rejection / fail-closed paths for the v1 surface.
 *
 * Every untested refusal is a claim nobody has executed. This file walks the
 * presence matrix, hex/Bech32m/key/ownership gates, half-agg boundaries, and
 * the three pre-sign refusals that still lacked a dedicated cause assertion.
 *
 * Crypto is real where a signature is produced; length/type guards are pure
 * encoding checks and do not mock verify/commVerify.
 */

import { describe, expect, it } from 'vitest';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { schnorr } from '@noble/curves/secp256k1.js';

import {
  aggregationCoefficients,
  aggregateSig,
  aggregateVerify,
  assertProofData,
  assertTransitionRequest,
  bip340NormaliseSecret,
  bytesEqual,
  buildOwnershipProof,
  canonicalHostFromApiUrl,
  chanBindForHost,
  commRetrieve,
  commVerify,
  computeNpkCommit,
  decodeHexExact,
  decodeZkAddress,
  deriveSk0,
  deriveSpendKey,
  encodeHexLower,
  encodeZkAddress,
  hashProofData,
  isAcceptableCommittedR,
  KeyBindingRefusalError,
  liftXOnly,
  mStateBytes,
  mStateString,
  NpkCommitRefusalError,
  parseExpiryDecimal,
  pointHasEvenY,
  pullChallengeMessage,
  PULL_CHALLENGE_DOMAIN,
  redactBearerToken,
  refuseOrSignTransition,
  requireCanonicalScalar,
  SECP256K1_ORDER,
  seedFromMnemonicV1,
  serializeProofData,
  signBodyFromSignature,
  transitionRequestToJson,
  TransitionSignatureError,
  tweakScalarOrReject,
  verify,
  xOnlyPubkeyFromSecret,
  type AwaitingSignature,
  type Network,
  type ProofData,
  type TransitionRequest,
} from '../../src/v1/index.js';
import { runWithRedrawBudget, signTransitionTrace } from '../../src/v1/transitionSignature.js';

const MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const V8_SK1 = hexToBytes('22f508c0a93b29fa87ca8d9abcec996f01620656cd7a7e4ab5418b2e76beccf4');
const V8_PK1 = hexToBytes('e7f2a98e7b45e9424e3e0cb1d937a1698ebd339c6d8344906db979642cf20474');

/**
 * BIP-340 invalid public key (not on the curve).
 * Proven off-curve: Legendre(x³+7, p) = −1 for secp256k1 field prime p.
 * Note: x = 1 and x = 0x0101…01 *are* on the curve — do not use them as off-curve probes.
 */
const OFF_CURVE_XONLY = hexToBytes(
  'eefdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34',
);

function field32(tag: number): Uint8Array {
  const out = new Uint8Array(32);
  out[0] = tag & 0xff;
  for (let i = 1; i < 32; i++) {
    out[i] = (out[i - 1]! + tag + i) & 0xff;
  }
  return out;
}

function sampleProofData(): ProofData {
  return {
    newAccountStateHash: field32(1),
    outputCoinsRoot: field32(2),
    inputNullifiersRoot: field32(3),
    coinHistoryRoot: field32(4),
    navCommitment: field32(5),
    npkCommit: field32(6),
  };
}

// ---------------------------------------------------------------------------
// hex.ts
// ---------------------------------------------------------------------------

describe('hex helpers — rejection paths', () => {
  it('encodeHexLower round-trips lowercase pairs', () => {
    const bytes = hexToBytes('0a1b2cff');
    expect(encodeHexLower(bytes)).toBe('0a1b2cff');
  });

  it('decodeHexExact rejects non-string via plain-JS call shape', () => {
    const args: [string, number, string] = ['00', 1, 'field'];
    Reflect.set(args, 0, 42);
    expect(() => Reflect.apply(decodeHexExact, undefined, args)).toThrow(/expected hex string/);
  });

  it('decodeHexExact rejects wrong length with the expected count', () => {
    expect(() => decodeHexExact('aabb', 32, 'pk')).toThrow(/expected 64 hex chars, got 4/);
  });

  it('decodeHexExact rejects uppercase / non-alphabet', () => {
    // Correct length (64 hex chars) so the alphabet check is the one that fires.
    expect(() => decodeHexExact('AA'.repeat(32), 32, 'pk')).toThrow(/non-canonical hex/);
    // `0x` prefix at total length 64 (not 66) — length is checked first.
    expect(() => decodeHexExact('0x' + 'aa'.repeat(31), 32, 'pk')).toThrow(/non-canonical hex/);
    expect(() => decodeHexExact('aa'.repeat(31) + 'gg', 32, 'pk')).toThrow(/non-canonical hex/);
  });

  it('bytesEqual is false on length mismatch and true on equal digests', () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([1, 2, 3]);
    const c = new Uint8Array([1, 2]);
    expect(bytesEqual(a, b)).toBe(true);
    expect(bytesEqual(a, c)).toBe(false);
    expect(bytesEqual(a, new Uint8Array([1, 2, 4]))).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// mstate.ts — exhaustive default via runtime overwrite
// ---------------------------------------------------------------------------

describe('m_state unknown network', () => {
  it('mStateBytes throws on a network outside the closed set', () => {
    const holder: { network: Network } = { network: 'testnet' };
    Reflect.set(holder, 'network', 'mutinynet');
    expect(() => mStateBytes(holder.network)).toThrow(/unknown network.*"mutinynet"/);
  });

  it('mStateString throws on a network outside the closed set', () => {
    const holder: { network: Network } = { network: 'mainnet' };
    Reflect.set(holder, 'network', 'signet');
    expect(() => mStateString(holder.network)).toThrow(/unknown network.*"signet"/);
  });
});

// ---------------------------------------------------------------------------
// proofData.ts
// ---------------------------------------------------------------------------

describe('ProofData field type guard', () => {
  it('rejects a field that is not a Uint8Array', () => {
    const pd = sampleProofData();
    Reflect.set(pd, 'npkCommit', 'not-bytes');
    expect(() => assertProofData(pd)).toThrow(/ProofData\.npkCommit: expected Uint8Array/);
    expect(() => serializeProofData(pd)).toThrow(/ProofData\.npkCommit: expected Uint8Array/);
  });
});

// ---------------------------------------------------------------------------
// keys.ts
// ---------------------------------------------------------------------------

describe('v1 keys — bounds and mnemonic gates', () => {
  const seed = seedFromMnemonicV1(MNEMONIC);

  it('deriveSpendKey rejects non-integer / negative / oversized indices', () => {
    expect(() => deriveSpendKey(seed, -1, 0)).toThrow(
      /account: expected integer in \[0, 2\^31-1\]/,
    );
    expect(() => deriveSpendKey(seed, 0, 1.5)).toThrow(/index: expected integer/);
    expect(() => deriveSpendKey(seed, 0, 0x80000000)).toThrow(/index: expected integer/);
  });

  it('deriveSpendKey rejects an empty seed', () => {
    expect(() => deriveSpendKey(new Uint8Array(0), 0, 0)).toThrow(
      /seed must be a non-empty Uint8Array/,
    );
    const notBytes: { seed: Uint8Array } = { seed };
    Reflect.set(notBytes, 'seed', 'nope');
    expect(() => deriveSpendKey(notBytes.seed, 0, 0)).toThrow(
      /seed must be a non-empty Uint8Array/,
    );
  });

  it("deriveSk0 is A/0'/0' and matches deriveSpendKey(..., 0)", () => {
    const a = deriveSk0(seed, 0);
    const b = deriveSpendKey(seed, 0, 0);
    expect(encodeHexLower(a.secretKey)).toBe(encodeHexLower(b.secretKey));
    expect(a.path).toBe("m/1798'/0'/0'/0'");
  });

  it('seedFromMnemonicV1 refuses a non-empty passphrase and empty mnemonic', () => {
    expect(() => seedFromMnemonicV1(MNEMONIC, 'secret')).toThrow(
      /passphrase is not applicable in v1/,
    );
    expect(() => seedFromMnemonicV1('')).toThrow(/mnemonic is required/);
    expect(() => seedFromMnemonicV1('   ')).toThrow(/mnemonic is required/);
  });

  it('seedFromMnemonicV1 refuses invalid BIP-39 (wordlist / count / checksum)', () => {
    // Without validateMnemonic these would silently produce a non-recoverable seed.
    expect(() =>
      seedFromMnemonicV1(
        'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon notaword',
      ),
    ).toThrow(/invalid BIP-39 mnemonic/);
    expect(() => seedFromMnemonicV1('abandon abandon abandon')).toThrow(/invalid BIP-39 mnemonic/);
    // Valid words + valid length but broken checksum (last word wrong for abandon×11).
    expect(() =>
      seedFromMnemonicV1(
        'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon',
      ),
    ).toThrow(/invalid BIP-39 mnemonic/);
    // Positive control: the V.2-ext mnemonic still derives.
    expect(seedFromMnemonicV1(MNEMONIC)).toBeInstanceOf(Uint8Array);
    expect(seedFromMnemonicV1(MNEMONIC).length).toBe(64);
  });

  it('xOnlyPubkeyFromSecret matches BIP-340 normalisation', () => {
    const pk = xOnlyPubkeyFromSecret(V8_SK1);
    expect(encodeHexLower(pk)).toBe(encodeHexLower(bip340NormaliseSecret(V8_SK1).pkBytes));
  });

  // deriveSpendKey's missing-privateKey check is expectPresent(child.privateKey, …).
  // With a real seed the value is always present (fully hardened path from
  // HDKey.fromMasterSeed). The throw arm of expectPresent is exercised by
  // client parsers (awaiting_signature absent; SSE body null) — same helper,
  // real bad inputs, no prototype patch and no keys-only seam.
});

// ---------------------------------------------------------------------------
// errors.ts — NpkCommitRefusalError + redact edge
// ---------------------------------------------------------------------------

describe('error helpers', () => {
  it('redactBearerToken is a no-op for empty tokens', () => {
    expect(redactBearerToken('Bearer abc', '')).toBe('Bearer abc');
  });

  it('redactBearerToken substitutes every occurrence of the secret', () => {
    expect(redactBearerToken('tok=SECRET and SECRET again', 'SECRET')).toBe(
      'tok=<redacted-session-token> and <redacted-session-token> again',
    );
  });
});

// ---------------------------------------------------------------------------
// transitionRequest.ts — full presence matrix
// ---------------------------------------------------------------------------

describe('TransitionRequest presence matrix (full)', () => {
  const base = {
    subject: 'zk1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq6gtw5c',
    next_pubkey: 'aa'.repeat(32),
    npk_rand: 'bb'.repeat(32),
  };
  const oneOut = [{ recipient: base.subject, asset_id: 'dd'.repeat(32), amount: '1' }];

  it('rejects non-object / missing required common fields', () => {
    expect(() => assertTransitionRequest(null)).toThrow(/expected object/);
    expect(() => assertTransitionRequest('send')).toThrow(/expected object/);
    expect(() =>
      assertTransitionRequest({
        kind: 'send',
        next_pubkey: 'x',
        npk_rand: 'y',
        input_coins: ['a'],
        output_templates: oneOut,
      }),
    ).toThrow(/subject is required/);
    expect(() =>
      assertTransitionRequest({
        kind: 'send',
        subject: '',
        next_pubkey: 'x',
        npk_rand: 'y',
        input_coins: ['a'],
        output_templates: oneOut,
      }),
    ).toThrow(/subject is required/);
    expect(() =>
      assertTransitionRequest({
        kind: 'send',
        subject: base.subject,
        next_pubkey: '',
        npk_rand: base.npk_rand,
        input_coins: ['a'],
        output_templates: oneOut,
      }),
    ).toThrow(/next_pubkey is required/);
    expect(() =>
      assertTransitionRequest({
        kind: 'send',
        subject: base.subject,
        next_pubkey: base.next_pubkey,
        npk_rand: '',
        input_coins: ['a'],
        output_templates: oneOut,
      }),
    ).toThrow(/npk_rand is required/);
  });

  it('rejects unknown kind', () => {
    expect(() => assertTransitionRequest({ kind: 'burn', ...base })).toThrow(
      /kind must be mint\|send\|receive/,
    );
  });

  it('send: rejects empty outputs and forbidden fold/issuance', () => {
    expect(() =>
      assertTransitionRequest({
        kind: 'send',
        ...base,
        input_coins: ['cc'.repeat(32)],
        output_templates: [],
      }),
    ).toThrow(/non-empty output_templates/);
    expect(() =>
      assertTransitionRequest({
        kind: 'send',
        ...base,
        input_coins: ['cc'.repeat(32)],
        output_templates: oneOut,
        fold_coin_ids: ['ee'.repeat(32)],
      }),
    ).toThrow(/must not carry fold_coin_ids/);
    expect(() =>
      assertTransitionRequest({
        kind: 'send',
        ...base,
        input_coins: ['cc'.repeat(32)],
        output_templates: oneOut,
        issuance: {
          name: 'x',
          decimals: 0,
          issuance_version: 1,
          amount: '1',
          creator_pubkey: 'aa'.repeat(32),
        },
      }),
    ).toThrow(/must not carry issuance/);
  });

  it('mint: rejects empty outputs, missing/invalid issuance, and forbidden fields', () => {
    expect(() =>
      assertTransitionRequest({
        kind: 'mint',
        ...base,
        output_templates: [],
        issuance: {
          name: 'x',
          decimals: 0,
          issuance_version: 1,
          amount: '1',
          creator_pubkey: 'aa'.repeat(32),
        },
      }),
    ).toThrow(/non-empty output_templates/);
    expect(() =>
      assertTransitionRequest({
        kind: 'mint',
        ...base,
        output_templates: oneOut,
        issuance: null,
      }),
    ).toThrow(/requires issuance/);
    expect(() =>
      assertTransitionRequest({
        kind: 'mint',
        ...base,
        output_templates: oneOut,
        input_coins: ['cc'.repeat(32)],
        issuance: {
          name: 'x',
          decimals: 0,
          issuance_version: 1,
          amount: '1',
          creator_pubkey: 'aa'.repeat(32),
        },
      }),
    ).toThrow(/must not carry input_coins/);
    expect(() =>
      assertTransitionRequest({
        kind: 'mint',
        ...base,
        output_templates: oneOut,
        fold_coin_ids: ['ee'.repeat(32)],
        issuance: {
          name: 'x',
          decimals: 0,
          issuance_version: 1,
          amount: '1',
          creator_pubkey: 'aa'.repeat(32),
        },
      }),
    ).toThrow(/must not carry fold_coin_ids/);
    expect(() =>
      assertTransitionRequest({
        kind: 'mint',
        ...base,
        output_templates: oneOut,
        issuance: 'not-an-object',
      }),
    ).toThrow(/issuance must be an object/);
    expect(() =>
      assertTransitionRequest({
        kind: 'mint',
        ...base,
        output_templates: oneOut,
        issuance: {
          name: 'x',
          decimals: 0,
          issuance_version: 3,
          amount: '1',
          creator_pubkey: 'aa'.repeat(32),
        },
      }),
    ).toThrow(/issuance_version must be 1 or 2/);
    expect(() =>
      assertTransitionRequest({
        kind: 'mint',
        ...base,
        output_templates: oneOut,
        issuance: {
          name: 'x',
          decimals: 0,
          issuance_version: 2,
          amount: '1',
          creator_pubkey: 'aa'.repeat(32),
        },
      }),
    ).toThrow(/issuance_version=2 requires cap_total and terms_salt/);
  });

  it('receive: rejects empty fold and forbidden fields', () => {
    expect(() =>
      assertTransitionRequest({
        kind: 'receive',
        ...base,
        fold_coin_ids: [],
      }),
    ).toThrow(/non-empty fold_coin_ids/);
    expect(() =>
      assertTransitionRequest({
        kind: 'receive',
        ...base,
        fold_coin_ids: ['ee'.repeat(32)],
        input_coins: ['cc'.repeat(32)],
      }),
    ).toThrow(/must not carry input_coins/);
    expect(() =>
      assertTransitionRequest({
        kind: 'receive',
        ...base,
        fold_coin_ids: ['ee'.repeat(32)],
        output_templates: oneOut,
      }),
    ).toThrow(/must not carry output_templates/);
    expect(() =>
      assertTransitionRequest({
        kind: 'receive',
        ...base,
        fold_coin_ids: ['ee'.repeat(32)],
        issuance: {
          name: 'x',
          decimals: 0,
          issuance_version: 1,
          amount: '1',
          creator_pubkey: 'aa'.repeat(32),
        },
      }),
    ).toThrow(/must not carry issuance/);
  });

  it('mint/send: reject genesis_pubkey; receive accepts and round-trips it', () => {
    expect(() =>
      assertTransitionRequest({
        kind: 'mint',
        ...base,
        output_templates: oneOut,
        genesis_pubkey: 'd0'.repeat(32),
        issuance: {
          name: 'x',
          decimals: 0,
          issuance_version: 1,
          amount: '1',
          creator_pubkey: 'aa'.repeat(32),
        },
      }),
    ).toThrow(/must not carry genesis_pubkey/);
    expect(() =>
      assertTransitionRequest({
        kind: 'send',
        ...base,
        input_coins: ['cc'.repeat(32)],
        output_templates: oneOut,
        genesis_pubkey: 'd0'.repeat(32),
      }),
    ).toThrow(/must not carry genesis_pubkey/);

    const withGenesis: TransitionRequest = assertTransitionRequest({
      kind: 'receive',
      ...base,
      fold_coin_ids: ['ee'.repeat(32)],
      genesis_pubkey: 'd0'.repeat(32),
    });
    expect(withGenesis.kind).toBe('receive');
    if (withGenesis.kind !== 'receive') throw new Error('expected receive');
    expect(withGenesis.genesis_pubkey).toBe('d0'.repeat(32));
    const jsonWith = transitionRequestToJson(withGenesis);
    expect(jsonWith.genesis_pubkey).toBe('d0'.repeat(32));

    const withoutGenesis: TransitionRequest = assertTransitionRequest({
      kind: 'receive',
      ...base,
      fold_coin_ids: ['ee'.repeat(32)],
    });
    const jsonWithout = transitionRequestToJson(withoutGenesis);
    expect(jsonWithout).not.toHaveProperty('genesis_pubkey');

    expect(() =>
      assertTransitionRequest({
        kind: 'receive',
        ...base,
        fold_coin_ids: ['ee'.repeat(32)],
        genesis_pubkey: 'd0'.repeat(16),
      }),
    ).toThrow(/genesis_pubkey/);
  });

  it('serialises legal mint (v1 + v2) and receive, including publisher', () => {
    const mintV1: TransitionRequest = {
      kind: 'mint',
      ...base,
      output_templates: oneOut,
      issuance: {
        name: 'zkUSD',
        decimals: 8,
        issuance_version: 1,
        amount: '1000',
        creator_pubkey: 'aa'.repeat(32),
      },
    };
    const j1 = transitionRequestToJson(mintV1);
    expect(j1.kind).toBe('mint');
    expect(j1.issuance).toEqual(mintV1.issuance);
    expect(j1).not.toHaveProperty('input_coins');
    expect(j1).not.toHaveProperty('fee_address');

    const mintV2: TransitionRequest = {
      kind: 'mint',
      ...base,
      publisher_pubkey: 'ee'.repeat(32),
      output_templates: oneOut,
      issuance: {
        name: 'zkUSD',
        decimals: 8,
        issuance_version: 2,
        amount: '1000',
        cap_total: '1000000',
        terms_salt: 'ff'.repeat(32),
        creator_pubkey: 'aa'.repeat(32),
      },
    };
    const j2 = transitionRequestToJson(mintV2);
    expect(j2.publisher_pubkey).toBe('ee'.repeat(32));
    expect(j2.issuance).toEqual(mintV2.issuance);

    const recv: TransitionRequest = {
      kind: 'receive',
      ...base,
      fold_coin_ids: ['11'.repeat(32), '22'.repeat(32)],
    };
    const j3 = transitionRequestToJson(recv);
    expect(j3.fold_coin_ids).toEqual(recv.fold_coin_ids);
    expect(j3).not.toHaveProperty('output_templates');
  });

  it('rejects non-hex coin ids, incomplete issuance, and v1 carrying v2 fields', () => {
    // Numeric input_coins slipped through when only Array.isArray was checked.
    expect(() =>
      assertTransitionRequest({
        kind: 'send',
        ...base,
        input_coins: [1],
        output_templates: oneOut,
      }),
    ).toThrow(/input_coins\[0\] must be a 32-byte hex string/);
    expect(() =>
      assertTransitionRequest({
        kind: 'send',
        ...base,
        input_coins: ['not-hex'],
        output_templates: oneOut,
      }),
    ).toThrow(/input_coins\[0\]/);
    expect(() =>
      assertTransitionRequest({
        kind: 'receive',
        ...base,
        fold_coin_ids: [42],
      }),
    ).toThrow(/fold_coin_ids\[0\] must be a 32-byte hex string/);

    // Issuance name/decimals/amount were unchecked.
    expect(() =>
      assertTransitionRequest({
        kind: 'mint',
        ...base,
        output_templates: oneOut,
        issuance: {
          decimals: 0,
          issuance_version: 1,
          amount: '1',
          creator_pubkey: 'aa'.repeat(32),
        },
      }),
    ).toThrow(/issuance\.name is required/);
    expect(() =>
      assertTransitionRequest({
        kind: 'mint',
        ...base,
        output_templates: oneOut,
        issuance: {
          name: 'x',
          decimals: 0,
          issuance_version: 1,
          amount: '1',
        },
      }),
    ).toThrow(/issuance\.creator_pubkey is required/);
    expect(() =>
      assertTransitionRequest({
        kind: 'mint',
        ...base,
        output_templates: oneOut,
        issuance: {
          name: 'x',
          decimals: 1.5,
          issuance_version: 1,
          amount: '1',
          creator_pubkey: 'aa'.repeat(32),
        },
      }),
    ).toThrow(/issuance\.decimals must be a non-negative integer/);
    expect(() =>
      assertTransitionRequest({
        kind: 'mint',
        ...base,
        output_templates: oneOut,
        issuance: {
          name: 'x',
          decimals: 0,
          issuance_version: 1,
          amount: '01',
          creator_pubkey: 'aa'.repeat(32),
        },
      }),
    ).toThrow(/issuance\.amount/);
    expect(() =>
      assertTransitionRequest({
        kind: 'mint',
        ...base,
        output_templates: oneOut,
        issuance: {
          name: 'x',
          decimals: 0,
          issuance_version: 1,
          amount: '1',
          creator_pubkey: 'aa'.repeat(32),
          cap_total: '100',
        },
      }),
    ).toThrow(/issuance_version=1 must not carry cap_total or terms_salt/);
    expect(() =>
      assertTransitionRequest({
        kind: 'mint',
        ...base,
        output_templates: oneOut,
        issuance: {
          name: 'x',
          decimals: 0,
          issuance_version: 1,
          amount: '1',
          creator_pubkey: 'aa'.repeat(32),
          terms_salt: 'ff'.repeat(32),
        },
      }),
    ).toThrow(/issuance_version=1 must not carry cap_total or terms_salt/);

    // Normalised return drops undefined publisher and re-validates hex.
    const normalised = assertTransitionRequest({
      kind: 'send',
      ...base,
      input_coins: ['cc'.repeat(32)],
      output_templates: oneOut,
    });
    expect(normalised).toEqual({
      kind: 'send',
      subject: base.subject,
      next_pubkey: base.next_pubkey,
      npk_rand: base.npk_rand,
      input_coins: ['cc'.repeat(32)],
      output_templates: oneOut,
    });
    expect(normalised).not.toHaveProperty('publisher_pubkey');
  });

  it('receive with publisher_pubkey is normalised (case c)', () => {
    const out = assertTransitionRequest({
      kind: 'receive',
      ...base,
      publisher_pubkey: 'ee'.repeat(32),
      fold_coin_ids: ['11'.repeat(32)],
    });
    expect(out).toEqual({
      kind: 'receive',
      subject: base.subject,
      next_pubkey: base.next_pubkey,
      npk_rand: base.npk_rand,
      publisher_pubkey: 'ee'.repeat(32),
      fold_coin_ids: ['11'.repeat(32)],
    });
    const json = transitionRequestToJson(out);
    expect(json.publisher_pubkey).toBe('ee'.repeat(32));
    expect(json.fold_coin_ids).toEqual(['11'.repeat(32)]);
  });

  it('rejects non-array coin id lists', () => {
    expect(() =>
      assertTransitionRequest({
        kind: 'send',
        ...base,
        input_coins: 'cc'.repeat(32),
        output_templates: oneOut,
      }),
    ).toThrow(/input_coins must be an array/);
    expect(() =>
      assertTransitionRequest({
        kind: 'receive',
        ...base,
        fold_coin_ids: { id: 'ee'.repeat(32) },
      }),
    ).toThrow(/fold_coin_ids must be an array/);
  });

  it('rejects malformed output_templates entries (object/fields)', () => {
    expect(() =>
      assertTransitionRequest({
        kind: 'send',
        ...base,
        input_coins: ['cc'.repeat(32)],
        output_templates: [null],
      }),
    ).toThrow(/output_templates\[0\] must be an object/);
    expect(() =>
      assertTransitionRequest({
        kind: 'send',
        ...base,
        input_coins: ['cc'.repeat(32)],
        output_templates: [['not', 'object']],
      }),
    ).toThrow(/output_templates\[0\] must be an object/);
    expect(() =>
      assertTransitionRequest({
        kind: 'send',
        ...base,
        input_coins: ['cc'.repeat(32)],
        output_templates: [{ asset_id: 'dd'.repeat(32), amount: '1' }],
      }),
    ).toThrow(/output_templates\[0\]\.recipient is required/);
    expect(() =>
      assertTransitionRequest({
        kind: 'send',
        ...base,
        input_coins: ['cc'.repeat(32)],
        output_templates: [{ recipient: base.subject, amount: '1' }],
      }),
    ).toThrow(/output_templates\[0\]\.asset_id is required/);
    expect(() =>
      assertTransitionRequest({
        kind: 'send',
        ...base,
        input_coins: ['cc'.repeat(32)],
        output_templates: [{ recipient: base.subject, asset_id: 'dd'.repeat(32) }],
      }),
    ).toThrow(/output_templates\[0\]\.amount is required/);
    expect(() =>
      assertTransitionRequest({
        kind: 'send',
        ...base,
        input_coins: ['cc'.repeat(32)],
        output_templates: [{ recipient: '', asset_id: 'dd'.repeat(32), amount: '1' }],
      }),
    ).toThrow(/output_templates\[0\]\.recipient is required/);
  });

  it('rejects issuance missing amount and v2 missing terms_salt after cap_total', () => {
    expect(() =>
      assertTransitionRequest({
        kind: 'mint',
        ...base,
        output_templates: oneOut,
        issuance: {
          name: 'x',
          decimals: 0,
          issuance_version: 1,
          creator_pubkey: 'aa'.repeat(32),
        },
      }),
    ).toThrow(/issuance\.amount is required/);
    expect(() =>
      assertTransitionRequest({
        kind: 'mint',
        ...base,
        output_templates: oneOut,
        issuance: {
          name: 'x',
          decimals: 0,
          issuance_version: 2,
          amount: '1',
          creator_pubkey: 'aa'.repeat(32),
          cap_total: '100',
        },
      }),
    ).toThrow(/issuance_version=2 requires cap_total and terms_salt/);
    // Empty terms_salt after a present cap_total hits the second gate.
    expect(() =>
      assertTransitionRequest({
        kind: 'mint',
        ...base,
        output_templates: oneOut,
        issuance: {
          name: 'x',
          decimals: 0,
          issuance_version: 2,
          amount: '1',
          creator_pubkey: 'aa'.repeat(32),
          cap_total: '100',
          terms_salt: '',
        },
      }),
    ).toThrow(/issuance_version=2 requires cap_total and terms_salt/);
  });
});

// ---------------------------------------------------------------------------
// signGate.ts — remaining refusals + sign body length
// ---------------------------------------------------------------------------

describe('signGate remaining refusals', () => {
  const nextPubkey = new Uint8Array(32).fill(0x11);
  const npkRand = new Uint8Array(32).fill(0x22);
  const npkCommit = computeNpkCommit(nextPubkey, npkRand);
  const pd: ProofData = { ...sampleProofData(), npkCommit };
  const accountState = { current_pubkey: encodeHexLower(V8_PK1), send_counter: 0 };

  function awaiting(overrides: Partial<AwaitingSignature> = {}): AwaitingSignature {
    return {
      new_account_state_hash: encodeHexLower(pd.newAccountStateHash),
      output_coins_root: encodeHexLower(pd.outputCoinsRoot),
      input_nullifiers_root: encodeHexLower(pd.inputNullifiersRoot),
      coin_history_root: encodeHexLower(pd.coinHistoryRoot),
      nav_commitment: encodeHexLower(pd.navCommitment),
      npk_commit: encodeHexLower(npkCommit),
      proof_data_hash: encodeHexLower(hashProofData(pd)),
      txn_pubkey: encodeHexLower(V8_PK1),
      send_counter: 0,
      ...overrides,
    };
  }

  it('refuses when send_counter disagrees (KeyBindingRefusalError with the proposed counter)', () => {
    try {
      refuseOrSignTransition({
        localPubkey: V8_PK1,
        secretKey: V8_SK1,
        accountState,
        awaiting: awaiting({ send_counter: 7 }),
        walletNetwork: 'testnet',
        nextPubkey,
        npkRand,
      });
      expect.unreachable('expected KeyBindingRefusalError');
    } catch (err) {
      expect(err).toBeInstanceOf(KeyBindingRefusalError);
      if (!(err instanceof KeyBindingRefusalError)) throw err;
      expect(err.sendCounter).toBe(7);
      expect(err.message).toMatch(/key binding failed/);
    }
  });

  it('refuses when npk_commit does not recompute from wallet material', () => {
    try {
      refuseOrSignTransition({
        localPubkey: V8_PK1,
        secretKey: V8_SK1,
        accountState,
        awaiting: awaiting({ npk_commit: 'ab'.repeat(32) }),
        walletNetwork: 'testnet',
        nextPubkey,
        npkRand,
      });
      expect.unreachable('expected NpkCommitRefusalError');
    } catch (err) {
      expect(err).toBeInstanceOf(NpkCommitRefusalError);
      if (!(err instanceof NpkCommitRefusalError)) throw err;
      expect(err.recomputed).toBe(encodeHexLower(npkCommit));
      expect(err.serverClaimed).toBe('ab'.repeat(32));
      expect(err.message).toMatch(/npk_commit mismatch/);
    }
  });

  it('signBodyFromSignature rejects wrong signature / s2c_nonce lengths', () => {
    expect(() =>
      signBodyFromSignature({ signature: new Uint8Array(63), s2cNonce: new Uint8Array(32) }),
    ).toThrow(/signature must be 64 bytes, got 63/);
    expect(() =>
      signBodyFromSignature({ signature: new Uint8Array(64), s2cNonce: new Uint8Array(16) }),
    ).toThrow(/s2c_nonce must be 32 bytes, got 16/);
  });

  it('throws when secretKey does not derive localPubkey', () => {
    const wrongSecret = new Uint8Array(32).fill(0x03);
    expect(encodeHexLower(xOnlyPubkeyFromSecret(wrongSecret))).not.toBe(encodeHexLower(V8_PK1));
    expect(() =>
      refuseOrSignTransition({
        localPubkey: V8_PK1,
        secretKey: wrongSecret,
        accountState,
        awaiting: awaiting(),
        walletNetwork: 'testnet',
        nextPubkey,
        npkRand,
      }),
    ).toThrow(/secretKey does not match localPubkey/);
  });
});

// ---------------------------------------------------------------------------
// ownership.ts
// ---------------------------------------------------------------------------

describe('ownership / chan_bind / expiry gates', () => {
  it('chanBindForHost rejects empty host', () => {
    expect(() => chanBindForHost('')).toThrow(/host is required/);
  });

  it('canonicalHostFromApiUrl normalises and rejects invalid / empty hosts', () => {
    expect(canonicalHostFromApiUrl('https://Node.Example.COM:443/path')).toBe('node.example.com');
    expect(canonicalHostFromApiUrl('http://node.test:80/')).toBe('node.test');
    expect(canonicalHostFromApiUrl('https://node.test:8443/')).toBe('node.test:8443');
    expect(canonicalHostFromApiUrl('http://node.test:8080')).toBe('node.test:8080');
    expect(canonicalHostFromApiUrl('zkcoins://node.test:1798/path')).toBe('node.test:1798');
    // Trailing dot on hostname
    expect(canonicalHostFromApiUrl('https://node.test./')).toBe('node.test');
    expect(() => canonicalHostFromApiUrl('not a url')).toThrow(/invalid URL/);
    expect(() => canonicalHostFromApiUrl('https:///')).toThrow(/empty hostname|invalid URL/);
    // file: URLs parse successfully but carry an empty hostname → explicit gate.
    expect(() => canonicalHostFromApiUrl('file:///tmp/x')).toThrow(/empty hostname/);
  });

  it('pullChallengeMessage rejects malformed inputs', () => {
    const ok = {
      domain: PULL_CHALLENGE_DOMAIN,
      nonce: new Uint8Array(32),
      chanBind: new Uint8Array(32),
      subjectRaw: new Uint8Array(32),
      expiry: 1n,
    };
    expect(() => pullChallengeMessage({ ...ok, domain: '' })).toThrow(/domain is required/);
    expect(() => pullChallengeMessage({ ...ok, nonce: new Uint8Array(16) })).toThrow(
      /nonce must be 32 bytes/,
    );
    expect(() => pullChallengeMessage({ ...ok, chanBind: new Uint8Array(16) })).toThrow(
      /chan_bind must be 32 bytes/,
    );
    expect(() => pullChallengeMessage({ ...ok, subjectRaw: new Uint8Array(16) })).toThrow(
      /subject must be 32 bytes/,
    );
    expect(() => pullChallengeMessage({ ...ok, expiry: -1n })).toThrow(/expiry out of u64 range/);
    expect(() => pullChallengeMessage({ ...ok, expiry: 0x1_0000_0000_0000_0000n })).toThrow(
      /expiry out of u64 range/,
    );
  });

  it('parseExpiryDecimal accepts canonical u64 and rejects the rest', () => {
    expect(parseExpiryDecimal('0')).toBe(0n);
    expect(parseExpiryDecimal('1700000060')).toBe(1700000060n);
    expect(() => parseExpiryDecimal('')).toThrow(/empty/);
    // Leading-zero gate fires before the decimal regex (also covers "0x…").
    expect(() => parseExpiryDecimal('01')).toThrow(/leading zeros are not allowed/);
    expect(() => parseExpiryDecimal('0x10')).toThrow(/leading zeros are not allowed/);
    // Non-decimal alphabet without a leading zero — hits the canonical-decimal regex.
    expect(() => parseExpiryDecimal('12a')).toThrow(/not a canonical u64 decimal/);
    expect(() => parseExpiryDecimal('18446744073709551616')).toThrow(/out of u64 range/); // 2^64
  });

  it('buildOwnershipProof rejects wrong domain and wrong nk_commit length', () => {
    const seed = seedFromMnemonicV1(MNEMONIC);
    const sk0 = deriveSk0(seed, 0);
    const subject = encodeZkAddress(sha256(new Uint8Array(64)));
    expect(() =>
      buildOwnershipProof({
        subject,
        sk0: sk0.secretKey,
        nkCommit: new Uint8Array(32),
        challenge: {
          nonce: 'aa'.repeat(32),
          expiry: '1',
          domain: 'zkCoins/v1/Wrong',
        },
        host: 'node.test',
      }),
    ).toThrow(/unexpected challenge domain/);
    expect(() =>
      buildOwnershipProof({
        subject,
        sk0: sk0.secretKey,
        nkCommit: new Uint8Array(16),
        challenge: {
          nonce: 'aa'.repeat(32),
          expiry: '1',
          domain: PULL_CHALLENGE_DOMAIN,
        },
        host: 'node.test',
      }),
    ).toThrow(/nk_commit must be 32 bytes/);
  });

  it('buildOwnershipProof rejects subject that does not match Pk0||nk_commit', () => {
    const seed = seedFromMnemonicV1(MNEMONIC);
    const sk0 = deriveSk0(seed, 0);
    const nkCommit = new Uint8Array(32);
    // Foreign subject — not SHA-256(pk0 || nk_commit)
    const subject = encodeZkAddress(sha256(new Uint8Array(64)));
    expect(() =>
      buildOwnershipProof({
        subject,
        sk0: sk0.secretKey,
        nkCommit,
        challenge: {
          nonce: 'aa'.repeat(32),
          expiry: '1',
          domain: PULL_CHALLENGE_DOMAIN,
        },
        host: 'node.test',
      }),
    ).toThrow(/subject does not match/);
  });

  it('computeNpkCommit rejects wrong lengths', () => {
    expect(() => computeNpkCommit(new Uint8Array(16), new Uint8Array(32))).toThrow(
      /next_pubkey must be 32 bytes/,
    );
    expect(() => computeNpkCommit(new Uint8Array(32), new Uint8Array(16))).toThrow(
      /npk_rand must be 32 bytes/,
    );
  });
});

// ---------------------------------------------------------------------------
// bech32m.ts
// ---------------------------------------------------------------------------

describe('Bech32m zk address rejection paths', () => {
  it('rejects padding with at least one full input word left over', () => {
    const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
    const BECH32M_CONST = 0x2bc830a3;
    const generators = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    const polymod = (values: number[]): number => {
      let chk = 1;
      for (const value of values) {
        const top = chk >>> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ value;
        for (let i = 0; i < 5; i += 1) {
          if ((top >>> i) & 1) chk ^= generators[i]!;
        }
      }
      return chk;
    };
    const hrpExpand = (hrp: string): number[] => [
      ...Array.from(hrp, (char) => char.charCodeAt(0) >>> 5),
      0,
      ...Array.from(hrp, (char) => char.charCodeAt(0) & 31),
    ];
    const data = Array<number>(49).fill(0);
    const mod = polymod([...hrpExpand('zk'), ...data, 0, 0, 0, 0, 0, 0]) ^ BECH32M_CONST;
    const checksum = Array.from({ length: 6 }, (_, i) => (mod >>> (5 * (5 - i))) & 31);
    const forged = `zk1${[...data, ...checksum].map((value) => CHARSET[value]).join('')}`;

    expect(() => decodeZkAddress(forged)).toThrow(/non-canonical padding/);
  });

  const payload = new Uint8Array(32).fill(0xab);
  const valid = encodeZkAddress(payload);

  /** Test-only Bech32m encoder (same BIP-350 rules) for non-32-byte payloads. */
  function encodeBech32mForTest(hrp: string, bytes: Uint8Array): string {
    const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
    const BECH32M_CONST = 0x2bc830a3;
    const polymod = (values: number[]): number => {
      let chk = 1;
      for (const v of values) {
        const b = chk >>> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ v;
        if (b & 1) chk ^= 0x3b6a57b2;
        if (b & 2) chk ^= 0x26508e6d;
        if (b & 4) chk ^= 0x1ea119fa;
        if (b & 8) chk ^= 0x3d4233dd;
        if (b & 16) chk ^= 0x2a1462b3;
      }
      return chk >>> 0;
    };
    const hrpExpand = (h: string): number[] => {
      const ret: number[] = [];
      for (let i = 0; i < h.length; i++) ret.push(h.charCodeAt(i) >>> 5);
      ret.push(0);
      for (let i = 0; i < h.length; i++) ret.push(h.charCodeAt(i) & 31);
      return ret;
    };
    // 8→5 with padding
    let acc = 0;
    let bits = 0;
    const data: number[] = [];
    for (const value of bytes) {
      acc = (acc << 8) | value;
      bits += 8;
      while (bits >= 5) {
        bits -= 5;
        data.push((acc >> bits) & 31);
      }
    }
    if (bits > 0) data.push((acc << (5 - bits)) & 31);
    const values = hrpExpand(hrp).concat(data).concat([0, 0, 0, 0, 0, 0]);
    const mod = polymod(values) ^ BECH32M_CONST;
    let out = `${hrp}1`;
    for (const d of data) out += CHARSET[d]!;
    for (let p = 0; p < 6; p++) out += CHARSET[(mod >>> (5 * (5 - p))) & 31]!;
    return out;
  }

  it('encode rejects wrong payload length', () => {
    expect(() => encodeZkAddress(new Uint8Array(16))).toThrow(/payload must be 32 bytes, got 16/);
    expect(() => encodeZkAddress(new Uint8Array(33))).toThrow(/payload must be 32 bytes, got 33/);
  });

  it('decode rejects empty, mixed case, bad HRP, missing separator, invalid char, checksum', () => {
    expect(() => decodeZkAddress('')).toThrow(/empty address/);
    // Mixed case
    const mixed = valid.slice(0, 4).toUpperCase() + valid.slice(4);
    expect(() => decodeZkAddress(mixed)).toThrow(/mixed-case/);
    // Wrong HRP
    expect(() => decodeZkAddress('bc1' + valid.slice(3))).toThrow(/expected HRP "zk"/);
    // No separator
    expect(() =>
      decodeZkAddress('zkqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq'),
    ).toThrow(/missing separator/);
    // Invalid charset character 'b' (not in bech32 alphabet)
    const withB = valid.slice(0, -1) + 'b';
    expect(() => decodeZkAddress(withB)).toThrow(/invalid character/);
    // Checksum failure: flip last character within charset
    const flipped = valid.slice(0, -1) + (valid.endsWith('q') ? 'p' : 'q');
    expect(() => decodeZkAddress(flipped)).toThrow(/checksum failed/);
  });

  it('decode rejects wrong payload length and non-canonical padding', () => {
    // 20-byte payload is valid Bech32m under HRP zk but not a zkCoins address.
    const short = encodeBech32mForTest('zk', new Uint8Array(20).fill(0x11));
    expect(() => decodeZkAddress(short)).toThrow(/payload must be 32 bytes, got 20/);

    // Force non-canonical residual padding: encode 32 zero bytes (last 5-bit
    // group is pure pad zeros), set the low pad bit, recompute Bech32m checksum.
    const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
    const BECH32M_CONST = 0x2bc830a3;
    const polymod = (values: number[]): number => {
      let chk = 1;
      for (const v of values) {
        const b = chk >>> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ v;
        if (b & 1) chk ^= 0x3b6a57b2;
        if (b & 2) chk ^= 0x26508e6d;
        if (b & 4) chk ^= 0x1ea119fa;
        if (b & 8) chk ^= 0x3d4233dd;
        if (b & 16) chk ^= 0x2a1462b3;
      }
      return chk >>> 0;
    };
    const hrpExpand = (h: string): number[] => {
      const ret: number[] = [];
      for (let i = 0; i < h.length; i++) ret.push(h.charCodeAt(i) >>> 5);
      ret.push(0);
      for (let i = 0; i < h.length; i++) ret.push(h.charCodeAt(i) & 31);
      return ret;
    };
    // 32 zero bytes → 52 five-bit groups, last group is 0 (padding only).
    const data = new Array<number>(52).fill(0);
    data[51] = 1; // non-zero padding bit in the final group
    const hrp = 'zk';
    const values = hrpExpand(hrp).concat(data).concat([0, 0, 0, 0, 0, 0]);
    const mod = polymod(values) ^ BECH32M_CONST;
    let forged = `${hrp}1`;
    for (const d of data) forged += CHARSET[d]!;
    for (let p = 0; p < 6; p++) forged += CHARSET[(mod >>> (5 * (5 - p))) & 31]!;
    expect(() => decodeZkAddress(forged)).toThrow(/non-canonical padding/);
  });

  it('round-trip preserves the 32-byte payload (including all-zero)', () => {
    const zero = new Uint8Array(32);
    expect(bytesToHex(decodeZkAddress(encodeZkAddress(zero)))).toBe(bytesToHex(zero));
    expect(bytesToHex(decodeZkAddress(valid))).toBe(bytesToHex(payload));
    // Uppercase-only is allowed by BIP-173
    expect(bytesToHex(decodeZkAddress(valid.toUpperCase()))).toBe(bytesToHex(payload));
  });
});

// ---------------------------------------------------------------------------
// halfAgg.ts — empty / sparse / length / sAgg=0 / commRetrieve
// ---------------------------------------------------------------------------

describe('half-aggregation rejection paths', () => {
  it('aggregationCoefficients / aggregateSig reject empty member lists', () => {
    expect(() => aggregationCoefficients([])).toThrow(/empty member list/);
    expect(() => aggregateSig([])).toThrow(/cannot half-aggregate zero signatures/);
  });

  it('aggregationCoefficients rejects a member count that does not fit in u32', () => {
    // JS Array length is a uint32, so a real array cannot exceed 0xffffffff.
    // A plain array-like with an oversized `length` still hits the gate.
    const oversized = {
      length: 0x1_0000_0000,
      *[Symbol.iterator](): IterableIterator<{ pk: Uint8Array; r: Uint8Array }> {
        // unused — length check runs first
      },
    };
    const args: [{ pk: Uint8Array; r: Uint8Array }[]] = [[]];
    Reflect.set(args, 0, oversized);
    expect(() => Reflect.apply(aggregationCoefficients, undefined, args)).toThrow(
      /member count exceeds u32/,
    );
  });

  it('aggregateSig rejects wrong-length member fields and off-curve points', () => {
    const good = signTransitionTrace({
      secretKey: V8_SK1,
      network: 'regtest',
      mSc: randomBytes(32),
    });
    expect(() => aggregateSig([{ pk: good.pk, r: good.r, s: new Uint8Array(16) }])).toThrow(
      TransitionSignatureError,
    );
    // Real off-curve x (BIP-340 vector) — not x=0x0101…01, which is on-curve.
    expect(() => aggregateSig([{ pk: OFF_CURVE_XONLY, r: good.r, s: good.s }])).toThrow(
      /not on secp256k1/,
    );
  });

  it('aggregateSig rejects a hole in a sparse member array', () => {
    const s1 = signTransitionTrace({
      secretKey: V8_SK1,
      network: 'regtest',
      mSc: randomBytes(32),
    });
    const members = [{ pk: s1.pk, r: s1.r, s: s1.s }];
    members.length = 2; // members[1] is a hole
    expect(() => aggregateSig(members)).toThrow(/missing member at index 1/);
  });

  it('aggregateVerify returns false for empty, s_agg ≥ n, s_agg = 0 with non-zero rhs, off-curve', () => {
    expect(aggregateVerify({ members: [], sAgg: new Uint8Array(32), network: 'testnet' })).toBe(
      false,
    );

    const s1 = signTransitionTrace({
      secretKey: V8_SK1,
      network: 'testnet',
      mSc: randomBytes(32),
    });
    const nBytes = hexToBytes('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
    expect(
      aggregateVerify({
        members: [{ pk: s1.pk, r: s1.r }],
        sAgg: nBytes,
        network: 'testnet',
      }),
    ).toBe(false);

    // s_agg = 0 with a real member → rhs ≠ ∞ → false (covers the sAgg===0 branch)
    expect(
      aggregateVerify({
        members: [{ pk: s1.pk, r: s1.r }],
        sAgg: new Uint8Array(32),
        network: 'testnet',
      }),
    ).toBe(false);

    expect(
      aggregateVerify({
        members: [{ pk: OFF_CURVE_XONLY, r: s1.r }],
        sAgg: s1.s,
        network: 'testnet',
      }),
    ).toBe(false);

    // Sparse hole → false
    const sparse = [{ pk: s1.pk, r: s1.r }];
    sparse.length = 2;
    expect(
      aggregateVerify({
        members: sparse,
        sAgg: s1.s,
        network: 'testnet',
      }),
    ).toBe(false);
  });

  it('requireBytes-style length / type errors surface through aggregationCoefficients', () => {
    expect(() =>
      aggregationCoefficients([{ pk: new Uint8Array(16), r: new Uint8Array(32) }]),
    ).toThrow(/expected 32 bytes/);
    const bad = { pk: new Uint8Array(32), r: new Uint8Array(32) };
    Reflect.set(bad, 'pk', 'not-bytes');
    expect(() => aggregationCoefficients([bad])).toThrow(/expected Uint8Array/);
  });

  it('commRetrieve validates index and 32-byte R entries', () => {
    const r = randomBytes(32);
    expect(encodeHexLower(commRetrieve([r], 0))).toBe(encodeHexLower(r));
    expect(() => commRetrieve([r], -1)).toThrow(/non-negative integer/);
    expect(() => commRetrieve([r], 1.5)).toThrow(/non-negative integer/);
    expect(() => commRetrieve([r], 1)).toThrow(/out of range/);
    expect(() => commRetrieve([new Uint8Array(16)], 0)).toThrow(/expected 32 bytes/);
  });

  it('pointHasEvenY lifts a real x-only key and rejects off-curve', () => {
    expect(pointHasEvenY(V8_PK1)).toBe(true);
    expect(() => pointHasEvenY(OFF_CURVE_XONLY)).toThrow(/not on secp256k1/);
  });
});

// ---------------------------------------------------------------------------
// transitionSignature.ts — canonical scalar / lift / verify / commVerify edges
// ---------------------------------------------------------------------------

describe('transition signature encoding refusals', () => {
  it('bip340NormaliseSecret rejects 0 and ≥ n', () => {
    expect(() => bip340NormaliseSecret(new Uint8Array(32))).toThrow(
      /not a canonical secp256k1 scalar/,
    );
    const nBytes = new Uint8Array(32);
    // SECP256K1_ORDER as 32-byte BE
    let n = SECP256K1_ORDER;
    for (let i = 31; i >= 0; i--) {
      nBytes[i] = Number(n & 0xffn);
      n >>= 8n;
    }
    expect(() => bip340NormaliseSecret(nBytes)).toThrow(/not a canonical secp256k1 scalar/);
  });

  it('requireCanonicalScalar rejects int ≥ n and wrong length', () => {
    const nBytes = hexToBytes('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
    expect(() => requireCanonicalScalar(nBytes, 's')).toThrow(/not canonical \(int ≥ n\)/);
    expect(() => requireCanonicalScalar(new Uint8Array(16), 's')).toThrow(/expected 32 bytes/);
  });

  it('liftXOnly rejects x ≥ p and x not on the curve', () => {
    // p = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F
    const geP = hexToBytes('fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f');
    expect(() => liftXOnly(geP, 'pk')).toThrow(/not a valid field element/);
    // x = p + 1 still fails the field-element gate (not the curve equation).
    const gtP = hexToBytes('fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30');
    expect(() => liftXOnly(gtP, 'pk')).toThrow(/not a valid field element/);
    // BIP-340 invalid pubkey: 0 < x < p but y² = x³+7 is a non-residue.
    expect(() => liftXOnly(OFF_CURVE_XONLY, 'pk')).toThrow(/not on secp256k1/);
  });

  it('verify fails closed when publicKey is not a Uint8Array (plain-JS shape)', () => {
    const input = {
      publicKey: V8_PK1,
      signature: new Uint8Array(64),
      network: 'testnet' as const,
    };
    Reflect.set(input, 'publicKey', 'not-bytes');
    expect(verify(input)).toBe(false);
  });

  it('verify rejects s = 0', () => {
    const r = hexToBytes('e7f2a98e7b45e9424e3e0cb1d937a1698ebd339c6d8344906db979642cf20474');
    const sig = new Uint8Array(64);
    sig.set(r, 0);
    // s = 0
    expect(verify({ publicKey: V8_PK1, signature: sig, network: 'testnet' })).toBe(false);
  });

  it('commVerify rejects a wrong opening (m_SC mismatch)', () => {
    const real = signTransitionTrace({
      secretKey: V8_SK1,
      network: 'testnet',
      mSc: randomBytes(32),
    });
    expect(
      commVerify({
        r: real.signature.subarray(0, 32),
        mSc: new Uint8Array(32).fill(0xff),
        rPrime: real.s2cNonce,
      }),
    ).toBe(false);
  });

  it('signTransition rejects a non-32-byte mSc', () => {
    expect(() =>
      signTransitionTrace({
        secretKey: V8_SK1,
        network: 'testnet',
        mSc: new Uint8Array(16),
      }),
    ).toThrow(/mSc: expected 32 bytes/);
  });
});

// ---------------------------------------------------------------------------
// transitionSignature pure gates (decomposition, not injection)
// ---------------------------------------------------------------------------

/** Encode a bigint as a 32-byte big-endian field element (may be ≥ n). */
function bigintToBe32(n: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let x = n;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

describe('tweakScalarOrReject (§1.7.10 unreduced S2C tweak)', () => {
  it('accepts int(t) ∈ [0, n)', () => {
    expect(tweakScalarOrReject(new Uint8Array(32))).toBe(0n);
    expect(tweakScalarOrReject(bigintToBe32(1n))).toBe(1n);
    expect(tweakScalarOrReject(bigintToBe32(SECP256K1_ORDER - 1n))).toBe(SECP256K1_ORDER - 1n);
  });

  it('rejects int(t) ≥ n without reducing (n, n+1, 0xff…ff)', () => {
    expect(tweakScalarOrReject(bigintToBe32(SECP256K1_ORDER))).toBeNull();
    expect(tweakScalarOrReject(bigintToBe32(SECP256K1_ORDER + 1n))).toBeNull();
    expect(tweakScalarOrReject(new Uint8Array(32).fill(0xff))).toBeNull();
  });

  it('refuses non-32-byte input', () => {
    expect(() => tweakScalarOrReject(new Uint8Array(16))).toThrow(/expected 32 bytes/);
  });
});

describe('isAcceptableCommittedR (§3.2 step 3b)', () => {
  const Point = schnorr.Point;

  it('accepts a finite even-y point', () => {
    const even = liftXOnly(V8_PK1, 'pk');
    expect(even.y % 2n === 0n).toBe(true);
    expect(isAcceptableCommittedR(even)).toBe(true);
  });

  it('rejects the point at infinity', () => {
    expect(isAcceptableCommittedR(Point.ZERO)).toBe(false);
  });

  it('rejects a finite odd-y point (never negate R)', () => {
    const even = liftXOnly(V8_PK1, 'pk');
    const odd = even.negate();
    expect(odd.y % 2n === 1n).toBe(true);
    expect(isAcceptableCommittedR(odd)).toBe(false);
  });
});

describe('runWithRedrawBudget', () => {
  it('returns the first non-null attempt', () => {
    const seen: number[] = [];
    const value = runWithRedrawBudget(5, (ctr) => {
      seen.push(ctr);
      if (ctr < 2) return null;
      return `ok-${ctr}`;
    });
    expect(value).toBe('ok-2');
    expect(seen).toEqual([0, 1, 2]);
  });

  it('exhausts a small budget without spinning 10_000 rounds', () => {
    let calls = 0;
    expect(() =>
      runWithRedrawBudget(3, () => {
        calls += 1;
        return null;
      }),
    ).toThrow(/exhausted redraw budget \(3\)/);
    expect(calls).toBe(3);
  });

  it('budget 0 throws immediately', () => {
    let calls = 0;
    expect(() =>
      runWithRedrawBudget(0, () => {
        calls += 1;
        return null;
      }),
    ).toThrow(/exhausted redraw budget \(0\)/);
    expect(calls).toBe(0);
  });
});

describe('production Sign still produces verifying signatures', () => {
  it('signTransitionTrace verifies and opens under the real hash (no draw seam)', () => {
    const mSc = randomBytes(32);
    const trace = signTransitionTrace({
      secretKey: V8_SK1,
      network: 'testnet',
      mSc,
    });
    expect(verify({ publicKey: V8_PK1, signature: trace.signature, network: 'testnet' })).toBe(
      true,
    );
    expect(
      commVerify({
        r: trace.signature.subarray(0, 32),
        mSc,
        rPrime: trace.s2cNonce,
      }),
    ).toBe(true);
  });
});
