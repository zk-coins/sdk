/**
 * Poseidon-over-Goldilocks, E(·), Hc — unit + pinned V.4 vector tests.
 *
 * Target digests come from the independent Rust generator
 * `node/shared/tests/generated_poseidon_vectors.txt`. Never edit those pins.
 */

import { describe, expect, it } from 'vitest';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

import {
  GOLDILOCKS_P,
  GOLDILOCKS_EPSILON,
  reduce,
  fromCanonicalU64,
  fromU64,
  toCanonicalU64,
  add,
  sub,
  mul,
  pow7,
  beBytesToU64,
  u64ToBeBytes,
} from '../src/poseidon/goldilocks.js';
import {
  poseidonPermute,
  hashNoPad,
  digestsEqual,
  ZERO_DIGEST,
  type Digest,
} from '../src/poseidon/poseidon.js';
import {
  EncodingError,
  HcInput,
  encodeByteString,
  encodeDigest,
  encodeSmallNumeric,
  digestToBytes,
  digestFromBytes,
  digestToHex,
  digestFromHex,
  hc,
  MAX_BYTE_STRING_LEN,
  MAX_SMALL_NUMERIC,
} from '../src/poseidon/hc.js';
import {
  GENESIS_TAG,
  TAG_NFLOG_EMPTY,
  TAG_NK_COMMIT,
  NETWORK_TAG_MAINNET,
} from '../src/poseidon/tags.js';
import {
  nkCommit,
  nullifier,
  assetIdV1,
  assetIdV2,
  termsHashV1,
  termsHashV2,
  networkId,
  networkIdMainnet,
  networkIdTestnet,
  networkIdRegtest,
  navCommitment,
  detectTag,
  nflogEmpty,
  nflogRoot,
  coinhistLeafHash,
  coinhistNodeHash,
  coinhistEmptyRoot,
} from '../src/poseidon/hashes.js';
// Exercise the barrel so coverage includes pure re-exports.
import * as poseidonBarrel from '../src/poseidon/index.js';

// ---------------------------------------------------------------------------
// Pinned V.4 digests (from generated_poseidon_vectors.txt — do not edit)
// ---------------------------------------------------------------------------

const PIN_NFLOG_EMPTY = 'f7599780b12dc6120b6e305e77feb04d1db533fbeb19f3fd25ca22b5b222c2bc';
const PIN_COINHIST_EMPTY_ROOT = '7d558733b6f685d85aff62341e3d017234056105bced89ce0319166dc90a6dcf';
const PIN_NK_COMMIT_SAMPLE = '444981ebd6edc1116dc1a13d51e7ed2c47988cc66ad5fb95c12de4f2efa4456e';
const PIN_ASSET_ID = 'da7deb2e2d8ad91a2ec9e2aafc6756b2b11f092c79650ce313658f3a9b2ab7cf';
const PIN_NETWORK_MAINNET = 'fb5080433fbd3d5c9ed7aad0e1feced2954859c4492ecb0880b0713f6b09ec8c';
const PIN_NETWORK_TESTNET = 'edd03cfdd9de40d33160fac02396576b5bcf94f94c568bbcef291a49f61b5e28';
const PIN_NETWORK_REGTEST = 'f26dcd6b70992a28ef809001793c1e9a3c0aa68c3a7dcc9b43b1ca0e919467de';
const PIN_DETECT_TAG = '52f38f5972d4b44ef361fadfd8e5f927f3ec9ed8d34c888435fe91d0ff76ea4c';
const PIN_ASSET_ID_V2 = '299c74853e87d0a617b8631285752d90362481e7ff06f940c6f219545c4194ab';
const PIN_TERMS_HASH_V1 = 'aa80213d58ea4fc9990f5425f71afd56f5117841ab7a3e52f46beb46330fbbf4';
const PIN_TERMS_HASH_V2 = '305bb19e79746450253d3eb2a4c1f68c4727d5792c019fe3b734e8720fbb3c2f';
const PIN_NAV_ROOT_EMPTY = 'cf2717e42bab4463cde1b657f010e65fd2940d459a2af8ea862dbf22702c14d0';
const PIN_NAV_COMMITMENT_0 = 'eec40cabb6cece9f2c76cd3fde2f55c2bf193def66c4482bd94f1cb44acbe34d';

function sha256Label(label: string): Uint8Array {
  return sha256(new TextEncoder().encode(label));
}

describe('poseidon barrel', () => {
  it('re-exports the load-bearing primitives', () => {
    expect(poseidonBarrel.GOLDILOCKS_P).toBe(GOLDILOCKS_P);
    expect(typeof poseidonBarrel.hc).toBe('function');
    expect(typeof poseidonBarrel.nflogEmpty).toBe('function');
    expect(poseidonBarrel.TAG_NFLOG_EMPTY).toBe(TAG_NFLOG_EMPTY);
  });
});

// ---------------------------------------------------------------------------
// Goldilocks field
// ---------------------------------------------------------------------------

describe('Goldilocks field', () => {
  it('ORDER matches plonky2 GoldilocksField::ORDER', () => {
    expect(GOLDILOCKS_P).toBe(0xffffffff00000001n);
    expect(GOLDILOCKS_EPSILON).toBe(0xffffffffn);
    expect(GOLDILOCKS_P).toBe((1n << 64n) - (1n << 32n) + 1n);
  });

  it('reduce maps into [0, p) including negatives', () => {
    expect(reduce(0n)).toBe(0n);
    expect(reduce(GOLDILOCKS_P)).toBe(0n);
    expect(reduce(GOLDILOCKS_P + 5n)).toBe(5n);
    expect(reduce(-1n)).toBe(GOLDILOCKS_P - 1n);
  });

  it('fromCanonicalU64 accepts [0, p) and rejects p', () => {
    expect(fromCanonicalU64(0n)).toBe(0n);
    expect(fromCanonicalU64(GOLDILOCKS_P - 1n)).toBe(GOLDILOCKS_P - 1n);
    expect(() => fromCanonicalU64(GOLDILOCKS_P)).toThrow(/out of range/);
    expect(() => fromCanonicalU64(-1n)).toThrow(/out of range/);
  });

  it('fromU64 reduces non-canonical u64 and rejects out-of-u64', () => {
    expect(fromU64(GOLDILOCKS_P)).toBe(0n);
    // 2^64 − 1 ≡ 2^32 − 2 (mod p)
    expect(fromU64(0xffffffffffffffffn)).toBe(0xfffffffen);
    expect(() => fromU64(-1n)).toThrow(/not a u64/);
    expect(() => fromU64(1n << 64n)).toThrow(/not a u64/);
  });

  it('toCanonicalU64 rejects non-canonical internal values', () => {
    expect(toCanonicalU64(3n)).toBe(3n);
    expect(() => toCanonicalU64(GOLDILOCKS_P)).toThrow(/non-canonical/);
    expect(() => toCanonicalU64(-1n)).toThrow(/non-canonical/);
  });

  it('add / sub / mul / pow7 are field operations', () => {
    expect(add(GOLDILOCKS_P - 1n, 2n)).toBe(1n);
    expect(sub(1n, 2n)).toBe(GOLDILOCKS_P - 1n);
    expect(mul(2n, 3n)).toBe(6n);
    // 2^7 = 128
    expect(pow7(2n)).toBe(128n);
    // 0^7 = 0, 1^7 = 1
    expect(pow7(0n)).toBe(0n);
    expect(pow7(1n)).toBe(1n);
  });

  it('u64ToBeBytes / beBytesToU64 round-trip and length checks', () => {
    const bytes = u64ToBeBytes(0x0102030405060708n);
    expect(bytesToHex(bytes)).toBe('0102030405060708');
    expect(beBytesToU64(bytes)).toBe(0x0102030405060708n);
    expect(() => beBytesToU64(new Uint8Array(7))).toThrow(/expected 8 bytes/);
    expect(() => u64ToBeBytes(GOLDILOCKS_P)).toThrow(/non-canonical/);
  });
});

// ---------------------------------------------------------------------------
// Poseidon permutation — plonky2 test vectors
// ---------------------------------------------------------------------------

describe('poseidonPermute (plonky2 test vectors)', () => {
  it('all-zero state matches poseidon_goldilocks.rs test_vectors', () => {
    const out = poseidonPermute(new Array(12).fill(0n));
    const expected = [
      0x3c18a9786cb0b359n,
      0xc4055e3364a246c3n,
      0x7953db0ab48808f4n,
      0xc71603f33a1144can,
      0xd7709673896996dcn,
      0x46a84e87642f44edn,
      0xd032648251ee0b3cn,
      0x1c687363b207df62n,
      0xdf8565563e8045fen,
      0x40f5b37ff4254daen,
      0xd070f637b431067cn,
      0x1792b1c4342109d7n,
    ];
    expect(out).toEqual(expected);
  });

  it('range 0..11 state matches poseidon_goldilocks.rs test_vectors', () => {
    const out = poseidonPermute([0n, 1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n, 10n, 11n]);
    const expected = [
      0xd64e1e3efc5b8e9en,
      0x53666633020aaa47n,
      0xd40285597c6a8825n,
      0x613a4f81e81231d2n,
      0x414754bfebd051f0n,
      0xcb1f8980294a023fn,
      0x6eb2a9e4d54a9d0fn,
      0x1902bc3af467e056n,
      0xf045d5eafdc6021fn,
      0xe4150f77caaa3be5n,
      0xc9bfd01d39b50ccen,
      0x5c0a27fcb0e1459bn,
    ];
    expect(out).toEqual(expected);
  });

  it('all-ones (NEG_ONE) state matches poseidon_goldilocks.rs test_vectors', () => {
    const negOne = GOLDILOCKS_P - 1n;
    const out = poseidonPermute(new Array(12).fill(negOne));
    const expected = [
      0xbe0085cfc57a8357n,
      0xd95af71847d05c09n,
      0xcf55a13d33c1c953n,
      0x95803a74f4530e82n,
      0xfcd99eb30a135df1n,
      0xe095905e913a3029n,
      0xde0392461b42919bn,
      0x7d3260e24e81d031n,
      0x10d3d0465d9deaa0n,
      0xa87571083dfc2a47n,
      0xe18263681e9958f8n,
      0xe28e96f1ae5e60d3n,
    ];
    expect(out).toEqual(expected);
  });

  it('rejects wrong width', () => {
    expect(() => poseidonPermute([0n, 1n])).toThrow(/expected width 12/);
  });

  it('hashNoPad of empty input is the zero digest (no absorb)', () => {
    expect(hashNoPad([])).toEqual(ZERO_DIGEST);
  });

  it('digestsEqual compares limbs', () => {
    expect(digestsEqual(ZERO_DIGEST, [0n, 0n, 0n, 0n])).toBe(true);
    expect(digestsEqual(ZERO_DIGEST, [1n, 0n, 0n, 0n])).toBe(false);
    // runtime-invalid shape: 5 limbs with matching prefix — static Digest forbids it
    const tooLong = [1n, 2n, 3n, 4n, 5n] as unknown as Digest;
    expect(digestsEqual([1n, 2n, 3n, 4n], tooLong)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// E(·) encoding
// ---------------------------------------------------------------------------

describe('encodeByteString (§1.7.2 big-endian, length-prefixed)', () => {
  it('empty string → single length element 0', () => {
    // Hand check: L=0, no chunks.
    const e = encodeByteString(new Uint8Array(0));
    expect(e).toEqual([0n]);
  });

  it('exactly 7 bytes "ABCDEFG" → length 7 + one BE chunk', () => {
    // E(b"ABCDEFG"): length 7 + one 7-byte BE chunk "ABCDEFG"
    // u64 = 0x0041424344454647  (implicit leading 0)
    const e = encodeByteString(new TextEncoder().encode('ABCDEFG'));
    expect(e).toHaveLength(2);
    expect(e[0]).toBe(7n);
    const expectedChunk = 0x0041424344454647n;
    expect(e[1]).toBe(expectedChunk);
  });

  it('partial final chunk is right-padded with zeros (L % 7 != 0)', () => {
    // "AB" → length 2, chunk = AB + 5 zero pads → 0x0041420000000000
    const e = encodeByteString(new TextEncoder().encode('AB'));
    expect(e).toHaveLength(2);
    expect(e[0]).toBe(2n);
    expect(e[1]).toBe(0x0041420000000000n);
  });

  it('big-endian block direction: LE packing would produce a different limb', () => {
    // Construct so BE and LE disagree. Bytes [0x01, 0x02]:
    //   BE (spec): 0x00_01_02_00_00_00_00_00
    //   LE (wrong, old model style): pad then LE → 0x00_00_00_00_00_02_01 (or similar)
    const bytes = new Uint8Array([0x01, 0x02]);
    const e = encodeByteString(bytes);
    const beLimb = 0x0001020000000000n;
    // Little-endian 7-byte read of the same padded block [01,02,0,0,0,0,0]:
    // LE u64 of [01,02,00,00,00,00,00] with leading zero byte would be
    // interpreting seven as low bytes LE: 0x00000000000201
    const leLimb = 0x00000000000201n;
    expect(e[1]).toBe(beLimb);
    expect(e[1]).not.toBe(leLimb);
    // If encodeByteString were little-endian, this assertion would fail.
  });

  it('32 bytes → 1 + 5 elements; 16 → 4; 8 → 3', () => {
    expect(encodeByteString(new Uint8Array(32))).toHaveLength(1 + 5);
    expect(encodeByteString(new Uint8Array(16))).toHaveLength(4);
    expect(encodeByteString(new Uint8Array(8))).toHaveLength(3);
  });

  it('rejects L >= 2^56 with kind ByteStringTooLong', () => {
    // Real TypedArrays cannot be 2^56 long; length is checked before content.
    const huge = { length: Number(MAX_BYTE_STRING_LEN) } as unknown as Uint8Array;
    try {
      encodeByteString(huge);
      expect.unreachable('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(EncodingError);
      const e = err as EncodingError;
      expect(e.kind).toBe('ByteStringTooLong');
      expect(e.details.len).toBe(Number(MAX_BYTE_STRING_LEN));
    }
  });
});

describe('encodeSmallNumeric', () => {
  it('accepts v = 2^56 - 1 and rejects v = 2^56', () => {
    expect(encodeSmallNumeric(MAX_SMALL_NUMERIC - 1n)).toBe(MAX_SMALL_NUMERIC - 1n);
    try {
      encodeSmallNumeric(MAX_SMALL_NUMERIC);
      expect.unreachable('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(EncodingError);
      const e = err as EncodingError;
      expect(e.kind).toBe('SmallNumericOutOfRange');
      expect(e.details.value).toBe(MAX_SMALL_NUMERIC);
    }
  });

  it('rejects negative values with SmallNumericOutOfRange', () => {
    try {
      encodeSmallNumeric(-1n);
      expect.unreachable('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(EncodingError);
      expect((err as EncodingError).kind).toBe('SmallNumericOutOfRange');
    }
  });
});

describe('encodeDigest', () => {
  it('returns the four limbs without a length prefix', () => {
    const d = [1n, 2n, 3n, 4n] as const;
    expect(encodeDigest(d)).toEqual(d);
  });

  it('rejects digests with wrong limb count', () => {
    // runtime-invalid shape: 5 limbs — static Digest forbids it
    const tooLong = [1n, 2n, 3n, 4n, 5n] as unknown as Digest;
    // runtime-invalid shape: 3 limbs — static Digest forbids it
    const tooShort = [1n, 2n, 3n] as unknown as Digest;
    // runtime-invalid shape: object with numeric keys, not a tuple — static Digest forbids it
    const notArray = { 0: 1n, 1: 2n, 2: 3n, 3: 4n } as unknown as Digest;
    for (const forged of [tooLong, tooShort, notArray]) {
      try {
        encodeDigest(forged);
        expect.unreachable('should have thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(EncodingError);
        expect((err as EncodingError).kind).toBe('InvalidDigestLength');
      }
    }
  });

  it('rejects a digest limb that is not a bigint', () => {
    // runtime-invalid shape: limb 3 is a string, not bigint — static Digest forbids it
    const forged = [0n, 0n, 0n, 'x'] as unknown as Digest;
    try {
      encodeDigest(forged);
      expect.unreachable('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(EncodingError);
      const e = err as EncodingError;
      expect(e.kind).toBe('NonCanonicalDigestLimb');
      expect(e.details.limbIndex).toBe(3);
      expect(e.details.value).toBe('x');
    }
  });
});

// ---------------------------------------------------------------------------
// digestToBytes / digestFromBytes
// ---------------------------------------------------------------------------

describe('digestToBytes / digestFromBytes', () => {
  it('round-trips a non-zero digest', () => {
    const d = hc(TAG_NK_COMMIT, [HcInput.byteString(new Uint8Array(32).fill(1))]);
    const bytes = digestToBytes(d);
    expect(bytes).toHaveLength(32);
    const back = digestFromBytes(bytes);
    expect(digestsEqual(back, d)).toBe(true);
  });

  it('zero digest encodes to 32 zero bytes', () => {
    expect(digestToBytes(ZERO_DIGEST)).toEqual(new Uint8Array(32));
    expect(digestFromBytes(new Uint8Array(32))).toEqual(ZERO_DIGEST);
  });

  it('digestFromBytes rejects limb >= p (NonCanonicalDigestLimb)', () => {
    const bytes = new Uint8Array(32);
    // limb 0 = ORDER as big-endian u64; remaining limbs zero.
    let p = GOLDILOCKS_P;
    for (let i = 7; i >= 0; i--) {
      bytes[i] = Number(p & 0xffn);
      p >>= 8n;
    }
    try {
      digestFromBytes(bytes);
      expect.unreachable('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(EncodingError);
      const e = err as EncodingError;
      expect(e.kind).toBe('NonCanonicalDigestLimb');
      expect(e.details.limbIndex).toBe(0);
      expect(e.details.value).toBe(GOLDILOCKS_P);
    }
  });

  it('digestFromBytes rejects wrong length', () => {
    try {
      digestFromBytes(new Uint8Array(31));
      expect.unreachable('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(EncodingError);
      expect((err as EncodingError).kind).toBe('InvalidDigestLength');
    }
  });

  it('digestToBytes rejects digests with wrong limb count', () => {
    // runtime-invalid shape: 3 limbs — static Digest forbids it
    const tooShort = [1n, 2n, 3n] as unknown as Digest;
    // runtime-invalid shape: 5 limbs — static Digest forbids it
    const tooLong = [1n, 2n, 3n, 4n, 5n] as unknown as Digest;
    for (const forged of [tooShort, tooLong]) {
      try {
        digestToBytes(forged);
        expect.unreachable('should have thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(EncodingError);
        expect((err as EncodingError).kind).toBe('InvalidDigestLength');
      }
    }
  });

  it('digestToHex / digestFromHex with optional 0x prefix', () => {
    const d = nflogEmpty();
    const hex = digestToHex(d);
    expect(hex).toBe(PIN_NFLOG_EMPTY);
    expect(digestsEqual(digestFromHex(hex), d)).toBe(true);
    expect(digestsEqual(digestFromHex('0x' + hex), d)).toBe(true);
    expect(digestsEqual(digestFromHex('0X' + hex), d)).toBe(true);
  });

  it('digestFromHex rejects bad length and non-hex', () => {
    try {
      digestFromHex('ab');
      expect.unreachable('should have thrown');
    } catch (err) {
      expect((err as EncodingError).kind).toBe('InvalidDigestLength');
    }
    try {
      digestFromHex('zz'.repeat(32));
      expect.unreachable('should have thrown');
    } catch (err) {
      expect((err as EncodingError).kind).toBe('InvalidDigestLength');
    }
  });

  it('digestFromHex rejects partial-nibble garbage that parseInt would accept', () => {
    // parseInt('0g', 16) === 0 — without a strict alphabet check this would
    // silently decode as a different (wrong) digest instead of throwing.
    const good = digestToHex(nflogEmpty());
    const with0g = '0g' + good.slice(2);
    const withG0 = 'g0' + good.slice(2);
    expect(with0g.length).toBe(64);
    expect(withG0.length).toBe(64);
    try {
      digestFromHex(with0g);
      expect.unreachable('0g must throw');
    } catch (err) {
      expect(err).toBeInstanceOf(EncodingError);
      expect((err as EncodingError).kind).toBe('InvalidDigestLength');
    }
    try {
      digestFromHex(withG0);
      expect.unreachable('g0 must throw');
    } catch (err) {
      expect(err).toBeInstanceOf(EncodingError);
      expect((err as EncodingError).kind).toBe('InvalidDigestLength');
    }
    // Trailing bad nibble pair also rejected (not only leading).
    try {
      digestFromHex(good.slice(0, 62) + '0g');
      expect.unreachable('trailing 0g must throw');
    } catch (err) {
      expect((err as EncodingError).kind).toBe('InvalidDigestLength');
    }
  });
});

// ---------------------------------------------------------------------------
// Hc composition + sensitivity
// ---------------------------------------------------------------------------

describe('hc', () => {
  it('is deterministic', () => {
    const a = hc(TAG_NK_COMMIT, [HcInput.byteString(new Uint8Array(32).fill(1))]);
    const b = hc(TAG_NK_COMMIT, [HcInput.byteString(new Uint8Array(32).fill(1))]);
    expect(digestsEqual(a, b)).toBe(true);
  });

  it('throws on unknown HcInput.type (fail-closed; never silently skip)', () => {
    // runtime-invalid shape: unknown HcInput.type 'NotARealKind' — static HcInput forbids it
    const forged = { type: 'NotARealKind', bytes: new Uint8Array(0) } as unknown as ReturnType<
      typeof HcInput.byteString
    >;
    try {
      hc(TAG_NK_COMMIT, [forged]);
      expect.unreachable('unknown type must throw');
    } catch (err) {
      expect(err).toBeInstanceOf(EncodingError);
      expect((err as EncodingError).kind).toBe('UnknownHcInputType');
    }
  });

  it('throws on non-canonical digest limbs (≥ p) instead of reducing', () => {
    // Two distinct malformed digests that reduce to the same residue class
    // under silent % p would otherwise collide inside hc.
    const nonCanon: Digest = [GOLDILOCKS_P, 0n, 0n, 0n];
    const nonCanonPlus: Digest = [GOLDILOCKS_P + 1n, 0n, 0n, 0n];
    try {
      hc(TAG_NK_COMMIT, [HcInput.digest(nonCanon)]);
      expect.unreachable('limb = p must throw');
    } catch (err) {
      expect(err).toBeInstanceOf(EncodingError);
      expect((err as EncodingError).kind).toBe('NonCanonicalDigestLimb');
    }
    try {
      hc(TAG_NK_COMMIT, [HcInput.digest(nonCanonPlus)]);
      expect.unreachable('limb = p+1 must throw');
    } catch (err) {
      expect((err as EncodingError).kind).toBe('NonCanonicalDigestLimb');
    }
    try {
      encodeDigest(nonCanon);
      expect.unreachable('encodeDigest must reject non-canonical limbs');
    } catch (err) {
      expect((err as EncodingError).kind).toBe('NonCanonicalDigestLimb');
    }
  });

  it('is sensitive to tag, byte, digest, numeric, and argument order', () => {
    const bytes = new Uint8Array(32).fill(7);
    const d = ZERO_DIGEST;
    const n = 3n;
    const base = hc(TAG_NK_COMMIT, [
      HcInput.byteString(bytes),
      HcInput.digest(d),
      HcInput.smallNumeric(n),
    ]);

    // tag change
    expect(
      digestsEqual(
        base,
        hc('zkCoins/v1/NkCommiu', [
          HcInput.byteString(bytes),
          HcInput.digest(d),
          HcInput.smallNumeric(n),
        ]),
      ),
    ).toBe(false);

    // one byte
    const bytes2 = new Uint8Array(bytes);
    bytes2[0] = 6;
    expect(
      digestsEqual(
        base,
        hc(TAG_NK_COMMIT, [HcInput.byteString(bytes2), HcInput.digest(d), HcInput.smallNumeric(n)]),
      ),
    ).toBe(false);

    // digest limb
    expect(
      digestsEqual(
        base,
        hc(TAG_NK_COMMIT, [
          HcInput.byteString(bytes),
          HcInput.digest([1n, 0n, 0n, 0n]),
          HcInput.smallNumeric(n),
        ]),
      ),
    ).toBe(false);

    // small-numeric
    expect(
      digestsEqual(
        base,
        hc(TAG_NK_COMMIT, [
          HcInput.byteString(bytes),
          HcInput.digest(d),
          HcInput.smallNumeric(n + 1n),
        ]),
      ),
    ).toBe(false);

    // argument order
    expect(
      digestsEqual(
        base,
        hc(TAG_NK_COMMIT, [HcInput.digest(d), HcInput.byteString(bytes), HcInput.smallNumeric(n)]),
      ),
    ).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Pinned V.4 vectors (independent of this implementation)
// ---------------------------------------------------------------------------

describe('V.4 pinned Poseidon digests', () => {
  it('nflog_empty = Hc(NfLog/Empty, SmallNumeric(0))', () => {
    expect(digestToHex(nflogEmpty())).toBe(PIN_NFLOG_EMPTY);
    // Same via raw hc
    expect(digestToHex(hc(TAG_NFLOG_EMPTY, [HcInput.smallNumeric(0n)]))).toBe(PIN_NFLOG_EMPTY);
  });

  it("coinhist_empty_root = E'_256 via leaf/node Hc ladder", () => {
    expect(digestToHex(coinhistEmptyRoot())).toBe(PIN_COINHIST_EMPTY_ROOT);
  });

  it('nk_commit_sample = Hc(NkCommit, ByteString(sha256("…/nk")))', () => {
    const nk = sha256Label('zkCoins/v1/test-vector/nk');
    expect(bytesToHex(nk)).toBe('2dc00b27c0d2991514b1b997af97b0e12c5da159b5726481124032c1578115b2');
    expect(digestToHex(nkCommit(nk))).toBe(PIN_NK_COMMIT_SAMPLE);
  });

  it('asset_id (v1 sample)', () => {
    const pk0 = sha256Label('zkCoins/v1/test-vector/Pk0');
    const nameHashUsd = sha256(new TextEncoder().encode('USD-Demo'));
    expect(bytesToHex(nameHashUsd)).toBe(
      'aff024cf2705e0450bfb51b461a1ed90c125efe0e43554191380b69a6a6be313',
    );
    const id = assetIdV1(GENESIS_TAG, pk0, nameHashUsd, 2, 1);
    expect(digestToHex(id)).toBe(PIN_ASSET_ID);
  });

  it('network_id mainnet / testnet / regtest', () => {
    expect(digestToHex(networkIdMainnet())).toBe(PIN_NETWORK_MAINNET);
    expect(digestToHex(networkIdTestnet())).toBe(PIN_NETWORK_TESTNET);
    expect(digestToHex(networkIdRegtest())).toBe(PIN_NETWORK_REGTEST);
    expect(digestToHex(networkId(NETWORK_TAG_MAINNET))).toBe(PIN_NETWORK_MAINNET);
  });

  it('detect_tag fixture (V.10 ss/epk)', () => {
    const ss = hexToBytes('842f5821fa577c0374ae48e4c5afa887e3e0900df7245370e5675d88466fa05f');
    const epk = hexToBytes('e15129c95c4e7528810d91bdc9312389a1c6466bee0237147540c426926af154');
    expect(digestToHex(detectTag(ss, epk))).toBe(PIN_DETECT_TAG);
  });

  it('asset_id_v2 + terms_hash_v1 + terms_hash_v2', () => {
    const pk0 = sha256Label('zkCoins/v1/test-vector/Pk0');
    const nameHashEur = sha256(new TextEncoder().encode('EUR-Demo'));
    const termsSalt = sha256Label('zkCoins/v1/test-vector/terms_salt');
    const idV2 = assetIdV2(GENESIS_TAG, pk0, nameHashEur, 2, 2, 500_000_000n, termsSalt);
    expect(digestToHex(idV2)).toBe(PIN_ASSET_ID_V2);

    const nameHashUsd = sha256(new TextEncoder().encode('USD-Demo'));
    const idV1 = assetIdV1(GENESIS_TAG, pk0, nameHashUsd, 2, 1);
    expect(digestToHex(termsHashV1(idV1, 1))).toBe(PIN_TERMS_HASH_V1);
    expect(digestToHex(termsHashV2(idV2, 2, 500_000_000n, termsSalt))).toBe(PIN_TERMS_HASH_V2);
  });

  it('nav_root_empty + nav_commitment_0', () => {
    const empty = nflogEmpty();
    const navRoot = nflogRoot(0n, empty);
    expect(digestToHex(navRoot)).toBe(PIN_NAV_ROOT_EMPTY);
    const navRand = sha256Label('zkCoins/v1/test-vector/nav_rand');
    expect(bytesToHex(navRand)).toBe(
      'e3b0e624bff8dbe486dd0761c14dcb84b4ccaf026fc60c58b69d653e6f656560',
    );
    expect(digestToHex(navCommitment(navRoot, navRand))).toBe(PIN_NAV_COMMITMENT_0);
  });
});

// ---------------------------------------------------------------------------
// Helper error paths (coverage)
// ---------------------------------------------------------------------------

describe('hash helper argument checks', () => {
  const b32 = new Uint8Array(32);
  const b31 = new Uint8Array(31);
  const d = ZERO_DIGEST;

  it('nkCommit / nullifier / detectTag / navCommitment length checks', () => {
    expect(() => nkCommit(b31)).toThrow(/32 bytes/);
    expect(() => nullifier(b31, d)).toThrow(/32 bytes/);
    expect(digestToHex(nullifier(b32, d)).length).toBe(64);
    expect(() => detectTag(b31, b32)).toThrow(/ss must be 32/);
    expect(() => detectTag(b32, b31)).toThrow(/epk must be 32/);
    expect(() => navCommitment(d, b31)).toThrow(/navRand must be 32/);
  });

  it('assetIdV1 / assetIdV2 argument checks', () => {
    expect(() => assetIdV1(GENESIS_TAG, b31, b32, 2, 1)).toThrow(/creatorPubkey/);
    expect(() => assetIdV1(GENESIS_TAG, b32, b31, 2, 1)).toThrow(/nameHash/);
    expect(() => assetIdV1(GENESIS_TAG, b32, b32, -1, 1)).toThrow(/decimals/);
    expect(() => assetIdV1(GENESIS_TAG, b32, b32, 2, 256)).toThrow(/issuanceVersion/);

    expect(() => assetIdV2(GENESIS_TAG, b31, b32, 2, 2, 1n, b32)).toThrow(/creatorPubkey/);
    expect(() => assetIdV2(GENESIS_TAG, b32, b31, 2, 2, 1n, b32)).toThrow(/nameHash/);
    expect(() => assetIdV2(GENESIS_TAG, b32, b32, 2, 2, 1n, b31)).toThrow(/termsSalt/);
    expect(() => assetIdV2(GENESIS_TAG, b32, b32, 1.5, 2, 1n, b32)).toThrow(/decimals/);
    expect(() => assetIdV2(GENESIS_TAG, b32, b32, 2, -1, 1n, b32)).toThrow(/issuanceVersion/);
    expect(() => assetIdV2(GENESIS_TAG, b32, b32, 2, 2, -1n, b32)).toThrow(/capTotal/);
    expect(() => assetIdV2(GENESIS_TAG, b32, b32, 2, 2, 1n << 128n, b32)).toThrow(/capTotal/);
  });

  it('termsHashV1 / termsHashV2 argument checks', () => {
    expect(() => termsHashV1(d, 256)).toThrow(/issuanceVersion/);
    expect(() => termsHashV2(d, 256, 1n, b32)).toThrow(/issuanceVersion/);
    expect(() => termsHashV2(d, 1, 1n, b31)).toThrow(/termsSalt/);
    expect(() => termsHashV2(d, 1, -1n, b32)).toThrow(/capTotal/);
    expect(() => termsHashV2(d, 1, 1n << 128n, b32)).toThrow(/capTotal/);
  });

  it('nflogRoot size checks and coinhist level checks', () => {
    expect(() => nflogRoot(-1n, d)).toThrow(/u64/);
    expect(() => nflogRoot(1n << 64n, d)).toThrow(/u64/);
    expect(digestToHex(coinhistLeafHash(1)).length).toBe(64);
    expect(digestToHex(coinhistLeafHash(2)).length).toBe(64);
    expect(() => coinhistLeafHash(3 as 0)).toThrow(RangeError);
    expect(() => coinhistLeafHash(1.5 as 0)).toThrow(RangeError);
    expect(() => coinhistLeafHash(-1 as 0)).toThrow(RangeError);
    expect(() => coinhistNodeHash(257, d, d)).toThrow(/0\.\.=256/);
    expect(() => coinhistNodeHash(-1, d, d)).toThrow(/0\.\.=256/);
    expect(digestToHex(coinhistNodeHash(0, d, d)).length).toBe(64);
  });
});
