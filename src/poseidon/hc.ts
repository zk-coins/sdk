/**
 * Field encoding E(·) and the Hc primitive (spec §§1.7.1–1.7.3).
 *
 * Hc(tag, x1, …, xn) := PoseidonHash::hash_no_pad(E(tag) ‖ E(x1) ‖ … ‖ E(xn)).
 *
 * Port of `zk-coins/node/shared/src/spec_v1/encoding.rs`.
 *
 * **Critical differences from the old model** (see that module's docs):
 * - Byte strings use a length element + **big-endian** 7-byte chunks.
 * - `digestToBytes` reduces each limb with `to_canonical_u64` before BE encode.
 * - `digestFromBytes` rejects limbs `>= p` (never silent reduce).
 */

import {
  beBytesToU64,
  fromCanonicalU64,
  GOLDILOCKS_P,
  toCanonicalU64,
  u64ToBeBytes,
} from './goldilocks.js';
import { hashNoPad, type Digest, ZERO_DIGEST } from './poseidon.js';

/** Maximum byte-string length: L < 2^56. */
export const MAX_BYTE_STRING_LEN = 1n << 56n;

/** Maximum small-numeric value: v < 2^56. */
export const MAX_SMALL_NUMERIC = 1n << 56n;

/** Error kinds for encoding / digest parse failures. */
export type EncodingErrorKind =
  | 'ByteStringTooLong'
  | 'SmallNumericOutOfRange'
  | 'NonCanonicalDigestLimb'
  | 'InvalidDigestLength';

export class EncodingError extends Error {
  public readonly kind: EncodingErrorKind;
  public readonly details: Readonly<Record<string, string | number | bigint>>;

  constructor(
    kind: EncodingErrorKind,
    message: string,
    details: Record<string, string | number | bigint>,
  ) {
    super(message);
    this.name = 'EncodingError';
    this.kind = kind;
    this.details = details;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** Typed Hc input, classified per §1.7.3. */
export type HcInput =
  | { readonly type: 'ByteString'; readonly bytes: Uint8Array }
  | { readonly type: 'Digest'; readonly digest: Digest }
  | { readonly type: 'SmallNumeric'; readonly value: bigint };

export const HcInput = {
  byteString(bytes: Uint8Array): HcInput {
    return { type: 'ByteString', bytes };
  },
  digest(digest: Digest): HcInput {
    return { type: 'Digest', digest };
  },
  smallNumeric(value: bigint): HcInput {
    return { type: 'SmallNumeric', value };
  },
} as const;

/**
 * Encode a byte-string per §1.7.2:
 * one length element L, then ceil(L/7) big-endian 7-byte chunks
 * (final chunk right-padded with zero bytes).
 *
 * Corresponds to `encode_byte_string` in encoding.rs.
 */
export function encodeByteString(bytes: Uint8Array): bigint[] {
  const len = BigInt(bytes.length);
  if (len >= MAX_BYTE_STRING_LEN) {
    throw new EncodingError(
      'ByteStringTooLong',
      `encodeByteString: length ${bytes.length} >= 2^56`,
      { len: bytes.length },
    );
  }
  const nChunks = bytes.length === 0 ? 0 : Math.ceil(bytes.length / 7);
  const out = new Array<bigint>(1 + nChunks);
  out[0] = fromCanonicalU64(len);
  for (let c = 0; c < nChunks; c++) {
    const start = c * 7;
    // Right-pad the final chunk to 7 bytes with zeros, then interpret
    // as the low 7 bytes of an 8-byte big-endian u64 (implicit leading 0).
    let limb = 0n;
    for (let j = 0; j < 7; j++) {
      const idx = start + j;
      const b = idx < bytes.length ? BigInt(bytes[idx]!) : 0n;
      limb = (limb << 8n) | b;
    }
    // limb is a 56-bit value = the BE u64 with leading zero byte.
    out[1 + c] = fromCanonicalU64(limb);
  }
  return out;
}

/**
 * Encode a digest: the four limbs, no length prefix.
 * Corresponds to `encode_digest`.
 */
export function encodeDigest(d: Digest): readonly [bigint, bigint, bigint, bigint] {
  return d;
}

/**
 * Encode a small-numeric input as one field element. Fails if v ≥ 2^56.
 * Corresponds to `encode_small_numeric`.
 */
export function encodeSmallNumeric(v: bigint): bigint {
  if (v < 0n) {
    throw new EncodingError(
      'SmallNumericOutOfRange',
      `encodeSmallNumeric: negative value ${v.toString()}`,
      { value: v },
    );
  }
  if (v >= MAX_SMALL_NUMERIC) {
    throw new EncodingError(
      'SmallNumericOutOfRange',
      `encodeSmallNumeric: value ${v.toString()} >= 2^56`,
      { value: v },
    );
  }
  return fromCanonicalU64(v);
}

/**
 * Canonical Poseidon-digest → 32-byte encoding per §1.7.1:
 * each of the 4 limbs reduced, then 8 bytes big-endian, in order.
 * Corresponds to `digest_to_bytes`.
 */
export function digestToBytes(d: Digest): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) {
    const limb = toCanonicalU64(d[i]!);
    out.set(u64ToBeBytes(limb), i * 8);
  }
  return out;
}

/**
 * Canonical 32-byte → Poseidon digest per §1.7.1 (fail-loud).
 * Each 8-byte BE limb MUST be strictly < p; never silently reduced.
 * Corresponds to `digest_from_bytes`.
 */
export function digestFromBytes(bytes: Uint8Array): Digest {
  if (bytes.length !== 32) {
    throw new EncodingError(
      'InvalidDigestLength',
      `digestFromBytes: expected 32 bytes, got ${bytes.length}`,
      { length: bytes.length },
    );
  }
  const elements: [bigint, bigint, bigint, bigint] = [0n, 0n, 0n, 0n];
  for (let i = 0; i < 4; i++) {
    const limb = beBytesToU64(bytes.subarray(i * 8, (i + 1) * 8));
    if (limb >= GOLDILOCKS_P) {
      throw new EncodingError(
        'NonCanonicalDigestLimb',
        `digestFromBytes: limb ${i} value ${limb.toString()} >= p`,
        { limbIndex: i, value: limb },
      );
    }
    elements[i] = fromCanonicalU64(limb);
  }
  return elements;
}

/**
 * Hex (lowercase, no 0x) of `digestToBytes(d)`.
 */
export function digestToHex(d: Digest): string {
  const bytes = digestToBytes(d);
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i]!.toString(16).padStart(2, '0');
  }
  return hex;
}

/**
 * Parse a 64-char hex digest (optional 0x prefix) via `digestFromBytes`.
 */
export function digestFromHex(hex: string): Digest {
  const h = hex.startsWith('0x') || hex.startsWith('0X') ? hex.slice(2) : hex;
  if (h.length !== 64) {
    throw new EncodingError(
      'InvalidDigestLength',
      `digestFromHex: expected 64 hex chars, got ${h.length}`,
      { length: h.length },
    );
  }
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    const byte = Number.parseInt(h.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) {
      throw new EncodingError('InvalidDigestLength', `digestFromHex: invalid hex at byte ${i}`, {
        length: h.length,
      });
    }
    bytes[i] = byte;
  }
  return digestFromBytes(bytes);
}

/**
 * Hc(tag, inputs…): single hash_no_pad over the concatenated encodings.
 * `tag` is absorbed as a byte-string (UTF-8 of the full "zkCoins/v1/<Context>").
 * Corresponds to `hc` in encoding.rs.
 */
export function hc(tag: string, inputs: readonly HcInput[]): Digest {
  const elements: bigint[] = encodeByteString(new TextEncoder().encode(tag));
  for (const input of inputs) {
    switch (input.type) {
      case 'ByteString':
        elements.push(...encodeByteString(input.bytes));
        break;
      case 'Digest':
        elements.push(input.digest[0], input.digest[1], input.digest[2], input.digest[3]);
        break;
      case 'SmallNumeric':
        elements.push(encodeSmallNumeric(input.value));
        break;
    }
  }
  return hashNoPad(elements);
}

export { ZERO_DIGEST };
export type { Digest };
