/**
 * Goldilocks prime field F_p with p = 2^64 − 2^32 + 1.
 *
 * Representation: canonical `bigint` in `[0, p)`. JS `number` only carries
 * 53 bits of integer precision, so every 64-bit limb and every intermediate
 * product goes through `bigint`. Matches
 * `plonky2_field::goldilocks_field::GoldilocksField` (ORDER = 0xFFFFFFFF00000001).
 */

/** Field modulus p = 2^64 − 2^32 + 1. */
export const GOLDILOCKS_P = 0xffffffff00000001n;

/** 2^32 − 1; appears in plonky2's reduction identities. */
export const GOLDILOCKS_EPSILON = 0xffffffffn;

/** Maximum u64. */
const U64_MAX = 0xffffffffffffffffn;

/**
 * Reduce an arbitrary integer into the canonical range `[0, p)`.
 * Corresponds to the mathematical value of a Goldilocks element.
 */
export function reduce(n: bigint): bigint {
  const r = n % GOLDILOCKS_P;
  return r < 0n ? r + GOLDILOCKS_P : r;
}

/**
 * Construct a field element from a canonical u64 (`n < p`).
 * Corresponds to `GoldilocksField::from_canonical_u64`.
 * Throws if `n >= p` (fail-loud; no silent reduction).
 */
export function fromCanonicalU64(n: bigint): bigint {
  if (n < 0n || n >= GOLDILOCKS_P) {
    throw new RangeError(
      `Goldilocks fromCanonicalU64: value out of range [0, p), got ${n.toString()}`,
    );
  }
  return n;
}

/**
 * Construct a field element from a raw u64, reducing mod p if needed.
 * Corresponds to `GoldilocksField::from_noncanonical_u64` followed by
 * canonicalisation when a canonical value is required.
 */
export function fromU64(n: bigint): bigint {
  if (n < 0n || n > U64_MAX) {
    throw new RangeError(`Goldilocks fromU64: not a u64, got ${n.toString()}`);
  }
  return reduce(n);
}

/**
 * Canonical u64 representative (`to_canonical_u64`).
 * Input is already stored canonically; this is the identity for our rep.
 */
export function toCanonicalU64(a: bigint): bigint {
  if (a < 0n || a >= GOLDILOCKS_P) {
    throw new RangeError(`Goldilocks toCanonicalU64: non-canonical internal value ${a.toString()}`);
  }
  return a;
}

/** Field addition. Corresponds to `GoldilocksField::add`. */
export function add(a: bigint, b: bigint): bigint {
  return reduce(a + b);
}

/** Field subtraction. Corresponds to `GoldilocksField::sub`. */
export function sub(a: bigint, b: bigint): bigint {
  return reduce(a - b);
}

/** Field multiplication. Corresponds to `GoldilocksField::mul`. */
export function mul(a: bigint, b: bigint): bigint {
  return reduce(a * b);
}

/**
 * x ↦ x^7 (Poseidon S-box monomial).
 * Corresponds to `Poseidon::sbox_monomial` (x² → x⁴ → x³=x·x² → x⁷=x³·x⁴).
 */
export function pow7(x: bigint): bigint {
  const x2 = mul(x, x);
  const x4 = mul(x2, x2);
  const x3 = mul(x, x2);
  return mul(x3, x4);
}

/** Emit 8 big-endian bytes of a canonical limb. */
export function u64ToBeBytes(n: bigint): Uint8Array {
  const c = toCanonicalU64(n);
  const out = new Uint8Array(8);
  let v = c;
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/** Parse 8 big-endian bytes as a u64 bigint (no field reduction). */
export function beBytesToU64(bytes: Uint8Array): bigint {
  if (bytes.length !== 8) {
    throw new RangeError(`beBytesToU64: expected 8 bytes, got ${bytes.length}`);
  }
  let v = 0n;
  for (let i = 0; i < 8; i++) {
    v = (v << 8n) | BigInt(bytes[i]!);
  }
  return v;
}
