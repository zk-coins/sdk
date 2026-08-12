/**
 * §1.7.10 NISSHAC half-aggregation.
 *
 * - `AggregateSig` / `AggregateVerify` / `CommRetrieve`
 * - Coefficients `aⱼ` are reduced mod n; the S2C tweak `t` is **not**
 *   (handled in `commVerify`).
 * - Aggregation index `j` starts at **1** (V.8 pins `a₁`, `a₂`).
 * - Ordinary BIP-340 batch verification is **not** a substitute: this module
 *   implements the coefficient-bound multi-scalar relation.
 */

import { schnorr } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';

import { mStateBytes, type Network } from './mstate.js';
import {
  liftXOnly,
  requireCanonicalScalar,
  TransitionSignatureError,
} from './transitionSignature.js';

const Point = schnorr.Point;
const { Fn } = Point;
const taggedHash = schnorr.utils.taggedHash;

const FIELD_LEN = 32;
const HALF_AGG_DOMAIN = new TextEncoder().encode('zkCoins/v1/HalfAgg');

/** One ordinary BIP-340 signature member of a half-aggregate. */
export interface HalfAggMember {
  /** x-only public key `Pkⱼ`, 32 bytes. */
  pk: Uint8Array;
  /** Committed nonce `Rⱼ`, 32 bytes. */
  r: Uint8Array;
  /** Signature scalar `sⱼ`, 32 bytes. */
  s: Uint8Array;
}

/** Result of {@link aggregateSig}. */
export interface AggregateSigResult {
  /** `z = H("zkCoins/v1/HalfAgg" ‖ R₁ ‖ Pk₁ ‖ … ‖ R_k ‖ Pk_k)`. */
  z: Uint8Array;
  /** Coefficients `aⱼ` as 32-byte big-endian, index 0 = a₁ (j starts at 1). */
  coefficients: Uint8Array[];
  /** `s_agg = Σⱼ aⱼ·sⱼ mod n`, 32 bytes. */
  sAgg: Uint8Array;
}

function requireBytes(value: Uint8Array, len: number, label: string): Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new TransitionSignatureError(`${label}: expected Uint8Array`);
  }
  if (value.length !== len) {
    throw new TransitionSignatureError(`${label}: expected ${len} bytes, got ${value.length}`);
  }
  return value;
}

function bytesToBigint(bytes: Uint8Array): bigint {
  let n = 0n;
  for (const b of bytes) {
    n = (n << 8n) | BigInt(b);
  }
  return n;
}

function bigintToBytes32(n: bigint): Uint8Array {
  return Fn.toBytes(Fn.create(n));
}

/** Encode `n` as 4-byte big-endian. Caller guarantees `n` fits in u32. */
function u32Be(n: number): Uint8Array {
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

function isEvenY(point: InstanceType<typeof Point>): boolean {
  return point.y % 2n === 0n;
}

/**
 * Validate a member's encodings (canonical x-only points, scalar in [0, n)).
 * Throws on malformation — used by AggregateSig so bad input fails loud.
 */
function validateMember(member: HalfAggMember, index: number): void {
  const label = `member[${index}]`;
  requireBytes(member.pk, FIELD_LEN, `${label}.pk`);
  requireBytes(member.r, FIELD_LEN, `${label}.r`);
  requireBytes(member.s, FIELD_LEN, `${label}.s`);
  // Point on curve, even-y lift.
  liftXOnly(member.pk, `${label}.pk`);
  liftXOnly(member.r, `${label}.r`);
  requireCanonicalScalar(member.s, `${label}.s`);
}

/**
 * Derive `z` and the per-index coefficients `aⱼ = int(H(z ‖ u32-be(j))) mod n`
 * with **j starting at 1**.
 *
 * Transcript order matches §1.7.10 / V.8 and the Rust reference:
 * `H("zkCoins/v1/HalfAgg" ‖ bytes(R₁) ‖ Pk₁ ‖ … ‖ bytes(R_k) ‖ Pk_k)`.
 */
export function aggregationCoefficients(
  members: ReadonlyArray<{ pk: Uint8Array; r: Uint8Array }>,
): { z: Uint8Array; coefficients: bigint[] } {
  if (members.length === 0) {
    throw new TransitionSignatureError('aggregationCoefficients: empty member list');
  }
  if (members.length > 0xffff_ffff) {
    throw new TransitionSignatureError('aggregationCoefficients: member count exceeds u32');
  }

  let transcriptLen = HALF_AGG_DOMAIN.length;
  for (const m of members) {
    requireBytes(m.pk, FIELD_LEN, 'member.pk');
    requireBytes(m.r, FIELD_LEN, 'member.r');
    transcriptLen += 64;
  }
  const transcript = new Uint8Array(transcriptLen);
  transcript.set(HALF_AGG_DOMAIN, 0);
  let offset = HALF_AGG_DOMAIN.length;
  for (const m of members) {
    // R then Pk — §1.7.10 / V.8 / half_agg.rs
    transcript.set(m.r, offset);
    offset += 32;
    transcript.set(m.pk, offset);
    offset += 32;
  }
  const z = sha256(transcript);

  const coefficients: bigint[] = [];
  for (let j = 1; j <= members.length; j++) {
    const preimage = new Uint8Array(36);
    preimage.set(z, 0);
    preimage.set(u32Be(j), 32);
    // Explicitly reduced: aⱼ = int(H(z ‖ u32-be(j))) mod n
    coefficients.push(Fn.create(bytesToBigint(sha256(preimage))));
  }
  return { z, coefficients };
}

/**
 * `AggregateSig` (§1.7.10): half-aggregate the signature scalars.
 * No secret keys; publisher-side. Returns `z`, each `aⱼ`, and `s_agg`.
 */
export function aggregateSig(members: ReadonlyArray<HalfAggMember>): AggregateSigResult {
  if (members.length === 0) {
    throw new TransitionSignatureError('aggregateSig: cannot half-aggregate zero signatures');
  }
  for (let i = 0; i < members.length; i++) {
    const m = members[i];
    if (m === undefined) {
      throw new TransitionSignatureError(`aggregateSig: missing member at index ${i}`);
    }
    validateMember(m, i);
  }

  const { z, coefficients } = aggregationCoefficients(members);
  // coefficients is built 1:1 with members (same length); the sparse-member
  // gate above already refused holes. Index both by the same loop variable.
  let sAgg = 0n;
  for (let i = 0; i < members.length; i++) {
    const m = members[i]!;
    const a = coefficients[i]!;
    const s = bytesToBigint(m.s);
    sAgg = Fn.create(sAgg + a * s);
  }

  return {
    z: z.slice(),
    coefficients: coefficients.map((a) => bigintToBytes32(a)),
    sAgg: bigintToBytes32(sAgg),
  };
}

/**
 * `AggregateVerify` (§1.7.10): the single multi-scalar relation
 * `s_agg·G == Σⱼ aⱼ·(Rⱼ + eⱼ·Pkⱼ)`.
 *
 * **Not** a loop over ordinary BIP-340 `Verify`. Rejects non-canonical
 * encodings by returning `false`.
 */
export function aggregateVerify(input: {
  members: ReadonlyArray<Pick<HalfAggMember, 'pk' | 'r'>>;
  sAgg: Uint8Array;
  network: Network;
}): boolean {
  try {
    const { members, network } = input;
    if (members.length === 0) {
      return false;
    }
    const sAggBytes = requireBytes(input.sAgg, FIELD_LEN, 'sAgg');
    const sAgg = bytesToBigint(sAggBytes);
    if (sAgg >= Fn.ORDER) {
      return false;
    }

    for (let i = 0; i < members.length; i++) {
      const m = members[i];
      if (m === undefined) {
        return false;
      }
      requireBytes(m.pk, FIELD_LEN, `member[${i}].pk`);
      requireBytes(m.r, FIELD_LEN, `member[${i}].r`);
      // Fail closed on off-curve / non-canonical.
      liftXOnly(m.pk, `member[${i}].pk`);
      liftXOnly(m.r, `member[${i}].r`);
    }

    const mState = mStateBytes(network);
    const { coefficients } = aggregationCoefficients(members);

    // rhs = Σⱼ aⱼ·(Rⱼ + eⱼ·Pkⱼ). members.length ≥ 1 (empty rejected above);
    // coefficients is 1:1 with members after the sparse-member gate.
    let rhs: InstanceType<typeof Point> = Point.ZERO;
    let rhsInit = false;
    for (let i = 0; i < members.length; i++) {
      const m = members[i]!;
      const a = coefficients[i]!;
      const R = liftXOnly(m.r, `member[${i}].r`);
      const P = liftXOnly(m.pk, `member[${i}].pk`);
      const e = Fn.create(bytesToBigint(taggedHash('BIP0340/challenge', m.r, m.pk, mState)));
      // sig_rhs = R + e·P  (public scalars → multiplyUnsafe; e/a may be 0)
      /* v8 ignore next -- a SHA-256-derived challenge equals zero with probability ~2^-256 and has no production injection seam */
      const sigRhs = e === 0n ? R : R.add(P.multiplyUnsafe(e));
      /* v8 ignore next -- a tagged-hash-derived aggregation coefficient equals zero with probability ~2^-256 and has no production injection seam */
      const term = a === 0n ? Point.ZERO : sigRhs.multiplyUnsafe(a);
      rhs = rhsInit ? rhs.add(term) : term;
      rhsInit = true;
    }

    // lhs = s_agg·G
    if (sAgg === 0n) {
      return rhs.is0();
    }
    const lhs = Point.BASE.multiplyUnsafe(sAgg);
    return lhs.equals(rhs);
  } catch {
    return false;
  }
}

/**
 * `CommRetrieve(σ_agg, j)` — return the retained commitment `R` at
 * **zero-based** member index `j` (array index; matches the Rust helper).
 * Throws on out-of-range.
 */
export function commRetrieve(rs: ReadonlyArray<Uint8Array>, j: number): Uint8Array {
  if (!Number.isInteger(j) || j < 0) {
    throw new TransitionSignatureError(
      `commRetrieve: index must be a non-negative integer, got ${j}`,
    );
  }
  const r = rs[j];
  if (r === undefined) {
    throw new TransitionSignatureError(
      `commRetrieve: index ${j} out of range (length ${rs.length})`,
    );
  }
  return requireBytes(r, FIELD_LEN, `rs[${j}]`).slice();
}

/** Re-export even-y helper for tests that inspect aggregate terms. */
export function pointHasEvenY(xOnly: Uint8Array): boolean {
  const p = liftXOnly(xOnly, 'point');
  return isEvenY(p);
}
