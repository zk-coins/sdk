/**
 * §3.2 Transition signing: BIP-340 + sign-to-contract.
 *
 * Production nonce: BIP-340 nonce hygiene with fresh CSPRNG aux-rand on every
 * draw (including every step-3b redraw). Never reuses a nonce across two
 * commitments. This is the **only** nonce path shipped in the public package.
 *
 * The V.8 deterministic fixture-nonce signer lives under `test/fixtures/` —
 * not here — because its k' does not bind `m_SC` and must not be callable by
 * package consumers.
 *
 * Output wire shape (node `signature.rs` wallet contract):
 *   - `signature` = bytes(R) ‖ bytes(s)   (64 bytes)
 *   - `s2cNonce`  = x-only even-y R'      (32 bytes)  — the `s2c_nonce` field
 */

import { schnorr } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { randomBytes } from '@noble/hashes/utils.js';

import { mStateBytes, type Network } from './mstate.js';
import { hashProofData, type ProofData } from './proofData.js';

const Point = schnorr.Point;
const { Fn, Fp } = Point;
const taggedHash = schnorr.utils.taggedHash;
const liftX = schnorr.utils.lift_x;

const FIELD_LEN = 32;
const SIG_LEN = 64;
/** Bound on §3.2 step-3b redraws; honest draws terminate in ~2 expected attempts. */
const REDRAW_BUDGET = 10_000;

export class TransitionSignatureError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'TransitionSignatureError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** 64-byte BIP-340 signature + 32-byte S2C opening randomness. */
export interface TransitionSignature {
  /** `bytes(R) ‖ bytes(s)` — 64 bytes. */
  signature: Uint8Array;
  /** x-only even-y encoding of pre-tweak `R'` — 32 bytes (`s2c_nonce` on the wire). */
  s2cNonce: Uint8Array;
}

/**
 * Full intermediate transcript of a successful Sign. Used by V.8 bit-for-bit
 * tests and the cross-rust parity ops; production callers only need
 * {@link TransitionSignature}.
 */
export interface SignTrace extends TransitionSignature {
  /** BIP-340-normalised secret scalar `d` (even-y key), 32 bytes. */
  d: Uint8Array;
  /** x-only public key `Pkᵢ`, 32 bytes. */
  pk: Uint8Array;
  /** Pre-tweak nonce point `R'`, x-only, 32 bytes (same bytes as `s2cNonce`). */
  rPrime: Uint8Array;
  /** Unreduced S2C tweak `t = H(bytes(R') ‖ m_SC)`, 32 bytes, with `int(t) < n`. */
  t: Uint8Array;
  /** Committed nonce `R`, x-only, 32 bytes. */
  r: Uint8Array;
  /** BIP-340 challenge `e`, 32 bytes (reduced mod n). */
  e: Uint8Array;
  /** Signature scalar `s`, 32 bytes. */
  s: Uint8Array;
  /**
   * Nonce-draw counter that produced this signature.
   * - Production: number of aux-rand draws consumed (0-based index of success).
   * - Fixture: the V.8 `ctr` value (Signer 2 of V.8 pins `ctr = 2`).
   */
  nonceCounter: number;
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

function xOnlyBytes(point: InstanceType<typeof Point>): Uint8Array {
  // Compressed SEC1 is 0x02/0x03 ‖ x; BIP-340 x-only is the x coordinate alone.
  return point.toBytes(true).slice(1);
}

function isEvenY(point: InstanceType<typeof Point>): boolean {
  return point.y % 2n === 0n;
}

/**
 * §1.7.10 / §3.2: interpret a 32-byte S2C tweak **unreduced**.
 *
 * Returns `int(t)` when `int(t) < n`; returns `null` when `int(t) ≥ n`
 * (caller must redraw on Sign, or reject on CommVerify). Never reduces mod n.
 *
 * Shared by the Sign path and {@link commVerify} so the unreduced-tweak rule
 * lives in one place. Under honest H the `null` arm is ~2^-128; it is unit-
 * tested here with constructed `tBytes`. A test-only injection seam on the
 * nested Sign path was tried twice and removed — testing this pure gate is
 * the right place for the rule, not a seam that production could misuse.
 */
export function tweakScalarOrReject(tBytes: Uint8Array): bigint | null {
  requireBytes(tBytes, FIELD_LEN, 't');
  const tInt = bytesToBigint(tBytes);
  if (tInt >= Fn.ORDER) {
    return null;
  }
  return tInt;
}

/**
 * §3.2 step 3b: accept the committed nonce `R` only when it is finite and
 * even-y. `false` ⇒ discard the draw and redraw (never negate `R`).
 *
 * Odds under honest draws: odd-y ~½ (common redraw), R = ∞ ~2^-256. Both
 * decisions are unit-tested here with constructed points so `signWithNonceDraws`
 * needs no injection seam for coverage of the rare R = ∞ edge.
 */
export function isAcceptableCommittedR(point: InstanceType<typeof Point>): boolean {
  return !point.is0() && isEvenY(point);
}

/**
 * Run `attempt` for `ctr ∈ [0, budget)`. The first non-null result wins;
 * if every attempt returns `null`, throw {@link TransitionSignatureError}.
 *
 * Production Sign passes the module redraw budget and a single-draw attempt.
 * Budget and attempt are ordinary required arguments — no defaults, no
 * test-only override surface on the public Sign entry points.
 */
export function runWithRedrawBudget<T>(budget: number, attempt: (ctr: number) => T | null): T {
  for (let ctr = 0; ctr < budget; ctr++) {
    const result = attempt(ctr);
    if (result !== null) {
      return result;
    }
  }
  throw new TransitionSignatureError(
    `sign: exhausted redraw budget (${budget}) without a valid §3.2 signature`,
  );
}

/**
 * BIP-340 key normalisation: return even-y `(d, Pk_bytes)`.
 * Throws if the secret is 0 or ≥ n.
 */
export function bip340NormaliseSecret(secretKey: Uint8Array): {
  d: bigint;
  dBytes: Uint8Array;
  pkBytes: Uint8Array;
} {
  requireBytes(secretKey, FIELD_LEN, 'secretKey');
  const dIn = bytesToBigint(secretKey);
  if (dIn === 0n || dIn >= Fn.ORDER) {
    throw new TransitionSignatureError('secretKey is not a canonical secp256k1 scalar in [1, n)');
  }
  const P = Point.BASE.multiply(dIn);
  // Negating d flips y(d·G). Exactly one of {dIn, −dIn} has even y, so the
  // re-derived pkPoint is even-y by construction — no second check.
  const d = isEvenY(P) ? dIn : Fn.neg(dIn);
  const pkPoint = Point.BASE.multiply(d);
  return { d, dBytes: bigintToBytes32(d), pkBytes: xOnlyBytes(pkPoint) };
}

/**
 * Lift an x-only encoding to the even-y curve point, or throw if non-canonical
 * (wrong length, x ≥ p, or not on the curve).
 */
export function liftXOnly(bytes: Uint8Array, label: string): InstanceType<typeof Point> {
  requireBytes(bytes, FIELD_LEN, label);
  const x = bytesToBigint(bytes);
  if (!Fp.isValidNot0(x)) {
    throw new TransitionSignatureError(`${label}: x-coordinate is not a valid field element`);
  }
  try {
    return liftX(x);
  } catch (cause) {
    throw new TransitionSignatureError(`${label}: x-coordinate is not on secp256k1`, {
      cause,
    });
  }
}

/**
 * Parse a 32-byte big-endian scalar that **must already be in [0, n)**.
 * Unreduced values (used for the S2C tweak `t`) are rejected — never silently
 * reduced.
 */
export function requireCanonicalScalar(bytes: Uint8Array, label: string): bigint {
  requireBytes(bytes, FIELD_LEN, label);
  const n = bytesToBigint(bytes);
  if (n >= Fn.ORDER) {
    throw new TransitionSignatureError(`${label}: scalar is not canonical (int ≥ n)`);
  }
  return n;
}

/** BIP-340 challenge `e = int(H_BIP340(bytes(R) ‖ bytes(Pk) ‖ m)) mod n`. */
function bip340Challenge(r: Uint8Array, pk: Uint8Array, mState: Uint8Array): bigint {
  const digest = taggedHash('BIP0340/challenge', r, pk, mState);
  return Fn.create(bytesToBigint(digest));
}

/**
 * §3.2 steps 1–6 given a k'-draw callback and a redraw budget.
 *
 * `redrawBudget` is a required ordinary argument (no default). Production
 * passes the module redraw budget with a CSPRNG-backed draw.
 */
function signWithNonceDraws(
  d: bigint,
  pkBytes: Uint8Array,
  mSc: Uint8Array,
  mState: Uint8Array,
  drawKPrime: (ctr: number) => bigint,
  redrawBudget: number,
): SignTrace {
  requireBytes(mSc, FIELD_LEN, 'mSc');

  return runWithRedrawBudget(redrawBudget, (ctr) => {
    const kDrawn = drawKPrime(ctr);
    // k' = 0 → redraw (~2^-256). Nested under the success path so one shared
    // `return null` covers this arm and the common step-3b redraw (~½ of
    // honest draws). No test seam: forcing k'=0 would mean injecting into the
    // production nonce draw solely for coverage.
    /* v8 ignore next -- forcing k'=0 would mean injecting into the production nonce draw solely for coverage */
    if (kDrawn !== 0n) {
      let kPrime = kDrawn;

      // Step 1: R' = k'·G
      let rPrimePoint = Point.BASE.multiply(kPrime);
      // Step 1b: even-y normalise R'.
      if (!isEvenY(rPrimePoint)) {
        kPrime = Fn.neg(kPrime);
        rPrimePoint = rPrimePoint.negate();
      }
      const rPrimeBytes = xOnlyBytes(rPrimePoint);

      // Step 2: t = H(bytes(R') ‖ m_SC) — **unreduced**; int(t) ≥ n → redraw.
      const tweakPreimage = new Uint8Array(64);
      tweakPreimage.set(rPrimeBytes, 0);
      tweakPreimage.set(mSc, 32);
      const tBytes = sha256(tweakPreimage);
      const t = tweakScalarOrReject(tBytes);
      // int(t) ≥ n → discard (~2^-128). Rule covered by unit tests of
      // {@link tweakScalarOrReject}; a Sign-path seam is the worse answer.
      /* v8 ignore next -- the int(t) >= n rule is unit-tested directly; a Sign-path seam is the worse answer */
      if (t !== null) {
        // Step 3: R = R' + t·G. t = 0 keeps R = R' (~2^-256); both arms are
        // legal. The rare true-zero edge is not worth a production seam.
        /* v8 ignore next -- the rare true-zero tweak edge is not worth a production seam */
        const rPoint = t === 0n ? rPrimePoint : rPrimePoint.add(Point.BASE.multiply(t));
        // Step 3b: R = ∞ or y(R) odd → discard and redraw. Never negate R.
        // Rule covered by {@link isAcceptableCommittedR} (odd-y ~½, ∞ ~2^-256).
        if (isAcceptableCommittedR(rPoint)) {
          const rBytes = xOnlyBytes(rPoint);

          // Step 4: e = H_BIP340(bytes(R) ‖ bytes(Pk) ‖ m_state)
          const e = bip340Challenge(rBytes, pkBytes, mState);

          // Step 5: s = (k' + t + e·d) mod n
          const s = Fn.create(kPrime + t + e * d);
          // s = 0 is a valid field element but rejected as a signature scalar
          // (~2^-256). No injection seam — same rationale as k' = 0 above.
          /* v8 ignore next -- forcing s=0 needs an injection seam, the same rationale as k'=0 */
          if (s !== 0n) {
            const sBytes = bigintToBytes32(s);

            // Step 6: signature = bytes(R) ‖ bytes(s)
            const signature = new Uint8Array(SIG_LEN);
            signature.set(rBytes, 0);
            signature.set(sBytes, 32);

            return {
              signature,
              s2cNonce: rPrimeBytes.slice(),
              d: bigintToBytes32(d),
              pk: pkBytes.slice(),
              rPrime: rPrimeBytes.slice(),
              // Raw hash output (unreduced encoding); int(t) < n by the gate above.
              t: tBytes.slice(),
              r: rBytes.slice(),
              e: bigintToBytes32(e),
              s: sBytes.slice(),
              nonceCounter: ctr,
            };
          }
        }
      }
    }
    return null;
  });
}

/**
 * Production Sign (§3.2 steps 1–6).
 *
 * Nonce: BIP-340 hygiene with **fresh CSPRNG aux-rand** on every draw
 * (including every step-3b redraw). This is the only production path.
 *
 * `mSc` is `H(ProofData)` (32 bytes). Use {@link signTransitionOverProofData}
 * when you hold the six fields.
 */
export function signTransition(input: {
  secretKey: Uint8Array;
  network: Network;
  mSc: Uint8Array;
}): TransitionSignature {
  const trace = signTransitionTrace(input);
  return { signature: trace.signature, s2cNonce: trace.s2cNonce };
}

/** Like {@link signTransition} but returns the full intermediate transcript. */
export function signTransitionTrace(input: {
  secretKey: Uint8Array;
  network: Network;
  mSc: Uint8Array;
}): SignTrace {
  const { d, pkBytes } = bip340NormaliseSecret(input.secretKey);
  const mState = mStateBytes(input.network);
  const mSc = requireBytes(input.mSc, FIELD_LEN, 'mSc');

  // BIP-340 production nonce: masked = d XOR tagged_hash("BIP0340/aux", aux),
  // rand = tagged_hash("BIP0340/nonce", masked ‖ Pk ‖ m_state), with a **fresh**
  // aux from CSPRNG on every draw so redraws never reuse a nonce.
  return signWithNonceDraws(
    d,
    pkBytes,
    mSc,
    mState,
    () => {
      const aux = randomBytes(32);
      const masked = new Uint8Array(FIELD_LEN);
      const dBytes = bigintToBytes32(d);
      const auxHash = taggedHash('BIP0340/aux', aux);
      // Both digests are fixed 32-byte outputs; TypedArrays have no holes.
      for (let i = 0; i < FIELD_LEN; i++) {
        masked[i] = dBytes[i]! ^ auxHash[i]!;
      }
      const rand = taggedHash('BIP0340/nonce', masked, pkBytes, mState);
      return Fn.create(bytesToBigint(rand));
    },
    REDRAW_BUDGET,
  );
}

/**
 * Sign over `ProofData`: computes `m_SC = H(ProofData)` then runs production Sign.
 */
export function signTransitionOverProofData(input: {
  secretKey: Uint8Array;
  network: Network;
  proofData: ProofData;
}): TransitionSignature {
  return signTransition({
    secretKey: input.secretKey,
    network: input.network,
    mSc: hashProofData(input.proofData),
  });
}

/**
 * Ordinary BIP-340 `Verify` (§1.7.10): `s·G == R + e·Pk` with
 * `e = H_BIP340(bytes(R) ‖ bytes(Pk) ‖ m_state)`.
 *
 * Does **not** check the S2C commitment — use {@link commVerify} for that.
 * Rejects non-canonical point/scalar encodings (returns `false`).
 */
export function verify(input: {
  publicKey: Uint8Array;
  signature: Uint8Array;
  network: Network;
}): boolean {
  try {
    const pk = requireBytes(input.publicKey, FIELD_LEN, 'publicKey');
    const sig = requireBytes(input.signature, SIG_LEN, 'signature');
    const rBytes = sig.subarray(0, 32);
    const sBytes = sig.subarray(32, 64);

    // Canonical encodings: lift R and Pk (even-y); s ∈ [1, n).
    const R = liftXOnly(rBytes, 'signature.R');
    const P = liftXOnly(pk, 'publicKey');
    const s = bytesToBigint(sBytes);
    if (s === 0n || s >= Fn.ORDER) {
      return false;
    }

    const mState = mStateBytes(input.network);
    const e = bip340Challenge(rBytes, pk, mState);

    // s·G == R + e·P. Public scalars use multiplyUnsafe (e may be 0).
    // BIP-340 / §1.7.10 do **not** require even y on s·G (rhs here): the
    // even-y rule applies to the x-only encodings of R and Pk, already
    // enforced by lift_x above. Checking y(s·G) would reject ~half of all
    // valid signatures.
    // s ∈ [1, n) ⇒ s·G ≠ ∞. If rhs were ∞, equals(lhs) is already false
    // (lhs is a non-∞ multiple of G). No separate is0 short-circuit.
    const lhs = Point.BASE.multiply(s);
    /* v8 ignore next -- a BIP-340 SHA-256 challenge equals zero with probability ~2^-256 and has no production seam */
    const rhs = e === 0n ? R : R.add(P.multiplyUnsafe(e));
    return lhs.equals(rhs);
  } catch {
    return false;
  }
}

/**
 * Sign-to-contract opening `CommVerify` (§1.7.10 / §3.2):
 * `R == R' + H(bytes(R') ‖ m_SC)·G`.
 *
 * The tweak is used **unreduced**: `int(t) ≥ n` → `false` (never `mod n`).
 * Rejects non-canonical encodings.
 */
export function commVerify(input: { r: Uint8Array; mSc: Uint8Array; rPrime: Uint8Array }): boolean {
  try {
    const rBytes = requireBytes(input.r, FIELD_LEN, 'r');
    const mSc = requireBytes(input.mSc, FIELD_LEN, 'mSc');
    const rPrimeBytes = requireBytes(input.rPrime, FIELD_LEN, 'rPrime');

    const commitment = liftXOnly(rBytes, 'r');
    const opening = liftXOnly(rPrimeBytes, 'rPrime');

    const tweakPreimage = new Uint8Array(64);
    tweakPreimage.set(rPrimeBytes, 0);
    tweakPreimage.set(mSc, 32);
    const tBytes = sha256(tweakPreimage);
    const tInt = tweakScalarOrReject(tBytes);
    // Unreduced: int(t) ≥ n is invalid — do not reduce. The null arm is the
    // same decision as Sign's redraw gate; tested via {@link tweakScalarOrReject}.
    // §1.7.10 rejects ∞, but `commitment` is a lift_x point (never ∞), so
    // `equals` is already false when `opened` is ∞. Odd y is likewise rejected
    // by inequality against the even-y commitment.
    return (
      /* v8 ignore next -- null arm of && is int(t)>=n; unit-tested via tweakScalarOrReject; commVerify has no hash injection seam */
      tInt !== null &&
      commitment.equals(
        /* v8 ignore next -- rare true-zero tweak ~2^-256; not worth a production seam */
        tInt === 0n ? opening : opening.add(Point.BASE.multiplyUnsafe(tInt)),
      )
    );
  } catch {
    return false;
  }
}

/** Expose group order for tests that craft non-canonical scalars. */
export const SECP256K1_ORDER = Fn.ORDER;
