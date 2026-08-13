/**
 * V.8 fixture-nonce Sign — **test-vector only**.
 *
 * Lives under `test/` deliberately: the deterministic k' does not bind `m_SC`,
 * so two signatures under the same key/network/counter leak the secret scalar.
 * The public package surface exposes only the CSPRNG-nonce production path
 * (`signTransition`).
 *
 * Rule (V.8):
 * ```
 * masked   = d XOR int(tagged_hash("BIP0340/aux", 0x00×32))
 * rand_ctr = tagged_hash("BIP0340/nonce", masked ‖ Pk ‖ m_state ‖ u32-be(ctr))
 * k'       = int(rand_ctr) mod n
 * ```
 * starting at `ctr = 0`, incrementing on every §3.2 step-3b redraw and on
 * `k' = 0`. Step 1b even-y normalisation of `R'` is applied after each draw.
 */

import { schnorr } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';

import {
  bip340NormaliseSecret,
  isAcceptableCommittedR,
  mStateBytes,
  tweakScalarOrReject,
  type Network,
} from '../../src/v1/index.js';
import { runWithRedrawBudget, type SignTrace } from '../../src/v1/transitionSignature.js';

const Point = schnorr.Point;
const { Fn } = Point;
const taggedHash = schnorr.utils.taggedHash;

const FIELD_LEN = 32;
const SIG_LEN = 64;
/** Same redraw budget as production Sign; honest draws terminate quickly. */
const REDRAW_BUDGET = 10_000;

function requireBytes(value: Uint8Array, len: number, label: string): Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new Error(`${label}: expected Uint8Array`);
  }
  if (value.length !== len) {
    throw new Error(`${label}: expected ${len} bytes, got ${value.length}`);
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
  return point.toBytes(true).slice(1);
}

function isEvenY(point: InstanceType<typeof Point>): boolean {
  return point.y % 2n === 0n;
}

function bip340Challenge(r: Uint8Array, pk: Uint8Array, mState: Uint8Array): bigint {
  const digest = taggedHash('BIP0340/challenge', r, pk, mState);
  return Fn.create(bytesToBigint(digest));
}

/**
 * Deterministic fixture-nonce Sign for V.8 / cross-rust bit-for-bit checks.
 * **Not for production.** Never import from package consumers.
 */
export function signTransitionWithFixtureNonce(input: {
  secretKey: Uint8Array;
  network: Network;
  mSc: Uint8Array;
}): SignTrace {
  const { d, dBytes, pkBytes } = bip340NormaliseSecret(input.secretKey);
  const mState = mStateBytes(input.network);
  const mSc = requireBytes(input.mSc, FIELD_LEN, 'mSc');

  const aux = taggedHash('BIP0340/aux', new Uint8Array(32));
  const masked = new Uint8Array(FIELD_LEN);
  for (let i = 0; i < FIELD_LEN; i++) {
    masked[i] = dBytes[i]! ^ aux[i]!;
  }

  return runWithRedrawBudget(REDRAW_BUDGET, (ctr) => {
    const ctrBe = new Uint8Array(4);
    ctrBe[0] = (ctr >>> 24) & 0xff;
    ctrBe[1] = (ctr >>> 16) & 0xff;
    ctrBe[2] = (ctr >>> 8) & 0xff;
    ctrBe[3] = ctr & 0xff;
    const preimage = new Uint8Array(masked.length + pkBytes.length + mState.length + 4);
    preimage.set(masked, 0);
    preimage.set(pkBytes, masked.length);
    preimage.set(mState, masked.length + pkBytes.length);
    preimage.set(ctrBe, masked.length + pkBytes.length + mState.length);
    const randCtr = taggedHash('BIP0340/nonce', preimage);
    const kDrawn = Fn.create(bytesToBigint(randCtr));

    if (kDrawn === 0n) {
      return null;
    }

    let kPrime = kDrawn;
    let rPrimePoint = Point.BASE.multiply(kPrime);
    if (!isEvenY(rPrimePoint)) {
      kPrime = Fn.neg(kPrime);
      rPrimePoint = rPrimePoint.negate();
    }
    const rPrimeBytes = xOnlyBytes(rPrimePoint);

    const tweakPreimage = new Uint8Array(64);
    tweakPreimage.set(rPrimeBytes, 0);
    tweakPreimage.set(mSc, 32);
    const tBytes = sha256(tweakPreimage);
    const t = tweakScalarOrReject(tBytes);
    if (t === null) {
      return null;
    }

    const rPoint = t === 0n ? rPrimePoint : rPrimePoint.add(Point.BASE.multiply(t));
    if (!isAcceptableCommittedR(rPoint)) {
      return null;
    }
    const rBytes = xOnlyBytes(rPoint);

    const e = bip340Challenge(rBytes, pkBytes, mState);
    const s = Fn.create(kPrime + t + e * d);
    if (s === 0n) {
      return null;
    }
    const sBytes = bigintToBytes32(s);

    const signature = new Uint8Array(SIG_LEN);
    signature.set(rBytes, 0);
    signature.set(sBytes, 32);

    return {
      signature,
      s2cNonce: rPrimeBytes.slice(),
      d: bigintToBytes32(d),
      pk: pkBytes.slice(),
      rPrime: rPrimeBytes.slice(),
      t: tBytes.slice(),
      r: rBytes.slice(),
      e: bigintToBytes32(e),
      s: sBytes.slice(),
      nonceCounter: ctr,
    };
  });
}
