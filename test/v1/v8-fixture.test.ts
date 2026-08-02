/**
 * V.8 bit-for-bit fixture + V.9 negative controls that are executable against it.
 *
 * Anchor: normative spec V.8 (synthetic signing & half-aggregation fixture,
 * testnet `m_state`). The same values are already recomputed by the Rust
 * reference (`script-plonky2/tests/generated_sig_agg_vectors_test.rs`).
 */

import { describe, expect, it } from 'vitest';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { schnorr } from '@noble/curves/secp256k1.js';

import {
  aggregateSig,
  aggregateVerify,
  bip340NormaliseSecret,
  commVerify,
  hashProofData,
  mStateBytes,
  mStateString,
  serializeProofData,
  SECP256K1_ORDER,
  verify,
  type Network,
  type ProofData,
} from '../../src/v1/index.js';
import { signTransitionWithFixtureNonce } from '../fixtures/signTransitionWithFixtureNonce.js';

const Point = schnorr.Point;
const { Fn } = Point;

/**
 * Test-only: sign **without** §3.2 step 1b (even-y normalisation of `R'`).
 * Lives in the test file — production must not ship a signer with a security
 * rule switched off.
 *
 * Outcomes name the gate that fired so the load-bearing-1b test can assert
 * both paths honestly (3b abort **or** failed opening), never a silent
 * throw on the first random k'.
 */
type Without1bOutcome =
  | { kind: 'even_y_r_prime' }
  | { kind: 't_ge_n' }
  | { kind: 'step_3b_abort' }
  | { kind: 's_zero' }
  | {
      kind: 'built';
      signature: Uint8Array;
      s2cNonce: Uint8Array;
      rPrimeHadOddY: true;
    };

function attemptSignWithoutStep1b(input: {
  secretKey: Uint8Array;
  network: Network;
  mSc: Uint8Array;
  kPrime: bigint;
}): Without1bOutcome {
  const { d, pkBytes } = bip340NormaliseSecret(input.secretKey);
  const mSc = input.mSc;
  if (mSc.length !== 32) throw new Error('mSc length');
  const mState = mStateBytes(input.network);

  const kPrime = Fn.create(input.kPrime);
  if (kPrime === 0n) throw new Error('kPrime must be non-zero');

  // Deliberately **skip** step 1b — keep whatever y parity k'·G has.
  const rPrimePoint = Point.BASE.multiply(kPrime);
  if (rPrimePoint.y % 2n === 0n) {
    return { kind: 'even_y_r_prime' };
  }
  const rPrimeBytes = rPrimePoint.toBytes(true).slice(1);

  const tweakPreimage = new Uint8Array(64);
  tweakPreimage.set(rPrimeBytes, 0);
  tweakPreimage.set(mSc, 32);
  const tBytes = sha256(tweakPreimage);
  const tInt = BigInt('0x' + bytesToHex(tBytes));
  if (tInt >= SECP256K1_ORDER) {
    return { kind: 't_ge_n' };
  }

  // Geometric commitment over the **odd-y** R' (lift_x would use the even twin).
  const rPoint = tInt === 0n ? rPrimePoint : rPrimePoint.add(Point.BASE.multiply(tInt));
  if (rPoint.is0() || rPoint.y % 2n === 1n) {
    return { kind: 'step_3b_abort' };
  }
  const rBytes = rPoint.toBytes(true).slice(1);

  const e = Fn.create(
    BigInt(
      '0x' + bytesToHex(schnorr.utils.taggedHash('BIP0340/challenge', rBytes, pkBytes, mState)),
    ),
  );
  const s = Fn.create(kPrime + tInt + e * d);
  if (s === 0n) {
    return { kind: 's_zero' };
  }

  const signature = new Uint8Array(64);
  signature.set(rBytes, 0);
  signature.set(Fn.toBytes(s), 32);
  return {
    kind: 'built',
    signature,
    s2cNonce: rPrimeBytes,
    rPrimeHadOddY: true,
  };
}

// ── V.8 pinned values (spec; lowercase hex, no 0x) ──────────────────────────

const V8 = {
  network: 'testnet' as const,
  sk1: '22f508c0a93b29fa87ca8d9abcec996f01620656cd7a7e4ab5418b2e76beccf4',
  d1: '22f508c0a93b29fa87ca8d9abcec996f01620656cd7a7e4ab5418b2e76beccf4',
  pk1: 'e7f2a98e7b45e9424e3e0cb1d937a1698ebd339c6d8344906db979642cf20474',
  pd1: {
    ash: 'f882df3ef57d11032e01c2214525060766250b110b09586cd6cecbed8e3ed4f7',
    ocr: '0852ae9e41b56cb6320977d06df0b11463919fda0364a5b1cfd3d22358211f24',
    inr: '25af2581385ea1e3688958c7e915c2b46b426daf62536945caaeecc8e3c3a6c6',
    chr: '7014c090cbf7eeb37519e4ff815a747384f46943a2b0cc3f4a0094e62cdfaaba',
    navc: '4dcf2ab90710006a8fe0c9fb0363e5465100858fc0d69155f69db53468e6af7c',
    npkc: '23461051f1c23cf0660eab775049d51ea90bd08c31dabe5cc3d1a0e4767fe259',
    mSc: 'bf50cc59a665bcdc2b5f0754dd754a73e37552a6b1b69eb9e42c07ddd1ae73e2',
  },
  rPrime1: '5657f2e91dc3a2d248501a37dbe674d2cf8ed1a13c89b7710ca89aad3b9fe050',
  t1: '423984fa39ce7b1a4d8eb164ab2a300d56b9de4f4ed3134339db5ead7ccc17c2',
  r1: 'c41ff1a78f2006e5f5aa800efa84b2d2046d108dfa968909974ec37fcb87f6c4',
  e1: '88aa41dbac65bb97f235c7fe064ebd5b8882d2bc04f8792aebec2c8c4df7fd4f',
  s1: '748ae8e2fded9df9830cbaa8893484e753fdfd141cccc8b35a27ab5a870a83d2',

  sk2: '86b75c297fd9a0af472d06fbf889f7e4667c9e42b7d7efc8b1ca7e66b95462c0',
  d2: '7948a3d680265f50b8d2f9040776081a54323ea3f770b0730e07e02616e1de81',
  pk2: '21799353e64a65ee4b1f414998c44878c56270cf8a81046cb3636e5ec31a3341',
  pd2: {
    ash: '1713c51edabaa2a6e64ef24d084d4f88e776e135514ae04ad3780c5cd154f660',
    ocr: '7791a68e5387e0a22f90bc7c7347a5712fe42bc82f7559333d7c578b79fd0022',
    inr: '8fa4a67faf24c981a64328ec227207a06a066e9ac0444621f5d3066b8f405bca',
    chr: '23027099bb0e04dadb0ae9cb76208e377270c6d4dd761962b98c9db793e109be',
    navc: '69266372d1705851901e48dd1e40e6cde4bda048fb04e622b97cf4346f90632f',
    npkc: 'bdae5bcf45668f6f6b2670bdce70882c3211334c78248cdf9d4aa5639074d154',
    mSc: '85d06ebe2f0f5173af9ff8bdd2d4d594303a640d7b2f1c8819d5a48abfa4773d',
  },
  rPrime2: '9c18a07c07be5225b688895f73daaffefdd62cbb49e1b854dd47f5aee1484193',
  t2: 'e21ed3e78e2d5abf9e227e8f0e3ba079010400c5103bd8a41187394b2e43527b',
  r2: 'bd22b77069c75431ee3676bea7324a59e9b6466a62a9a3021f831e6ccf5d3220',
  e2: '3d57531ad9f5f4df812184559e0bda68c8695e2ba673546c1976732602d016b3',
  s2: 'caa0374d3cf77e1874298c98d3d3fe8b416f89d51823d6909c3e1cdbf91d3002',

  z: '5aca3de396d19dc1e0e2d69b4aed8816d1de535e3c180819f32037beeb49049a',
  a1: 'ebc0ffd7fabac87c4114b82c11031482af6210be3cbdfd224a3152a41ef8f738',
  a2: 'd37756039310968a42ab8c386a6bbdcf4211d02b8a8f7bc91257c0aa7f2d70a0',
  sAgg: 'cfb0c36a8399589b5580ba41cafaf66b7d707443a202e4113f3635872ca58b78',
};

function pdFromParts(p: {
  ash: string;
  ocr: string;
  inr: string;
  chr: string;
  navc: string;
  npkc: string;
}): ProofData {
  return {
    newAccountStateHash: hexToBytes(p.ash),
    outputCoinsRoot: hexToBytes(p.ocr),
    inputNullifiersRoot: hexToBytes(p.inr),
    coinHistoryRoot: hexToBytes(p.chr),
    navCommitment: hexToBytes(p.navc),
    npkCommit: hexToBytes(p.npkc),
  };
}

function hexEq(actual: Uint8Array, expectedHex: string, label: string): void {
  expect(bytesToHex(actual), label).toBe(expectedHex);
}

describe('V.8 ProofData field order and H(ProofData)', () => {
  it('serializes the six fields in §1.4 order and matches pinned m_SC', () => {
    const pd1 = pdFromParts(V8.pd1);
    const ser1 = serializeProofData(pd1);
    expect(ser1.length).toBe(192);
    // Order: ash ‖ ocr ‖ inr ‖ chr ‖ navc ‖ npkc
    expect(bytesToHex(ser1.subarray(0, 32))).toBe(V8.pd1.ash);
    expect(bytesToHex(ser1.subarray(32, 64))).toBe(V8.pd1.ocr);
    expect(bytesToHex(ser1.subarray(64, 96))).toBe(V8.pd1.inr);
    expect(bytesToHex(ser1.subarray(96, 128))).toBe(V8.pd1.chr);
    expect(bytesToHex(ser1.subarray(128, 160))).toBe(V8.pd1.navc);
    expect(bytesToHex(ser1.subarray(160, 192))).toBe(V8.pd1.npkc);
    hexEq(hashProofData(pd1), V8.pd1.mSc, 'm_SC_1');

    const pd2 = pdFromParts(V8.pd2);
    hexEq(hashProofData(pd2), V8.pd2.mSc, 'm_SC_2');
  });

  it('synthetic fields equal H of the short V.8 labels', () => {
    const labels1 = ['ash', 'ocr', 'inr', 'chr', 'navc', 'npkc'] as const;
    const expected1 = [V8.pd1.ash, V8.pd1.ocr, V8.pd1.inr, V8.pd1.chr, V8.pd1.navc, V8.pd1.npkc];
    for (let i = 0; i < labels1.length; i++) {
      const digest = sha256(new TextEncoder().encode(`zkCoins/v1/test-vector/pd1/${labels1[i]}`));
      expect(bytesToHex(digest), `pd1/${labels1[i]}`).toBe(expected1[i]);
    }
  });
});

describe('V.8 m_state', () => {
  it('pins testnet and has no silent default', () => {
    expect(mStateString('testnet')).toBe('zkCoins/v1/StateUpdate/testnet');
    expect(new TextDecoder().decode(mStateBytes('testnet'))).toBe('zkCoins/v1/StateUpdate/testnet');
    // Compile-time Network union; runtime exhaustiveness is covered by the
    // switch — unknown strings are not assignable to Network.
  });
});

describe('V.8 Signer 1 (even-y key, ctr = 0)', () => {
  it('normalises d_1 = sk_sig_1 and matches Pk_1', () => {
    const { dBytes, pkBytes } = bip340NormaliseSecret(hexToBytes(V8.sk1));
    hexEq(dBytes, V8.d1, 'd_1');
    hexEq(pkBytes, V8.pk1, 'Pk_1');
  });

  it('fixture-nonce Sign reproduces every intermediate bit-for-bit', () => {
    const signed = signTransitionWithFixtureNonce({
      secretKey: hexToBytes(V8.sk1),
      network: V8.network,
      mSc: hexToBytes(V8.pd1.mSc),
    });
    expect(signed.nonceCounter, 'Signer 1 uses ctr = 0').toBe(0);
    hexEq(signed.rPrime, V8.rPrime1, "R'_1");
    hexEq(signed.t, V8.t1, 't_1');
    hexEq(signed.r, V8.r1, 'R_1');
    hexEq(signed.e, V8.e1, 'e_1');
    hexEq(signed.s, V8.s1, 's_1');
    hexEq(signed.s2cNonce, V8.rPrime1, 's2c_nonce_1');
    expect(bytesToHex(signed.signature)).toBe(V8.r1 + V8.s1);
  });
});

describe('V.8 Signer 2 (odd-y key, ctr = 2 — two 3b redraws)', () => {
  it('normalises the odd-y sk_sig_2 to the pinned d_2 (negation branch)', () => {
    const raw = hexToBytes(V8.sk2);
    const { dBytes, pkBytes } = bip340NormaliseSecret(raw);
    // d_2 ≠ sk_sig_2 — the odd-y key was negated.
    expect(bytesToHex(dBytes)).not.toBe(V8.sk2);
    hexEq(dBytes, V8.d2, 'd_2');
    hexEq(pkBytes, V8.pk2, 'Pk_2');
    // Prove the raw key really was the odd-y branch: raw·G has odd y.
    const rawScalar = BigInt('0x' + V8.sk2);
    const rawP = Point.BASE.multiply(rawScalar);
    expect(rawP.y % 2n === 1n, 'sk_sig_2·G must have odd y so normalisation fires').toBe(true);
  });

  it('fixture-nonce Sign needs ctr = 2 (two step-3b discards) and matches every byte', () => {
    const signed = signTransitionWithFixtureNonce({
      secretKey: hexToBytes(V8.sk2),
      network: V8.network,
      mSc: hexToBytes(V8.pd2.mSc),
    });
    // Redraw proof: the successful draw is ctr = 2 ⇒ ctr 0 and 1 were discarded.
    expect(signed.nonceCounter, 'Signer 2 V.8 pin: ctr = 2').toBe(2);
    hexEq(signed.rPrime, V8.rPrime2, "R'_2");
    hexEq(signed.t, V8.t2, 't_2');
    hexEq(signed.r, V8.r2, 'R_2');
    hexEq(signed.e, V8.e2, 'e_2');
    hexEq(signed.s, V8.s2, 's_2');
    expect(bytesToHex(signed.signature)).toBe(V8.r2 + V8.s2);
  });

  it('proves ctr 0 and ctr 1 are rejected by step 3b before ctr 2 succeeds', () => {
    // Reconstruct the fixture draws and assert the first two fail 3b.
    const { dBytes, pkBytes } = bip340NormaliseSecret(hexToBytes(V8.sk2));
    const mState = mStateBytes('testnet');
    const mSc = hexToBytes(V8.pd2.mSc);
    const aux = schnorr.utils.taggedHash('BIP0340/aux', new Uint8Array(32));
    const masked = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      const dB = dBytes[i];
      const aB = aux[i];
      if (dB === undefined || aB === undefined) throw new Error('length');
      masked[i] = dB ^ aB;
    }

    const fails3b: boolean[] = [];
    for (let ctr = 0; ctr < 3; ctr++) {
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
      const rand = schnorr.utils.taggedHash('BIP0340/nonce', preimage);
      const k = Fn.create(BigInt('0x' + bytesToHex(rand)));
      if (k === 0n) {
        fails3b.push(true);
        continue;
      }
      // Step 1b: even-y normalise R' (and the matching k'). Only R' is needed
      // for the 3b check below; the negated scalar is not re-used here.
      let rPrime = Point.BASE.multiply(k);
      if (rPrime.y % 2n === 1n) {
        rPrime = rPrime.negate();
      }
      const rPrimeBytes = rPrime.toBytes(true).slice(1);
      const tweakPre = new Uint8Array(64);
      tweakPre.set(rPrimeBytes, 0);
      tweakPre.set(mSc, 32);
      const tBytes = sha256(tweakPre);
      const tInt = BigInt('0x' + bytesToHex(tBytes));
      if (tInt >= SECP256K1_ORDER) {
        fails3b.push(true);
        continue;
      }
      const R = rPrime.add(Point.BASE.multiply(tInt));
      const bad = R.is0() || R.y % 2n === 1n;
      fails3b.push(bad);
    }
    expect(fails3b[0], 'ctr=0 must fail step 3b').toBe(true);
    expect(fails3b[1], 'ctr=1 must fail step 3b').toBe(true);
    expect(fails3b[2], 'ctr=2 must succeed step 3b').toBe(false);
  });
});

describe('V.8 acceptance (Verify / CommVerify / AggregateVerify)', () => {
  it('Verify and CommVerify accept both signers; AggregateVerify accepts the batch', () => {
    const sig1 = hexToBytes(V8.r1 + V8.s1);
    const sig2 = hexToBytes(V8.r2 + V8.s2);

    expect(
      verify({ publicKey: hexToBytes(V8.pk1), signature: sig1, network: 'testnet' }),
      'Verify signer 1',
    ).toBe(true);
    expect(
      verify({ publicKey: hexToBytes(V8.pk2), signature: sig2, network: 'testnet' }),
      'Verify signer 2',
    ).toBe(true);

    expect(
      commVerify({
        r: hexToBytes(V8.r1),
        mSc: hexToBytes(V8.pd1.mSc),
        rPrime: hexToBytes(V8.rPrime1),
      }),
      'CommVerify signer 1',
    ).toBe(true);
    expect(
      commVerify({
        r: hexToBytes(V8.r2),
        mSc: hexToBytes(V8.pd2.mSc),
        rPrime: hexToBytes(V8.rPrime2),
      }),
      'CommVerify signer 2',
    ).toBe(true);

    const agg = aggregateSig([
      { pk: hexToBytes(V8.pk1), r: hexToBytes(V8.r1), s: hexToBytes(V8.s1) },
      { pk: hexToBytes(V8.pk2), r: hexToBytes(V8.r2), s: hexToBytes(V8.s2) },
    ]);
    hexEq(agg.z, V8.z, 'z');
    const a1 = agg.coefficients[0];
    const a2 = agg.coefficients[1];
    if (a1 === undefined || a2 === undefined) throw new Error('missing coefficients');
    hexEq(a1, V8.a1, 'a_1');
    hexEq(a2, V8.a2, 'a_2');
    hexEq(agg.sAgg, V8.sAgg, 's_agg');

    expect(
      aggregateVerify({
        members: [
          { pk: hexToBytes(V8.pk1), r: hexToBytes(V8.r1) },
          { pk: hexToBytes(V8.pk2), r: hexToBytes(V8.r2) },
        ],
        sAgg: agg.sAgg,
        network: 'testnet',
      }),
      'AggregateVerify',
    ).toBe(true);
  });

  it('Verify accepts a valid signature whose s·G has odd y (BIP-340 does not require even y on s·G)', () => {
    // Signer 2 of V.8 is exactly this case: y(s₂·G) is odd, yet the signature
    // is valid. A Verify that checked isEvenY(s·G) (or isEvenY(R+e·P)) would
    // reject ~half of all honest signatures and still pass Signer 1 alone.
    const s2 = BigInt('0x' + V8.s2);
    const sG = Point.BASE.multiply(s2);
    expect(sG.y % 2n === 1n, 'V.8 Signer 2: y(s₂·G) must be odd (the property under test)').toBe(
      true,
    );

    // Cross-check the equation: s·G must equal R + e·P (both sides same point).
    const R = schnorr.utils.lift_x(BigInt('0x' + V8.r2));
    const P = schnorr.utils.lift_x(BigInt('0x' + V8.pk2));
    const e = BigInt('0x' + V8.e2);
    const rhs = R.add(P.multiplyUnsafe(e));
    expect(sG.equals(rhs), 's₂·G == R₂ + e₂·Pk₂ (odd y on both sides)').toBe(true);
    expect(rhs.y % 2n === 1n, 'rhs also has odd y').toBe(true);

    expect(
      verify({
        publicKey: hexToBytes(V8.pk2),
        signature: hexToBytes(V8.r2 + V8.s2),
        network: 'testnet',
      }),
      'Verify must accept Signer 2 despite odd y(s·G)',
    ).toBe(true);
  });
});

describe('V.9 negative controls (executable against V.8)', () => {
  it('N-01: flip byte 0 of ash₁ → CommVerify false', () => {
    const pd = pdFromParts(V8.pd1);
    const mutated = pd.newAccountStateHash.slice();
    const b0 = mutated[0];
    if (b0 === undefined) throw new Error('empty ash');
    mutated[0] = b0 ^ 0x01;
    const badMsc = hashProofData({ ...pd, newAccountStateHash: mutated });
    expect(bytesToHex(badMsc)).not.toBe(V8.pd1.mSc);
    expect(
      commVerify({
        r: hexToBytes(V8.r1),
        mSc: badMsc,
        rPrime: hexToBytes(V8.rPrime1),
      }),
      'N-01 CommVerify must reject flipped ash',
    ).toBe(false);
  });

  it('N-02: swap R₁ and R₂ in the aggregate (keys unchanged) → AggregateVerify false', () => {
    expect(
      aggregateVerify({
        members: [
          { pk: hexToBytes(V8.pk1), r: hexToBytes(V8.r2) }, // swapped R
          { pk: hexToBytes(V8.pk2), r: hexToBytes(V8.r1) },
        ],
        sAgg: hexToBytes(V8.sAgg),
        network: 'testnet',
      }),
      'N-02 AggregateVerify must reject swapped R',
    ).toBe(false);
  });

  it('N-12: substitute a different valid H(ProofData) into CommVerify → false', () => {
    // Use signer 2's m_SC (valid digest) as the opening for signer 1's R.
    expect(
      commVerify({
        r: hexToBytes(V8.r1),
        mSc: hexToBytes(V8.pd2.mSc),
        rPrime: hexToBytes(V8.rPrime1),
      }),
      'N-12 CommVerify must reject foreign H(ProofData)',
    ).toBe(false);
  });

  it('N-19: testnet signature verified under mainnet m_state is rejected (cross-network replay closed)', () => {
    const sig1 = hexToBytes(V8.r1 + V8.s1);
    expect(
      verify({ publicKey: hexToBytes(V8.pk1), signature: sig1, network: 'testnet' }),
      'control: testnet Verify accepts',
    ).toBe(true);
    expect(
      verify({ publicKey: hexToBytes(V8.pk1), signature: sig1, network: 'mainnet' }),
      'N-19: mainnet m_state must reject the testnet signature',
    ).toBe(false);

    expect(
      aggregateVerify({
        members: [
          { pk: hexToBytes(V8.pk1), r: hexToBytes(V8.r1) },
          { pk: hexToBytes(V8.pk2), r: hexToBytes(V8.r2) },
        ],
        sAgg: hexToBytes(V8.sAgg),
        network: 'mainnet',
      }),
      'N-19 AggregateVerify under mainnet must reject',
    ).toBe(false);
  });
});

describe('canonical encodings rejected', () => {
  it('rejects scalar ≥ n in AggregateVerify / Verify', () => {
    // n as 32-byte BE is not a canonical scalar in [0, n).
    const nBytes = hexToBytes('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
    const sig = new Uint8Array(64);
    sig.set(hexToBytes(V8.r1), 0);
    sig.set(nBytes, 32);
    expect(
      verify({ publicKey: hexToBytes(V8.pk1), signature: sig, network: 'testnet' }),
      's ≥ n',
    ).toBe(false);

    expect(
      aggregateVerify({
        members: [{ pk: hexToBytes(V8.pk1), r: hexToBytes(V8.r1) }],
        sAgg: nBytes,
        network: 'testnet',
      }),
      's_agg ≥ n',
    ).toBe(false);
  });

  it('rejects an x-coordinate not on the curve', () => {
    // BIP-340 invalid pubkey (not on the curve). x=1 *is* on secp256k1 — do not use it.
    const offCurve = hexToBytes('eefdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34');
    expect(
      verify({
        publicKey: offCurve,
        signature: hexToBytes(V8.r1 + V8.s1),
        network: 'testnet',
      }),
      'off-curve pk',
    ).toBe(false);
    expect(
      commVerify({
        r: offCurve,
        mSc: hexToBytes(V8.pd1.mSc),
        rPrime: hexToBytes(V8.rPrime1),
      }),
      'off-curve R',
    ).toBe(false);
  });

  it('rejects wrong-length inputs', () => {
    expect(
      verify({
        publicKey: hexToBytes(V8.pk1),
        signature: hexToBytes(V8.r1), // 32 bytes, not 64
        network: 'testnet',
      }),
    ).toBe(false);
    expect(
      commVerify({
        r: hexToBytes(V8.r1),
        mSc: hexToBytes(V8.pd1.mSc),
        rPrime: new Uint8Array(16),
      }),
    ).toBe(false);
  });
});

describe('§3.2 step 1b is load-bearing', () => {
  it('without even-y normalisation of R′, the signature is unusable (3b abort or failed opening)', () => {
    // Honest claim: skip step 1b → no usable transition signature.
    // Two legitimate outcomes (both count as "unusable"):
    //   (A) step 3b rejects R = R'_odd + t·G (∞ or odd y) — construction aborts;
    //   (B) construction succeeds, but CommVerify fails because lift_x(bytes(R'))
    //       recovers the even-y twin, not the odd-y point the signer committed with.
    // We require at least one (B) so the lift_x mismatch is exhibited, not only (A).
    //
    // Search bound: for successive k' ∈ [1, n], y(k'·G) is odd with ~½ probability
    // (independent of the even-y rule we deliberately skip). Conditional on odd y,
    // outcomes (A) and (B) each arise with ~½ probability under a random-looking
    // tweak t = H(R' ‖ m_SC). So ~32 odd-y draws already make “missing either path”
    // vanish as 2·2^{-32}. Bound k' ≤ 64 ⇒ E[odd-y] ≈ 32; a few dozen scalar muls
    // stay well inside the default 5 s gate — no testTimeout inflation.
    const SEARCH_K_MAX = 64n;
    const secretKey = hexToBytes(V8.sk1);
    const mSc = hexToBytes(V8.pd1.mSc);
    let step3bAborts = 0;
    let openingFailures = 0;
    let fullyAccepted = 0;
    let sawOddY = false;

    for (let k = 1n; k <= SEARCH_K_MAX; k++) {
      const outcome = attemptSignWithoutStep1b({
        secretKey,
        network: 'testnet',
        mSc,
        kPrime: k,
      });
      if (
        outcome.kind === 'even_y_r_prime' ||
        outcome.kind === 't_ge_n' ||
        outcome.kind === 's_zero'
      ) {
        continue;
      }
      if (outcome.kind === 'step_3b_abort') {
        sawOddY = true;
        step3bAborts += 1;
        continue;
      }
      // kind === 'built'
      sawOddY = true;
      expect(outcome.rPrimeHadOddY).toBe(true);
      const openOk = commVerify({
        r: outcome.signature.subarray(0, 32),
        mSc,
        rPrime: outcome.s2cNonce,
      });
      const verifyOk = verify({
        publicKey: hexToBytes(V8.pk1),
        signature: outcome.signature,
        network: 'testnet',
      });
      if (openOk && verifyOk) {
        fullyAccepted += 1;
      } else {
        // Opening must fail: lift_x(bytes(R')) ≠ geometric odd-y R'.
        expect(openOk, `k'=${k}: CommVerify must reject the odd-y opening`).toBe(false);
        openingFailures += 1;
      }
    }

    expect(sawOddY, "search must hit at least one odd-y R'").toBe(true);
    expect(
      openingFailures,
      'must exhibit the lift_x mismatch path (built sig + CommVerify false), not only 3b aborts',
    ).toBeGreaterThan(0);
    expect(fullyAccepted, 'without step 1b no signature may pass both CommVerify and Verify').toBe(
      0,
    );
    // Document that path (A) also occurs for this (sk, m_SC) search space.
    expect(
      step3bAborts,
      "path (A): some odd-y R' draws fail step 3b (named, not papered over)",
    ).toBeGreaterThan(0);
  });
});
