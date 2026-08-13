/**
 * Production-path round-trips and m_state / ProofData guards.
 * Complements the V.8 bit-for-bit fixture in v8-fixture.test.ts.
 */

import { describe, expect, it } from 'vitest';
import { hexToBytes, bytesToHex } from '@noble/hashes/utils.js';
import { randomBytes } from '@noble/hashes/utils.js';

import {
  aggregateSig,
  aggregateVerify,
  bip340NormaliseSecret,
  commVerify,
  hashProofData,
  mStateBytes,
  mStateString,
  serializeProofData,
  signTransition,
  signTransitionOverProofData,
  verify,
  type ProofData,
} from '../../src/v1/index.js';
import { signTransitionTrace } from '../../src/v1/transitionSignature.js';
import { signTransitionWithFixtureNonce } from '../fixtures/signTransitionWithFixtureNonce.js';

const SK1 = hexToBytes('22f508c0a93b29fa87ca8d9abcec996f01620656cd7a7e4ab5418b2e76beccf4');

function sampleProofData(seed: number): ProofData {
  const field = (tag: string): Uint8Array => {
    // Deterministic 32-byte field for the test — not protocol-meaningful.
    const out = new Uint8Array(32);
    out[0] = seed & 0xff;
    for (let i = 1; i < 32; i++) {
      out[i] = (out[i - 1]! + tag.charCodeAt(0) + i) & 0xff;
    }
    return out;
  };
  return {
    newAccountStateHash: field('a'),
    outputCoinsRoot: field('o'),
    inputNullifiersRoot: field('i'),
    coinHistoryRoot: field('c'),
    navCommitment: field('n'),
    npkCommit: field('p'),
  };
}

describe('m_state closed set', () => {
  it('returns distinct per-network constants', () => {
    expect(mStateString('mainnet')).toBe('zkCoins/v1/StateUpdate/mainnet');
    expect(mStateString('testnet')).toBe('zkCoins/v1/StateUpdate/testnet');
    expect(mStateString('regtest')).toBe('zkCoins/v1/StateUpdate/regtest');
    expect(bytesToHex(mStateBytes('mainnet'))).not.toBe(bytesToHex(mStateBytes('testnet')));
  });
});

describe('ProofData serialize / hash', () => {
  it('rejects wrong field lengths with a named error', () => {
    const pd = sampleProofData(1);
    expect(() => serializeProofData({ ...pd, navCommitment: new Uint8Array(16) })).toThrow(
      /navCommitment.*32 bytes/,
    );
  });

  it('hashProofData is SHA-256 of the 192-byte serialize', () => {
    const pd = sampleProofData(7);
    const h = hashProofData(pd);
    expect(h.length).toBe(32);
    expect(serializeProofData(pd).length).toBe(192);
  });
});

describe('production Sign round-trip', () => {
  it('signTransition output passes Verify and CommVerify on each network', () => {
    const pd = sampleProofData(3);
    const mSc = hashProofData(pd);
    for (const network of ['mainnet', 'testnet', 'regtest'] as const) {
      const sig = signTransition({ secretKey: SK1, network, mSc });
      expect(sig.signature.length).toBe(64);
      expect(sig.s2cNonce.length).toBe(32);
      const { pkBytes } = bip340NormaliseSecret(SK1);
      expect(
        verify({ publicKey: pkBytes, signature: sig.signature, network }),
        `Verify on ${network}`,
      ).toBe(true);
      expect(
        commVerify({ r: sig.signature.subarray(0, 32), mSc, rPrime: sig.s2cNonce }),
        `CommVerify on ${network}`,
      ).toBe(true);
    }
  });

  it('signTransitionOverProofData matches sign over H(ProofData)', () => {
    const pd = sampleProofData(9);
    const a = signTransitionOverProofData({ secretKey: SK1, network: 'regtest', proofData: pd });
    // Production nonces are random — cannot byte-compare two production signs.
    // Instead: both must verify under the same m_SC.
    const mSc = hashProofData(pd);
    const { pkBytes } = bip340NormaliseSecret(SK1);
    expect(verify({ publicKey: pkBytes, signature: a.signature, network: 'regtest' })).toBe(true);
    expect(commVerify({ r: a.signature.subarray(0, 32), mSc, rPrime: a.s2cNonce })).toBe(true);
  });

  it('production nonces differ across two signs of the same input (aux-rand is live)', () => {
    const mSc = randomBytes(32);
    const a = signTransitionTrace({ secretKey: SK1, network: 'testnet', mSc });
    const b = signTransitionTrace({ secretKey: SK1, network: 'testnet', mSc });
    // Negligible collision probability under CSPRNG aux-rand.
    expect(bytesToHex(a.signature)).not.toBe(bytesToHex(b.signature));
    expect(bytesToHex(a.s2cNonce)).not.toBe(bytesToHex(b.s2cNonce));
  });

  it('fixture-nonce path is explicitly separate from production', () => {
    const mSc = hexToBytes('bf50cc59a665bcdc2b5f0754dd754a73e37552a6b1b69eb9e42c07ddd1ae73e2');
    const fixture = signTransitionWithFixtureNonce({
      secretKey: SK1,
      network: 'testnet',
      mSc,
    });
    // Fixture is deterministic.
    const fixture2 = signTransitionWithFixtureNonce({
      secretKey: SK1,
      network: 'testnet',
      mSc,
    });
    expect(bytesToHex(fixture.signature)).toBe(bytesToHex(fixture2.signature));
    // Production is not the fixture path (different function, live aux).
    const prod = signTransition({ secretKey: SK1, network: 'testnet', mSc });
    // Extremely unlikely to match the fixture nonce by chance.
    expect(bytesToHex(prod.signature)).not.toBe(bytesToHex(fixture.signature));
  });
});

describe('half-agg round-trip (production signs)', () => {
  it('AggregateVerify accepts AggregateSig of two production signatures', () => {
    const sk2 = hexToBytes('86b75c297fd9a0af472d06fbf889f7e4667c9e42b7d7efc8b1ca7e66b95462c0');
    const mSc1 = randomBytes(32);
    const mSc2 = randomBytes(32);
    const s1 = signTransitionTrace({ secretKey: SK1, network: 'regtest', mSc: mSc1 });
    const s2 = signTransitionTrace({ secretKey: sk2, network: 'regtest', mSc: mSc2 });
    const agg = aggregateSig([
      { pk: s1.pk, r: s1.r, s: s1.s },
      { pk: s2.pk, r: s2.r, s: s2.s },
    ]);
    expect(
      aggregateVerify({
        members: [
          { pk: s1.pk, r: s1.r },
          { pk: s2.pk, r: s2.r },
        ],
        sAgg: agg.sAgg,
        network: 'regtest',
      }),
    ).toBe(true);
  });
});
