/**
 * JS ↔ Rust primitive parity (DoD §6(b) / V.7 matrix for the live SDK surface).
 *
 * Spawns the real `zkcoins-sdk-shim` release binary (built from
 * `test/cross-rust/shim/`) and compares pure-JS outputs against it for
 * every randomized input. No mocks: both sides run real BIP-39 / BIP-32 /
 * BIP-340 / SHA-256.
 *
 * If the shim binary is missing the suite fails — never skips. See
 * `test/cross-rust/README.md` for the scope decision.
 */

import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';

import {
  derivePublicKeys,
  deriveSigningKey,
  generateAccountKeysFromMnemonic,
  mnemonicFromEntropy,
  validateMnemonic,
} from '../../src/derivation.js';
import { createCommitment, signSchnorr } from '../../src/signing.js';
import {
  aggregateSig,
  aggregateVerify,
  bip340NormaliseSecret,
  commVerify,
  verify,
} from '../../src/v1/index.js';
import { signTransitionWithFixtureNonce } from '../fixtures/signTransitionWithFixtureNonce.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { schnorr } from '@noble/curves/secp256k1.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const SHIM_BIN = join(HERE, 'shim', 'target', 'release', 'zkcoins-sdk-shim');

const SAMPLES = 100;
const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

/**
 * Fixed default seed for the test PRNG. Not a crypto seed — only drives
 * sample generation so a failing case can be re-run bit-for-bit.
 * Override with env `CROSS_RUST_SEED` (unsigned 32-bit decimal or 0x-hex).
 */
const DEFAULT_PRNG_SEED = 0x5eed_c0de;

type ShimResult = { ok: true; result: unknown } | { ok: false; error: string };

/**
 * Tiny xorshift32 PRNG for reproducible test inputs.
 * State must never be 0 (xorshift fixed point); resolvePrngSeed rejects that.
 */
class XorShift32 {
  private state: number;

  constructor(seed: number) {
    if (seed === 0) {
      throw new Error('XorShift32 seed must be non-zero');
    }
    this.state = seed >>> 0;
  }

  nextU32(): number {
    let x = this.state;
    x ^= x << 13;
    x ^= x >>> 17;
    x ^= x << 5;
    this.state = x >>> 0;
    return this.state;
  }

  bytes(byteLen: number): Uint8Array {
    if (!Number.isInteger(byteLen) || byteLen < 0) {
      throw new Error(
        `XorShift32.bytes: byteLen must be a non-negative integer, got ${String(byteLen)}`,
      );
    }
    const out = new Uint8Array(byteLen);
    for (let i = 0; i < byteLen; i++) {
      out[i] = this.nextU32() & 0xff;
    }
    return out;
  }
}

function resolvePrngSeed(): number {
  const raw = process.env.CROSS_RUST_SEED;
  if (raw === undefined) {
    return DEFAULT_PRNG_SEED;
  }
  if (raw === '') {
    throw new Error(
      'CROSS_RUST_SEED is set but empty. Unset it for the default seed, or supply an unsigned 32-bit integer (decimal or 0x-hex).',
    );
  }
  const parsed =
    raw.startsWith('0x') || raw.startsWith('0X')
      ? Number.parseInt(raw, 16)
      : Number.parseInt(raw, 10);
  if (!Number.isInteger(parsed) || parsed < 0 || parsed > 0xffff_ffff) {
    throw new Error(
      `CROSS_RUST_SEED must be an unsigned 32-bit integer (decimal or 0x-hex); got ${JSON.stringify(raw)}`,
    );
  }
  if (parsed === 0) {
    throw new Error('CROSS_RUST_SEED must be non-zero (xorshift32 has a fixed point at 0)');
  }
  return parsed >>> 0;
}

const PRNG_SEED = resolvePrngSeed();
// One shared stream for the whole randomized suite so a single seed
// fully determines every sample input across all ops.
const prng = new XorShift32(PRNG_SEED);

function randomHex(byteLen: number): string {
  const bytes = prng.bytes(byteLen);
  let hex = '';
  for (const b of bytes) {
    hex += b.toString(16).padStart(2, '0');
  }
  return hex;
}

function requireShim(): void {
  if (!existsSync(SHIM_BIN)) {
    throw new Error(
      `cross-rust shim binary missing at ${SHIM_BIN}. ` +
        `Build it with: cargo build --release --manifest-path test/cross-rust/shim/Cargo.toml. ` +
        `A missing shim is a hard failure — the parity gate must not skip.`,
    );
  }
}

function callShim(request: Record<string, unknown>): unknown {
  requireShim();
  const proc = spawnSync(SHIM_BIN, [], {
    input: `${JSON.stringify(request)}\n`,
    encoding: 'utf8',
    maxBuffer: 4 * 1024 * 1024,
  });
  if (proc.error) {
    throw new Error(`failed to spawn shim: ${proc.error.message}`);
  }
  if (proc.status !== 0) {
    throw new Error(
      `shim exited ${String(proc.status)}: stderr=${proc.stderr ?? ''} stdout=${proc.stdout ?? ''}`,
    );
  }
  const line = (proc.stdout ?? '').trim().split('\n').pop();
  if (!line) {
    throw new Error('shim produced empty stdout');
  }
  let parsed: ShimResult;
  try {
    parsed = JSON.parse(line) as ShimResult;
  } catch (e) {
    throw new Error(`shim stdout is not JSON: ${line} (${String(e)})`, { cause: e });
  }
  if (!parsed.ok) {
    throw new Error(`shim error for op=${String(request.op)}: ${parsed.error}`);
  }
  return parsed.result;
}

function printPrngSeed(): void {
  const source =
    process.env.CROSS_RUST_SEED === undefined
      ? 'default; override with CROSS_RUST_SEED'
      : 'from CROSS_RUST_SEED';
  // process.stdout so the line is not dropped by Vitest console intercept.
  process.stdout.write(
    `[cross-rust] PRNG seed=${PRNG_SEED} (0x${PRNG_SEED.toString(16)}) [${source}]\n`,
  );
}

printPrngSeed();

describe('cross-rust: shim presence is mandatory', () => {
  it('fails loudly when the release binary is absent (gate cannot silently skip)', () => {
    // Positive form: binary must exist for the rest of the suite.
    // Absence throws from requireShim — that is the fail-closed path.
    expect(() => requireShim()).not.toThrow();
  });
});

describe('cross-rust: fixed vectors (deterministic)', () => {
  it('validate_mnemonic agrees on the BIP-39 reference phrase', async () => {
    const js = await validateMnemonic(TEST_MNEMONIC);
    const rust = callShim({ op: 'validate_mnemonic', phrase: TEST_MNEMONIC });
    expect(rust).toBe(js);
    expect(js).toBe(true);
  });

  it('mnemonic_from_entropy agrees on all-zero 16-byte entropy', async () => {
    const entropy = '00'.repeat(16);
    const js = await mnemonicFromEntropy(entropy);
    const rust = callShim({ op: 'mnemonic_from_entropy', entropy_hex: entropy });
    expect(rust).toBe(js);
    expect(js).toBe(TEST_MNEMONIC);
  });

  it('account_from_mnemonic agrees on the BIP-39 reference phrase', async () => {
    const js = await generateAccountKeysFromMnemonic(TEST_MNEMONIC, '');
    const rust = callShim({
      op: 'account_from_mnemonic',
      mnemonic: TEST_MNEMONIC,
      passphrase: '',
    }) as { address: string; xpriv: string; numPubkeys: number };
    expect(rust.address).toBe(js.address);
    expect(rust.xpriv).toBe(js.xpriv);
    expect(rust.numPubkeys).toBe(js.numPubkeys);
  });

  it('derive_public_keys / derive_signing_key / sign_schnorr / create_commitment agree', async () => {
    const keys = await generateAccountKeysFromMnemonic(TEST_MNEMONIC, '');
    const pubsJs = await derivePublicKeys(keys.xpriv, 0);
    const pubsRust = callShim({
      op: 'derive_public_keys',
      xpriv: keys.xpriv,
      num_pubkeys: 0,
    }) as { publicKey: string; nextPublicKey: string };
    expect(pubsRust).toEqual(pubsJs);

    const skJs = await deriveSigningKey(keys.xpriv, 0);
    const skRust = callShim({
      op: 'derive_signing_key',
      xpriv: keys.xpriv,
      index: 0,
    });
    expect(skRust).toBe(skJs);

    const hash = '00'.repeat(32);
    const sigJs = await signSchnorr(skJs, hash);
    const sigRust = callShim({
      op: 'sign_schnorr',
      private_key_hex: skJs,
      hash_hex: hash,
    });
    expect(sigRust).toBe(sigJs);

    const ash = 'aa'.repeat(32);
    const ocr = 'bb'.repeat(32);
    const cJs = await createCommitment(keys.xpriv, 0, ash, ocr);
    const cRust = callShim({
      op: 'create_commitment',
      xpriv: keys.xpriv,
      num_pubkeys: 0,
      account_state_hash_hex: ash,
      output_coins_root_hex: ocr,
    });
    expect(cRust).toEqual(cJs);
  });
});

describe('cross-rust: randomized parity (100 samples per op)', () => {
  beforeAll(() => {
    // Re-print at suite start so the seed is adjacent to the random cases in CI logs.
    printPrngSeed();
  });

  it('mnemonic_from_entropy: 100 random 16-byte entropies', async () => {
    for (let i = 0; i < SAMPLES; i++) {
      const entropy = randomHex(16);
      const js = await mnemonicFromEntropy(entropy);
      const rust = callShim({ op: 'mnemonic_from_entropy', entropy_hex: entropy });
      expect(rust, `sample ${i} seed=${PRNG_SEED} entropy=${entropy}`).toBe(js);
    }
  });

  it('account_from_mnemonic: 100 random entropy-derived mnemonics', async () => {
    for (let i = 0; i < SAMPLES; i++) {
      const entropy = randomHex(16);
      const mnemonic = await mnemonicFromEntropy(entropy);
      const passphrase = i % 3 === 0 ? '' : `pass-${i}`;
      const js = await generateAccountKeysFromMnemonic(mnemonic, passphrase);
      const rust = callShim({
        op: 'account_from_mnemonic',
        mnemonic,
        passphrase,
      }) as { address: string; xpriv: string; numPubkeys: number };
      expect(
        rust.address,
        `sample ${i} seed=${PRNG_SEED} entropy=${entropy} passphrase=${JSON.stringify(passphrase)} address`,
      ).toBe(js.address);
      expect(
        rust.xpriv,
        `sample ${i} seed=${PRNG_SEED} entropy=${entropy} passphrase=${JSON.stringify(passphrase)} xpriv`,
      ).toBe(js.xpriv);
    }
  });

  it('derive_public_keys + derive_signing_key: 100 random indices on a fixed account', async () => {
    const keys = await generateAccountKeysFromMnemonic(TEST_MNEMONIC, '');
    for (let i = 0; i < SAMPLES; i++) {
      const index = i; // 0..99 covers a useful child range
      const pubsJs = await derivePublicKeys(keys.xpriv, index);
      const pubsRust = callShim({
        op: 'derive_public_keys',
        xpriv: keys.xpriv,
        num_pubkeys: index,
      });
      expect(
        pubsRust,
        `pubs sample ${i} seed=${PRNG_SEED} index=${index} xpriv=${keys.xpriv}`,
      ).toEqual(pubsJs);

      const skJs = await deriveSigningKey(keys.xpriv, index);
      const skRust = callShim({
        op: 'derive_signing_key',
        xpriv: keys.xpriv,
        index,
      });
      expect(skRust, `sk sample ${i} seed=${PRNG_SEED} index=${index} xpriv=${keys.xpriv}`).toBe(
        skJs,
      );
    }
  });

  it('sign_schnorr: 100 random (key, hash) pairs', async () => {
    const keys = await generateAccountKeysFromMnemonic(TEST_MNEMONIC, '');
    for (let i = 0; i < SAMPLES; i++) {
      const sk = await deriveSigningKey(keys.xpriv, i % 16);
      const hash = randomHex(32);
      const js = await signSchnorr(sk, hash);
      const rust = callShim({
        op: 'sign_schnorr',
        private_key_hex: sk,
        hash_hex: hash,
      });
      expect(rust, `sample ${i} seed=${PRNG_SEED} private_key_hex=${sk} hash_hex=${hash}`).toBe(js);
    }
  });

  it('create_commitment: 100 random (ash, ocr, index) triples', async () => {
    const keys = await generateAccountKeysFromMnemonic(TEST_MNEMONIC, '');
    for (let i = 0; i < SAMPLES; i++) {
      const index = i % 16;
      const ash = randomHex(32);
      const ocr = randomHex(32);
      const js = await createCommitment(keys.xpriv, index, ash, ocr);
      const rust = callShim({
        op: 'create_commitment',
        xpriv: keys.xpriv,
        num_pubkeys: index,
        account_state_hash_hex: ash,
        output_coins_root_hex: ocr,
      });
      expect(
        rust,
        `sample ${i} seed=${PRNG_SEED} index=${index} ash=${ash} ocr=${ocr} xpriv=${keys.xpriv}`,
      ).toEqual(js);
    }
  });
});

// ── V.8 fully-pinned fixture (Spec-anchored, not merely shim-anchored) ───────

const V8_SK_1 = '22f508c0a93b29fa87ca8d9abcec996f01620656cd7a7e4ab5418b2e76beccf4';
const V8_SK_2 = '86b75c297fd9a0af472d06fbf889f7e4667c9e42b7d7efc8b1ca7e66b95462c0';
const V8_M_SC_1 = 'bf50cc59a665bcdc2b5f0754dd754a73e37552a6b1b69eb9e42c07ddd1ae73e2';
const V8_M_SC_2 = '85d06ebe2f0f5173af9ff8bdd2d4d594303a640d7b2f1c8819d5a48abfa4773d';
const V8_R_1 = 'c41ff1a78f2006e5f5aa800efa84b2d2046d108dfa968909974ec37fcb87f6c4';
const V8_S_1 = '748ae8e2fded9df9830cbaa8893484e753fdfd141cccc8b35a27ab5a870a83d2';
const V8_R_2 = 'bd22b77069c75431ee3676bea7324a59e9b6466a62a9a3021f831e6ccf5d3220';
const V8_S_2 = 'caa0374d3cf77e1874298c98d3d3fe8b416f89d51823d6909c3e1cdbf91d3002';
const V8_S_AGG = 'cfb0c36a8399589b5580ba41cafaf66b7d707443a202e4113f3635872ca58b78';
const V8_PK_1 = 'e7f2a98e7b45e9424e3e0cb1d937a1698ebd339c6d8344906db979642cf20474';
const V8_PK_2 = '21799353e64a65ee4b1f414998c44878c56270cf8a81046cb3636e5ec31a3341';
const V8_R_PRIME_1 = '5657f2e91dc3a2d248501a37dbe674d2cf8ed1a13c89b7710ca89aad3b9fe050';
const V8_R_PRIME_2 = '9c18a07c07be5225b688895f73daaffefdd62cbb49e1b854dd47f5aee1484193';

describe('cross-rust: v1 transition / half-agg (Spec V.8 + randomized)', () => {
  it('transition_sign fixture-nonce matches V.8 for both signers (Spec-anchored)', () => {
    for (const sample of [
      {
        sk: V8_SK_1,
        mSc: V8_M_SC_1,
        r: V8_R_1,
        s: V8_S_1,
        rPrime: V8_R_PRIME_1,
        pk: V8_PK_1,
        ctr: 0,
      },
      {
        sk: V8_SK_2,
        mSc: V8_M_SC_2,
        r: V8_R_2,
        s: V8_S_2,
        rPrime: V8_R_PRIME_2,
        pk: V8_PK_2,
        ctr: 2,
      },
    ]) {
      const js = signTransitionWithFixtureNonce({
        secretKey: hexToBytes(sample.sk),
        network: 'testnet',
        mSc: hexToBytes(sample.mSc),
      });
      const rust = callShim({
        op: 'transition_sign',
        secret_key_hex: sample.sk,
        m_sc_hex: sample.mSc,
        network: 'testnet',
      }) as {
        r_prime: string;
        t: string;
        r: string;
        e: string;
        s: string;
        signature: string;
        s2c_nonce: string;
        pk: string;
        nonce_counter: number;
      };

      expect(bytesToHex(js.r), 'JS R vs V.8').toBe(sample.r);
      expect(bytesToHex(js.s), 'JS s vs V.8').toBe(sample.s);
      expect(bytesToHex(js.rPrime), "JS R' vs V.8").toBe(sample.rPrime);
      expect(js.nonceCounter, 'JS ctr vs V.8').toBe(sample.ctr);

      expect(rust.r, 'Rust R vs V.8').toBe(sample.r);
      expect(rust.s, 'Rust s vs V.8').toBe(sample.s);
      expect(rust.r_prime, "Rust R' vs V.8").toBe(sample.rPrime);
      expect(rust.nonce_counter, 'Rust ctr vs V.8').toBe(sample.ctr);
      expect(rust.signature).toBe(bytesToHex(js.signature));
      expect(rust.t).toBe(bytesToHex(js.t));
      expect(rust.e).toBe(bytesToHex(js.e));
      expect(rust.pk).toBe(sample.pk);
    }
  });

  it('half_agg over V.8 members matches pinned s_agg (Spec-anchored)', () => {
    const members = [
      { pk: hexToBytes(V8_PK_1), r: hexToBytes(V8_R_1), s: hexToBytes(V8_S_1) },
      { pk: hexToBytes(V8_PK_2), r: hexToBytes(V8_R_2), s: hexToBytes(V8_S_2) },
    ];
    const js = aggregateSig(members);
    expect(bytesToHex(js.sAgg)).toBe(V8_S_AGG);

    const rust = callShim({
      op: 'half_agg',
      members: members.map((m) => ({
        pk_hex: bytesToHex(m.pk),
        r_hex: bytesToHex(m.r),
        s_hex: bytesToHex(m.s),
      })),
    }) as { z: string; coefficients: string[]; s_agg: string };

    expect(rust.s_agg).toBe(V8_S_AGG);
    expect(rust.z).toBe(bytesToHex(js.z));
    expect(rust.coefficients).toEqual(js.coefficients.map(bytesToHex));
  });

  it('transition_verify / comm_verify / aggregate_verify agree on V.8 accept + N-19 reject', () => {
    const sig1 = V8_R_1 + V8_S_1;
    expect(
      callShim({
        op: 'transition_verify',
        public_key_hex: V8_PK_1,
        signature_hex: sig1,
        network: 'testnet',
      }),
    ).toBe(true);
    expect(
      verify({
        publicKey: hexToBytes(V8_PK_1),
        signature: hexToBytes(sig1),
        network: 'testnet',
      }),
    ).toBe(true);

    // N-19 cross-network
    expect(
      callShim({
        op: 'transition_verify',
        public_key_hex: V8_PK_1,
        signature_hex: sig1,
        network: 'mainnet',
      }),
    ).toBe(false);
    expect(
      verify({
        publicKey: hexToBytes(V8_PK_1),
        signature: hexToBytes(sig1),
        network: 'mainnet',
      }),
    ).toBe(false);

    expect(
      callShim({
        op: 'comm_verify',
        r_hex: V8_R_1,
        m_sc_hex: V8_M_SC_1,
        r_prime_hex: V8_R_PRIME_1,
      }),
    ).toBe(true);
    expect(
      commVerify({
        r: hexToBytes(V8_R_1),
        mSc: hexToBytes(V8_M_SC_1),
        rPrime: hexToBytes(V8_R_PRIME_1),
      }),
    ).toBe(true);

    const members = [
      { pk_hex: V8_PK_1, r_hex: V8_R_1 },
      { pk_hex: V8_PK_2, r_hex: V8_R_2 },
    ];
    expect(
      callShim({
        op: 'aggregate_verify',
        members,
        s_agg_hex: V8_S_AGG,
        network: 'testnet',
      }),
    ).toBe(true);
    expect(
      aggregateVerify({
        members: [
          { pk: hexToBytes(V8_PK_1), r: hexToBytes(V8_R_1) },
          { pk: hexToBytes(V8_PK_2), r: hexToBytes(V8_R_2) },
        ],
        sAgg: hexToBytes(V8_S_AGG),
        network: 'testnet',
      }),
    ).toBe(true);
  });

  it('transition_sign + verify + comm_verify: 100 random (sk, m_sc) pairs (shim-anchored)', () => {
    const networks = ['mainnet', 'testnet', 'regtest'] as const;
    for (let i = 0; i < SAMPLES; i++) {
      // Sample a valid secret key in [1, n) by hashing PRNG output through the
      // curve order (reject zero).
      let skHex = randomHex(32);
      let skBytes = hexToBytes(skHex);
      // Ensure it's a valid scalar by re-drawing until bip340Normalise accepts.
      for (let attempt = 0; attempt < 16; attempt++) {
        try {
          bip340NormaliseSecret(skBytes);
          break;
        } catch {
          skHex = randomHex(32);
          skBytes = hexToBytes(skHex);
        }
      }
      const mScHex = randomHex(32);
      const network = networks[i % 3];
      if (network === undefined) throw new Error('network');

      const js = signTransitionWithFixtureNonce({
        secretKey: skBytes,
        network,
        mSc: hexToBytes(mScHex),
      });
      const rust = callShim({
        op: 'transition_sign',
        secret_key_hex: skHex,
        m_sc_hex: mScHex,
        network,
      }) as {
        r_prime: string;
        t: string;
        r: string;
        e: string;
        s: string;
        signature: string;
        s2c_nonce: string;
        pk: string;
        nonce_counter: number;
      };

      expect(rust.signature, `sign sample ${i} seed=${PRNG_SEED} sk=${skHex} mSc=${mScHex}`).toBe(
        bytesToHex(js.signature),
      );
      expect(rust.r_prime).toBe(bytesToHex(js.rPrime));
      expect(rust.t).toBe(bytesToHex(js.t));
      expect(rust.r).toBe(bytesToHex(js.r));
      expect(rust.e).toBe(bytesToHex(js.e));
      expect(rust.s).toBe(bytesToHex(js.s));
      expect(rust.nonce_counter).toBe(js.nonceCounter);

      const jsVerify = verify({
        publicKey: js.pk,
        signature: js.signature,
        network,
      });
      const rustVerify = callShim({
        op: 'transition_verify',
        public_key_hex: bytesToHex(js.pk),
        signature_hex: bytesToHex(js.signature),
        network,
      });
      expect(jsVerify, `verify sample ${i}`).toBe(true);
      expect(rustVerify).toBe(true);

      const jsComm = commVerify({
        r: js.r,
        mSc: hexToBytes(mScHex),
        rPrime: js.rPrime,
      });
      const rustComm = callShim({
        op: 'comm_verify',
        r_hex: bytesToHex(js.r),
        m_sc_hex: mScHex,
        r_prime_hex: bytesToHex(js.rPrime),
      });
      expect(jsComm, `comm_verify sample ${i}`).toBe(true);
      expect(rustComm).toBe(true);
    }
  });

  it('half_agg + aggregate_verify: 100 random two-member batches (shim-anchored)', () => {
    // Match the project gate: 100 independent batches per primitive.
    const BATCHES = 100;
    for (let i = 0; i < BATCHES; i++) {
      const network = 'regtest' as const;
      const members = [];
      for (let j = 0; j < 2; j++) {
        let skHex = randomHex(32);
        let skBytes = hexToBytes(skHex);
        for (let attempt = 0; attempt < 16; attempt++) {
          try {
            bip340NormaliseSecret(skBytes);
            break;
          } catch {
            skHex = randomHex(32);
            skBytes = hexToBytes(skHex);
          }
        }
        // Force a few odd-y keys so normalisation is exercised.
        if (j === 1) {
          const raw = BigInt('0x' + skHex);
          const P = schnorr.Point.BASE.multiply(raw % schnorr.Point.Fn.ORDER || 1n);
          if (P.y % 2n === 0n) {
            // Flip to odd-y by using n - sk when the point is even (same pk after norm).
            // Prefer re-draw until odd.
            for (let attempt = 0; attempt < 32; attempt++) {
              skHex = randomHex(32);
              try {
                const n = BigInt('0x' + skHex);
                if (n === 0n || n >= schnorr.Point.Fn.ORDER) continue;
                const Q = schnorr.Point.BASE.multiply(n);
                if (Q.y % 2n === 1n) break;
              } catch {
                /* redraw */
              }
            }
            skBytes = hexToBytes(skHex);
          }
        }
        const mScHex = randomHex(32);
        const signed = signTransitionWithFixtureNonce({
          secretKey: skBytes,
          network,
          mSc: hexToBytes(mScHex),
        });
        members.push({ pk: signed.pk, r: signed.r, s: signed.s });
      }

      const jsAgg = aggregateSig(members);
      const rustAgg = callShim({
        op: 'half_agg',
        members: members.map((m) => ({
          pk_hex: bytesToHex(m.pk),
          r_hex: bytesToHex(m.r),
          s_hex: bytesToHex(m.s),
        })),
      }) as { z: string; coefficients: string[]; s_agg: string };

      expect(rustAgg.s_agg, `half_agg sample ${i} seed=${PRNG_SEED}`).toBe(bytesToHex(jsAgg.sAgg));
      expect(rustAgg.z).toBe(bytesToHex(jsAgg.z));

      const jsOk = aggregateVerify({
        members: members.map((m) => ({ pk: m.pk, r: m.r })),
        sAgg: jsAgg.sAgg,
        network,
      });
      const rustOk = callShim({
        op: 'aggregate_verify',
        members: members.map((m) => ({
          pk_hex: bytesToHex(m.pk),
          r_hex: bytesToHex(m.r),
        })),
        s_agg_hex: bytesToHex(jsAgg.sAgg),
        network,
      });
      expect(jsOk, `aggregate_verify sample ${i}`).toBe(true);
      expect(rustOk).toBe(true);
    }
  });
});
