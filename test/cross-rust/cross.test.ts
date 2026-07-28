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
      throw new Error(`XorShift32.bytes: byteLen must be a non-negative integer, got ${String(byteLen)}`);
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
  const parsed = raw.startsWith('0x') || raw.startsWith('0X') ? Number.parseInt(raw, 16) : Number.parseInt(raw, 10);
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
    throw new Error(`shim stdout is not JSON: ${line} (${String(e)})`);
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
      expect(pubsRust, `pubs sample ${i} seed=${PRNG_SEED} index=${index} xpriv=${keys.xpriv}`).toEqual(
        pubsJs,
      );

      const skJs = await deriveSigningKey(keys.xpriv, index);
      const skRust = callShim({
        op: 'derive_signing_key',
        xpriv: keys.xpriv,
        index,
      });
      expect(skRust, `sk sample ${i} seed=${PRNG_SEED} index=${index} xpriv=${keys.xpriv}`).toBe(skJs);
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
