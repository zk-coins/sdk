import { describe, expect, it } from 'vitest';
import { schnorr } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

import { generateAccountKeysFromMnemonic, deriveSigningKey } from '../src/derivation.js';
import { createCommitment, signSchnorr } from '../src/signing.js';

const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const ZERO_HASH = '0000000000000000000000000000000000000000000000000000000000000000';
const ALL_ONES_HASH = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';

describe('signSchnorr', () => {
  it('produces a 64-byte hex signature', async () => {
    const { xpriv } = await generateAccountKeysFromMnemonic(TEST_MNEMONIC);
    const sk = await deriveSigningKey(xpriv, 0);
    const sig = await signSchnorr(sk, ZERO_HASH);
    expect(sig).toMatch(/^[0-9a-f]{128}$/);
  });

  it('produces a verifying signature (BIP-340)', async () => {
    const { xpriv } = await generateAccountKeysFromMnemonic(TEST_MNEMONIC);
    const sk = await deriveSigningKey(xpriv, 0);
    const sig = await signSchnorr(sk, ZERO_HASH);

    // BIP-340 verify against the x-only pubkey derived from the same secret.
    const xOnlyPub = schnorr.getPublicKey(hexToBytes(sk));
    const ok = schnorr.verify(hexToBytes(sig), hexToBytes(ZERO_HASH), xOnlyPub);
    expect(ok).toBe(true);
  });

  it('is deterministic (no-aux-rand contract matches Rust)', async () => {
    const { xpriv } = await generateAccountKeysFromMnemonic(TEST_MNEMONIC);
    const sk = await deriveSigningKey(xpriv, 0);
    const a = await signSchnorr(sk, ALL_ONES_HASH);
    const b = await signSchnorr(sk, ALL_ONES_HASH);
    expect(a).toBe(b);
  });

  it('different hashes produce different signatures', async () => {
    const { xpriv } = await generateAccountKeysFromMnemonic(TEST_MNEMONIC);
    const sk = await deriveSigningKey(xpriv, 0);
    const a = await signSchnorr(sk, ZERO_HASH);
    const b = await signSchnorr(sk, ALL_ONES_HASH);
    expect(a).not.toBe(b);
  });

  it('throws on non-32-byte private key', async () => {
    await expect(signSchnorr('abcd', ZERO_HASH)).rejects.toThrow(/32 bytes/);
  });

  it('throws on non-32-byte hash', async () => {
    const { xpriv } = await generateAccountKeysFromMnemonic(TEST_MNEMONIC);
    const sk = await deriveSigningKey(xpriv, 0);
    await expect(signSchnorr(sk, 'ab')).rejects.toThrow(/32 bytes/);
  });

  it('throws on invalid hex in private key', async () => {
    await expect(signSchnorr('zzzz', ZERO_HASH)).rejects.toThrow();
  });
});

describe('createCommitment', () => {
  it('returns publicKey, signature, message (all hex)', async () => {
    const { xpriv } = await generateAccountKeysFromMnemonic(TEST_MNEMONIC);
    const ash = '11'.repeat(32);
    const ocr = '22'.repeat(32);
    const c = await createCommitment(xpriv, 0, ash, ocr);
    expect(c.publicKey).toMatch(/^(02|03)[0-9a-f]{64}$/);
    expect(c.signature).toMatch(/^[0-9a-f]{128}$/);
    expect(c.message).toBe(ash + ocr);
  });

  it('signature verifies against sha256(message) under the returned x-only pubkey', async () => {
    const { xpriv } = await generateAccountKeysFromMnemonic(TEST_MNEMONIC);
    const ash = 'aa'.repeat(32);
    const ocr = 'bb'.repeat(32);
    const c = await createCommitment(xpriv, 0, ash, ocr);

    const msgBytes = hexToBytes(c.message);
    const digest = sha256(msgBytes);

    // The commitment ships a compressed pubkey; BIP-340 verify uses
    // the x-only form (drop the parity byte).
    const xOnlyPub = hexToBytes(c.publicKey).slice(1);
    const ok = schnorr.verify(hexToBytes(c.signature), digest, xOnlyPub);
    expect(ok).toBe(true);
  });

  it('is deterministic for the same xpriv + index + ash + ocr', async () => {
    const { xpriv } = await generateAccountKeysFromMnemonic(TEST_MNEMONIC);
    const ash = 'ab'.repeat(32);
    const ocr = 'cd'.repeat(32);
    const a = await createCommitment(xpriv, 3, ash, ocr);
    const b = await createCommitment(xpriv, 3, ash, ocr);
    expect(a).toEqual(b);
  });

  it('different signing index produces different signature + publicKey', async () => {
    const { xpriv } = await generateAccountKeysFromMnemonic(TEST_MNEMONIC);
    const ash = '11'.repeat(32);
    const ocr = '22'.repeat(32);
    const a = await createCommitment(xpriv, 0, ash, ocr);
    const b = await createCommitment(xpriv, 1, ash, ocr);
    expect(a.publicKey).not.toBe(b.publicKey);
    expect(a.signature).not.toBe(b.signature);
    expect(a.message).toBe(b.message); // message doesn't depend on index
  });

  it('different ash + ocr produce different signatures', async () => {
    const { xpriv } = await generateAccountKeysFromMnemonic(TEST_MNEMONIC);
    const a = await createCommitment(xpriv, 0, '11'.repeat(32), '22'.repeat(32));
    const b = await createCommitment(xpriv, 0, '33'.repeat(32), '44'.repeat(32));
    expect(a.signature).not.toBe(b.signature);
    expect(a.message).not.toBe(b.message);
  });

  it('accepts non-32-byte ash/ocr (message is opaque to this builder)', async () => {
    // Layout matches Rust which decodes hex then concatenates — no
    // length check. The server-side may reject odd shapes; the SDK
    // does not double-validate.
    const { xpriv } = await generateAccountKeysFromMnemonic(TEST_MNEMONIC);
    const c = await createCommitment(xpriv, 0, 'aa', 'bbbb');
    expect(c.message).toBe('aabbbb');
  });

  it('throws on invalid hex in ash or ocr', async () => {
    const { xpriv } = await generateAccountKeysFromMnemonic(TEST_MNEMONIC);
    await expect(createCommitment(xpriv, 0, 'zz', 'aa')).rejects.toThrow();
    await expect(createCommitment(xpriv, 0, 'aa', 'zz')).rejects.toThrow();
  });

  it('reused signing key produces identical signature output across primitives', async () => {
    // Sanity: the createCommitment hex output equals what you'd get
    // by hand-rolling derive → hash → sign.
    const { xpriv } = await generateAccountKeysFromMnemonic(TEST_MNEMONIC);
    const ash = 'de'.repeat(32);
    const ocr = 'ad'.repeat(32);

    const c = await createCommitment(xpriv, 2, ash, ocr);

    const sk = await deriveSigningKey(xpriv, 2);
    const digest = sha256(hexToBytes(ash + ocr));
    const sig = await signSchnorr(sk, bytesToHex(digest));

    expect(c.signature).toBe(sig);
  });
});
