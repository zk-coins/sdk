import { describe, expect, it } from 'vitest';

import {
  derivePublicKeys,
  deriveSigningKey,
  generateAccountKeys,
  generateAccountKeysFromMnemonic,
  generateMnemonic,
  mnemonicFromEntropy,
  validateMnemonic,
} from '../src/derivation.js';

// Canonical BIP-39 test vector (all-`abandon` + `about` checksum).
const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

// 16 bytes of entropy — known-valid for BIP-39 128-bit input.
const TEST_ENTROPY_HEX = '00000000000000000000000000000000';
const TEST_ENTROPY_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

describe('generateMnemonic', () => {
  it('produces a 12-word phrase', async () => {
    const phrase = await generateMnemonic();
    expect(phrase.split(/\s+/)).toHaveLength(12);
  });

  it('produces a valid mnemonic (checksum holds)', async () => {
    const phrase = await generateMnemonic();
    expect(await validateMnemonic(phrase)).toBe(true);
  });

  it('produces distinct phrases on repeated calls (CSPRNG sanity)', async () => {
    const a = await generateMnemonic();
    const b = await generateMnemonic();
    expect(a).not.toBe(b);
  });
});

describe('validateMnemonic', () => {
  it('accepts the canonical test vector', async () => {
    expect(await validateMnemonic(TEST_MNEMONIC)).toBe(true);
  });

  it('rejects an arbitrary string', async () => {
    expect(await validateMnemonic('not a valid mnemonic')).toBe(false);
  });

  it('rejects a too-short phrase', async () => {
    expect(await validateMnemonic('abandon abandon abandon')).toBe(false);
  });

  it('rejects an empty string', async () => {
    expect(await validateMnemonic('')).toBe(false);
  });

  it('rejects a phrase with bad checksum', async () => {
    // 12 valid words but bad checksum (last word swapped from `about` to `ability`)
    expect(
      await validateMnemonic(
        'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ability',
      ),
    ).toBe(false);
  });
});

describe('mnemonicFromEntropy', () => {
  it('produces the canonical all-zeros vector', async () => {
    expect(await mnemonicFromEntropy(TEST_ENTROPY_HEX)).toBe(TEST_ENTROPY_MNEMONIC);
  });

  it('is deterministic for the same entropy', async () => {
    const a = await mnemonicFromEntropy(TEST_ENTROPY_HEX);
    const b = await mnemonicFromEntropy(TEST_ENTROPY_HEX);
    expect(a).toBe(b);
  });

  it('throws on invalid hex', async () => {
    await expect(mnemonicFromEntropy('zz')).rejects.toThrow();
  });

  it('throws on wrong-length entropy (8 bytes instead of 16)', async () => {
    await expect(mnemonicFromEntropy('00000000000000ff')).rejects.toThrow();
  });
});

describe('generateAccountKeys', () => {
  it('produces all three fields', async () => {
    const keys = await generateAccountKeys();
    expect(keys.address).toMatch(/^[0-9a-f]{64}$/);
    expect(keys.xpriv).toMatch(/^xprv/);
    expect(keys.numPubkeys).toBe(0);
  });

  it('produces distinct accounts on repeated calls (CSPRNG sanity)', async () => {
    const a = await generateAccountKeys();
    const b = await generateAccountKeys();
    expect(a.xpriv).not.toBe(b.xpriv);
    expect(a.address).not.toBe(b.address);
  });
});

describe('generateAccountKeysFromMnemonic', () => {
  it('is deterministic for the same mnemonic + passphrase', async () => {
    const a = await generateAccountKeysFromMnemonic(TEST_MNEMONIC);
    const b = await generateAccountKeysFromMnemonic(TEST_MNEMONIC);
    expect(a).toEqual(b);
  });

  it('passphrase changes the derived account', async () => {
    const a = await generateAccountKeysFromMnemonic(TEST_MNEMONIC);
    const b = await generateAccountKeysFromMnemonic(TEST_MNEMONIC, 'extra-secret');
    expect(a.xpriv).not.toBe(b.xpriv);
    expect(a.address).not.toBe(b.address);
  });

  it('address is 32 bytes (64 hex chars)', async () => {
    const keys = await generateAccountKeysFromMnemonic(TEST_MNEMONIC);
    expect(keys.address).toMatch(/^[0-9a-f]{64}$/);
  });

  it('numPubkeys starts at 0', async () => {
    const keys = await generateAccountKeysFromMnemonic(TEST_MNEMONIC);
    expect(keys.numPubkeys).toBe(0);
  });

  it('xpriv has the mainnet base58 prefix', async () => {
    const keys = await generateAccountKeysFromMnemonic(TEST_MNEMONIC);
    expect(keys.xpriv.startsWith('xprv')).toBe(true);
  });
});

describe('derivePublicKeys', () => {
  it('returns 33-byte compressed pubkeys (current + next)', async () => {
    const { xpriv } = await generateAccountKeysFromMnemonic(TEST_MNEMONIC);
    const { publicKey, nextPublicKey } = await derivePublicKeys(xpriv, 0);
    expect(publicKey).toMatch(/^(02|03)[0-9a-f]{64}$/);
    expect(nextPublicKey).toMatch(/^(02|03)[0-9a-f]{64}$/);
    expect(publicKey).not.toBe(nextPublicKey);
  });

  it('is deterministic for the same xpriv + index', async () => {
    const { xpriv } = await generateAccountKeysFromMnemonic(TEST_MNEMONIC);
    const a = await derivePublicKeys(xpriv, 5);
    const b = await derivePublicKeys(xpriv, 5);
    expect(a).toEqual(b);
  });

  it('different indices produce different pubkeys', async () => {
    const { xpriv } = await generateAccountKeysFromMnemonic(TEST_MNEMONIC);
    const a = await derivePublicKeys(xpriv, 0);
    const b = await derivePublicKeys(xpriv, 7);
    expect(a.publicKey).not.toBe(b.publicKey);
  });

  it('throws on a malformed xpriv string', async () => {
    await expect(derivePublicKeys('not an xpriv', 0)).rejects.toThrow();
  });
});

describe('deriveSigningKey', () => {
  it('returns a 32-byte hex string', async () => {
    const { xpriv } = await generateAccountKeysFromMnemonic(TEST_MNEMONIC);
    const sk = await deriveSigningKey(xpriv, 0);
    expect(sk).toMatch(/^[0-9a-f]{64}$/);
  });

  it('is deterministic for the same xpriv + index', async () => {
    const { xpriv } = await generateAccountKeysFromMnemonic(TEST_MNEMONIC);
    const a = await deriveSigningKey(xpriv, 3);
    const b = await deriveSigningKey(xpriv, 3);
    expect(a).toBe(b);
  });

  it('different indices produce different signing keys', async () => {
    const { xpriv } = await generateAccountKeysFromMnemonic(TEST_MNEMONIC);
    const a = await deriveSigningKey(xpriv, 0);
    const b = await deriveSigningKey(xpriv, 1);
    expect(a).not.toBe(b);
  });

  it('throws when handed an xpub (no privateKey)', async () => {
    const { xpriv } = await generateAccountKeysFromMnemonic(TEST_MNEMONIC);
    // Manually compute the xpub by re-importing as a public-only key.
    // @scure/bip32 exposes `publicExtendedKey` from a private one — use
    // that to construct an xpub-only HDKey for the test.
    const { HDKey } = await import('@scure/bip32');
    const xpub = HDKey.fromExtendedKey(xpriv).publicExtendedKey;
    await expect(deriveSigningKey(xpub, 0)).rejects.toThrow(/no privateKey/);
  });

  it('throws on a malformed xpriv string', async () => {
    await expect(deriveSigningKey('not an xpriv', 0)).rejects.toThrow();
  });
});
