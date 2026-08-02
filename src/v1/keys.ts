/**
 * v1 BIP-32 key hierarchy (§1.2): `A = m/1798'/account'`, SPEND `A/0'/i'`.
 *
 * All branch separations are hardened. This module is independent of the
 * legacy non-hardened derivation in `src/derivation.ts`.
 *
 * Pinned V.2-ext (mnemonic `abandon…about`, account 0):
 *   sk₀ = m/1798'/0'/0'/0'
 *   skᵢ = m/1798'/0'/0'/i'
 */

import { HDKey } from '@scure/bip32';
import { mnemonicToSeedSync, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';

import { expectPresent } from './expectPresent.js';
import { bip340NormaliseSecret } from './transitionSignature.js';

/** BIP-43 purpose index for zkCoins (§1.2 D17). */
export const ZKCOINS_PURPOSE = 1798;

/** SPEND branch under account root A (§1.2). */
export const SPEND_BRANCH = 0;

export interface SpendKey {
  /** BIP-32 child private key (32 bytes, pre BIP-340 even-y normalisation). */
  secretKey: Uint8Array;
  /** BIP-340 x-only public key (32 bytes, even-y). */
  publicKey: Uint8Array;
  /** Hardened account index. */
  account: number;
  /** SPEND child index i (`send_counter`). */
  index: number;
  /** BIP-32 path string, e.g. `m/1798'/0'/0'/3'`. */
  path: string;
}

function requireNonNegInt(n: number, label: string): number {
  if (!Number.isInteger(n) || n < 0 || n > 0x7fffffff) {
    throw new Error(`${label}: expected integer in [0, 2^31-1], got ${String(n)}`);
  }
  return n;
}

function masterFromSeed(seed: Uint8Array): HDKey {
  if (!(seed instanceof Uint8Array) || seed.length === 0) {
    throw new Error('v1 keys: seed must be a non-empty Uint8Array');
  }
  // BIP-39 seed is 64 bytes; BIP-32 also accepts other lengths — refuse empty only.
  return HDKey.fromMasterSeed(seed);
}

/**
 * Derive the SPEND key `skᵢ = A/0'/i'` = `m/1798'/account'/0'/index'`.
 *
 * `publicKey` is the BIP-340 x-only encoding after even-y normalisation — the
 * form that must equal `current_pubkey` / `txn_pubkey` on the wire.
 */
export function deriveSpendKey(seed: Uint8Array, account: number, index: number): SpendKey {
  const acc = requireNonNegInt(account, 'account');
  const i = requireNonNegInt(index, 'index');
  const path = `m/${ZKCOINS_PURPOSE}'/${acc}'/${SPEND_BRANCH}'/${i}'`;
  const master = masterFromSeed(seed);
  const child = master.derive(path);
  // Fail-closed on missing key material. With a real seed this always
  // returns: path is fully hardened from HDKey.fromMasterSeed, and
  // @scure/bip32 then always sets privateKey (hardened derive from a
  // public-only parent throws instead). The throw arm lives in
  // expectPresent and is covered via other call sites.
  const secretKey = expectPresent(
    child.privateKey,
    `deriveSpendKey: no private key at ${path}`,
  ).slice();
  const { pkBytes } = bip340NormaliseSecret(secretKey);
  return {
    secretKey,
    publicKey: pkBytes,
    account: acc,
    index: i,
    path,
  };
}

/** `sk₀` — initial signing key that, with `nk_commit`, fixes the address. */
export function deriveSk0(seed: Uint8Array, account: number): SpendKey {
  return deriveSpendKey(seed, account, 0);
}

/**
 * BIP-39 → 64-byte seed for v1 (§1.2): empty passphrase only.
 * A non-empty passphrase is a v2 feature and is refused here.
 *
 * Validates wordlist membership and BIP-39 checksum before deriving —
 * a typo must not silently produce a different, unrecoverable account.
 */
export function seedFromMnemonicV1(mnemonic: string, passphrase?: string): Uint8Array {
  if (passphrase !== undefined && passphrase.length > 0) {
    throw new Error(
      'seedFromMnemonicV1: non-empty BIP-39 passphrase is not applicable in v1 (§1.2)',
    );
  }
  if (typeof mnemonic !== 'string' || mnemonic.trim().length === 0) {
    throw new Error('seedFromMnemonicV1: mnemonic is required');
  }
  if (!validateMnemonic(mnemonic, wordlist)) {
    throw new Error(
      'seedFromMnemonicV1: invalid BIP-39 mnemonic (unknown word, wrong word count, or bad checksum)',
    );
  }
  return mnemonicToSeedSync(mnemonic, '');
}

/**
 * x-only public key from a raw 32-byte secret (BIP-340 normalised).
 * Exposed for tests that pin V.2-ext without going through BIP-32.
 */
export function xOnlyPubkeyFromSecret(secretKey: Uint8Array): Uint8Array {
  return bip340NormaliseSecret(secretKey).pkBytes;
}
