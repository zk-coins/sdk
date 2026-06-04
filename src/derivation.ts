/**
 * BIP-39 mnemonic + BIP-32 HD-derivation primitives.
 *
 * Pure-JS replacement for the corresponding WASM exports in
 * `zk-coins/app/rust/client/src/lib.rs` (functions `generate_mnemonic`,
 * `validate_mnemonic`, `mnemonic_from_entropy`, `generate_account_keys`,
 * `generate_account_keys_from_mnemonic`, `derive_public_keys`,
 * `derive_signing_key`).
 *
 * The behaviour is byte-equivalent to the Rust reference — the
 * `test/cross-rust/` suite asserts this for 100 randomized inputs per
 * function. The contract is:
 *
 *   - BIP-39 entropy is **16 bytes (128 bits)** → 12-word mnemonic.
 *   - BIP-32 master xpriv is mainnet-prefixed (`xprv...`) regardless of
 *     which Bitcoin network the SDK is talking to; the prefix is a
 *     parser hint, not a chain selector.
 *   - The wallet address is `sha256(publicKey_at_index_0)` truncated to
 *     32 bytes (no truncation needed — sha256 is already 32 bytes).
 *   - Child key derivation is **non-hardened** (`ChildNumber::Normal`
 *     in Rust = `HDKey.deriveChild(index)` with `index < 0x80000000`).
 *     Single-step from master xpriv; no BIP-44 / BIP-84 path levels.
 *
 * Functions are `async` even though the underlying libraries are
 * synchronous — this keeps the SDK's public surface identical to the
 * WASM-era exports (every consumer call site uses `await`), so the
 * future "drop @zkcoins/wasm" follow-up PR on `zk-coins/app` becomes
 * a pure import-path rename.
 */

import { generateMnemonic as scureGenerateMnemonic } from '@scure/bip39';
import {
  entropyToMnemonic,
  mnemonicToSeedSync,
  validateMnemonic as scureValidateMnemonic,
} from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { HDKey } from '@scure/bip32';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

/** Account material returned by `generateAccountKeys` and friends. */
export interface AccountKeys {
  /** 32-byte sha256(publicKey at index 0), hex-encoded. */
  address: string;
  /** Base58-encoded BIP-32 master extended private key (mainnet prefix). */
  xpriv: string;
  /** Index counter for the next outgoing pubkey. Starts at 0. */
  numPubkeys: number;
}

/** Generate a fresh 12-word BIP-39 mnemonic from CSPRNG entropy (128 bits). */
export async function generateMnemonic(): Promise<string> {
  return scureGenerateMnemonic(wordlist, 128);
}

/** True if the phrase parses as a valid BIP-39 English mnemonic. */
export async function validateMnemonic(phrase: string): Promise<boolean> {
  return scureValidateMnemonic(phrase, wordlist);
}

/**
 * Deterministic BIP-39 mnemonic from 16-byte entropy (hex).
 *
 * Used by the passkey-PRF flow in `zk-coins/app/src/lib/crypto/
 * key-derivation.ts`: PRF output → HKDF → 16 bytes → mnemonic. The
 * 16-byte size is hard-coded to match Rust's `mnemonic_from_entropy`.
 */
export async function mnemonicFromEntropy(entropyHex: string): Promise<string> {
  const entropy = hexToBytes(entropyHex);
  return entropyToMnemonic(entropy, wordlist);
}

/**
 * Generate a brand-new account from CSPRNG-sourced seed.
 *
 * Mirrors Rust's `generate_account_keys` (which calls
 * `new_master_private_key` → 32 random bytes → `Xpriv::new_master`).
 * The seed length here is 32 bytes specifically so the cross-test can
 * reproduce: if the seed length differed the xpriv would differ.
 */
export async function generateAccountKeys(): Promise<AccountKeys> {
  const seed = new Uint8Array(32);
  crypto.getRandomValues(seed);
  return accountFromSeed(seed);
}

/**
 * Derive an account from a BIP-39 mnemonic + optional passphrase.
 *
 * Mirrors Rust's `generate_account_keys_from_mnemonic` which calls
 * `mnemonic_to_seed(mnemonic, passphrase)` (standard BIP-39 PBKDF2 →
 * 64 bytes) then `master_private_key_from_seed(seed)`.
 */
export async function generateAccountKeysFromMnemonic(
  mnemonic: string,
  passphrase = '',
): Promise<AccountKeys> {
  const seed = mnemonicToSeedSync(mnemonic, passphrase);
  return accountFromSeed(seed);
}

/**
 * Derive the current + next compressed public keys for an outgoing send.
 *
 * `numPubkeys` is the **current** index; `numPubkeys + 1` is the next.
 * The wire format is hex-encoded compressed SEC1 (33 bytes, `02`/`03`
 * prefix). Mirrors Rust's `derive_public_keys`.
 */
export async function derivePublicKeys(
  xpriv: string,
  numPubkeys: number,
): Promise<{ publicKey: string; nextPublicKey: string }> {
  const hd = HDKey.fromExtendedKey(xpriv);
  const child = hd.deriveChild(numPubkeys);
  const next = hd.deriveChild(numPubkeys + 1);
  /* c8 ignore start — defensive guard against @scure/bip32 typing
     `publicKey?: Uint8Array`. In practice a child derived from an HDKey
     that has a privateKey *always* yields a publicKey; this throw
     exists to satisfy strict null-checking, not to handle a runtime
     path. */
  if (!child.publicKey || !next.publicKey) {
    throw new Error('derivePublicKeys: HDKey produced no publicKey for the derived child');
  }
  /* c8 ignore stop */
  return {
    publicKey: bytesToHex(child.publicKey),
    nextPublicKey: bytesToHex(next.publicKey),
  };
}

/**
 * Derive the raw 32-byte private key at a given BIP-32 non-hardened
 * index. The output is hex-encoded and intended to be fed straight
 * into `signSchnorr(privateKeyHex, hashHex)`.
 *
 * Mirrors Rust's `derive_signing_key`.
 */
export async function deriveSigningKey(xpriv: string, index: number): Promise<string> {
  const hd = HDKey.fromExtendedKey(xpriv);
  const child = hd.deriveChild(index);
  if (!child.privateKey) {
    throw new Error(
      'deriveSigningKey: HDKey produced no privateKey — the supplied xpriv is likely an xpub',
    );
  }
  return bytesToHex(child.privateKey);
}

/**
 * Common path from a master seed to `{ address, xpriv, numPubkeys }`.
 *
 * Identical to Rust's `ClientAccount::new(master_xpriv)`:
 *   1. `HDKey.fromMasterSeed(seed)` → master xpriv
 *   2. derive child at index 0 (non-hardened)
 *   3. address = sha256(compressed publicKey at index 0)
 *   4. numPubkeys initialised to 0
 */
function accountFromSeed(seed: Uint8Array): AccountKeys {
  const hd = HDKey.fromMasterSeed(seed);
  const pk0 = hd.deriveChild(0).publicKey;
  /* c8 ignore next 3 — same defensive guard as in derivePublicKeys;
     `HDKey.fromMasterSeed` always produces a private key, so the
     derived child always exposes a public key in practice. */
  if (!pk0) {
    throw new Error('accountFromSeed: HDKey produced no publicKey for child 0');
  }
  const address = sha256(pk0);
  return {
    address: bytesToHex(address),
    xpriv: hd.privateExtendedKey,
    numPubkeys: 0,
  };
}
