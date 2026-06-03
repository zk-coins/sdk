/**
 * BIP-340 Schnorr signing primitives.
 *
 * Pure-JS replacement for the WASM exports `sign_schnorr` and
 * `create_commitment` in `zk-coins/app/rust/client/src/lib.rs`.
 *
 * **Determinism contract.** Rust signs via
 * `secp.sign_schnorr_no_aux_rand(&msg, &keypair)` — BIP-340 with
 * the aux-rand argument forced to all-zeros, which makes the
 * nonce deterministic. We replicate this by passing a 32-byte
 * zero-filled `auxRand` to `@noble/curves/secp256k1.js::schnorr.sign`.
 * Without this match, every signature would differ between Rust
 * and JS for the same inputs — and the cross-test would fail.
 *
 * Both inputs and outputs are hex-encoded — same wire shape as
 * the WASM-era exports, so the migration to this SDK is a pure
 * import-path rename for consumers.
 */

import { schnorr } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

import { deriveSigningKey, derivePublicKeys } from './derivation.js';

/** All-zero 32-byte auxRand → deterministic BIP-340 (matches Rust). */
const NO_AUX_RAND = new Uint8Array(32);

/**
 * Sign a 32-byte hash with a Schnorr signature.
 *
 * Both inputs are hex-encoded 32-byte strings. Returns the hex-
 * encoded 64-byte BIP-340 signature. Throws on bad hex, wrong
 * length, or invalid secret.
 *
 * Mirrors Rust's `sign_schnorr(private_key_hex, hash_hex)`.
 */
export async function signSchnorr(privateKeyHex: string, hashHex: string): Promise<string> {
  const privateKey = hexToBytes(privateKeyHex);
  if (privateKey.length !== 32) {
    throw new Error(`signSchnorr: private key must be 32 bytes, got ${privateKey.length}`);
  }
  const hash = hexToBytes(hashHex);
  if (hash.length !== 32) {
    throw new Error(`signSchnorr: hash must be 32 bytes, got ${hash.length}`);
  }
  const sig = schnorr.sign(hash, privateKey, NO_AUX_RAND);
  return bytesToHex(sig);
}

/** Output of `createCommitment` — what the API's `/api/commit` consumes. */
export interface Commitment {
  /** Compressed SEC1 public key at the signing index, hex (33 bytes). */
  publicKey: string;
  /** BIP-340 Schnorr signature over `sha256(message)`, hex (64 bytes). */
  signature: string;
  /** Pre-hash message bytes = ash || ocr, hex (typically 64 bytes). */
  message: string;
}

/**
 * Build the two-phase send commitment.
 *
 * Layout (matches `Commitment::new` server-side and the WASM
 * reference in `zk-coins/app/rust/client/`):
 *
 *   1. Concat `account_state_hash || output_coins_root`. Both are
 *      hex-decoded first, then concatenated as raw bytes.
 *   2. Hash the concat with SHA-256 → 32-byte digest.
 *   3. Schnorr-sign the digest with the private key derived from
 *      `xpriv` at index `numPubkeys` (deterministic nonce).
 *   4. Return the commitment with the compressed public key at the
 *      same index, the signature, and the **un-hashed** message
 *      bytes (the server re-hashes to verify).
 */
export async function createCommitment(
  xpriv: string,
  numPubkeys: number,
  accountStateHashHex: string,
  outputCoinsRootHex: string,
): Promise<Commitment> {
  const ash = hexToBytes(accountStateHashHex);
  const ocr = hexToBytes(outputCoinsRootHex);
  const message = new Uint8Array(ash.length + ocr.length);
  message.set(ash, 0);
  message.set(ocr, ash.length);

  const digest = sha256(message);

  const privateKeyHex = await deriveSigningKey(xpriv, numPubkeys);
  const signatureHex = await signSchnorr(privateKeyHex, bytesToHex(digest));

  // The commitment also reports the public key at the signing index.
  // `derivePublicKeys` returns the current + next pubkey; we use the
  // current.
  const { publicKey } = await derivePublicKeys(xpriv, numPubkeys);

  return {
    publicKey,
    signature: signatureHex,
    message: bytesToHex(message),
  };
}
