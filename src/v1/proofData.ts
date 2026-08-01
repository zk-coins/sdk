/**
 * `ProofData` public inputs and their canonical serialization (§1.4).
 *
 * Field order (fixed, 6 × 32 bytes = 192 bytes):
 *   1. new_account_state_hash
 *   2. output_coins_root
 *   3. input_nullifiers_root
 *   4. coin_history_root
 *   5. nav_commitment
 *   6. npk_commit
 *
 * `H(ProofData) = SHA-256(serialize(ProofData))` is the sign-to-contract tweak
 * digest committed in the transition signature nonce (§3.2).
 *
 * Beleg: spec §1.4 (`serialize(ProofData) := …` in that exact order);
 * Rust `shared/src/spec_v1/serialize.rs` `serialize_proof_data` (lines 160–169).
 */

import { sha256 } from '@noble/hashes/sha2.js';

/** Fixed width of one ProofData field / of H(ProofData). */
export const PROOF_DATA_FIELD_LEN = 32;
/** Fixed width of `serialize(ProofData)`. */
export const PROOF_DATA_SERIALIZED_LEN = 192;

/**
 * The six public inputs of the per-account compliance proof.
 * Each field is a raw 32-byte digest (not hex).
 */
export interface ProofData {
  newAccountStateHash: Uint8Array;
  outputCoinsRoot: Uint8Array;
  inputNullifiersRoot: Uint8Array;
  coinHistoryRoot: Uint8Array;
  navCommitment: Uint8Array;
  npkCommit: Uint8Array;
}

function requireField32(field: Uint8Array, name: string): void {
  if (!(field instanceof Uint8Array)) {
    throw new Error(`ProofData.${name}: expected Uint8Array`);
  }
  if (field.length !== PROOF_DATA_FIELD_LEN) {
    throw new Error(
      `ProofData.${name}: expected ${PROOF_DATA_FIELD_LEN} bytes, got ${field.length}`,
    );
  }
}

/**
 * Validate that every field is exactly 32 bytes. Loud on any mismatch —
 * no silent pad/truncate.
 */
export function assertProofData(pd: ProofData): void {
  requireField32(pd.newAccountStateHash, 'newAccountStateHash');
  requireField32(pd.outputCoinsRoot, 'outputCoinsRoot');
  requireField32(pd.inputNullifiersRoot, 'inputNullifiersRoot');
  requireField32(pd.coinHistoryRoot, 'coinHistoryRoot');
  requireField32(pd.navCommitment, 'navCommitment');
  requireField32(pd.npkCommit, 'npkCommit');
}

/**
 * Canonical 192-byte serialization of `ProofData` in the §1.4 field order.
 */
export function serializeProofData(pd: ProofData): Uint8Array {
  assertProofData(pd);
  const out = new Uint8Array(PROOF_DATA_SERIALIZED_LEN);
  out.set(pd.newAccountStateHash, 0);
  out.set(pd.outputCoinsRoot, 32);
  out.set(pd.inputNullifiersRoot, 64);
  out.set(pd.coinHistoryRoot, 96);
  out.set(pd.navCommitment, 128);
  out.set(pd.npkCommit, 160);
  return out;
}

/**
 * `H(ProofData) = SHA-256(serialize(ProofData))` — the S2C commitment digest.
 */
export function hashProofData(pd: ProofData): Uint8Array {
  return sha256(serializeProofData(pd));
}
