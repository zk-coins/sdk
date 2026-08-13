/**
 * Pre-sign refusals (§7.5 wallet-side recomputation).
 *
 * A wallet is not a signature automaton: it refuses unless the three bindings
 * hold. Each refusal is a distinct error class carrying the two compared values.
 */

import {
  KeyBindingRefusalError,
  NetworkMismatchRefusalError,
  NpkCommitRefusalError,
  ProofDataHashRefusalError,
} from './errors.js';
import { bytesEqual, decodeHexExact, encodeHexLower } from './hex.js';
import { xOnlyPubkeyFromSecret } from './keys.js';
import type { Network } from './mstate.js';
import { computeNpkCommit } from './ownership.js';
import { hashProofData, type ProofData } from './proofData.js';
import { signTransition, type TransitionSignature } from './transitionSignature.js';

/** Wire shape of `awaiting_signature` (§7.5 L2961–L2970; api/src/jobs.rs L573–585). */
export interface AwaitingSignature {
  new_account_state_hash: string;
  output_coins_root: string;
  input_nullifiers_root: string;
  coin_history_root: string;
  nav_commitment: string;
  npk_commit: string;
  proof_data_hash: string;
  txn_pubkey: string;
  send_counter: number;
}

/** Subset of `GET /v1/account/state` needed for the key-binding check. */
export interface AccountStateHead {
  current_pubkey: string;
  send_counter: number;
}

function proofDataFromAwaiting(a: AwaitingSignature): ProofData {
  return {
    newAccountStateHash: decodeHexExact(
      a.new_account_state_hash,
      32,
      'awaiting_signature.new_account_state_hash',
    ),
    outputCoinsRoot: decodeHexExact(
      a.output_coins_root,
      32,
      'awaiting_signature.output_coins_root',
    ),
    inputNullifiersRoot: decodeHexExact(
      a.input_nullifiers_root,
      32,
      'awaiting_signature.input_nullifiers_root',
    ),
    coinHistoryRoot: decodeHexExact(
      a.coin_history_root,
      32,
      'awaiting_signature.coin_history_root',
    ),
    navCommitment: decodeHexExact(a.nav_commitment, 32, 'awaiting_signature.nav_commitment'),
    npkCommit: decodeHexExact(a.npk_commit, 32, 'awaiting_signature.npk_commit'),
  };
}

/**
 * Run the three (plus npk_commit) refusals and, if all pass, sign with the
 * **recomputed** `H(ProofData)` — never the server-supplied digest alone.
 *
 * @param localPubkey  `derive(A/0'/send_counter).pubkey` (BIP-340 x-only)
 * @param secretKey    the matching `skᵢ` (raw BIP-32 child)
 * @param walletNetwork  network the wallet was configured for (`m_state`)
 * @param nodeNetwork  network from `GET /v1/info` when known; if both are set
 *                     and disagree → {@link NetworkMismatchRefusalError}
 */
export function refuseOrSignTransition(input: {
  localPubkey: Uint8Array;
  secretKey: Uint8Array;
  accountState: AccountStateHead;
  awaiting: AwaitingSignature;
  walletNetwork: Network;
  nodeNetwork?: Network;
  /** Wallet-chosen rotation key (32 bytes). Required for npk_commit check. */
  nextPubkey: Uint8Array;
  /** Fresh `npk_rand` the wallet supplied on `POST /v1/tx` (32 bytes). */
  npkRand: Uint8Array;
}): TransitionSignature {
  const { awaiting, accountState } = input;

  // ── Refusal 3: network (when both sides known) ──────────────────────────
  if (input.nodeNetwork !== undefined && input.nodeNetwork !== input.walletNetwork) {
    throw new NetworkMismatchRefusalError({
      walletNetwork: input.walletNetwork,
      nodeNetwork: input.nodeNetwork,
    });
  }

  // ── Refusal 1: key binding (all three must match) ───────────────────────
  const txnPubkey = decodeHexExact(awaiting.txn_pubkey, 32, 'awaiting_signature.txn_pubkey');
  const currentPubkey = decodeHexExact(
    accountState.current_pubkey,
    32,
    'account_state.current_pubkey',
  );
  if (awaiting.send_counter !== accountState.send_counter) {
    // send_counter disagreement is part of the same binding: the node is
    // proposing a different transition index than the head the wallet holds.
    throw new KeyBindingRefusalError({
      localPubkey: input.localPubkey,
      currentPubkey,
      txnPubkey,
      sendCounter: awaiting.send_counter,
    });
  }
  if (
    !bytesEqual(input.localPubkey, currentPubkey) ||
    !bytesEqual(input.localPubkey, txnPubkey) ||
    !bytesEqual(currentPubkey, txnPubkey)
  ) {
    throw new KeyBindingRefusalError({
      localPubkey: input.localPubkey,
      currentPubkey,
      txnPubkey,
      sendCounter: awaiting.send_counter,
    });
  }

  // ── npk_commit: wallet-verifiable rotation (§7.5 (a)) ───────────────────
  const expectedNpk = computeNpkCommit(input.nextPubkey, input.npkRand);
  const serverNpk = decodeHexExact(awaiting.npk_commit, 32, 'awaiting_signature.npk_commit');
  if (!bytesEqual(expectedNpk, serverNpk)) {
    throw new NpkCommitRefusalError({ recomputed: expectedNpk, serverClaimed: serverNpk });
  }

  // ── Refusal 2: recompute H(ProofData) from the six fields ───────────────
  const proofData = proofDataFromAwaiting(awaiting);
  const recomputed = hashProofData(proofData);
  const serverHash = decodeHexExact(
    awaiting.proof_data_hash,
    32,
    'awaiting_signature.proof_data_hash',
  );
  if (!bytesEqual(recomputed, serverHash)) {
    throw new ProofDataHashRefusalError({
      recomputed,
      serverClaimed: serverHash,
    });
  }

  // secretKey must derive the localPubkey the wallet bound above — otherwise
  // the signature would open under a different key than the refused-or-matched head.
  const derivedLocal = xOnlyPubkeyFromSecret(input.secretKey);
  if (!bytesEqual(derivedLocal, input.localPubkey)) {
    throw new Error('secretKey does not match localPubkey');
  }

  // Sign the **recomputed** digest under the wallet's network m_state.
  // Never pass `serverHash` as the sole source of m_SC without the compare above.
  return signTransition({
    secretKey: input.secretKey,
    network: input.walletNetwork,
    mSc: recomputed,
  });
}

/** Wire body for `POST /v1/jobs/<id>/sign` (node signature.rs wallet contract). */
export function signBodyFromSignature(sig: TransitionSignature): {
  signature: string;
  s2c_nonce: string;
} {
  if (sig.signature.length !== 64) {
    throw new Error(`sign body: signature must be 64 bytes, got ${sig.signature.length}`);
  }
  if (sig.s2cNonce.length !== 32) {
    throw new Error(`sign body: s2c_nonce must be 32 bytes, got ${sig.s2cNonce.length}`);
  }
  return {
    signature: encodeHexLower(sig.signature),
    s2c_nonce: encodeHexLower(sig.s2cNonce),
  };
}
