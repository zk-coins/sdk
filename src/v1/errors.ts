/**
 * Fail-closed error types for the v1 wallet surface.
 *
 * The three pre-sign refusals each have their own class so an operator can
 * see *which* binding failed and the two values that did not match — never a
 * shared "validation failed".
 */

import { encodeHexLower } from './hex.js';
import type { Network } from './mstate.js';

/** CSPRNG is required for `npk_rand` and production nonces — no Math.random fallback. */
export class CsprngUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CsprngUnavailableError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Refusal 1 — key binding (§7.5):
 * `derive(A/0'/send_counter).pubkey == current_pubkey == txn_pubkey` failed.
 */
export class KeyBindingRefusalError extends Error {
  readonly localPubkey: string;
  readonly currentPubkey: string;
  readonly txnPubkey: string;
  readonly sendCounter: number;

  constructor(input: {
    localPubkey: Uint8Array;
    currentPubkey: Uint8Array;
    txnPubkey: Uint8Array;
    sendCounter: number;
  }) {
    const local = encodeHexLower(input.localPubkey);
    const current = encodeHexLower(input.currentPubkey);
    const txn = encodeHexLower(input.txnPubkey);
    super(
      `refuse to sign: key binding failed — ` +
        `local(A/0'/${input.sendCounter})=${local} ` +
        `current_pubkey=${current} txn_pubkey=${txn}`,
    );
    this.name = 'KeyBindingRefusalError';
    this.localPubkey = local;
    this.currentPubkey = current;
    this.txnPubkey = txn;
    this.sendCounter = input.sendCounter;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Refusal 2 — H(ProofData) recomputed from the six fields does not equal the
 * server's `proof_data_hash`. Sign the recomputed digest only; never the
 * server-supplied claim.
 */
export class ProofDataHashRefusalError extends Error {
  readonly recomputed: string;
  readonly serverClaimed: string;

  constructor(input: { recomputed: Uint8Array; serverClaimed: Uint8Array }) {
    const recomputed = encodeHexLower(input.recomputed);
    const serverClaimed = encodeHexLower(input.serverClaimed);
    super(
      `refuse to sign: H(ProofData) mismatch — recomputed=${recomputed} server=${serverClaimed}`,
    );
    this.name = 'ProofDataHashRefusalError';
    this.recomputed = recomputed;
    this.serverClaimed = serverClaimed;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Refusal 3 — network conflict (V.9 N-19 / §7.5): wallet `m_state` network
 * disagrees with the network the node advertises.
 */
export class NetworkMismatchRefusalError extends Error {
  readonly walletNetwork: Network;
  readonly nodeNetwork: Network;

  constructor(input: { walletNetwork: Network; nodeNetwork: Network }) {
    super(
      `refuse to sign: network mismatch — wallet=${input.walletNetwork} node=${input.nodeNetwork}`,
    );
    this.name = 'NetworkMismatchRefusalError';
    this.walletNetwork = input.walletNetwork;
    this.nodeNetwork = input.nodeNetwork;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Surfaced `npk_commit` does not equal `H("zkCoins/v1/NpkCommit" ‖ next_pubkey ‖ npk_rand)`
 * recomputed from the wallet's own rotation material (§7.5 wallet-side recomputation (a)).
 */
export class NpkCommitRefusalError extends Error {
  readonly recomputed: string;
  readonly serverClaimed: string;

  constructor(input: { recomputed: Uint8Array; serverClaimed: Uint8Array }) {
    const recomputed = encodeHexLower(input.recomputed);
    const serverClaimed = encodeHexLower(input.serverClaimed);
    super(`refuse to sign: npk_commit mismatch — recomputed=${recomputed} server=${serverClaimed}`);
    this.name = 'NpkCommitRefusalError';
    this.recomputed = recomputed;
    this.serverClaimed = serverClaimed;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * §7.5 generic REST error from the v1 API edge.
 *
 * `machineCode` is the closed `error` field (`unauthorized`, `session_expired`,
 * `challenge_expired`, …). Status+code pairs are **not** collapsed: a 410 with
 * `session_expired` is distinct from a 410 with `challenge_expired` and from a
 * 401 `unauthorized` so the caller can decide whether to re-challenge.
 *
 * Session bearer tokens **must never** appear in `message` / `rawBody` that we
 * re-emit — redacted at construction time when a token is supplied.
 */
export class V1ApiError extends Error {
  readonly status: number;
  readonly machineCode: string;
  readonly rawBody: string | undefined;

  constructor(status: number, machineCode: string, message: string, rawBody?: string) {
    super(`zkCoins v1 API error ${status} ${machineCode}: ${message}`);
    this.name = 'V1ApiError';
    this.status = status;
    this.machineCode = machineCode;
    this.rawBody = rawBody;
    Object.setPrototypeOf(this, new.target.prototype);
  }

  /** Missing/invalid bearer or bad OwnershipProof — do not treat as "retry with same token". */
  isUnauthorized(): boolean {
    return this.status === 401 && this.machineCode === 'unauthorized';
  }

  /** Pull-session expired / unknown / chan_bind mismatch — open a fresh session. */
  isSessionExpired(): boolean {
    return this.status === 410 && this.machineCode === 'session_expired';
  }

  /** Challenge nonce expired / consumed / unknown — open a fresh challenge. */
  isChallengeExpired(): boolean {
    return this.status === 410 && this.machineCode === 'challenge_expired';
  }
}

/**
 * Redact an opaque bearer token from a string so it never lands in a thrown
 * message or diagnostic field.
 */
export function redactBearerToken(text: string, token: string): string {
  if (token.length === 0) {
    return text;
  }
  // Split/join avoids regex metacharacter pitfalls in the secret.
  return text.split(token).join('<redacted-session-token>');
}
