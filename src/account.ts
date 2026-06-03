/**
 * High-level wallet adapter.
 *
 * `ZkCoinsAccount` is the recommended entry point for wallet
 * integrators (Cake Wallet's `cw_zkcoins`, Layerz Wallet's
 * `ZkcoinsWallet`, the in-tree web app post-migration). It composes
 * the primitives — derivation, signing, message construction, REST
 * client — into a small `InterfaceAccountBasedWallet`-style API:
 *
 *   fromMnemonic → getBalance → pay → ... → claimUsername → ...
 *
 * The class deliberately holds **only the minimum state** needed
 * across calls: the derived `xpriv`, the current `numPubkeys`
 * counter, the cached `address`, and a `ZkCoinsClient`. Everything
 * else — balance, transaction history, username metadata — is
 * server-authoritative and re-fetched on demand.
 *
 * **Thin-client invariant.** `pay()` re-fetches the balance from
 * the server before constructing the send request. This matches the
 * documented contract for the zkCoins backend (see memory note
 * `feedback_zkcoins_thin_client`): the server is the source of
 * truth for every signed operation; the wallet only holds the keys.
 *
 * **numPubkeys tracking.** This is the one piece of local state the
 * wallet has to maintain: a monotonic counter incremented after each
 * successful send, so the next outgoing pubkey is unique. It is
 * deterministic given the account's send history, so a wallet that
 * loses its local copy can in principle reconstruct by scanning
 * usage — but the SDK does not implement that recovery path. If a
 * higher-level integrator needs to restore state, it should persist
 * `numPubkeys` alongside the mnemonic.
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';

import { ZkCoinsClient, type SignedClaimRequest, type SignedSendRequest } from './client.js';
import {
  derivePublicKeys,
  deriveSigningKey,
  generateAccountKeysFromMnemonic,
} from './derivation.js';
import { HISTORY_TRACKING_URL, NotImplementedError } from './errors.js';
import { buildClaimMessage, buildSendMessage } from './messages.js';
import type {
  BalanceResponse,
  HistoryResponse,
  ResolveUsernameResponse,
  SendResponse,
  UsernameResponse,
} from './schemas.js';
import { signSchnorr } from './signing.js';

export interface ZkCoinsAccountOptions {
  /**
   * Base URL of the zkCoins node. Resolution order (handled inside
   * `ZkCoinsClient`):
   *   1. this option (programmatic override)
   *   2. `ZKCOINS_API_URL` env var
   *   3. `API_URL` constant in `./config.ts`
   *
   * Ignored when `client` is also passed (the override's `apiUrl`
   * wins). Both options exist so simple call sites pass `apiUrl` and
   * test/advanced call sites can inject a pre-built `ZkCoinsClient`.
   */
  apiUrl?: string;
  /** Optional BIP-39 passphrase (advanced; leave empty for the default flow). */
  passphrase?: string;
  /** Optional `ZkCoinsClient` override — primarily for tests. */
  client?: ZkCoinsClient;
}

export interface PayResult {
  /** Server-issued proof id, available on a successful send. */
  proofId: number | null | undefined;
  /** Server-returned account_state_hash, if present. */
  accountStateHash: string | undefined;
  /** Server-returned output_coins_root, if present. */
  outputCoinsRoot: string | undefined;
}

export interface HistoryOpts {
  limit?: number;
  offset?: number;
}

export class ZkCoinsAccount {
  /** Hex-encoded account address (sha256 of publicKey at index 0). */
  public readonly address: string;
  /** The underlying REST client; exposed so advanced consumers can reuse it. */
  public readonly client: ZkCoinsClient;

  private readonly xpriv: string;
  private numPubkeys: number;

  private constructor(opts: { address: string; xpriv: string; client: ZkCoinsClient }) {
    this.address = opts.address;
    this.xpriv = opts.xpriv;
    this.client = opts.client;
    this.numPubkeys = 0;
  }

  /**
   * Derive an account from a BIP-39 mnemonic.
   *
   * `accountIndex` is reserved for future multi-account support; today
   * it is required for API compat and ignored at the derivation level
   * (the SDK + server protocol use a single root xpriv per mnemonic).
   * Pass `0` for the standard flow.
   */
  static async fromMnemonic(
    mnemonic: string,
    accountIndex: number,
    opts: ZkCoinsAccountOptions = {},
  ): Promise<ZkCoinsAccount> {
    // Today the derivation does not branch on accountIndex; future
    // multi-account support would extend the BIP-32 path here. The
    // parameter is consumed (referenced) so it shows up in stack
    // traces / logs if the integrator passes something unusual.
    if (!Number.isInteger(accountIndex) || accountIndex < 0) {
      throw new Error(
        `ZkCoinsAccount.fromMnemonic: accountIndex must be a non-negative integer, got ${accountIndex}`,
      );
    }

    const keys = await generateAccountKeysFromMnemonic(mnemonic, opts.passphrase ?? '');
    // Pass `apiUrl` only when set so `exactOptionalPropertyTypes` is
    // satisfied; ZkCoinsClient runs its own resolution (option → env →
    // config) when the option is absent.
    const client = opts.client ?? new ZkCoinsClient(opts.apiUrl ? { apiUrl: opts.apiUrl } : {});

    return new ZkCoinsAccount({
      address: keys.address,
      xpriv: keys.xpriv,
      client,
    });
  }

  /** Re-fetch balance + username from the server (source of truth). */
  async getBalance(): Promise<BalanceResponse> {
    return this.client.balance(this.address);
  }

  /**
   * Send `amountSats` to `recipient`.
   *
   * Steps (all server-mediated):
   *
   *   1. Refresh balance from the server — the thin-client invariant.
   *      The server is authoritative; never sign against stale local
   *      state.
   *   2. Derive `public_key` at index `numPubkeys` and
   *      `next_public_key` at index `numPubkeys + 1`.
   *   3. Build the send message (UTF-8 hex address + recipient +
   *      8-byte little-endian amount + timestamp) and hash it with
   *      SHA-256.
   *   4. Sign the digest with the Schnorr key at index `numPubkeys`
   *      (deterministic nonce, matches Rust).
   *   5. POST `/api/send`.
   *   6. Increment `numPubkeys` locally so the next send uses the
   *      next derivation index.
   */
  async pay(recipient: string, amountSats: number): Promise<PayResult> {
    // 1. Re-fetch authoritative state. The result isn't used directly
    // here, but the call surfaces "balance too low" / "address unknown"
    // / "API down" as a regular ApiError before we sign anything.
    await this.client.balance(this.address);

    // 2. Derive the pubkey pair for this send.
    const { publicKey, nextPublicKey } = await derivePublicKeys(this.xpriv, this.numPubkeys);

    // 3. Build + hash the message.
    const timestamp = Math.floor(Date.now() / 1000);
    const messageBytes = buildSendMessage({
      accountAddress: this.address,
      recipient,
      amount: amountSats,
      timestamp,
    });
    const digestHex = bytesToHex(sha256(messageBytes));

    // 4. Sign.
    const signingKey = await deriveSigningKey(this.xpriv, this.numPubkeys);
    const signature = await signSchnorr(signingKey, digestHex);

    // 5. POST the signed request.
    const signed: SignedSendRequest = {
      account_address: this.address,
      recipient,
      amount: amountSats,
      public_key: publicKey,
      next_public_key: nextPublicKey,
      signature,
      timestamp,
    };
    const res: SendResponse = await this.client.send(signed);

    // 6. Advance the index counter. Server may also persist this on
    // its side, but the local counter is what drives the next derive.
    this.numPubkeys += 1;

    return {
      proofId: res.proof_id,
      accountStateHash: res.account_state_hash,
      outputCoinsRoot: res.output_coins_root,
    };
  }

  /**
   * Per-address transaction history. **Throws `NotImplementedError`
   * until zk-coins/node issue #153 ships.** The method signature is
   * stable; only the underlying server endpoint is missing.
   */
  async getTransactions(_opts: HistoryOpts = {}): Promise<HistoryResponse> {
    throw new NotImplementedError('ZkCoinsAccount.getTransactions', HISTORY_TRACKING_URL);
  }

  /**
   * Claim `username` for this account.
   *
   * Mirrors the app's inline `signClaimRequest` flow: signs a fixed-
   * prefix message with the identity key at index 0, then POSTs the
   * signature + public_key + timestamp.
   */
  async claimUsername(username: string): Promise<UsernameResponse> {
    const timestamp = Math.floor(Date.now() / 1000);
    const messageBytes = buildClaimMessage({
      address: this.address,
      username,
      timestamp,
    });
    const digestHex = bytesToHex(sha256(messageBytes));

    // Identity key always at index 0 — matches the Rust contract.
    const { publicKey } = await derivePublicKeys(this.xpriv, 0);
    const signingKey = await deriveSigningKey(this.xpriv, 0);
    const signature = await signSchnorr(signingKey, digestHex);

    const req: SignedClaimRequest = {
      username,
      address: this.address,
      public_key: publicKey,
      signature,
      timestamp,
    };
    return this.client.claimUsername(req);
  }

  /** Pass-through to the public username resolver — no signing involved. */
  async resolveUsername(username: string): Promise<ResolveUsernameResponse> {
    return this.client.resolveUsername(username);
  }

  /**
   * Current local `numPubkeys` counter. Exposed for integrators that
   * want to persist + restore wallet state across sessions; see the
   * class doc-comment on the recovery semantics.
   */
  getNumPubkeys(): number {
    return this.numPubkeys;
  }

  /**
   * Override the local `numPubkeys` counter — restore-from-storage
   * path. The counter is monotonic by construction (it only ever
   * increments on a successful send), so a future `setNumPubkeys` to
   * a lower value would silently reuse a derivation index. This
   * setter refuses to go backwards.
   */
  setNumPubkeys(value: number): void {
    if (!Number.isInteger(value) || value < this.numPubkeys) {
      throw new Error(
        `ZkCoinsAccount.setNumPubkeys: value must be an integer ≥ current (${this.numPubkeys}), got ${value}`,
      );
    }
    this.numPubkeys = value;
  }
}
