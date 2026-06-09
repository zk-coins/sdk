/**
 * High-level wallet adapter.
 *
 * `ZkCoinsAccount` is the recommended entry point for wallet
 * integrators (Cake Wallet's `cw_zkcoins`, Layerz Wallet's
 * `ZkcoinsWallet`, the in-tree web app post-migration). It composes
 * the primitives — derivation, signing, message construction, REST
 * client — into a small `InterfaceAccountBasedWallet`-style API:
 *
 *   fromMnemonic → getBalance → mint → pay → getTransactions → claimUsername → ...
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
 * loses its local copy can re-hydrate it from `balance().num_sends`.
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';

import {
  ZkCoinsClient,
  newIdempotencyKey,
  type CommitRequest,
  type HistoryOpts,
  type JobStatusWithRetry,
  type SignedClaimRequest,
  type SignedSendRequest,
} from './client.js';
import {
  derivePublicKeys,
  deriveSigningKey,
  generateAccountKeysFromMnemonic,
} from './derivation.js';
import { JobFailedError } from './errors.js';
import { buildClaimMessage, buildMintMessage, buildSendMessage } from './messages.js';
import type {
  BalanceResponse,
  HistoryResponse,
  JobStatus,
  OwnerBalanceResponse,
  ResolveUsernameResponse,
  UsernameResponse,
} from './schemas.js';
import { createCommitment, signSchnorr } from './signing.js';

export interface ZkCoinsAccountOptions {
  /**
   * Base URL of the zkCoins node. Resolution order (handled inside
   * `ZkCoinsClient`):
   *   1. this option (programmatic override)
   *   2. `API_URL` constant in `./config.ts`
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

/** Result of a completed creator-signed mint job. */
export interface MintResult {
  /** The job id, for follow-up / audit. */
  jobId: string;
  /** Server-issued staged-mint proof id echoed back at commit time. */
  proofId: number;
}

/** Result of a completed send (`pay`) job. */
export interface PayResult {
  /** The send job id. */
  jobId: string;
  /** Server-issued proof id for the send. */
  proofId: number;
}

/** Knobs for `waitForJob`'s poll loop. */
export interface WaitForJobOpts {
  /** Invoked on each distinct phase transition observed. */
  onPhase?: (status: JobStatus) => void;
  /** Floor poll interval when the node omits a `Retry-After`. Default 1500ms. */
  pollIntervalMs?: number;
  /** Hard timeout for the whole wait. Default 180_000ms (3 min). */
  timeoutMs?: number;
  /** Abort the wait early. */
  signal?: AbortSignal;
}

/** Knobs for `waitForIncoming`'s balance-polling loop. */
export interface WaitForIncomingOpts {
  /**
   * Balance (in sats) below which the helper keeps waiting. Defaults to
   * the balance read at the moment `waitForIncoming` is called, so the
   * helper resolves on the first observed *increase*. Pass an explicit
   * value to wait until the balance reaches a known target instead.
   */
  fromBalance?: number;
  /** Poll interval in ms. Default 5000. */
  pollIntervalMs?: number;
  /** Hard timeout for the whole wait. Default 300_000ms (5 min). */
  timeoutMs?: number;
  /** Invoked on each poll with the freshly-read balance. */
  onPoll?: (balance: BalanceResponse) => void;
  /** Abort the wait early. */
  signal?: AbortSignal;
}

/** A `waitForJob` target — one or more non-terminal statuses to stop at, plus the terminal set. */
type StopStatus = JobStatus['status'];

const DEFAULT_POLL_INTERVAL_MS = 1_500;
const DEFAULT_WAIT_TIMEOUT_MS = 180_000;
const DEFAULT_INCOMING_POLL_INTERVAL_MS = 5_000;
const DEFAULT_INCOMING_TIMEOUT_MS = 300_000;
const TERMINAL_STATUSES: ReadonlySet<StopStatus> = new Set(['completed', 'failed', 'cancelled']);

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
    if (!Number.isInteger(accountIndex) || accountIndex < 0) {
      throw new Error(
        `ZkCoinsAccount.fromMnemonic: accountIndex must be a non-negative integer, got ${accountIndex}`,
      );
    }

    const keys = await generateAccountKeysFromMnemonic(mnemonic, opts.passphrase ?? '');
    // Pass `apiUrl` only when set so `exactOptionalPropertyTypes` is
    // satisfied; ZkCoinsClient runs its own resolution (option →
    // config) when the option is absent.
    const client = opts.client ?? new ZkCoinsClient(opts.apiUrl ? { apiUrl: opts.apiUrl } : {});

    return new ZkCoinsAccount({
      address: keys.address,
      xpriv: keys.xpriv,
      client,
    });
  }

  /**
   * Re-fetch the balance of one asset for this account — the per-asset
   * `GET /api/balance?address=&asset_id=`. There is no native/default
   * asset under the neutral multi-asset model, so the asset must be
   * named. Use {@link getAssets} to discover which assets this account
   * holds (and their ids).
   */
  async getBalance(assetId: string): Promise<BalanceResponse> {
    return this.client.balance(this.address, assetId);
  }

  /**
   * List every asset this account holds — `GET /api/balance/:address`.
   * One entry per asset with its own balance / num_sends / display
   * metadata. The wallet's home screen renders this; the returned
   * `asset_id`s feed {@link pay} / {@link getBalance}.
   */
  async getAssets(signal?: AbortSignal): Promise<OwnerBalanceResponse> {
    return this.client.ownerBalances(this.address, signal);
  }

  /**
   * Create / mint `amount` units of the asset identified by
   * `(name, decimals)` into this account's own balance.
   *
   * Neutral, permissionless model: the asset_id is
   * `calculate_asset_id(creator_pubkey, H(name), decimals)` and the
   * owner is `H(creator_pubkey)` — both derived node-side from the
   * creator's identity key (BIP-32 index 0). The first mint of a given
   * `(name, decimals)` brings the asset into existence; further mints
   * grow its supply. Nobody but the creator can mint it.
   *
   * Two-phase like a send (the mint proof carries no signature, so the
   * node binds the on-chain commitment to the creator key at commit
   * time — the soundness gate):
   *
   *   1. Sign the mint message with the creator key (index 0).
   *   2. Admit `POST /api/jobs/mint`; poll to `awaiting_signature`.
   *   3. Build the commitment over `account_state_hash ‖
   *      output_coins_root` with the SAME creator key (the gate
   *      requires `commitment.public_key == account.public_key ==
   *      creator_pubkey`).
   *   4. `POST /api/jobs/:id/commit`; poll to `completed`.
   */
  async mint(params: { name: string; decimals: number; amount: number }): Promise<MintResult> {
    const { name, decimals, amount } = params;
    const timestamp = Math.floor(Date.now() / 1000);

    // The creator key is the wallet's identity key at index 0; the node
    // derives owner = H(creator_pubkey) and asset_id from it. The mint
    // also rotates the commitment to the wallet's NEXT key like a send,
    // so we include `next_public_key` in the request body (the mint
    // message + commitment are still signed with the creator key).
    const { publicKey: creatorPubkey, nextPublicKey } = await derivePublicKeys(this.xpriv, 0);
    const messageBytes = buildMintMessage({ creatorPubkey, name, decimals, amount, timestamp });
    const digestHex = bytesToHex(sha256(messageBytes));
    const signingKey = await deriveSigningKey(this.xpriv, 0);
    const signature = await signSchnorr(signingKey, digestHex);

    const idempotencyKey = newIdempotencyKey();
    const accepted = await this.client.mintJob(
      {
        creator_pubkey: creatorPubkey,
        name,
        decimals,
        amount,
        next_public_key: nextPublicKey,
        signature,
        timestamp,
      },
      idempotencyKey,
    );
    const jobId = accepted.job_id;

    // Phase 2: park at awaiting_signature, sign the commitment with the
    // creator key (index 0 — the gate binds the commitment key to it),
    // commit, and poll to completion.
    const awaiting = await this.waitForJob(
      jobId,
      new Set<StopStatus>(['awaiting_signature', ...TERMINAL_STATUSES]),
    );
    if (awaiting.status !== 'awaiting_signature') {
      throw new JobFailedError(
        jobId,
        'failed',
        `mint job ended in ${awaiting.status} before commit`,
      );
    }
    const proofId = awaiting.proof_id;
    if (proofId === null || proofId === undefined) {
      throw new JobFailedError(
        jobId,
        'failed',
        'awaiting_signature mint job did not carry a proof_id',
      );
    }

    const { accountStateHash, outputCoinsRoot } = extractCommitInputs(awaiting, jobId);
    const commitment = await createCommitment(this.xpriv, 0, accountStateHash, outputCoinsRoot);
    const commitReq: CommitRequest = {
      proof_id: proofId,
      public_key: commitment.publicKey,
      signature: commitment.signature,
      message: commitment.message,
    };
    await this.client.commitJob(jobId, commitReq);
    await this.waitForJob(jobId, TERMINAL_STATUSES);

    return { jobId, proofId };
  }

  /**
   * Send `amountSats` to `recipient`.
   *
   * Steps (all server-mediated):
   *
   *   1. Refresh balance from the server — the thin-client invariant —
   *      and hydrate `numPubkeys` forward from the authoritative
   *      `num_sends`.
   *   2. Derive `public_key` at index `numPubkeys` and
   *      `next_public_key` at index `numPubkeys + 1`.
   *   3. Build + SHA-256 the send message, Schnorr-sign at `numPubkeys`.
   *   4. Admit the send job (`Idempotency-Key`).
   *   5. Poll to `awaiting_signature`.
   *   6. Build the commitment over `account_state_hash || output_coins_root`.
   *   7. `POST /api/jobs/:id/commit`.
   *   8. Poll to `completed`.
   *   9. Advance `numPubkeys`.
   *
   * @param assetId the 32-byte-hex asset to send (REQUIRED — no native
   *   asset). Discover held assets via {@link getAssets}.
   */
  async pay(recipient: string, amountSats: number, assetId: string): Promise<PayResult> {
    // 1. Re-fetch authoritative state (surfaces "balance too low" /
    // "address unknown" / "API down" as a regular ApiError before we
    // sign anything). Under multi-asset the commitment pubkey must be
    // unique across the WHOLE wallet (the global commitment SMT is keyed
    // by pubkey, shared across assets), so the signing index is a global
    // monotonic counter, NOT the per-asset `num_sends`. Hydrate it from
    // the sum of every asset's `num_sends` (the total sends this wallet
    // has ever made) so a restored wallet picks the next unused index
    // instead of colliding with a past commitment. Never regress below
    // the local counter.
    const owned = await this.client.ownerBalances(this.address);
    const asset = owned.assets.find((a) => a.asset_id === assetId);
    const assetBalance = asset?.balance ?? 0;
    if (assetBalance < amountSats) {
      throw new Error(
        `pay: insufficient balance for asset ${assetId} — have ${assetBalance}, need ${amountSats}`,
      );
    }
    const totalSends = owned.assets.reduce((sum, a) => sum + a.num_sends, 0);
    if (totalSends > this.numPubkeys) {
      this.numPubkeys = totalSends;
    }

    // 2. Derive the pubkey pair for this send.
    const { publicKey, nextPublicKey } = await derivePublicKeys(this.xpriv, this.numPubkeys);

    // 3. Build + hash + sign the send message.
    const timestamp = Math.floor(Date.now() / 1000);
    const messageBytes = buildSendMessage({
      accountAddress: this.address,
      recipient,
      amount: amountSats,
      timestamp,
    });
    const digestHex = bytesToHex(sha256(messageBytes));
    const signingKey = await deriveSigningKey(this.xpriv, this.numPubkeys);
    const signature = await signSchnorr(signingKey, digestHex);

    const signed: SignedSendRequest = {
      account_address: this.address,
      recipient,
      amount: amountSats,
      public_key: publicKey,
      next_public_key: nextPublicKey,
      signature,
      timestamp,
      asset_id: assetId,
    };

    // 4. Admit the send job.
    const idempotencyKey = newIdempotencyKey();
    const accepted = await this.client.sendJob(signed, idempotencyKey);
    const jobId = accepted.job_id;

    // 5. Poll to `awaiting_signature`. The node parks the job here with
    // its send `proof_id` populated.
    const awaiting = await this.waitForJob(
      jobId,
      new Set<StopStatus>(['awaiting_signature', ...TERMINAL_STATUSES]),
    );
    if (awaiting.status !== 'awaiting_signature') {
      // A terminal status before awaiting_signature — waitForJob would
      // have thrown on failed/cancelled, so this is the (unexpected)
      // `completed`-without-commit case.
      throw new JobFailedError(
        jobId,
        'failed',
        `send job ended in ${awaiting.status} before commit`,
      );
    }
    const proofId = awaiting.proof_id;
    if (proofId === null || proofId === undefined) {
      throw new JobFailedError(jobId, 'failed', 'awaiting_signature job did not carry a proof_id');
    }

    // 6. Build the commitment over account_state_hash || output_coins_root.
    const { accountStateHash, outputCoinsRoot } = extractCommitInputs(awaiting, jobId);
    const commitment = await createCommitment(
      this.xpriv,
      this.numPubkeys,
      accountStateHash,
      outputCoinsRoot,
    );

    // 7. Attach the signed commitment.
    const commitReq: CommitRequest = {
      proof_id: proofId,
      public_key: commitment.publicKey,
      signature: commitment.signature,
      message: commitment.message,
    };
    await this.client.commitJob(jobId, commitReq);

    // 8. Poll to `completed`.
    await this.waitForJob(jobId, TERMINAL_STATUSES);

    // 9. Advance the index counter.
    this.numPubkeys += 1;

    return { jobId, proofId };
  }

  /** Per-address transaction history — `GET /api/history`. */
  async getTransactions(opts: HistoryOpts = {}): Promise<HistoryResponse> {
    return this.client.history(this.address, opts);
  }

  /**
   * Receiving on zkCoins.
   *
   * There is **no client-initiated "receive" call** — and there should
   * not be. A wallet receives by sharing its `address` (this account's
   * `account.address`); the sender's `pay()` credits it server-side.
   * The legacy `POST /api/receive` octet-stream route is internal
   * plumbing, not a wallet method, and is deliberately *not* mirrored
   * here (no fabricated endpoint).
   *
   * To observe an incoming credit, poll the authoritative balance /
   * history (`getBalance()` / `getTransactions()`). `waitForIncoming`
   * is an optional convenience over that polling loop: it reads the
   * current balance, then polls until the balance rises above the
   * baseline (or a caller-supplied `fromBalance`), and resolves with
   * the updated `BalanceResponse`. It performs no signing and adds no
   * trust assumption — it is purely `getBalance()` on a timer, so a
   * consumer that prefers its own loop can ignore it entirely.
   *
   * @throws on timeout (a balance increase was not observed within
   *   `timeoutMs`) or abort — never silently returns a stale balance.
   */
  async waitForIncoming(assetId: string, opts: WaitForIncomingOpts = {}): Promise<BalanceResponse> {
    const pollInterval = opts.pollIntervalMs ?? DEFAULT_INCOMING_POLL_INTERVAL_MS;
    const timeoutMs = opts.timeoutMs ?? DEFAULT_INCOMING_TIMEOUT_MS;
    const deadline = Date.now() + timeoutMs;

    // Baseline: the explicit target floor, or the balance at call time.
    const baseline =
      opts.fromBalance ?? (await this.client.balance(this.address, assetId, opts.signal)).balance;

    for (;;) {
      if (opts.signal?.aborted) {
        throw new Error('waitForIncoming: aborted');
      }
      const current = await this.client.balance(this.address, assetId, opts.signal);
      opts.onPoll?.(current);
      if (current.balance > baseline) {
        return current;
      }
      if (Date.now() >= deadline) {
        throw new Error(
          `waitForIncoming: timed out after ${timeoutMs}ms; balance still ${current.balance} (baseline ${baseline})`,
        );
      }
      await delay(pollInterval, opts.signal);
    }
  }

  /**
   * Poll a job until it reaches one of `stopAt` (always including the
   * terminal set). Respects the node's `Retry-After` backoff; throws
   * `JobFailedError` on `failed` / `cancelled` (no silent fallback).
   */
  async waitForJob(
    jobId: string,
    stopAt: ReadonlySet<StopStatus>,
    opts: WaitForJobOpts = {},
  ): Promise<JobStatus> {
    const pollFloor = opts.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;
    const timeoutMs = opts.timeoutMs ?? DEFAULT_WAIT_TIMEOUT_MS;
    const deadline = Date.now() + timeoutMs;
    let lastPhase: string | undefined;

    for (;;) {
      if (opts.signal?.aborted) {
        throw new Error(`waitForJob(${jobId}): aborted`);
      }
      const polled: JobStatusWithRetry = await this.client.getJobWithRetry(jobId, opts.signal);
      const { status: job, retryAfterMs } = polled;

      if (opts.onPhase && job.phase !== lastPhase) {
        lastPhase = job.phase;
        opts.onPhase(job);
      }

      if (job.status === 'failed' || job.status === 'cancelled') {
        throw new JobFailedError(jobId, job.status, job.error ?? undefined);
      }
      if (stopAt.has(job.status)) {
        return job;
      }

      if (Date.now() >= deadline) {
        throw new Error(
          `waitForJob(${jobId}): timed out after ${timeoutMs}ms in status ${job.status}`,
        );
      }

      const waitMs = Math.max(pollFloor, retryAfterMs ?? 0);
      await delay(waitMs, opts.signal);
    }
  }

  /**
   * Claim `username` for this account. Signs a fixed-prefix message
   * with the identity key at index 0, then POSTs the signature.
   */
  async claimUsername(username: string): Promise<UsernameResponse> {
    const timestamp = Math.floor(Date.now() / 1000);
    const messageBytes = buildClaimMessage({
      address: this.address,
      username,
      timestamp,
    });
    const digestHex = bytesToHex(sha256(messageBytes));

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
   * want to persist + restore wallet state across sessions.
   */
  getNumPubkeys(): number {
    return this.numPubkeys;
  }

  /**
   * Override the local `numPubkeys` counter — restore-from-storage
   * path (e.g. seed `setNumPubkeys(balance.num_sends)`). The counter is
   * monotonic by construction; this setter refuses to go backwards.
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

/**
 * Pull `account_state_hash` + `output_coins_root` out of an
 * `awaiting_signature` job so the wallet can sign the commitment.
 *
 * The node surfaces these on the job's `result` object once it carries
 * them. If they are absent the commit cannot be built, and we
 * fail-hard (no fabricated commitment): the only correct recovery is
 * the node populating them — see the type-level note below.
 */
function extractCommitInputs(
  job: JobStatus,
  jobId: string,
): { accountStateHash: string; outputCoinsRoot: string } {
  const ash = job.result?.account_state_hash;
  const ocr = job.result?.output_coins_root;
  if (typeof ash === 'string' && typeof ocr === 'string') {
    return { accountStateHash: ash, outputCoinsRoot: ocr };
  }
  throw new JobFailedError(
    jobId,
    'failed',
    'awaiting_signature job did not surface account_state_hash / output_coins_root as JSON; ' +
      'the commit message cannot be built client-side from a pure-TS SDK (the node currently ' +
      'exposes these only inside the binary CoinProof at GET /api/proof/:id). ' +
      'Resolved once the node carries them on the awaiting_signature JobStatus.',
  );
}

/** `setTimeout`-based delay that rejects if `signal` aborts mid-wait. */
function delay(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new Error('waitForJob: aborted'));
      return;
    }
    const handle = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    const onAbort = (): void => {
      clearTimeout(handle);
      reject(new Error('waitForJob: aborted'));
    };
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}
