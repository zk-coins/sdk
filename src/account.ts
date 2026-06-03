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
import { buildClaimMessage, buildSendMessage } from './messages.js';
import type {
  BalanceResponse,
  HistoryResponse,
  JobStatus,
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

/** Result of a completed mint job. */
export interface MintResult {
  /** The job id, for follow-up / audit. */
  jobId: string;
  /** Server-issued proof id, if the completed mint reported one. */
  proofId: number | null | undefined;
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

/** A `waitForJob` target — one or more non-terminal statuses to stop at, plus the terminal set. */
type StopStatus = JobStatus['status'];

const DEFAULT_POLL_INTERVAL_MS = 1_500;
const DEFAULT_WAIT_TIMEOUT_MS = 180_000;
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

  /** Re-fetch balance + username from the server (source of truth). */
  async getBalance(): Promise<BalanceResponse> {
    return this.client.balance(this.address);
  }

  /**
   * Mint `amountSats` to this account (DEV faucet / authorised
   * issuance). A mint is fully server-mediated — no wallet signature
   * step — so the flow is admit → poll to `completed`.
   *
   * @param assetId optional 32-byte-hex multi-asset selector; omit for
   *   the native asset.
   */
  async mint(amountSats: number, assetId?: string): Promise<MintResult> {
    const idempotencyKey = newIdempotencyKey();
    const accepted = await this.client.mintJob(
      {
        account_address: this.address,
        amount: amountSats,
        ...(assetId !== undefined ? { asset_id: assetId } : {}),
      },
      idempotencyKey,
    );
    const terminal = await this.waitForJob(accepted.job_id, TERMINAL_STATUSES);
    // `waitForJob` throws on failed/cancelled, so reaching here means
    // `completed`.
    return {
      jobId: accepted.job_id,
      proofId: terminal.result?.proof_id,
    };
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
   * @param assetId optional 32-byte-hex multi-asset selector.
   */
  async pay(recipient: string, amountSats: number, assetId?: string): Promise<PayResult> {
    // 1. Re-fetch authoritative state (surfaces "balance too low" /
    // "address unknown" / "API down" as a regular ApiError before we
    // sign anything). The server's `num_sends` is the canonical send
    // counter (thin-client invariant): hydrate our local derivation
    // index forward from it so a wallet that lost local state — or sent
    // from another device — derives at the correct next index instead
    // of reusing index 0. Never regress below the local counter, which
    // would risk reusing an in-flight derivation index.
    const balance = await this.client.balance(this.address);
    if (balance.num_sends > this.numPubkeys) {
      this.numPubkeys = balance.num_sends;
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
      ...(assetId !== undefined ? { asset_id: assetId } : {}),
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
