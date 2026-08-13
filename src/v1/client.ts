/**
 * v1 REST client for the §7.5 transition flow.
 *
 * Separate from the legacy `/api/*` surface in `src/client.ts` — that file is
 * untouched. Routes and body fields match what the API edge actually reads:
 *
 *   POST /v1/tx                      → api/src/jobs.rs `post_tx`
 *   GET  /v1/jobs/<id>               → api/src/jobs.rs `get_job` (+ Retry-After)
 *   GET  /v1/jobs/<id>/stream        → api/src/jobs.rs `stream_job` (SSE)
 *   POST /v1/jobs/<id>/sign          → api/src/jobs.rs `post_sign`
 *   POST /v1/jobs/<id>/cancel        → api/src/jobs.rs `post_cancel`
 *   POST /v1/pull/challenge          → api/src/pull.rs `post_pull_challenge`
 *   POST /v1/pull                    → api/src/pull.rs `post_pull` (nonce+expiry+proof)
 *   GET  /v1/account/state           → api/src/pull.rs `get_account_state` (Bearer)
 *   POST /v1/attest/balance/challenge → api/src/attest.rs `post_attest_balance_challenge`
 *   POST /v1/attest/balance          → api/src/attest.rs `post_attest_balance`
 *   POST /v1/grants/challenge        → api/src/grants.rs `post_grants_challenge`
 *   POST /v1/grants                  → api/src/grants.rs `post_grants`
 *   GET  /v1/info                    → api/src/info.rs `get_info`
 *
 * No mock mode. No silent fallbacks. Session tokens are never logged or
 * embedded in error messages.
 */

import { REQUEST_TIMEOUT_MS } from '../config.js';
import {
  ATTEST_BALANCE_CHALLENGE_DOMAIN,
  buildAttestOwnershipProof,
  ceilingEncoding,
} from './attest.js';
import { decodeZkAddress } from './bech32m.js';
import {
  assertOutputDeliveries,
  PaymentIdentityPinStore,
  type VerifyDeliveryOptions,
} from './delivery.js';
import { redactBearerToken, V1ApiError } from './errors.js';
import { expectPresent } from './expectPresent.js';
import {
  ISSUE_GRANT_CHALLENGE_DOMAIN,
  buildGrantProof,
  buildIssueGrantOwnershipProof,
  encodeGrantAssetIds,
  grantScopeToJsonBody,
  type GrantProofJson,
  type GrantScopeInput,
} from './grant.js';
import { decodeHexExact, encodeHexLower } from './hex.js';
import type { Network } from './mstate.js';
import {
  buildOwnershipProof,
  canonicalHostFromApiUrl,
  parseExpiryDecimal,
  type OwnershipProofJson,
  type PullChallenge,
  PULL_CHALLENGE_DOMAIN,
} from './ownership.js';
import {
  refuseOrSignTransition,
  signBodyFromSignature,
  type AccountStateHead,
  type AwaitingSignature,
} from './signGate.js';
import type { TransitionSignature } from './transitionSignature.js';
import { transitionRequestToJson, type TransitionRequest } from './transitionRequest.js';

// ---------------------------------------------------------------------------
// Wire response types (closed status set from §7.5 L2889)
// ---------------------------------------------------------------------------

export type V1JobStatusValue =
  | 'accepted'
  | 'proving'
  | 'awaiting_signature'
  | 'publishing'
  | 'completed'
  | 'failed'
  | 'cancelled';

export interface V1JobAccepted {
  job_id: string;
  status: 'accepted';
}

export interface V1JobErrorBody {
  error: string;
  message: string;
}

export interface V1JobResult {
  new_account_state_hash?: string;
  output_coins_root?: string;
  input_nullifiers_root?: string;
  /** Present only for kind ∈ {mint,send,receive}. Absent for attest_balance. */
  output_coin_ids?: string[];
  publisher_pubkey?: string;
  /** Present only for kind === 'attest_balance'. Absent for mint/send/receive. */
  attestation?: string;
}

export interface V1Job {
  job_id: string;
  kind: string;
  status: V1JobStatusValue;
  /** Diagnostic only — clients MUST NOT dispatch on this (§7.5). */
  phase?: string;
  progress: number;
  awaiting_signature?: AwaitingSignature;
  result?: V1JobResult;
  error?: V1JobErrorBody;
}

/**
 * Non-terminal SSE `phase` frame payload (§7.5 L2947 / L3033).
 *
 * Carries `status` / `progress`, optional diagnostic `phase`, and inline
 * `awaiting_signature` when `status === "awaiting_signature"`. Not a full
 * job object — no `job_id` / `kind` / terminal `result` / `error`.
 */
export interface V1SsePhasePayload {
  status: V1JobStatusValue;
  progress: number;
  /** Diagnostic only — clients MUST NOT dispatch on this (§7.5). */
  phase?: string;
  awaiting_signature?: AwaitingSignature;
}

/**
 * One frame yielded by {@link ZkCoinsV1Client.streamJob}.
 *
 * Discriminated by `full` (payload shape after parse), not by the SSE
 * `event` name: the server uses `phase` / `complete` / `error` only as
 * frame delimiters; clients dispatch on `status` (§7.5). Narrow with
 * `frame.full` to learn whether `job` is a full {@link V1Job}.
 */
export type V1SseStreamFrame =
  | {
      event: string;
      status: V1JobStatusValue;
      /** Payload went through `parseJob` (terminal frames or full job JSON). */
      full: true;
      job: V1Job;
    }
  | {
      event: string;
      status: V1JobStatusValue;
      /** Non-terminal phase-frame subset. */
      full: false;
      job: V1SsePhasePayload;
    };

export interface V1JobWithRetry {
  job: V1Job;
  /** Parsed `Retry-After` in ms; `null` when the header is absent. */
  retryAfterMs: number | null;
}

export interface V1AccountState {
  account_state: string;
  state_head: string;
  head_record_id?: string;
  send_counter: number;
  current_pubkey: string;
  last_nullifier?: { pubkey: string; r: string };
}

export interface V1PullResult {
  records: Array<{
    record_id: string;
    record_type: string;
    transition_kind?: string;
    blob_id: string;
    occurred_at: string;
  }>;
  /** Opaque bearer secret — never parse, never log, never put in errors. */
  session: string;
  session_expiry: string;
}

export interface V1Info {
  network: Network;
  protocol_version: string;
  features: string[];
  [key: string]: unknown;
}

export interface ZkCoinsV1ClientOptions {
  /**
   * Base URL of the node (scheme required). No silent fallback to a
   * hard-coded production host — the caller names the endpoint.
   */
  apiUrl: string;
  /** Override `fetch` (tests / RN polyfills). */
  fetch?: typeof globalThis.fetch;
  /** Per-request abort timeout in ms. */
  requestTimeoutMs?: number;
  /**
   * Wallet-configured network for `m_state`. Required for signing; compared
   * against `GET /v1/info` when that is also known.
   */
  network: Network;
  /**
   * §4.3 payment-identity pin set. When omitted the client owns a fresh
   * empty store (first contact is not an error; pin mismatches still
   * refuse silent payment once pins are recorded).
   */
  pinStore?: PaymentIdentityPinStore;
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

export class ZkCoinsV1Client {
  public readonly apiUrl: string;
  public readonly network: Network;
  /**
   * §4.3 payment-identity pin store. Checked when a delivery credential is
   * accepted on `submitTransition` (and by {@link placeDeliveryCredential}).
   */
  public readonly pinStore: PaymentIdentityPinStore;
  private readonly fetchImpl: typeof globalThis.fetch;
  private readonly requestTimeoutMs: number;
  /** Canonical host authority for `chan_bind` (derived from apiUrl). */
  public readonly host: string;

  constructor(opts: ZkCoinsV1ClientOptions) {
    if (typeof opts.apiUrl !== 'string' || opts.apiUrl.length === 0) {
      throw new Error('ZkCoinsV1Client: apiUrl is required');
    }
    if (!/^https?:\/\//.test(opts.apiUrl)) {
      throw new Error(
        `ZkCoinsV1Client: invalid apiUrl ${JSON.stringify(opts.apiUrl)} — must start with http:// or https://`,
      );
    }
    if (opts.network !== 'mainnet' && opts.network !== 'testnet' && opts.network !== 'regtest') {
      throw new Error(
        `ZkCoinsV1Client: network must be mainnet|testnet|regtest, got ${JSON.stringify(opts.network)}`,
      );
    }
    this.apiUrl = opts.apiUrl.replace(/\/+$/, '');
    this.network = opts.network;
    this.pinStore = opts.pinStore ?? new PaymentIdentityPinStore();
    this.host = canonicalHostFromApiUrl(this.apiUrl);
    this.fetchImpl = opts.fetch ?? globalThis.fetch.bind(globalThis);
    this.requestTimeoutMs =
      opts.requestTimeoutMs !== undefined ? opts.requestTimeoutMs : REQUEST_TIMEOUT_MS;
  }

  // ---- Info ---------------------------------------------------------------

  /** `GET /v1/info` — api/src/info.rs `get_info`. */
  async info(signal?: AbortSignal): Promise<V1Info> {
    const data = await this.requestJson('/v1/info', signal ? { signal } : {});
    return parseInfo(data);
  }

  // ---- Transition jobs ----------------------------------------------------

  /**
   * `POST /v1/tx` → 202 `{ job_id, status: "accepted" }`.
   * Beleg: api/src/jobs.rs `post_tx` L81–104; body `TransitionRequestJson` L31–48.
   *
   * Before the request leaves the wallet: for every output that carries a
   * `delivery` credential (and for every non-self output, which requires one)
   * the §4.3 / §7.5 sender checks run, including the payment-identity pin
   * comparison against {@link pinStore}. Pin mismatch refuses silent payment
   * unless `confirmPinMismatch` is set.
   */
  async submitTransition(
    body: TransitionRequest,
    opts: {
      idempotencyKey?: string;
      signal?: AbortSignal;
      /** Explicit user confirmation after a §4.3 pin-mismatch warning. */
      confirmPinMismatch?: boolean;
      /** Record a pin on first successful credential verification. */
      pinOnFirstUse?: boolean;
    } = {},
  ): Promise<V1JobAccepted> {
    this.assertDeliveriesForSubmit(body, {
      ...(opts.confirmPinMismatch !== undefined
        ? { confirmPinMismatch: opts.confirmPinMismatch }
        : {}),
      ...(opts.pinOnFirstUse !== undefined ? { pinOnFirstUse: opts.pinOnFirstUse } : {}),
    });
    const json = transitionRequestToJson(body);
    const headers: Record<string, string> = {};
    if (opts.idempotencyKey !== undefined) {
      headers['Idempotency-Key'] = opts.idempotencyKey;
    }
    const data = await this.requestJson('/v1/tx', {
      method: 'POST',
      body: JSON.stringify(json),
      headers,
      ...(opts.signal ? { signal: opts.signal } : {}),
    });
    return parseJobAccepted(data);
  }

  /**
   * Sender-side delivery presence + §4.3 checks for send/mint outputs.
   * Receive has no `output_templates` and is a no-op.
   */
  private assertDeliveriesForSubmit(
    body: TransitionRequest,
    pinOpts: { confirmPinMismatch?: boolean; pinOnFirstUse?: boolean },
  ): void {
    if (body.kind !== 'send' && body.kind !== 'mint') {
      return;
    }
    const verifyOpts: VerifyDeliveryOptions = {
      network: this.network,
      pinStore: this.pinStore,
      ...(pinOpts.confirmPinMismatch !== undefined
        ? { confirmPinMismatch: pinOpts.confirmPinMismatch }
        : {}),
      ...(pinOpts.pinOnFirstUse !== undefined ? { pinOnFirstUse: pinOpts.pinOnFirstUse } : {}),
    };
    assertOutputDeliveries(body.subject, body.output_templates, verifyOpts);
  }

  /**
   * `GET /v1/jobs/<job_id>` with `Retry-After` when non-terminal.
   * Beleg: api/src/jobs.rs `get_job` L107–129, `job_poll_headers` L653–663.
   */
  async getJob(jobId: string, signal?: AbortSignal): Promise<V1JobWithRetry> {
    if (jobId.length === 0) {
      throw new Error('getJob: job_id must not be empty');
    }
    const { data, headers } = await this.requestJsonWithHeaders(
      `/v1/jobs/${encodeURIComponent(jobId)}`,
      signal ? { signal } : {},
    );
    const job = parseJob(data);
    const raw = headers.get('retry-after');
    let retryAfterMs: number | null = null;
    if (raw !== null) {
      const secs = Number(raw);
      if (!Number.isFinite(secs) || secs < 0 || !Number.isInteger(secs)) {
        throw new Error(
          `getJob: non-canonical Retry-After ${JSON.stringify(raw)} (expected non-negative integer seconds)`,
        );
      }
      retryAfterMs = secs * 1000;
    }
    return { job, retryAfterMs };
  }

  /**
   * `POST /v1/jobs/<job_id>/sign` — body `{ signature, s2c_nonce }` lowercase hex.
   * Beleg: api/src/jobs.rs `post_sign` L153–173; node signature.rs wire contract.
   */
  async signJob(
    jobId: string,
    body: { signature: string; s2c_nonce: string },
    signal?: AbortSignal,
  ): Promise<V1Job> {
    if (jobId.length === 0) {
      throw new Error('signJob: job_id must not be empty');
    }
    const data = await this.requestJson(`/v1/jobs/${encodeURIComponent(jobId)}/sign`, {
      method: 'POST',
      body: JSON.stringify(body),
      ...(signal ? { signal } : {}),
    });
    return parseJob(data);
  }

  /**
   * `POST /v1/jobs/<job_id>/cancel`.
   * Beleg: api/src/jobs.rs `post_cancel` L176–185.
   */
  async cancelJob(jobId: string, signal?: AbortSignal): Promise<V1Job> {
    if (jobId.length === 0) {
      throw new Error('cancelJob: job_id must not be empty');
    }
    const data = await this.requestJson(`/v1/jobs/${encodeURIComponent(jobId)}/cancel`, {
      method: 'POST',
      body: '{}',
      ...(signal ? { signal } : {}),
    });
    return parseJob(data);
  }

  /**
   * `GET /v1/jobs/<job_id>/stream` — SSE. Dispatch **only** on `data.status`
   * (§7.5); `event:` names delimit frames (`phase` / `complete` / `error`)
   * but never drive control flow by themselves. `phase` field is ignored.
   *
   * Terminal `complete`/`error` frames carry the same job JSON as
   * `GET /v1/jobs/<id>` and go through the same `parseJob` as polling —
   * never a laxer SSE-only schema. Non-terminal `phase` frames are a
   * status/progress subset (plus inline `awaiting_signature` when applicable).
   * Beleg: api/src/jobs.rs `stream_job` L137–150, `job_event_to_sse` L248–269.
   */
  async *streamJob(
    jobId: string,
    signal?: AbortSignal,
  ): AsyncGenerator<V1SseStreamFrame, void, unknown> {
    if (jobId.length === 0) {
      throw new Error('streamJob: job_id must not be empty');
    }
    const controller = new AbortController();
    const timeoutHandle = setTimeout(() => controller.abort(), this.requestTimeoutMs);
    if (signal) {
      if (signal.aborted) controller.abort();
      else signal.addEventListener('abort', () => controller.abort(), { once: true });
    }
    try {
      const res = await this.fetchImpl(
        `${this.apiUrl}/v1/jobs/${encodeURIComponent(jobId)}/stream`,
        { signal: controller.signal, headers: { Accept: 'text/event-stream' } },
      );
      if (!res.ok) {
        const rawBody = await res.text();
        throw parseV1ApiError(res.status, rawBody);
      }
      const body = expectPresent(res.body, 'streamJob: response has no readable body for SSE');
      const reader = body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      /**
       * Parse one SSE frame text into a yieldable job view.
       * Shared by the read loop and the EOF flush path so final frames
       * without a trailing blank line are not dropped.
       * Terminal statuses: completed | failed | cancelled.
       */
      const consumeSseFrame = (
        frame: string,
      ): { yieldFrame: V1SseStreamFrame | null; terminal: boolean } => {
        let eventName = 'message';
        let dataPayload = '';
        // SSE: lines end with CRLF, LF, or CR (WHATWG / HTML Living Standard).
        for (const line of frame.split(/\r\n|\n|\r/)) {
          if (line.startsWith(':')) continue;
          if (line.startsWith('event:')) {
            eventName = line.slice('event:'.length).trim();
          } else if (line.startsWith('data:')) {
            // Accumulate multi-line data with newline (SSE); our frames are single-line JSON.
            const piece = line.slice('data:'.length).trimStart();
            dataPayload = dataPayload.length === 0 ? piece : `${dataPayload}\n${piece}`;
          }
        }
        if (dataPayload.length === 0) {
          return { yieldFrame: null, terminal: false };
        }
        const parsed: unknown = JSON.parse(dataPayload);
        const view = parseSseJobPayload(parsed);
        // Clients dispatch only on status — yield it explicitly.
        // Branch on `full` so the yielded value keeps the discriminated union
        // (object-spread would collapse the two arms into one mixed type).
        const yieldFrame: V1SseStreamFrame = view.full
          ? {
              event: eventName,
              status: view.status,
              full: true,
              job: view.job,
            }
          : {
              event: eventName,
              status: view.status,
              full: false,
              job: view.job,
            };
        const terminal =
          view.status === 'completed' ||
          view.status === 'failed' ||
          view.status === 'cancelled';
        return { yieldFrame, terminal };
      };

      for (;;) {
        const { value, done } = await reader.read();
        if (done) {
          // Some runtimes deliver a final chunk with done=true; absorb it before flush.
          if (value !== undefined) {
            buffer += decoder.decode(value, { stream: true });
          }
          // Flush decoder (final incomplete UTF-8 sequence) and drain remainder.
          buffer += decoder.decode();
          let sawTerminal = false;
          let boundary = findSseFrameBoundary(buffer);
          while (boundary !== null) {
            const frame = buffer.slice(0, boundary.index);
            buffer = buffer.slice(boundary.index + boundary.length);
            const result = consumeSseFrame(frame);
            if (result.yieldFrame !== null) {
              yield result.yieldFrame;
              if (result.terminal) {
                sawTerminal = true;
                break;
              }
            }
            boundary = findSseFrameBoundary(buffer);
          }
          // Trailing bytes without a closing blank line still form one frame.
          if (!sawTerminal && buffer.length > 0) {
            const result = consumeSseFrame(buffer);
            if (result.yieldFrame !== null) {
              yield result.yieldFrame;
              if (result.terminal) {
                sawTerminal = true;
              }
            }
          }
          if (sawTerminal) {
            return;
          }
          throw new Error('streamJob: stream ended without terminal status');
        }
        buffer += decoder.decode(value, { stream: true });
        let boundary = findSseFrameBoundary(buffer);
        while (boundary !== null) {
          const frame = buffer.slice(0, boundary.index);
          buffer = buffer.slice(boundary.index + boundary.length);
          const result = consumeSseFrame(frame);
          if (result.yieldFrame !== null) {
            yield result.yieldFrame;
            if (result.terminal) {
              return;
            }
          }
          boundary = findSseFrameBoundary(buffer);
        }
      }
    } finally {
      clearTimeout(timeoutHandle);
      controller.abort();
    }
  }

  /**
   * Poll until `awaiting_signature` or a terminal status. Respects
   * `Retry-After`. Missing `Retry-After` on a non-terminal status is
   * fail-closed (the node is required to send it for non-terminal polls).
   */
  async waitForAwaitingSignature(
    jobId: string,
    opts: { signal?: AbortSignal; sleep?: (ms: number) => Promise<void> } = {},
  ): Promise<V1Job> {
    const sleep =
      opts.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
    for (;;) {
      if (opts.signal?.aborted) {
        throw new Error(`waitForAwaitingSignature(${jobId}): aborted`);
      }
      const { job, retryAfterMs } = await this.getJob(jobId, opts.signal);
      if (job.status === 'awaiting_signature') {
        return job;
      }
      if (job.status === 'completed' || job.status === 'failed' || job.status === 'cancelled') {
        return job;
      }
      if (retryAfterMs === null) {
        throw new Error(
          `waitForAwaitingSignature(${jobId}): non-terminal status ${job.status} without Retry-After`,
        );
      }
      await sleep(retryAfterMs);
    }
  }

  // ---- Pull session (§5.1 / §7.5) ----------------------------------------

  /**
   * `POST /v1/pull/challenge`.
   * Beleg: api/src/pull.rs `post_pull_challenge` L295–337.
   */
  async openPullChallenge(subject: string, signal?: AbortSignal): Promise<PullChallenge> {
    if (subject.length === 0) {
      throw new Error('openPullChallenge: subject is required');
    }
    const data = await this.requestJson('/v1/pull/challenge', {
      method: 'POST',
      body: JSON.stringify({ subject }),
      ...(signal ? { signal } : {}),
    });
    return parsePullChallenge(data);
  }

  /**
   * `POST /v1/pull` with OwnershipProof or GrantProof.
   * Beleg: api/src/pull.rs `post_pull` — body `{ nonce, expiry, proof, scope? }`
   * (Redeem-body `expiry` normative on the stateless API edge).
   *
   * Returns the opaque session token; the caller holds it and presents it as
   * `Authorization: Bearer <token>`. The token is never stored on this client
   * instance and never appears in thrown messages.
   *
   * When `scope` is omitted the body is byte-identical to the ownership-only
   * form (no `scope` key). When provided, the resolved scope is echoed.
   */
  async openPullSession(
    input: {
      challenge: PullChallenge;
      proof: OwnershipProofJson | GrantProofJson;
      scope?: GrantScopeInput;
    },
    signal?: AbortSignal,
  ): Promise<V1PullResult> {
    const body = {
      nonce: input.challenge.nonce,
      expiry: input.challenge.expiry,
      proof: input.proof,
      ...(input.scope !== undefined ? { scope: grantScopeToJsonBody(input.scope) } : {}),
    };
    const data = await this.requestJson('/v1/pull', {
      method: 'POST',
      body: JSON.stringify(body),
      ...(signal ? { signal } : {}),
    });
    return parsePullResult(data);
  }

  /**
   * Convenience: challenge → sign OwnershipProof with sk₀ → pull session.
   */
  async openOwnershipPullSession(
    input: {
      subject: string;
      sk0: Uint8Array;
      nkCommit: Uint8Array;
    },
    signal?: AbortSignal,
  ): Promise<V1PullResult> {
    const challenge = await this.openPullChallenge(input.subject, signal);
    const proof = buildOwnershipProof({
      subject: input.subject,
      sk0: input.sk0,
      nkCommit: input.nkCommit,
      challenge,
      host: this.host,
    });
    return this.openPullSession({ challenge, proof }, signal);
  }

  /**
   * Convenience: pull challenge → sign GrantProof with grantee secret → pull session.
   * Uses the same `POST /v1/pull/challenge` as ownership (no separate grant-pull endpoint).
   * `subject` is the Bech32m address the grant names; the SDK decodes it to raw bytes
   * for the chal (it does not decode the opaque grant string).
   */
  async openGrantPullSession(
    input: {
      subject: string;
      grant: string;
      granteeSecret: Uint8Array;
    },
    scope?: GrantScopeInput,
    signal?: AbortSignal,
  ): Promise<V1PullResult> {
    // Fail-closed before the challenge request: malformed scopes must not
    // cause any network I/O.
    if (scope !== undefined) {
      grantScopeToJsonBody(scope);
    }
    const challenge = await this.openPullChallenge(input.subject, signal);
    const subjectRaw = decodeZkAddress(input.subject);
    const proof = buildGrantProof({
      grant: input.grant,
      granteeSecret: input.granteeSecret,
      subjectRaw,
      challenge,
      host: this.host,
    });
    return this.openPullSession(
      {
        challenge,
        proof,
        ...(scope !== undefined ? { scope } : {}),
      },
      signal,
    );
  }

  // ---- Attest balance (§7.5) ---------------------------------------------

  /**
   * `POST /v1/attest/balance/challenge`.
   * Beleg: api/src/attest.rs `post_attest_balance_challenge`.
   * Response shape matches PullChallenge (nonce/expiry/domain); domain is
   * checked against ATTEST_BALANCE_CHALLENGE_DOMAIN, not PULL_CHALLENGE_DOMAIN.
   */
  async openAttestBalanceChallenge(subject: string, signal?: AbortSignal): Promise<PullChallenge> {
    if (subject.length === 0) {
      throw new Error('openAttestBalanceChallenge: subject is required');
    }
    const data = await this.requestJson('/v1/attest/balance/challenge', {
      method: 'POST',
      body: JSON.stringify({ subject }),
      ...(signal ? { signal } : {}),
    });
    return parseAttestBalanceChallenge(data);
  }

  /**
   * Challenge → sign OwnershipProof (request_hash-bound) → POST /v1/attest/balance.
   * Beleg: api/src/attest.rs `post_attest_balance` — body carries subject,
   * asset_id, optional nav_ceiling/size_ceiling, challenge echo {nonce,expiry},
   * and ownership_proof. Response is `202 { job_id }` with no status field.
   *
   * navCeiling/sizeCeiling must both be set or both omitted — enforced before
   * any network call (ceilingEncoding fail-closed).
   */
  async attestBalance(
    input: {
      subject: string;
      sk0: Uint8Array;
      nkCommit: Uint8Array;
      assetId: Uint8Array;
      navCeiling?: Uint8Array;
      sizeCeiling?: bigint | number;
    },
    signal?: AbortSignal,
  ): Promise<{ job_id: string }> {
    // Fail-closed before network I/O: mixed ceilings must not open a challenge.
    ceilingEncoding(input.navCeiling, input.sizeCeiling);

    const challenge = await this.openAttestBalanceChallenge(input.subject, signal);
    const proof = buildAttestOwnershipProof({
      subject: input.subject,
      sk0: input.sk0,
      nkCommit: input.nkCommit,
      challenge,
      host: this.host,
      assetId: input.assetId,
      ...(input.navCeiling !== undefined ? { navCeiling: input.navCeiling } : {}),
      ...(input.sizeCeiling !== undefined ? { sizeCeiling: input.sizeCeiling } : {}),
    });

    const body: {
      subject: string;
      asset_id: string;
      nav_ceiling?: string;
      size_ceiling?: string;
      challenge: { nonce: string; expiry: string };
      ownership_proof: OwnershipProofJson;
    } = {
      subject: input.subject,
      asset_id: encodeHexLower(input.assetId),
      challenge: { nonce: challenge.nonce, expiry: challenge.expiry },
      ownership_proof: proof,
    };
    if (input.navCeiling !== undefined) {
      body.nav_ceiling = encodeHexLower(input.navCeiling);
    }
    if (input.sizeCeiling !== undefined) {
      body.size_ceiling = String(input.sizeCeiling);
    }

    const data = await this.requestJson('/v1/attest/balance', {
      method: 'POST',
      body: JSON.stringify(body),
      ...(signal ? { signal } : {}),
    });
    return parseAttestBalanceAccepted(data);
  }

  // ---- Issue view grant (§7.5) -------------------------------------------

  /**
   * `POST /v1/grants/challenge`.
   * Beleg: api/src/grants.rs `post_grants_challenge`.
   * Response shape matches PullChallenge (nonce/expiry/domain); domain is
   * checked against ISSUE_GRANT_CHALLENGE_DOMAIN, not PULL_CHALLENGE_DOMAIN.
   */
  async openGrantsChallenge(subject: string, signal?: AbortSignal): Promise<PullChallenge> {
    if (subject.length === 0) {
      throw new Error('openGrantsChallenge: subject is required');
    }
    const data = await this.requestJson('/v1/grants/challenge', {
      method: 'POST',
      body: JSON.stringify({ subject }),
      ...(signal ? { signal } : {}),
    });
    return parseGrantsChallenge(data);
  }

  /**
   * Challenge → sign OwnershipProof (request_hash-bound) → POST /v1/grants.
   * Beleg: api/src/grants.rs `post_grants` — body carries subject, grantee_pk,
   * scope, grant-level expiry, challenge echo {nonce,expiry}, and ownership_proof.
   * Response is `200 { grant }` (Bech32m zkgrant string).
   *
   * Scope asset encoding is validated before any network call (encodeGrantAssetIds
   * fail-closed), matching attestBalance's ceilingEncoding ordering.
   */
  async issueViewGrant(
    input: {
      subject: string;
      sk0: Uint8Array;
      nkCommit: Uint8Array;
      granteePk: Uint8Array;
      scope: GrantScopeInput;
      grantExpiry: bigint;
    },
    signal?: AbortSignal,
  ): Promise<{ grant: string }> {
    // Snapshot the scope before any await so the signed request_hash (derived
    // after the challenge round-trip) and the wire body (derived before it)
    // cannot diverge if the caller mutates the passed scope/assetIds during the
    // network I/O. All later derivations use this immutable snapshot only.
    const scope: GrantScopeInput =
      input.scope.allAssets === true
        ? { ...input.scope }
        : {
            ...input.scope,
            assetIds: input.scope.assetIds.map((id) => Uint8Array.from(id)),
          };

    // Fail-closed before network I/O: bad scope must not open a challenge.
    if (scope.allAssets === true) {
      encodeGrantAssetIds(true, []);
    } else {
      encodeGrantAssetIds(false, scope.assetIds);
    }
    const scopeBody = grantScopeToJsonBody(scope);

    const challenge = await this.openGrantsChallenge(input.subject, signal);
    const proof = buildIssueGrantOwnershipProof({
      subject: input.subject,
      sk0: input.sk0,
      nkCommit: input.nkCommit,
      challenge,
      host: this.host,
      granteePk: input.granteePk,
      scope,
      grantExpiry: input.grantExpiry,
    });

    const body = {
      subject: input.subject,
      grantee_pk: encodeHexLower(input.granteePk),
      scope: scopeBody,
      expiry: input.grantExpiry.toString(),
      challenge: { nonce: challenge.nonce, expiry: challenge.expiry },
      ownership_proof: proof,
    };

    const data = await this.requestJson('/v1/grants', {
      method: 'POST',
      body: JSON.stringify(body),
      ...(signal ? { signal } : {}),
    });
    return parseIssueGrantResult(data);
  }

  /**
   * `GET /v1/account/state` with pull-session Bearer token.
   * Beleg: api/src/pull.rs `get_account_state` L511–590.
   *
   * 401 unauthorized vs 410 session_expired are preserved as distinct
   * {@link V1ApiError} codes. The token never appears in the error message.
   */
  async getAccountState(sessionToken: string, signal?: AbortSignal): Promise<V1AccountState> {
    if (sessionToken.length === 0) {
      throw new Error('getAccountState: session token is required');
    }
    try {
      const data = await this.requestJson('/v1/account/state', {
        method: 'GET',
        headers: { Authorization: `Bearer ${sessionToken}` },
        ...(signal ? { signal } : {}),
      });
      return parseAccountState(data);
    } catch (err) {
      if (err instanceof V1ApiError) {
        throw redactError(err, sessionToken);
      }
      throw err;
    }
  }

  // ---- Sign gate (the three refusals) ------------------------------------

  /**
   * Run the three refusals against `awaiting_signature` + account head, then
   * produce a §3.2 signature. Does **not** POST — use {@link signJob} with
   * {@link signBodyFromSignature}.
   */
  signAwaiting(input: {
    localPubkey: Uint8Array;
    secretKey: Uint8Array;
    accountState: AccountStateHead;
    awaiting: AwaitingSignature;
    nextPubkey: Uint8Array;
    npkRand: Uint8Array;
    /** When set, compared to `this.network`; mismatch → NetworkMismatchRefusalError. */
    nodeNetwork?: Network;
  }): TransitionSignature {
    return refuseOrSignTransition({
      localPubkey: input.localPubkey,
      secretKey: input.secretKey,
      accountState: input.accountState,
      awaiting: input.awaiting,
      walletNetwork: this.network,
      ...(input.nodeNetwork !== undefined ? { nodeNetwork: input.nodeNetwork } : {}),
      nextPubkey: input.nextPubkey,
      npkRand: input.npkRand,
    });
  }

  /**
   * Full handshake step: refuse-or-sign then `POST …/sign`.
   * Returns the post-sign job object from the server.
   */
  async refuseOrSignAndSubmit(input: {
    jobId: string;
    localPubkey: Uint8Array;
    secretKey: Uint8Array;
    accountState: AccountStateHead;
    awaiting: AwaitingSignature;
    nextPubkey: Uint8Array;
    npkRand: Uint8Array;
    nodeNetwork?: Network;
    signal?: AbortSignal;
  }): Promise<{ signature: TransitionSignature; job: V1Job }> {
    const signature = this.signAwaiting({
      localPubkey: input.localPubkey,
      secretKey: input.secretKey,
      accountState: input.accountState,
      awaiting: input.awaiting,
      nextPubkey: input.nextPubkey,
      npkRand: input.npkRand,
      ...(input.nodeNetwork !== undefined ? { nodeNetwork: input.nodeNetwork } : {}),
    });
    const body = signBodyFromSignature(signature);
    const job = await this.signJob(input.jobId, body, input.signal);
    return { signature, job };
  }

  // ---- Internals ----------------------------------------------------------

  private async requestJson(
    path: string,
    options: RequestInit & { signal?: AbortSignal } = {},
  ): Promise<unknown> {
    const { data } = await this.requestJsonWithHeaders(path, options);
    return data;
  }

  private async requestJsonWithHeaders(
    path: string,
    options: RequestInit & { signal?: AbortSignal } = {},
  ): Promise<{ data: unknown; headers: Headers }> {
    const controller = new AbortController();
    const timeoutHandle = setTimeout(() => controller.abort(), this.requestTimeoutMs);
    if (options.signal) {
      if (options.signal.aborted) controller.abort();
      else options.signal.addEventListener('abort', () => controller.abort(), { once: true });
    }
    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        ...(options.headers as Record<string, string> | undefined),
      };
      const res = await this.fetchImpl(`${this.apiUrl}${path}`, {
        ...options,
        headers,
        signal: controller.signal,
      });
      const rawText = await res.text();
      if (!res.ok) {
        throw parseV1ApiError(res.status, rawText);
      }
      if (rawText.trim().length === 0) {
        return { data: {}, headers: res.headers };
      }
      return { data: JSON.parse(rawText) as unknown, headers: res.headers };
    } finally {
      clearTimeout(timeoutHandle);
    }
  }
}

// ---------------------------------------------------------------------------
// Parsers (fail-closed, no silent defaults)
// ---------------------------------------------------------------------------

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function requireString(obj: Record<string, unknown>, key: string): string {
  const v = obj[key];
  if (typeof v !== 'string') {
    throw new Error(`response.${key}: expected string`);
  }
  return v;
}

function requireNumber(obj: Record<string, unknown>, key: string): number {
  const v = obj[key];
  if (typeof v !== 'number' || !Number.isFinite(v)) {
    throw new Error(`response.${key}: expected finite number`);
  }
  return v;
}

function requireCounter(obj: Record<string, unknown>, key: string): number {
  const v = requireNumber(obj, key);
  if (!Number.isSafeInteger(v) || v < 0 || v > 0x7fffffff) {
    throw new Error(`response.${key}: expected integer in [0, 2^31-1]`);
  }
  return v;
}

function parseJobStatus(s: string): V1JobStatusValue {
  switch (s) {
    case 'accepted':
    case 'proving':
    case 'awaiting_signature':
    case 'publishing':
    case 'completed':
    case 'failed':
    case 'cancelled':
      return s;
    default:
      throw new Error(`job.status outside closed set: ${JSON.stringify(s)}`);
  }
}

/**
 * Map one SSE `data:` JSON payload to a status + job view.
 *
 * - Full job objects (`job_id` present — poll shape and `complete`/`error`
 *   frames) always go through `parseJob` (`full: true`).
 * - Terminal statuses without a full job object still go through
 *   `parseJob` so missing `result`/`error` fail with the same
 *   messages as polling (no SSE bypass).
 * - Non-terminal `phase` frames only carry `status` / `progress` /
 *   optional diagnostic `phase`, plus inline `awaiting_signature` when
 *   `status == "awaiting_signature"` (§7.5 L2947, L3033) (`full: false`).
 */
function parseSseJobPayload(
  data: unknown,
):
  | { status: V1JobStatusValue; full: true; job: V1Job }
  | { status: V1JobStatusValue; full: false; job: V1SsePhasePayload } {
  if (!isRecord(data) || typeof data.status !== 'string') {
    throw new Error('SSE/job payload missing status string');
  }
  const status = parseJobStatus(data.status);
  const isFullJobObject = typeof data.job_id === 'string' && typeof data.kind === 'string';

  if (isFullJobObject || status === 'completed' || status === 'failed' || status === 'cancelled') {
    // Full job JSON (poll shape / complete / error) — one shared parser.
    const job = parseJob(data);
    return { status: job.status, full: true, job };
  }

  // Phase-frame subset: progress is on the wire (api phase_event_data);
  // status-specific awaiting_signature is required when applicable.
  const job: V1SsePhasePayload = {
    status,
    progress: requireNumber(data, 'progress'),
  };
  if (typeof data.phase === 'string') {
    job.phase = data.phase;
  }
  if (status === 'awaiting_signature') {
    job.awaiting_signature = parseAwaitingSignature(
      expectPresent(
        data.awaiting_signature,
        'job status is awaiting_signature but payload is absent',
      ),
    );
  }
  return { status, full: false, job };
}

function parseJobAccepted(data: unknown): V1JobAccepted {
  if (!isRecord(data)) throw new Error('JobAccepted: expected object');
  const job_id = requireString(data, 'job_id');
  const status = requireString(data, 'status');
  if (status !== 'accepted') {
    throw new Error(`JobAccepted.status must be "accepted", got ${JSON.stringify(status)}`);
  }
  return { job_id, status: 'accepted' };
}

function parseAwaitingSignature(data: unknown): AwaitingSignature {
  if (!isRecord(data)) throw new Error('awaiting_signature: expected object');
  return {
    new_account_state_hash: requireString(data, 'new_account_state_hash'),
    output_coins_root: requireString(data, 'output_coins_root'),
    input_nullifiers_root: requireString(data, 'input_nullifiers_root'),
    coin_history_root: requireString(data, 'coin_history_root'),
    nav_commitment: requireString(data, 'nav_commitment'),
    npk_commit: requireString(data, 'npk_commit'),
    proof_data_hash: requireString(data, 'proof_data_hash'),
    txn_pubkey: requireString(data, 'txn_pubkey'),
    send_counter: requireCounter(data, 'send_counter'),
  };
}

/**
 * Parse a §7.5 job poll / terminal-SSE object. Fail-closed on terminal
 * payload rules (mirror api/src/jobs.rs `job_to_json` / `validate_job_result_for_kind`):
 *
 * - `awaiting_signature` → `awaiting_signature` object with all nine fields
 * - `completed` → kind-disjoint `result` (see below)
 * - `failed` | `cancelled` → `error` object `{ error, message }`
 *
 * Completed result shapes are hard-disjoint (api `validate_job_result_for_kind`):
 * - `kind ∈ {mint,send,receive}` → `output_coin_ids` (hex array) + the three
 *   32-byte digests (`new_account_state_hash`, `output_coins_root`,
 *   `input_nullifiers_root`) + optional `publisher_pubkey`; **never**
 *   `attestation`.
 * - `kind === 'attest_balance'` → exclusively `{ attestation: lowercase-hex }`
 *   (variable length); **never** digests / `output_coin_ids` / `publisher_pubkey`.
 * - any other `kind` → error (closed set: mint|send|receive|attest_balance).
 */
function parseJob(data: unknown): V1Job {
  if (!isRecord(data)) throw new Error('job: expected object');
  const status = parseJobStatus(requireString(data, 'status'));
  const kind = requireString(data, 'kind');
  const job: V1Job = {
    job_id: requireString(data, 'job_id'),
    kind,
    status,
    progress: requireNumber(data, 'progress'),
  };
  if (typeof data.phase === 'string') {
    job.phase = data.phase;
  }
  if (status === 'awaiting_signature') {
    job.awaiting_signature = parseAwaitingSignature(
      expectPresent(
        data.awaiting_signature,
        'job status is awaiting_signature but payload is absent',
      ),
    );
  }
  if (status === 'completed') {
    const resultRaw = expectPresent(data.result, 'job status is completed but result is absent');
    if (!isRecord(resultRaw)) throw new Error('job.result: expected object');

    if (kind === 'mint' || kind === 'send' || kind === 'receive') {
      if ('attestation' in resultRaw) {
        throw new Error(`job.result: mixed completed result for kind=${kind} includes attestation`);
      }
      const coinIds = resultRaw.output_coin_ids;
      if (!Array.isArray(coinIds)) {
        throw new Error('job.result.output_coin_ids: expected array');
      }
      const output_coin_ids = coinIds.map((c, i) => {
        if (typeof c !== 'string') {
          throw new Error(`job.result.output_coin_ids[${i}]: expected string`);
        }
        decodeHexExact(c, 32, `job.result.output_coin_ids[${i}]`);
        return c;
      });
      job.result = { output_coin_ids };

      job.result.new_account_state_hash = requireResultHex32(
        resultRaw,
        'new_account_state_hash',
        kind,
      );
      job.result.output_coins_root = requireResultHex32(resultRaw, 'output_coins_root', kind);
      job.result.input_nullifiers_root = requireResultHex32(
        resultRaw,
        'input_nullifiers_root',
        kind,
      );
      if (typeof resultRaw.publisher_pubkey === 'string') {
        decodeHexExact(resultRaw.publisher_pubkey, 32, 'job.result.publisher_pubkey');
        job.result.publisher_pubkey = resultRaw.publisher_pubkey;
      }
    } else if (kind === 'attest_balance') {
      // Wire form is exclusively { attestation } (node completed_attest_result;
      // api validates no transition digest fields).
      const transitionResultKeys = [
        'new_account_state_hash',
        'output_coins_root',
        'input_nullifiers_root',
        'output_coin_ids',
        'publisher_pubkey',
      ] as const;
      const unexpectedKey = transitionResultKeys.find((key) => key in resultRaw);
      if (unexpectedKey !== undefined) {
        throw new Error(
          `job.result: mixed completed result for kind=attest_balance includes ${unexpectedKey}`,
        );
      }
      const attestation = requireAttestationHex(resultRaw.attestation, 'job.result.attestation');
      job.result = { attestation };
    } else {
      // Closed set: api/src/jobs.rs CLOSED_JOB_KINDS = mint|send|receive|attest_balance.
      throw new Error(
        `job.result: unsupported completed job kind ${JSON.stringify(kind)} ` +
          '(closed set: mint|send|receive|attest_balance)',
      );
    }
  }
  if (status === 'failed' || status === 'cancelled') {
    const errorRaw = expectPresent(data.error, `job status is ${status} but error is absent`);
    if (!isRecord(errorRaw)) throw new Error('job.error: expected object');
    job.error = {
      error: requireString(errorRaw, 'error'),
      message: requireString(errorRaw, 'message'),
    };
  }
  return job;
}

/** Required 32-byte lowercase hex digest on a completed mint/send/receive result. */
function requireResultHex32(
  result: Record<string, unknown>,
  key: 'new_account_state_hash' | 'output_coins_root' | 'input_nullifiers_root',
  kind: string,
): string {
  const v = result[key];
  if (typeof v !== 'string') {
    throw new Error(
      `job.result.${key}: required 32-byte hex for completed kind=${kind} (fail-closed)`,
    );
  }
  decodeHexExact(v, 32, `job.result.${key}`);
  return v;
}

/**
 * Non-empty, even-length, lowercase-hex `attestation` on a completed
 * attest_balance result. No fixed byte length (variable-size C_balance
 * proof) — unlike requireResultHex32, this does not decode to bytes, the
 * SDK only passes the hex string through (thin-client: no proof
 * verification here).
 */
function requireAttestationHex(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`${field}: expected non-empty hex string`);
  }
  if (!/^(?:[0-9a-f]{2})+$/.test(value)) {
    throw new Error(
      `${field}: non-canonical hex (must be lowercase 0-9a-f byte-pairs, no 0x/whitespace)`,
    );
  }
  return value;
}

/**
 * Locate the next SSE event-stream frame boundary.
 *
 * WHATWG / HTML Living Standard allow CRLF, LF, or CR as line terminators;
 * a blank line is two consecutive terminators and ends a frame. Scan every
 * pair from {CRLF, LF, CR} × {CRLF, LF, CR}; the earliest match wins, and on
 * a shared index the longest match wins. A single `\r\n` is not a frame end.
 */
function findSseFrameBoundary(buffer: string): { index: number; length: number } | null {
  let best: { index: number; length: number } | null = null;
  const candidates: ReadonlyArray<readonly [string, number]> = [
    ['\r\n\r\n', 4],
    ['\r\n\n', 3],
    ['\r\n\r', 3],
    ['\n\r\n', 3],
    ['\n\n', 2],
    ['\n\r', 2],
    ['\r\r\n', 3],
    ['\r\r', 2],
  ];
  for (const [sep, length] of candidates) {
    const index = buffer.indexOf(sep);
    if (index === -1) continue;
    if (best === null || index < best.index || (index === best.index && length > best.length)) {
      best = { index, length };
    }
  }
  return best;
}

function parsePullChallenge(data: unknown): PullChallenge {
  if (!isRecord(data)) throw new Error('PullChallenge: expected object');
  const domain = requireString(data, 'domain');
  if (domain !== PULL_CHALLENGE_DOMAIN) {
    throw new Error(
      `PullChallenge.domain must be ${JSON.stringify(PULL_CHALLENGE_DOMAIN)}, got ${JSON.stringify(domain)}`,
    );
  }
  const nonce = requireString(data, 'nonce');
  decodeHexExact(nonce, 32, 'PullChallenge.nonce');
  const expiry = requireString(data, 'expiry');
  parseExpiryDecimal(expiry);
  return { nonce, expiry, domain };
}

/** AttestBalance challenge response — same fields as PullChallenge, own domain. */
function parseAttestBalanceChallenge(data: unknown): PullChallenge {
  if (!isRecord(data)) throw new Error('AttestBalanceChallenge: expected object');
  const domain = requireString(data, 'domain');
  if (domain !== ATTEST_BALANCE_CHALLENGE_DOMAIN) {
    throw new Error(
      `AttestBalanceChallenge.domain must be ${JSON.stringify(ATTEST_BALANCE_CHALLENGE_DOMAIN)}, got ${JSON.stringify(domain)}`,
    );
  }
  const nonce = requireString(data, 'nonce');
  decodeHexExact(nonce, 32, 'AttestBalanceChallenge.nonce');
  const expiry = requireString(data, 'expiry');
  parseExpiryDecimal(expiry);
  return { nonce, expiry, domain };
}

/**
 * §7.5 L2894: `202 { job_id }` — no status field on this admit response.
 * Do not reuse parseJobAccepted (which requires status: "accepted").
 */
function parseAttestBalanceAccepted(data: unknown): { job_id: string } {
  if (!isRecord(data)) throw new Error('AttestBalanceAccepted: expected object');
  const job_id = requireString(data, 'job_id');
  if (job_id.length === 0) {
    throw new Error('AttestBalanceAccepted.job_id is empty');
  }
  return { job_id };
}

/** IssueGrant challenge response — same fields as PullChallenge, own domain. */
function parseGrantsChallenge(data: unknown): PullChallenge {
  if (!isRecord(data)) throw new Error('GrantsChallenge: expected object');
  const domain = requireString(data, 'domain');
  if (domain !== ISSUE_GRANT_CHALLENGE_DOMAIN) {
    throw new Error(
      `GrantsChallenge.domain must be ${JSON.stringify(ISSUE_GRANT_CHALLENGE_DOMAIN)}, got ${JSON.stringify(domain)}`,
    );
  }
  const nonce = requireString(data, 'nonce');
  decodeHexExact(nonce, 32, 'GrantsChallenge.nonce');
  const expiry = requireString(data, 'expiry');
  parseExpiryDecimal(expiry);
  return { nonce, expiry, domain };
}

/** §7.5: `200 { grant }` — Bech32m zkgrant string. */
function parseIssueGrantResult(data: unknown): { grant: string } {
  if (!isRecord(data)) throw new Error('IssueGrantResult: expected object');
  const grant = requireString(data, 'grant');
  if (grant.length === 0) {
    throw new Error('IssueGrantResult.grant is empty');
  }
  return { grant };
}

function parsePullResult(data: unknown): V1PullResult {
  if (!isRecord(data)) throw new Error('PullResult: expected object');
  const session = requireString(data, 'session');
  if (session.length === 0) {
    throw new Error('PullResult.session is empty');
  }
  const recordsRaw = data.records;
  if (!Array.isArray(recordsRaw)) {
    throw new Error('PullResult.records: expected array');
  }
  const records = recordsRaw.map((r, i) => {
    if (!isRecord(r)) throw new Error(`PullResult.records[${i}]: expected object`);
    const rec: V1PullResult['records'][number] = {
      record_id: requireString(r, 'record_id'),
      record_type: requireString(r, 'record_type'),
      blob_id: requireString(r, 'blob_id'),
      occurred_at: requireString(r, 'occurred_at'),
    };
    if (typeof r.transition_kind === 'string') {
      rec.transition_kind = r.transition_kind;
    }
    return rec;
  });
  return {
    records,
    session,
    session_expiry: requireString(data, 'session_expiry'),
  };
}

function parseAccountState(data: unknown): V1AccountState {
  if (!isRecord(data)) throw new Error('AccountState: expected object');
  const out: V1AccountState = {
    account_state: requireString(data, 'account_state'),
    state_head: requireString(data, 'state_head'),
    send_counter: requireCounter(data, 'send_counter'),
    current_pubkey: requireString(data, 'current_pubkey'),
  };
  if (typeof data.head_record_id === 'string') {
    out.head_record_id = data.head_record_id;
  }
  if (data.last_nullifier !== undefined) {
    if (!isRecord(data.last_nullifier)) {
      throw new Error('AccountState.last_nullifier: expected object');
    }
    out.last_nullifier = {
      pubkey: requireString(data.last_nullifier, 'pubkey'),
      r: requireString(data.last_nullifier, 'r'),
    };
  }
  return out;
}

function parseInfo(data: unknown): V1Info {
  if (!isRecord(data)) throw new Error('Info: expected object');
  const network = requireString(data, 'network');
  if (network !== 'mainnet' && network !== 'testnet' && network !== 'regtest') {
    throw new Error(`Info.network outside closed set: ${JSON.stringify(network)}`);
  }
  const protocol_version = requireString(data, 'protocol_version');
  const featuresRaw = data.features;
  if (!Array.isArray(featuresRaw)) {
    throw new Error('Info.features: expected array');
  }
  const features = featuresRaw.map((f, i) => {
    if (typeof f !== 'string') throw new Error(`Info.features[${i}]: expected string`);
    return f;
  });
  return { ...data, network, protocol_version, features };
}

function parseV1ApiError(status: number, rawBody: string): V1ApiError {
  // honest default — do not masquerade as a real server machineCode
  let machineCode = 'unparseable_error_body';
  let message = rawBody;
  try {
    const parsed: unknown = JSON.parse(rawBody);
    if (isRecord(parsed)) {
      if (typeof parsed.error === 'string') {
        machineCode = parsed.error;
      }
      if (typeof parsed.message === 'string') {
        message = parsed.message;
      }
    }
  } catch {
    // keep raw body
  }
  return new V1ApiError(status, machineCode, message, rawBody);
}

function redactError(err: V1ApiError, token: string): V1ApiError {
  // err.message is `zkCoins v1 API error <status> <code>: <human>` — slice with
  // the original machineCode so startsWith matches, then rebuild with the
  // redacted code so a token in the JSON `error` field never reappears.
  const prefix = `zkCoins v1 API error ${err.status} ${err.machineCode}: `;
  const human = err.message.startsWith(prefix) ? err.message.slice(prefix.length) : err.message;
  const redactedHuman = redactBearerToken(human, token);
  const redactedCode = redactBearerToken(err.machineCode, token);
  const raw = err.rawBody !== undefined ? redactBearerToken(err.rawBody, token) : undefined;
  return new V1ApiError(err.status, redactedCode, redactedHuman, raw);
}
