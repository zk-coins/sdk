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
 *   GET  /v1/info                    → api/src/info.rs `get_info`
 *
 * No mock mode. No silent fallbacks. Session tokens are never logged or
 * embedded in error messages.
 */

import { REQUEST_TIMEOUT_MS } from '../config.js';
import { redactBearerToken, V1ApiError } from './errors.js';
import { expectPresent } from './expectPresent.js';
import type { Network } from './mstate.js';
import {
  buildOwnershipProof,
  canonicalHostFromApiUrl,
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
  output_coin_ids: string[];
  publisher_pubkey?: string;
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
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

export class ZkCoinsV1Client {
  public readonly apiUrl: string;
  public readonly network: Network;
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
   */
  async submitTransition(
    body: TransitionRequest,
    opts: { idempotencyKey?: string; signal?: AbortSignal } = {},
  ): Promise<V1JobAccepted> {
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
      for (;;) {
        const { value, done } = await reader.read();
        if (done) return;
        buffer += decoder.decode(value, { stream: true });
        let sep: number;
        while ((sep = buffer.indexOf('\n\n')) !== -1) {
          const frame = buffer.slice(0, sep);
          buffer = buffer.slice(sep + 2);
          let eventName = 'message';
          let dataPayload = '';
          for (const line of frame.split('\n')) {
            if (line.startsWith(':')) continue;
            if (line.startsWith('event:')) {
              eventName = line.slice('event:'.length).trim();
            } else if (line.startsWith('data:')) {
              // Accumulate multi-line data with newline (SSE); our frames are single-line JSON.
              const piece = line.slice('data:'.length).trimStart();
              dataPayload = dataPayload.length === 0 ? piece : `${dataPayload}\n${piece}`;
            }
          }
          if (dataPayload.length === 0) continue;
          const parsed: unknown = JSON.parse(dataPayload);
          const view = parseSseJobPayload(parsed);
          // Clients dispatch only on status — yield it explicitly.
          // Branch on `full` so the yielded value keeps the discriminated union
          // (object-spread would collapse the two arms into one mixed type).
          if (view.full) {
            yield {
              event: eventName,
              status: view.status,
              full: true,
              job: view.job,
            };
          } else {
            yield {
              event: eventName,
              status: view.status,
              full: false,
              job: view.job,
            };
          }
          if (
            view.status === 'completed' ||
            view.status === 'failed' ||
            view.status === 'cancelled'
          ) {
            return;
          }
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
   * `POST /v1/pull` with OwnershipProof.
   * Beleg: api/src/pull.rs `post_pull` L344–428 — body `{ nonce, expiry, proof }`
   * (Redeem-body `expiry` normative on the stateless API edge).
   *
   * Returns the opaque session token; the caller holds it and presents it as
   * `Authorization: Bearer <token>`. The token is never stored on this client
   * instance and never appears in thrown messages.
   */
  async openPullSession(
    input: {
      challenge: PullChallenge;
      proof: OwnershipProofJson;
    },
    signal?: AbortSignal,
  ): Promise<V1PullResult> {
    const body = {
      nonce: input.challenge.nonce,
      expiry: input.challenge.expiry,
      proof: input.proof,
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
    send_counter: requireNumber(data, 'send_counter'),
  };
}

/**
 * Parse a §7.5 job poll / terminal-SSE object. Fail-closed on terminal
 * payload rules (mirror api/src/jobs.rs `job_to_json`):
 *
 * - `awaiting_signature` → `awaiting_signature` object with all nine fields
 * - `completed` → `result` object (with `output_coin_ids: string[]`)
 * - `failed` | `cancelled` → `error` object `{ error, message }`
 *
 * Optional on `result` only: `publisher_pubkey?`, `attestation?`, and the
 * three digests when empty (attest_balance may omit them on the wire).
 */
function parseJob(data: unknown): V1Job {
  if (!isRecord(data)) throw new Error('job: expected object');
  const status = parseJobStatus(requireString(data, 'status'));
  const job: V1Job = {
    job_id: requireString(data, 'job_id'),
    kind: requireString(data, 'kind'),
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
    const coinIds = resultRaw.output_coin_ids;
    if (!Array.isArray(coinIds)) {
      throw new Error('job.result.output_coin_ids: expected array');
    }
    job.result = {
      output_coin_ids: coinIds.map((c, i) => {
        if (typeof c !== 'string') {
          throw new Error(`job.result.output_coin_ids[${i}]: expected string`);
        }
        return c;
      }),
    };
    // Digest fields are required for mint/send/receive on the wire shape
    // (§7.5 result = { ash, ocr, inr, output_coin_ids, … }) but may be
    // empty/omitted for kind == "attest_balance" (api job_result_json).
    // Presence is therefore not inventable — only copy when the server sent a string.
    if (typeof resultRaw.new_account_state_hash === 'string') {
      job.result.new_account_state_hash = resultRaw.new_account_state_hash;
    }
    if (typeof resultRaw.output_coins_root === 'string') {
      job.result.output_coins_root = resultRaw.output_coins_root;
    }
    if (typeof resultRaw.input_nullifiers_root === 'string') {
      job.result.input_nullifiers_root = resultRaw.input_nullifiers_root;
    }
    if (typeof resultRaw.publisher_pubkey === 'string') {
      job.result.publisher_pubkey = resultRaw.publisher_pubkey;
    }
    if (typeof resultRaw.attestation === 'string') {
      job.result.attestation = resultRaw.attestation;
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

function parsePullChallenge(data: unknown): PullChallenge {
  if (!isRecord(data)) throw new Error('PullChallenge: expected object');
  const domain = requireString(data, 'domain');
  if (domain !== PULL_CHALLENGE_DOMAIN) {
    throw new Error(
      `PullChallenge.domain must be ${JSON.stringify(PULL_CHALLENGE_DOMAIN)}, got ${JSON.stringify(domain)}`,
    );
  }
  return {
    nonce: requireString(data, 'nonce'),
    expiry: requireString(data, 'expiry'),
    domain,
  };
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
    send_counter: requireNumber(data, 'send_counter'),
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
  let machineCode = 'internal_error';
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
  // err.message is `zkCoins v1 API error <status> <code>: <human>` — rebuild
  // from redacted human text only so the token cannot reappear in the prefix.
  const prefix = `zkCoins v1 API error ${err.status} ${err.machineCode}: `;
  const human = err.message.startsWith(prefix) ? err.message.slice(prefix.length) : err.message;
  const redactedHuman = redactBearerToken(human, token);
  const raw = err.rawBody !== undefined ? redactBearerToken(err.rawBody, token) : undefined;
  return new V1ApiError(err.status, err.machineCode, redactedHuman, raw);
}
