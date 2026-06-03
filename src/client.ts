/**
 * Typed REST client over `/api/*`.
 *
 * Stateless `fetch`-wrapper. Every method validates the response
 * body against the matching Zod schema before returning — drift
 * between the SDK and the server surfaces as a `ZodError` at the
 * boundary, not as a `TypeError` six call frames deep.
 *
 * The client deliberately does **not** sign anything. Signed-
 * request inputs (`SignedSendRequest`, `CommitRequest`,
 * `SignedClaimRequest`) are accepted as-is. Higher-level
 * orchestration — derive → build message → sign → POST → poll —
 * lives in `account.ts`; downstream wallet integrators can either use
 * the high-level `ZkCoinsAccount` or compose the primitives
 * themselves via this client.
 *
 * ## Jobs API
 *
 * The node exposes mint/send/commit as **asynchronous jobs**
 * (`/api/jobs/*`). The synchronous `/api/{mint,send,commit}` routes
 * were removed node-side (PR #161); this client only speaks the Jobs
 * API. The lifecycle is:
 *
 *   `POST /api/jobs/mint`  → 202 `{job_id, status}`
 *   `POST /api/jobs/send`  → 202 `{job_id, status}` (signed body)
 *   `GET  /api/jobs/:id`   → `{status, phase, ...}` (poll; `Retry-After`)
 *   `POST /api/jobs/:id/commit` → 200 `{status:"broadcasting"}` (send only)
 *   `POST /api/jobs/:id/cancel` → 200 `{status:"cancelled"}` (queued only)
 *   `GET  /api/jobs/:id/stream` → SSE frames (`event: phase|complete`)
 *
 * Every admit + commit + cancel call requires (mint/send) or accepts a
 * caller-supplied `Idempotency-Key` so a retried POST never enqueues a
 * duplicate job. Use `newIdempotencyKey()` to mint one per logical
 * operation and reuse it across retries.
 *
 * Request timeout is 2 minutes — proof generation on the server side
 * can be slow, especially under load. Caller can override via the
 * `signal` parameter on each method.
 */

import type { z } from 'zod';

import { randomBytes } from '@noble/hashes/utils.js';

import { API_URL, REQUEST_TIMEOUT_MS } from './config.js';
import { ApiError } from './errors.js';
import {
  BalanceResponseSchema,
  ClaimUsernameResponseSchema,
  HistoryResponseSchema,
  InfoResponseSchema,
  JobAcceptedSchema,
  JobStatusSchema,
  ResolveUsernameResponseSchema,
  type BalanceResponse,
  type ClaimUsernameResponse,
  type HistoryResponse,
  type InfoResponse,
  type JobAccepted,
  type JobStatus,
  type ResolveUsernameResponse,
} from './schemas.js';

/** Inputs to a mint job (`POST /api/jobs/mint`). */
export interface MintRequest {
  account_address: string;
  amount: number;
  /**
   * Multi-asset selector. Omit for the native asset; a present value
   * MUST be valid 32-byte hex (the node 422s a malformed one — no
   * silent fallback to native).
   */
  asset_id?: string;
}

/** Inputs to `POST /api/jobs/send` *before* signing. */
export interface SendRequest {
  account_address: string;
  recipient: string;
  amount: number;
  public_key: string;
  next_public_key: string;
  prev_commitment_pubkey?: string;
  /** Multi-asset selector — see `MintRequest.asset_id`. */
  asset_id?: string;
}

/** Inputs to `POST /api/jobs/send` with signature + timestamp attached. */
export interface SignedSendRequest extends SendRequest {
  signature: string;
  timestamp: number;
}

/** Inputs to `POST /api/jobs/:id/commit`. */
export interface CommitRequest {
  proof_id: number;
  public_key: string;
  signature: string;
  message: string;
}

/** Inputs to `POST /api/username/claim`. */
export interface SignedClaimRequest {
  username: string;
  address: string;
  public_key: string;
  signature: string;
  timestamp: number;
}

/** Inputs to `GET /api/history`. */
export interface HistoryOpts {
  limit?: number;
  offset?: number;
  signal?: AbortSignal;
}

/**
 * A polled job status plus the parsed `Retry-After` hint the node
 * attaches to non-terminal poll responses. `retryAfterMs` is `null`
 * when the header is absent (terminal states omit it).
 */
export interface JobStatusWithRetry {
  status: JobStatus;
  retryAfterMs: number | null;
}

/** Options for `new ZkCoinsClient({...})`. */
export interface ZkCoinsClientOptions {
  /**
   * Base URL of the zkCoins node (no trailing slash). Falls back to
   * the `API_URL` constant in `./config.ts` when unset.
   *
   * Where you source this value — env var, config file, hardcoded —
   * is the integrating app's concern, not the SDK's. The SDK is
   * environment-agnostic; pass the URL explicitly when overriding.
   */
  apiUrl?: string;
  /** Override the global `fetch` (e.g. for testing or RN polyfills). */
  fetch?: typeof globalThis.fetch;
  /** Per-request abort timeout in ms. Default 120_000 (2 min). */
  requestTimeoutMs?: number;
}

/**
 * Generate a fresh UUID v4 idempotency key from 16 CSPRNG bytes via
 * `@noble/hashes` `randomBytes` (not `crypto.randomUUID`, which is
 * absent in some React Native runtimes the SDK targets). The version
 * (`4`) and variant (`8|9|a|b`) nibbles are set per RFC 4122 so the
 * node's `Idempotency-Key` parser accepts it.
 */
export function newIdempotencyKey(): string {
  const b = randomBytes(16);
  // Version 4 + RFC-4122 variant.
  b[6] = (b[6]! & 0x0f) | 0x40;
  b[8] = (b[8]! & 0x3f) | 0x80;
  const h = (n: number): string => n.toString(16).padStart(2, '0');
  const hex = Array.from(b, h).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export class ZkCoinsClient {
  /**
   * The fully-qualified base URL this client talks to, after option
   * resolution (caller's `apiUrl` or the internal fallback) and
   * trailing-slash normalization. Exposed read-only so integrators
   * and tests can introspect the effective endpoint without
   * reaching into private state or re-deriving from options.
   */
  public readonly apiUrl: string;
  private readonly fetchImpl: typeof globalThis.fetch;
  private readonly requestTimeoutMs: number;

  constructor(opts: ZkCoinsClientOptions = {}) {
    const rawUrl = opts.apiUrl ?? API_URL;
    if (!/^https?:\/\//.test(rawUrl)) {
      throw new Error(
        `ZkCoinsClient: invalid apiUrl ${JSON.stringify(opts.apiUrl)} — must start with http:// or https://`,
      );
    }
    // Strip a trailing slash so consumers can pass either form.
    this.apiUrl = rawUrl.replace(/\/+$/, '');
    this.fetchImpl = opts.fetch ?? globalThis.fetch.bind(globalThis);
    this.requestTimeoutMs = opts.requestTimeoutMs ?? REQUEST_TIMEOUT_MS;
  }

  // ---- Read endpoints ----------------------------------------------------

  async balance(address: string, signal?: AbortSignal): Promise<BalanceResponse> {
    const url = `/api/balance?address=${encodeURIComponent(address)}`;
    return this.request(url, BalanceResponseSchema, signal ? { signal } : {});
  }

  async info(signal?: AbortSignal): Promise<InfoResponse> {
    return this.request('/api/info', InfoResponseSchema, signal ? { signal } : {});
  }

  /** Per-address transaction history — `GET /api/history`. */
  async history(address: string, opts: HistoryOpts = {}): Promise<HistoryResponse> {
    const params = new URLSearchParams({ address });
    if (opts.limit !== undefined) {
      params.set('limit', String(opts.limit));
    }
    if (opts.offset !== undefined) {
      params.set('offset', String(opts.offset));
    }
    return this.request(
      `/api/history?${params.toString()}`,
      HistoryResponseSchema,
      opts.signal ? { signal: opts.signal } : {},
    );
  }

  // ---- Username endpoints -------------------------------------------------

  async claimUsername(
    req: SignedClaimRequest,
    signal?: AbortSignal,
  ): Promise<ClaimUsernameResponse> {
    return this.request('/api/username/claim', ClaimUsernameResponseSchema, {
      method: 'POST',
      body: JSON.stringify(req),
      ...(signal ? { signal } : {}),
    });
  }

  async resolveUsername(username: string, signal?: AbortSignal): Promise<ResolveUsernameResponse> {
    const url = `/api/username/resolve/${encodeURIComponent(username)}`;
    return this.request(url, ResolveUsernameResponseSchema, signal ? { signal } : {});
  }

  // ---- Jobs API -----------------------------------------------------------

  /**
   * Admit a mint job — `POST /api/jobs/mint` → 202 `{job_id, status}`.
   * The `Idempotency-Key` header is mandatory: a retried admit with the
   * same key returns the original job instead of enqueueing a second.
   */
  async mintJob(
    req: MintRequest,
    idempotencyKey: string,
    signal?: AbortSignal,
  ): Promise<JobAccepted> {
    return this.request('/api/jobs/mint', JobAcceptedSchema, {
      method: 'POST',
      body: JSON.stringify(req),
      headers: { 'Idempotency-Key': idempotencyKey },
      ...(signal ? { signal } : {}),
    });
  }

  /**
   * Admit a send job — `POST /api/jobs/send` → 202 `{job_id, status}`.
   * Body is the already-signed send request; the node verifies the
   * signature synchronously before admitting (a bad signature 401s
   * here, before a job row is burned). `Idempotency-Key` mandatory.
   */
  async sendJob(
    req: SignedSendRequest,
    idempotencyKey: string,
    signal?: AbortSignal,
  ): Promise<JobAccepted> {
    return this.request('/api/jobs/send', JobAcceptedSchema, {
      method: 'POST',
      body: JSON.stringify(req),
      headers: { 'Idempotency-Key': idempotencyKey },
      ...(signal ? { signal } : {}),
    });
  }

  /**
   * Poll a job — `GET /api/jobs/:id` → `JobStatus`. Non-terminal
   * states carry a `Retry-After: <seconds>` header; this method
   * returns only the parsed body. Use `getJobWithRetry` when you need
   * the backoff hint (`waitForJob` does).
   */
  async getJob(id: string, signal?: AbortSignal): Promise<JobStatus> {
    return (await this.getJobWithRetry(id, signal)).status;
  }

  /**
   * Poll a job and surface the `Retry-After` backoff hint alongside
   * the parsed body. `retryAfterMs` is `null` when the header is
   * absent (terminal states omit it).
   */
  async getJobWithRetry(id: string, signal?: AbortSignal): Promise<JobStatusWithRetry> {
    const { data, headers } = await this.requestWithHeaders(
      `/api/jobs/${encodeURIComponent(id)}`,
      JobStatusSchema,
      signal ? { signal } : {},
    );
    const raw = headers.get('retry-after');
    let retryAfterMs: number | null = null;
    if (raw !== null) {
      const secs = Number(raw);
      // Only honour the integer-seconds form (what the node emits:
      // `Retry-After: 2`). An HTTP-date form or a malformed value is
      // ignored rather than guessed at — the poll loop has its own
      // default interval to fall back on.
      if (Number.isFinite(secs) && secs >= 0) {
        retryAfterMs = secs * 1000;
      }
    }
    return { status: data, retryAfterMs };
  }

  /**
   * Attach the wallet-signed commitment to a send job that is
   * `awaiting_signature` — `POST /api/jobs/:id/commit` → 200
   * `{status:"broadcasting"}`. Resolves once the node has accepted the
   * commitment and woken its dispatcher; the caller then polls the job
   * to `completed`.
   */
  async commitJob(id: string, req: CommitRequest, signal?: AbortSignal): Promise<void> {
    await this.request(
      `/api/jobs/${encodeURIComponent(id)}/commit`,
      JobStatusSchema,
      {
        method: 'POST',
        body: JSON.stringify(req),
        ...(signal ? { signal } : {}),
      },
      // The commit accept body is `{status:"broadcasting"}` — a
      // partial `JobStatus` (no `phase`). Parse leniently: we only
      // need the call to have succeeded (2xx); the authoritative state
      // comes from the subsequent poll.
      { lenient: true },
    );
  }

  /**
   * Cancel a still-`queued` job — `POST /api/jobs/:id/cancel` → 200
   * `{status:"cancelled"}`. The node 409s once the prove leg has
   * started (the job is no longer cancellable); that surfaces as an
   * `ApiError`.
   */
  async cancelJob(id: string, signal?: AbortSignal): Promise<void> {
    await this.request(
      `/api/jobs/${encodeURIComponent(id)}/cancel`,
      JobStatusSchema,
      {
        method: 'POST',
        ...(signal ? { signal } : {}),
      },
      { lenient: true },
    );
  }

  /**
   * Stream a job's transitions over SSE — `GET /api/jobs/:id/stream`.
   * Yields each `JobStatus` frame as it arrives and returns after the
   * terminal `event: complete` frame (the node closes the stream
   * there). A `404` (unknown id) surfaces as an `ApiError` before the
   * generator yields. Pass `signal` to detach early.
   *
   * This is a minimal SSE reader: it tolerates `: heartbeat` comment
   * lines and parses `event:` / `data:` frame pairs. Consumers that
   * cannot use SSE (corporate proxies stripping `text/event-stream`)
   * fall back to `getJob` polling.
   */
  async *streamJob(id: string, signal?: AbortSignal): AsyncGenerator<JobStatus> {
    const controller = new AbortController();
    const timeoutHandle = setTimeout(() => controller.abort(), this.requestTimeoutMs);
    if (signal) {
      if (signal.aborted) {
        controller.abort();
      } else {
        signal.addEventListener('abort', () => controller.abort(), { once: true });
      }
    }

    try {
      const res = await this.fetchImpl(`${this.apiUrl}/api/jobs/${encodeURIComponent(id)}/stream`, {
        headers: { Accept: 'text/event-stream' },
        signal: controller.signal,
      });
      if (!res.ok) {
        const rawBody = await res.text();
        throw new ApiError(res.status, extractServerError(rawBody), rawBody);
      }
      if (!res.body) {
        throw new Error('streamJob: response has no readable body for SSE');
      }

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      let lastEvent = 'message';

      for (;;) {
        const { value, done } = await reader.read();
        if (done) {
          return;
        }
        buffer += decoder.decode(value, { stream: true });

        // SSE frames are separated by a blank line. Process every
        // complete frame in the buffer; keep the trailing partial.
        let sep: number;
        while ((sep = buffer.indexOf('\n\n')) !== -1) {
          const frame = buffer.slice(0, sep);
          buffer = buffer.slice(sep + 2);

          let eventName = 'message';
          let dataPayload = '';
          for (const line of frame.split('\n')) {
            if (line.startsWith(':')) {
              // SSE comment (`: heartbeat`) — ignore.
              continue;
            }
            if (line.startsWith('event:')) {
              eventName = line.slice('event:'.length).trim();
            } else if (line.startsWith('data:')) {
              dataPayload += line.slice('data:'.length).trim();
            }
          }
          lastEvent = eventName;

          if (dataPayload.length > 0) {
            const parsed: unknown = JSON.parse(dataPayload);
            yield JobStatusSchema.parse(parsed);
          }
          if (lastEvent === 'complete') {
            return;
          }
        }
      }
    } finally {
      clearTimeout(timeoutHandle);
      controller.abort();
    }
  }

  // ---- Internals ----------------------------------------------------------

  /**
   * Shared `fetch` path used by every public method. Validates the 2xx
   * body against `schema`; maps non-2xx onto `ApiError`.
   */
  private async request<T>(
    path: string,
    schema: z.ZodType<T>,
    options: RequestInit & { signal?: AbortSignal } = {},
    parse: { lenient?: boolean } = {},
  ): Promise<T> {
    const { data } = await this.requestWithHeaders(path, schema, options, parse);
    return data;
  }

  /**
   * Like `request` but also returns the response `Headers` so callers
   * that need a header (`Retry-After` on a job poll) can read it.
   *
   * - JSON body / response.
   * - Per-request timeout via `AbortController`, composed with the
   *   caller's `signal` if provided.
   * - Non-2xx responses are mapped to `ApiError` with the parsed
   *   `error` string from the structured failure envelope when the
   *   body is JSON in that shape; raw body retained for diagnostics.
   * - 2xx responses are validated against the supplied Zod schema. In
   *   `lenient` mode an empty / partial 2xx body (the commit + cancel
   *   accept envelopes) is allowed through as `{}` — the caller only
   *   needs the call to have succeeded.
   */
  private async requestWithHeaders<T>(
    path: string,
    schema: z.ZodType<T>,
    options: RequestInit & { signal?: AbortSignal } = {},
    parse: { lenient?: boolean } = {},
  ): Promise<{ data: T; headers: Headers }> {
    const controller = new AbortController();
    const timeoutHandle = setTimeout(() => controller.abort(), this.requestTimeoutMs);

    // If the caller passed a signal, abort our controller when theirs aborts.
    if (options.signal) {
      if (options.signal.aborted) {
        controller.abort();
      } else {
        options.signal.addEventListener('abort', () => controller.abort(), { once: true });
      }
    }

    try {
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      const res = await this.fetchImpl(`${this.apiUrl}${path}`, {
        ...options,
        headers: { ...headers, ...(options.headers as Record<string, string> | undefined) },
        signal: controller.signal,
      });

      if (!res.ok) {
        const rawBody = await res.text();
        throw new ApiError(res.status, extractServerError(rawBody), rawBody);
      }

      const rawText = await res.text();
      if (parse.lenient) {
        // The commit + cancel accept envelopes (`{status:"broadcasting"}`
        // / `{status:"cancelled"}`, or a future empty 204) are not a
        // full `JobStatus`, so we don't validate them — the 2xx alone
        // is the success signal the caller (`commitJob` / `cancelJob`)
        // needs. The authoritative state comes from the subsequent poll.
        const json: unknown = rawText.trim().length > 0 ? JSON.parse(rawText) : {};
        return { data: json as T, headers: res.headers };
      }
      return { data: schema.parse(JSON.parse(rawText)), headers: res.headers };
    } finally {
      clearTimeout(timeoutHandle);
    }
  }
}

/**
 * Pull the human-facing error string out of a failure body. Handles
 * both the Jobs-API `{error}` envelope and the legacy
 * `{success:false, error}` envelope; falls back to the raw body when
 * it is not JSON or has no `error` string.
 */
function extractServerError(rawBody: string): string {
  try {
    const parsed: unknown = JSON.parse(rawBody);
    if (
      typeof parsed === 'object' &&
      parsed !== null &&
      'error' in parsed &&
      typeof parsed.error === 'string'
    ) {
      return parsed.error;
    }
  } catch {
    // Body wasn't JSON — keep the raw text as the error message.
  }
  return rawBody;
}
