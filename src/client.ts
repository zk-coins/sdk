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
  AddressesResponseSchema,
  BalanceResponseSchema,
  ClaimUsernameResponseSchema,
  HistoryResponseSchema,
  InfoResponseSchema,
  InscriptionSummarySchema,
  JobAcceptedSchema,
  JobStatusSchema,
  OwnerBalanceResponseSchema,
  PublisherHealthResponseSchema,
  ReadyResponseSchema,
  ResolveUsernameResponseSchema,
  RootResponseSchema,
  TxDetailSchema,
  type AddressesResponse,
  type BalanceResponse,
  type ClaimUsernameResponse,
  type HistoryResponse,
  type OwnerBalanceResponse,
  type TxDetail,
  type InfoResponse,
  type InscriptionSummary,
  type JobAccepted,
  type JobStatus,
  type PublisherHealthResponse,
  type ReadyResponse,
  type ResolveUsernameResponse,
  type RootResponse,
} from './schemas.js';

/**
 * Inputs to a creator-signed mint job (`POST /api/jobs/mint`).
 *
 * Neutral, permissionless model (Model B): anyone creates their own
 * asset and mints their own supply; nobody can mint a foreign asset.
 * The owner (`H(creator_pubkey)`) and `asset_id`
 * (`calculate_asset_id(creator_pubkey, H(name), decimals)`) are DERIVED
 * server-side — they are never accepted from the wire. The request is
 * authenticated by a BIP-340 Schnorr signature over the mint fields
 * (see {@link buildMintMessage}); the mint is two-phase like a send
 * (admit → `awaiting_signature` → `POST /api/jobs/:id/commit`).
 */
export interface MintRequest {
  /** Compressed secp256k1 creator pubkey, 33-byte hex (66 chars). */
  creator_pubkey: string;
  /** Human-facing asset name; folded into the asset_id by the node. */
  name: string;
  /** Asset decimals (`u8`); part of the asset_id derivation. */
  decimals: number;
  /** Amount to mint into the creator's own balance, atomic units. */
  amount: number;
  /**
   * The wallet's NEXT rotation key; the mint commitment is signed by
   * `creator_pubkey` but the proof rotates to this fresh key like a send.
   * Compressed secp256k1 pubkey, 33-byte hex (66 chars).
   */
  next_public_key: string;
  /**
   * Hex BIP-340 Schnorr signature (64 bytes) over
   * `SHA256(creator_pubkey ‖ name ‖ [decimals] ‖ amount_le ‖ timestamp_le)`,
   * verifiable against `creator_pubkey`.
   */
  signature: string;
  /** Unix epoch seconds the signature was produced at (freshness-gated). */
  timestamp: number;
}

/** Inputs to `POST /api/jobs/send` *before* signing. */
export interface SendRequest {
  account_address: string;
  recipient: string;
  amount: number;
  public_key: string;
  next_public_key: string;
  prev_commitment_pubkey?: string;
  /**
   * The asset to move — 32-byte hex, REQUIRED. There is no native /
   * default asset under the neutral multi-asset model: the node 422s a
   * missing or malformed value (no silent fallback, which would move
   * the wrong asset under a `200`). Discover held assets + their ids
   * via {@link ZkCoinsClient.ownerBalances}. The send *signature* does
   * not cover this field — the asset is bound in-circuit through the
   * `account_state_hash` the wallet signs at commit time.
   */
  asset_id: string;
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

  // ---- Service + health endpoints ----------------------------------------

  /**
   * Service identification — `GET /` → `RootResponse`. Package name +
   * version, connected network, the advertised endpoint map, and a
   * docs pointer. Useful for a "is this URL a zkCoins node, and which
   * one?" preflight.
   */
  async root(signal?: AbortSignal): Promise<RootResponse> {
    return this.request('/', RootResponseSchema, signal ? { signal } : {});
  }

  /**
   * Liveness probe — `GET /health`. The node answers with the literal
   * text `ok` (not JSON), so this returns the trimmed body string
   * rather than a parsed object. A non-2xx surfaces as `ApiError`.
   */
  async health(signal?: AbortSignal): Promise<string> {
    const { text } = await this.requestText('/health', signal ? { signal } : {});
    return text.trim();
  }

  /**
   * Readiness probe — `GET /health/ready` → `ReadyResponse`.
   *
   * The node returns **200** when ready and **503** when not, and both
   * carry the same `ReadyResponse` body (the 503 lists the failing
   * dependencies in `failures`). A not-ready node is a legitimate
   * readiness answer, not a transport error, so this method parses and
   * returns the body for both the 200 and 503 branches — read
   * `result.ready` (or `result.failures`) to branch. Any *other*
   * non-2xx (e.g. a 500) still surfaces as `ApiError`.
   */
  async ready(signal?: AbortSignal): Promise<ReadyResponse> {
    return this.requestAllowingStatus(
      '/health/ready',
      ReadyResponseSchema,
      503,
      signal ? { signal } : {},
    );
  }

  /**
   * Publisher wallet state — `GET /health/publisher` →
   * `PublisherHealthResponse` (`{address, utxo_count, total_sats}`).
   *
   * This is the only fee-relevant figure the node exposes: inscription
   * fees are funded server-side from this wallet, so a depleting
   * `total_sats` is the observable fee-spend signal. There is no client
   * fee-estimation API (see the README "Fees" section). On an
   * Esplora-side error the node returns 503 with a different shape
   * (`{error, detail, address}`), which surfaces as `ApiError`.
   */
  async publisherHealth(signal?: AbortSignal): Promise<PublisherHealthResponse> {
    return this.request(
      '/health/publisher',
      PublisherHealthResponseSchema,
      signal ? { signal } : {},
    );
  }

  // ---- Read endpoints ----------------------------------------------------

  /**
   * Per-`(owner, asset)` balance — `GET /api/balance?address=&asset_id=`.
   *
   * Both params are REQUIRED under the neutral multi-asset model (there
   * is no native/default asset): a malformed or missing `asset_id` is a
   * node-side 422 (surfaced as `ApiError`), never a silent fallback. To
   * list every asset an owner holds in one call, use
   * {@link ownerBalances}.
   */
  async balance(address: string, assetId: string, signal?: AbortSignal): Promise<BalanceResponse> {
    const url = `/api/balance?address=${encodeURIComponent(address)}&asset_id=${encodeURIComponent(assetId)}`;
    return this.request(url, BalanceResponseSchema, signal ? { signal } : {});
  }

  /**
   * Cross-asset balance list — `GET /api/balance/:address` →
   * {@link OwnerBalanceResponse}. One entry per asset the owner holds,
   * each with its own balance / num_sends / display metadata. An
   * unobserved address returns `assets: []` (canonical, not a 404). This
   * is the multi-asset replacement for a single-balance read: the wallet
   * fetches it once to discover which assets it holds, then drives
   * per-asset sends with the returned `asset_id`s.
   */
  async ownerBalances(address: string, signal?: AbortSignal): Promise<OwnerBalanceResponse> {
    const url = `/api/balance/${encodeURIComponent(address)}`;
    return this.request(url, OwnerBalanceResponseSchema, signal ? { signal } : {});
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

  /**
   * Full detail for one transaction — `GET /api/history/{id}` →
   * {@link TxDetail}. `id` is a `TxItem.id` from a {@link history} page;
   * `address` scopes the lookup to the account the caller already knows
   * (a wrong-address or internal row 404s — surfaced as `ApiError`).
   * Malformed input (bad address hex, non-positive id) is a node-side
   * 422, mirroring the list endpoint's validation contract.
   */
  async getTransaction(id: number, address: string, signal?: AbortSignal): Promise<TxDetail> {
    const url = `/api/history/${encodeURIComponent(String(id))}?address=${encodeURIComponent(address)}`;
    return this.request(url, TxDetailSchema, signal ? { signal } : {});
  }

  /**
   * List the account addresses the node knows about — `GET /api/address`
   * → `AddressesResponse`. Feature-gated node-side behind `address-list`
   * (or `lnurl`): on a build without it the route is absent and the call
   * 404s (surfaces as `ApiError`). Gate on `info.capabilities.address_list`
   * before calling.
   */
  async addresses(signal?: AbortSignal): Promise<AddressesResponse> {
    return this.request('/api/address', AddressesResponseSchema, signal ? { signal } : {});
  }

  /**
   * Look up a single commit inscription by txid — `GET
   * /api/inscriptions/:txid` → `InscriptionSummary`. `txid` is the
   * big-endian display hex a block explorer shows (64 hex chars); the
   * node reverses it internally to match the stored little-endian
   * bytes. An unknown txid 404s, a malformed one 422s — both as
   * `ApiError`. This is an operator/forensics read, not part of the
   * spend flow.
   */
  async inscription(txid: string, signal?: AbortSignal): Promise<InscriptionSummary> {
    const url = `/api/inscriptions/${encodeURIComponent(txid)}`;
    return this.request(url, InscriptionSummarySchema, signal ? { signal } : {});
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
   * Like `request` but also accepts a single non-2xx status as a valid
   * response to parse rather than throw. Used by `ready()`, where the
   * node returns `503` with a full `ReadyResponse` body on a not-ready
   * node — a legitimate readiness answer, not a transport error. Any
   * other non-2xx (and the 2xx case) flows through `requestWithHeaders`
   * unchanged: those still map to `ApiError`.
   */
  private async requestAllowingStatus<T>(
    path: string,
    schema: z.ZodType<T>,
    allowStatus: number,
    options: RequestInit & { signal?: AbortSignal } = {},
  ): Promise<T> {
    const controller = new AbortController();
    const timeoutHandle = setTimeout(() => controller.abort(), this.requestTimeoutMs);
    if (options.signal) {
      if (options.signal.aborted) {
        controller.abort();
      } else {
        options.signal.addEventListener('abort', () => controller.abort(), { once: true });
      }
    }

    try {
      const res = await this.fetchImpl(`${this.apiUrl}${path}`, {
        ...options,
        headers: {
          'Content-Type': 'application/json',
          ...(options.headers as Record<string, string> | undefined),
        },
        signal: controller.signal,
      });
      const rawText = await res.text();
      if (!res.ok && res.status !== allowStatus) {
        throw new ApiError(res.status, extractServerError(rawText), rawText);
      }
      return schema.parse(JSON.parse(rawText));
    } finally {
      clearTimeout(timeoutHandle);
    }
  }

  /**
   * Plain-text variant of `request` for the one endpoint that does not
   * return JSON — `GET /health`, which answers with the literal body
   * `ok`. Maps non-2xx onto `ApiError` (raw body as the message); on a
   * 2xx returns the body text verbatim for the caller to trim/inspect.
   */
  private async requestText(
    path: string,
    options: RequestInit & { signal?: AbortSignal } = {},
  ): Promise<{ text: string }> {
    const controller = new AbortController();
    const timeoutHandle = setTimeout(() => controller.abort(), this.requestTimeoutMs);
    if (options.signal) {
      if (options.signal.aborted) {
        controller.abort();
      } else {
        options.signal.addEventListener('abort', () => controller.abort(), { once: true });
      }
    }

    try {
      const res = await this.fetchImpl(`${this.apiUrl}${path}`, {
        ...options,
        signal: controller.signal,
      });
      const text = await res.text();
      if (!res.ok) {
        throw new ApiError(res.status, extractServerError(text), text);
      }
      return { text };
    } finally {
      clearTimeout(timeoutHandle);
    }
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
