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
 * orchestration — derive → build message → sign → POST — lives in
 * `account.ts`; downstream wallet integrators can either use the
 * high-level `ZkCoinsAccount` or compose the primitives themselves
 * via this client.
 *
 * Request timeout is 2 minutes — proof generation on the server
 * side can be slow, especially under load. Caller can override via
 * the `signal` parameter on each method.
 */

import type { z } from 'zod';

import { API_URL, REQUEST_TIMEOUT_MS } from './config.js';
import { ApiError, HISTORY_TRACKING_URL, NotImplementedError } from './errors.js';
import {
  BalanceResponseSchema,
  ClaimUsernameResponseSchema,
  CommitResponseSchema,
  InfoResponseSchema,
  MintResponseSchema,
  ResolveUsernameResponseSchema,
  SendResponseSchema,
  type BalanceResponse,
  type ClaimUsernameResponse,
  type CommitResponse,
  type HistoryResponse,
  type InfoResponse,
  type MintResponse,
  type ResolveUsernameResponse,
  type SendResponse,
} from './schemas.js';

/** Inputs to `POST /api/send` *before* signing. */
export interface SendRequest {
  account_address: string;
  recipient: string;
  amount: number;
  public_key: string;
  next_public_key: string;
  prev_commitment_pubkey?: string;
}

/** Inputs to `POST /api/send` with signature + timestamp attached. */
export interface SignedSendRequest extends SendRequest {
  signature: string;
  timestamp: number;
}

/** Inputs to `POST /api/commit`. */
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

/** Inputs to `GET /api/history` (issue #153). */
export interface HistoryOpts {
  limit?: number;
  offset?: number;
  signal?: AbortSignal;
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

  async mint(address: string, amount = 10_000, signal?: AbortSignal): Promise<MintResponse> {
    return this.request('/api/mint', MintResponseSchema, {
      method: 'POST',
      body: JSON.stringify({ account_address: address, amount }),
      ...(signal ? { signal } : {}),
    });
  }

  async send(req: SignedSendRequest, signal?: AbortSignal): Promise<SendResponse> {
    return this.request('/api/send', SendResponseSchema, {
      method: 'POST',
      body: JSON.stringify(req),
      ...(signal ? { signal } : {}),
    });
  }

  async commit(req: CommitRequest, signal?: AbortSignal): Promise<CommitResponse> {
    return this.request('/api/commit', CommitResponseSchema, {
      method: 'POST',
      body: JSON.stringify(req),
      ...(signal ? { signal } : {}),
    });
  }

  async balance(address: string, signal?: AbortSignal): Promise<BalanceResponse> {
    const url = `/api/balance?address=${encodeURIComponent(address)}`;
    return this.request(url, BalanceResponseSchema, signal ? { signal } : {});
  }

  async info(signal?: AbortSignal): Promise<InfoResponse> {
    return this.request('/api/info', InfoResponseSchema, signal ? { signal } : {});
  }

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

  /**
   * Per-address transaction history. **Throws `NotImplementedError`
   * until zk-coins/node issue #153 ships.** The schema and method
   * shape are stable so consumer code can be written against the
   * final API today — only the underlying server endpoint is
   * missing.
   */
  // eslint-disable-next-line @typescript-eslint/no-unused-vars -- args reserved for the future signature
  async history(_address: string, _opts: HistoryOpts = {}): Promise<HistoryResponse> {
    throw new NotImplementedError('ZkCoinsClient.history', HISTORY_TRACKING_URL);
  }

  /**
   * Shared `fetch` path used by every public method.
   *
   * - JSON body / response.
   * - Per-request timeout via `AbortController`, composed with the
   *   caller's `signal` if provided.
   * - Non-2xx responses are mapped to `ApiError` with the parsed
   *   `error` string from the structured failure envelope when the
   *   body is JSON in that shape; raw body retained for diagnostics.
   * - 2xx responses are validated against the supplied Zod schema.
   */
  private async request<T>(
    path: string,
    schema: z.ZodType<T>,
    options: RequestInit & { signal?: AbortSignal } = {},
  ): Promise<T> {
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
        let serverError = rawBody;
        try {
          const parsed: unknown = JSON.parse(rawBody);
          if (
            typeof parsed === 'object' &&
            parsed !== null &&
            'error' in parsed &&
            typeof parsed.error === 'string'
          ) {
            serverError = parsed.error;
          }
        } catch {
          // Body wasn't JSON — keep the raw text as the error message.
        }
        throw new ApiError(res.status, serverError, rawBody);
      }

      return schema.parse(await res.json());
    } finally {
      clearTimeout(timeoutHandle);
    }
  }
}
