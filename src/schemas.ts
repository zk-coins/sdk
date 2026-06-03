/**
 * Zod schemas at the HTTP boundary.
 *
 * Mirrored from the live `zk-coins/node` router DTOs (the node is the
 * single source of truth for every wire shape — see
 * `zk-coins/node/node/src/router.rs`). The SDK is the long-term
 * canonical TypeScript mirror; once the app's follow-up migration PR
 * lands, `app/src/lib/api/schemas.ts` will be replaced by
 * `import { ... } from '@zkcoins/sdk'`.
 *
 * Conventions:
 *
 * - `z.object()` is **strip mode** (the default): unknown keys are
 *   dropped silently, so a new server field added in zk-coins/node
 *   doesn't break the client. Only a **rename** or a **removed**
 *   field surfaces as a parse error — exactly the failure modes
 *   that matter for client–server contract drift.
 * - Optional fields are explicitly `.optional()` and `.nullable()`
 *   when the server can emit `null` or elide the field
 *   (`skip_serializing_if = "Option::is_none"` on the Rust side).
 * - **No silent defaults.** A present-but-malformed field hard-fails
 *   at the boundary (`ZodError`) rather than coercing to a default —
 *   this is the SDK's no-fallback contract. `.optional()` is reserved
 *   for fields the server legitimately omits (forward/backward compat
 *   with self-hosts that predate a field), never to paper over a bad
 *   payload.
 * - Type aliases for each parsed shape are re-exported alongside the
 *   schema so consumers can `import type { InfoResponse }` without
 *   having to write `z.infer<typeof InfoResponseSchema>` themselves.
 */

import { z } from 'zod';

// ---------------------------------------------------------------------------
// Balance
// ---------------------------------------------------------------------------

/**
 * `GET /api/balance?address=` — `router::BalanceResponse`.
 *
 * `num_sends` is the authoritative BIP-32 child-index counter for the
 * account: the server always emits it (no `skip_serializing_if`), and
 * `0` is the canonical value for an account that has never sent. The
 * wallet hydrates its local `numPubkeys` from this value rather than
 * trusting local state. `username` is elided when the account has no
 * bound username (`skip_serializing_if = None`).
 */
export const BalanceResponseSchema = z.object({
  balance: z.number(),
  username: z.string().optional(),
  num_sends: z.number(),
});
export type BalanceResponse = z.infer<typeof BalanceResponseSchema>;

// ---------------------------------------------------------------------------
// Usernames
// ---------------------------------------------------------------------------

export const UsernameResponseSchema = z.object({
  username: z.string(),
  address: z.string(),
});
export type UsernameResponse = z.infer<typeof UsernameResponseSchema>;

// `claim` and `resolve` use the same `{username, address}` envelope.
export const ClaimUsernameResponseSchema = UsernameResponseSchema;
export type ClaimUsernameResponse = z.infer<typeof ClaimUsernameResponseSchema>;

export const ResolveUsernameResponseSchema = UsernameResponseSchema;
export type ResolveUsernameResponse = z.infer<typeof ResolveUsernameResponseSchema>;

// ---------------------------------------------------------------------------
// Node info + capabilities
// ---------------------------------------------------------------------------

/**
 * Server-side feature gates — `router::Capabilities`. Each boolean
 * reflects a compile-time Cargo feature on the running node binary, so
 * the client can gate UI on a single server-side source of truth.
 *
 * The node emits exactly these four flags (verified against the
 * `Capabilities` struct in `router.rs`). Permanent MVP endpoints (mint,
 * username resolve, history) are always available and intentionally
 * have **no** capability bit — clients must not gate on a flag that
 * would always be `true`.
 *
 * Consumers that depend on a capability should treat an absent value as
 * `false` (fail-closed), which is what the `.optional()` on the
 * `capabilities` field of `InfoResponse` allows for self-hosts that
 * predate capability advertising.
 */
export const CapabilitiesSchema = z.object({
  address_list: z.boolean(),
  /**
   * Username *claim* (write path). Gated by the `username-claim` Cargo
   * feature; off in hosted DEV + PRD images. Wallets hide the claim
   * input when this is `false`.
   */
  username_claim: z.boolean(),
  lnurl: z.boolean(),
  /**
   * Multi-asset support. When `true` the node accepts an `asset_id` on
   * mint/send; when `false` (or absent) only the native asset exists.
   */
  multi_asset: z.boolean(),
});
export type Capabilities = z.infer<typeof CapabilitiesSchema>;

/**
 * Normalized, machine-readable Bitcoin network identifier exposed on
 * `/api/info` as `bitcoin_network` (`serde(rename_all = "lowercase")`).
 * Clients switch behaviour on this typed value rather than the
 * free-text `network` label to avoid the case-sensitivity foot-gun.
 */
export const BitcoinNetworkSchema = z.enum(['mainnet', 'mutinynet']);
export type BitcoinNetwork = z.infer<typeof BitcoinNetworkSchema>;

/**
 * `GET /api/info` — `router::InfoResponse`.
 *
 * A current node always emits `network`, `capabilities`, and
 * `username_domain`. They are marked `.optional()` here for fail-open
 * compatibility with self-hosts that predate the corresponding node
 * PRs — an older node that simply omits one of them must not break a
 * newer client. When present they are validated strictly.
 *
 * `bitcoin_network` is the normalized network enum the node will start
 * emitting via zk-coins/node#193; it is `.optional()` (fail-open) so a
 * node that predates that PR parses fine — clients fall back to
 * matching the free-text `network` label when it is absent.
 */
export const InfoResponseSchema = z.object({
  /**
   * Human-readable network label (`"Mainnet"`, `"Mutinynet"`, …),
   * operator-overridable and intended for display only. Gate behaviour
   * on `bitcoin_network` instead.
   */
  network: z.string(),
  bitcoin_network: BitcoinNetworkSchema.optional(),
  capabilities: CapabilitiesSchema.optional(),
  /**
   * External hostname this node serves, used by the client to render
   * `<hex|username>@<domain>`. DEV and PRD share the chain identifier
   * but live behind different external hostnames.
   */
  username_domain: z.string().optional(),
});
export type InfoResponse = z.infer<typeof InfoResponseSchema>;

// ---------------------------------------------------------------------------
// History (`GET /api/history`)
// ---------------------------------------------------------------------------

/**
 * One row of `GET /api/history` — `router::HistoryItem`. Nullable
 * fields are emitted as explicit `null` (the Rust side serializes
 * `Option<T>` rather than eliding), so the schema uses `.nullable()`
 * (always present, value may be null) rather than `.optional()`.
 */
export const TxItemSchema = z.object({
  /** Server-internal monotonic id (`account_history.id`). Always set. */
  id: z.number(),
  /** Commit-inscription txid (lower-case hex), or `null` while unlinked. */
  txid: z.string().nullable(),
  timestamp: z.number(),
  direction: z.enum(['send', 'receive', 'mint']),
  /** Absolute balance delta in sats. */
  amount: z.number(),
  /** Counterparty address — currently always `null` (schema TODO node#160). */
  counterparty: z.string().nullable(),
  status: z.enum(['pending', 'confirmed', 'failed']),
  block_height: z.number().nullable(),
  /** Free-text memo — currently always `null` (no memo column yet). */
  memo: z.string().nullable(),
});
export type TxItem = z.infer<typeof TxItemSchema>;

/**
 * `GET /api/history` — `router::HistoryResponse`. `total` is the
 * unfiltered count for the queried address (not the count of returned
 * `items`) so the caller can drive pagination without a second query.
 */
export const HistoryResponseSchema = z.object({
  items: z.array(TxItemSchema),
  total: z.number(),
  limit: z.number(),
  offset: z.number(),
});
export type HistoryResponse = z.infer<typeof HistoryResponseSchema>;

// ---------------------------------------------------------------------------
// Jobs API (`/api/jobs/*`)
// ---------------------------------------------------------------------------

/**
 * Terminal + non-terminal job states — `job_store::JobStatus`
 * (`serde(rename_all = "snake_case")`). Verified against the
 * `JobStatus::as_str` arms in `job_store.rs`. Terminal: `completed`,
 * `failed`, `cancelled` (`JobStatus::is_terminal`).
 */
export const JobStatusValueSchema = z.enum([
  'queued',
  'proving',
  'awaiting_signature',
  'broadcasting',
  'completed',
  'failed',
  'cancelled',
]);
export type JobStatusValue = z.infer<typeof JobStatusValueSchema>;

/** Job kind — `job_store::JobKind` (`serde(rename_all = "snake_case")`). */
export const JobKindSchema = z.enum(['mint', 'send']);
export type JobKind = z.infer<typeof JobKindSchema>;

/**
 * 202 admit body for `POST /api/jobs/{mint,send}` —
 * `router::JobAcceptedResponse`. `job_id` is a UUID string; `status` is
 * the snake_case `JobStatus` the row was admitted at (`"queued"` for a
 * fresh job).
 */
export const JobAcceptedSchema = z.object({
  job_id: z.string(),
  status: z.string(),
});
export type JobAccepted = z.infer<typeof JobAcceptedSchema>;

/**
 * Terminal `result` payload of a completed mint/send job — the JSON
 * body `flow::{mint_flow,commit_flow}` returns, surfaced verbatim on
 * the job row's `result` once `status = completed`. Same shape the
 * pre-Jobs-API synchronous `/api/{mint,send,commit}` endpoints
 * returned: `{success, proof_id?, account_state_hash?, output_coins_root?}`.
 *
 * Parsed strictly (rather than left as `unknown`) so a consumer reading
 * `result` of a completed job gets a typed `proof_id` /
 * `account_state_hash` / `output_coins_root` without a second cast.
 */
export const JobResultSchema = z.object({
  success: z.boolean(),
  proof_id: z.number().nullable().optional(),
  account_state_hash: z.string().optional(),
  output_coins_root: z.string().optional(),
});
export type JobResult = z.infer<typeof JobResultSchema>;

/**
 * `GET /api/jobs/{id}` poll body **and** the SSE `data:` frame payload
 * — `router::JobStatusResponse` / `router::{initial_event_from_job,
 * event_from_phase}`.
 *
 * The two surfaces differ slightly, so one schema parses both:
 *
 * - The **poll body** always carries `job_id`, `kind`, `progress`;
 *   `proof_id` / `result` / `error` are elided
 *   (`skip_serializing_if = Option::is_none`) unless populated.
 * - The **SSE frame** omits `job_id`, `kind`, and `progress` entirely,
 *   and emits `proof_id` / `result` / `error` as explicit `null` when
 *   absent.
 *
 * Field availability is status-dependent (the node only populates a
 * field in the state where it is meaningful):
 *
 * - `proof_id` — set **only** when `status = awaiting_signature` (the
 *   id of the server-side proof for this send; the wallet echoes it
 *   back in the commit body).
 * - `result` — set **only** when `status = completed`; parsed via
 *   `JobResultSchema`.
 * - `error` — set **only** when `status = failed`.
 *
 * `job_id` / `kind` / `progress` are `.optional()` (absent from SSE
 * frames); `proof_id` / `result` / `error` are `.nullable().optional()`
 * (elided on poll, explicit `null` on SSE).
 */
export const JobStatusSchema = z.object({
  job_id: z.string().optional(),
  kind: JobKindSchema.optional(),
  status: JobStatusValueSchema,
  phase: z.string(),
  progress: z.number().optional(),
  proof_id: z.number().nullable().optional(),
  result: JobResultSchema.nullable().optional(),
  error: z.string().nullable().optional(),
});
export type JobStatus = z.infer<typeof JobStatusSchema>;

/**
 * Generic Jobs-API error envelope — `router::JobErrorResponse`
 * (`{ error: string }`). Distinct from the legacy
 * `{ success: false, error }` shape; the client's `ApiError` mapping
 * already handles both by reading `error` when present.
 */
export const JobErrorResponseSchema = z.object({
  error: z.string(),
});
export type JobErrorResponse = z.infer<typeof JobErrorResponseSchema>;
