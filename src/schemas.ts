/**
 * Zod schemas at the HTTP boundary.
 *
 * Mirrored from `zk-coins/app/src/lib/api/schemas.ts` — the SDK is
 * the long-term canonical source. Once the app's follow-up migration
 * PR lands, `app/src/lib/api/schemas.ts` will be replaced by
 * `import { ... } from '@zkcoins/sdk'` and the two files cease to
 * exist in parallel.
 *
 * Conventions (preserved from the upstream):
 *
 * - `z.object()` is **strip mode** (the default): unknown keys are
 *   dropped silently, so a new server field added in zk-coins/node
 *   doesn't break the client. Only a **rename** or a **removed**
 *   field surfaces as a parse error — exactly the failure modes
 *   that matter for client–server contract drift.
 * - Optional fields are explicitly `.optional()` and `.nullable()`
 *   when the server can emit `null` (e.g. `proof_id` on a
 *   successful mint that produces no proof).
 * - Type aliases for each parsed shape are re-exported alongside the
 *   schema so consumers can `import type { InfoResponse }` without
 *   having to write `z.infer<typeof InfoResponseSchema>` themselves.
 */

import { z } from 'zod';

export const SendResponseSchema = z.object({
  success: z.boolean(),
  // Structured failure envelope; present on 4xx/5xx, absent on 2xx.
  error: z.string().optional(),
  proof_id: z.number().nullable().optional(),
  account_state_hash: z.string().optional(),
  output_coins_root: z.string().optional(),
});
export type SendResponse = z.infer<typeof SendResponseSchema>;

// Mint and commit reuse the send envelope. Aliased rather than
// re-defined so a future divergence is a single-file change.
export const MintResponseSchema = SendResponseSchema;
export type MintResponse = z.infer<typeof MintResponseSchema>;

export const CommitResponseSchema = SendResponseSchema;
export type CommitResponse = z.infer<typeof CommitResponseSchema>;

export const BalanceResponseSchema = z.object({
  balance: z.number(),
  username: z.string().optional(),
});
export type BalanceResponse = z.infer<typeof BalanceResponseSchema>;

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

/**
 * Server-side feature gates — mirrored from
 * `zk-coins/node::server.rs::Capabilities`. Each boolean reflects a
 * compile-time Cargo feature on the running node binary, so the
 * client can gate UI on a single server-side source of truth.
 *
 * Marked `.optional()` here because a wallet on a self-host that
 * predates capability advertising (pre-PR-#29) may answer with an
 * older payload. Consumers that depend on a capability should treat
 * an absent value as `false` (fail-closed).
 */
export const CapabilitiesSchema = z.object({
  address_list: z.boolean(),
  faucet: z.boolean(),
  usernames: z.boolean(),
  lnurl: z.boolean(),
});
export type Capabilities = z.infer<typeof CapabilitiesSchema>;

export const InfoResponseSchema = z.object({
  /**
   * Human-readable network name as returned by the server (`Mainnet`,
   * `Mutinynet`, …). String comparison is fragile — wallet
   * integrators should consume the normalized form once
   * `bitcoin_network` lands per `project_zkcoins_api_info_normalization`.
   */
  network: z.string(),
  capabilities: CapabilitiesSchema.optional(),
});
export type InfoResponse = z.infer<typeof InfoResponseSchema>;

/**
 * Per-address transaction history row. Pending entry — the matching
 * server endpoint is tracked in zk-coins/node issue #153; the SDK
 * already exposes the schema so consumers can wire up types now and
 * the live wiring is a one-line client.ts change once the endpoint
 * ships.
 */
export const TxItemSchema = z.object({
  txid: z.string(),
  timestamp: z.number(),
  direction: z.enum(['send', 'receive', 'mint']),
  amount: z.number(),
  counterparty: z.string().optional(),
  status: z.enum(['pending', 'confirmed', 'failed']),
  block_height: z.number().optional(),
  memo: z.string().optional(),
});
export type TxItem = z.infer<typeof TxItemSchema>;

export const HistoryResponseSchema = z.object({
  items: z.array(TxItemSchema),
  total: z.number(),
  limit: z.number(),
  offset: z.number(),
});
export type HistoryResponse = z.infer<typeof HistoryResponseSchema>;
