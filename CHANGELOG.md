# Changelog

All notable changes to `@zkcoins/sdk` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project adheres to [Semantic Versioning](https://semver.org/).

## [0.2.0]

Migration to the asynchronous **Jobs API**. The node removed the
synchronous `/api/{mint,send,commit}` routes; this release replaces the
SDK's synchronous methods with the job lifecycle.

### Breaking

- **Sync → Jobs API.** `ZkCoinsClient.mint` / `.send` / `.commit` (the
  synchronous `/api/{mint,send,commit}` calls) are removed. Use the new
  job methods (`mintJob`, `sendJob`, `getJob`, `commitJob`, `cancelJob`,
  `streamJob`) or the high-level `ZkCoinsAccount.mint` / `.pay`, which
  drive the lifecycle and poll for you.
- **`Capabilities` fields changed.** Now `{ address_list, username_claim,
lnurl, multi_asset }` (was `{ address_list, faucet, usernames, lnurl }`)
  — matching the node's `router::Capabilities`. Code reading
  `capabilities.faucet` / `.usernames` must move to `.username_claim` /
  `.multi_asset`.
- **`getTransactions` / `history` no longer throw.** The
  `NotImplementedError` placeholder (and the `HISTORY_TRACKING_URL`
  constant) are removed — `/api/history` is live, so the methods perform
  a real request.
- **Removed schemas.** `SendResponseSchema`, `MintResponseSchema`,
  `CommitResponseSchema` (and their type aliases) are gone — they only
  described the removed synchronous endpoints. Use `JobAcceptedSchema`,
  `JobStatusSchema`, and `JobResultSchema` instead.
- **`PayResult` shape changed** to `{ jobId, proofId }`; `MintResult`
  (`{ jobId, proofId }`) is new.
- **`TxItem` nullables.** `txid`, `counterparty`, `block_height`, `memo`
  are now `.nullable()` (the node emits explicit `null`), and a new
  required `id: number` field was added — matching `router::HistoryItem`.

### Added

- **Jobs-API client methods** on `ZkCoinsClient`: `mintJob`, `sendJob`,
  `getJob` / `getJobWithRetry` (surfaces the `Retry-After` backoff),
  `commitJob`, `cancelJob`, and `streamJob` (SSE `AsyncGenerator`).
- **High-level account flows** `ZkCoinsAccount.mint(amountSats, assetId?)`
  and `pay(recipient, amountSats, assetId?)`, plus
  `waitForJob(jobId, stopAt, opts?)` (polls to a terminal/target status,
  respects `Retry-After`, throws on `failed` / `cancelled`).
- **`getTransactions(opts?)` / `ZkCoinsClient.history(address, opts?)`** —
  live `GET /api/history` with `{ limit, offset }` pagination.
- **`bitcoin_network`** on `InfoResponse` — typed `'mainnet' | 'mutinynet'`
  network switch (optional, fail-open for nodes that predate it), with a
  `BitcoinNetworkSchema` export.
- **`num_sends`** on `BalanceResponse` — the authoritative BIP-32
  child-index counter; seed `setNumPubkeys(balance.num_sends)` to
  re-hydrate local state.
- **`asset_id`** (multi-asset) — optional 32-byte-hex selector on
  `mint` / `pay` and on the `MintRequest` / `SendRequest` / `SignedSendRequest`
  shapes; a malformed value hard-fails server-side (no fallback to
  native). Gated by `capabilities.multi_asset`.
- **`newIdempotencyKey()`** — RFC-4122 v4 UUID from `@noble/hashes`
  `randomBytes` (not `crypto.randomUUID`, for React Native parity);
  reuse one per logical operation across retries.
- **`JobFailedError`** — thrown when a job ends `failed` / `cancelled`,
  distinct from `ApiError` (the HTTP call succeeded; the job failed).
- New schemas/types: `JobAccepted(Schema)`, `JobStatus(Schema)`,
  `JobStatusValue(Schema)`, `JobKind(Schema)`, `JobResult(Schema)`,
  `JobErrorResponse(Schema)`, `BitcoinNetwork(Schema)`.

### Changed

- `ApiError` now also extracts the Jobs-API `{ error }` envelope (in
  addition to the legacy `{ success: false, error }` shape).
- `NotImplementedError` removed (no longer needed).

## [0.1.1]

- Toolchain modernization (eslint 10 flat config, TypeScript 6,
  noble/scure 2.x, zod 4). No public API change.

## [0.1.0]

- Initial implementation: BIP-39/32 derivation, BIP-340 Schnorr signing,
  typed REST client, high-level account adapter.
