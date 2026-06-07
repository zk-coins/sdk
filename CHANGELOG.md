# Changelog

All notable changes to `@zkcoins/sdk` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project adheres to [Semantic Versioning](https://semver.org/).

## [0.4.0]

### Added

- **`ZkCoinsClient.getTransaction(id, address)`** — `GET
/api/history/{id}` → `TxDetail`. The full per-transaction detail
  behind the wallet's transaction-detail page: every `TxItem` core field
  plus the decoded account-state snapshot of the mutation
  (`balance_after` / `balance_before` / `num_sends_after` /
  `commitment_public_key`), the verifier `circuit_digest`, and the
  on-chain `commit_output_value`. Scoped by `address` (a wrong-address or
  internal row 404s as `ApiError`).
- **`TxDetailSchema` / `TxDetail`** — the wire schema, `extend`ing
  `TxItemSchema` so the shared list/detail core cannot drift. Mirrors the
  node's `router::TxDetail` serde.

Purely additive — no breaking changes to the 0.3.x surface.

## [0.3.1]

### Fixed

- **`JobResultSchema.success` is now optional.** The node's
  `awaiting_signature` send-job result (node #195) carries only
  `account_state_hash` / `output_coins_root` and **omits `success`** (see
  `job_dispatcher.rs::set_awaiting_signature`). Parsing `success` as
  required threw a `ZodError` on every real `awaiting_signature` poll,
  which stalled `ZkCoinsAccount.pay()` in the proving/awaiting phase and
  blocked the send lifecycle end-to-end. Verified against a live local
  node (Mutinynet) with #195 — `pay()` now completes the two-phase send.

## [0.3.0]

Endpoint-coverage completion. The SDK now mirrors **every** node
endpoint a wallet legitimately reads or drives, hardens error handling
across the new surface, and documents the receive pattern and the
(deliberate) absence of a fee API. Purely additive — no breaking
changes to the 0.2.0 surface.

### Added

- **Service + health client methods** on `ZkCoinsClient`:
  - `root()` — `GET /` → `RootResponse` (service id + advertised
    endpoint map + docs pointer).
  - `health()` — `GET /health` → the plain-text `"ok"` liveness body.
  - `ready()` — `GET /health/ready` → `ReadyResponse`. Returns the body
    for **both** the 200 (ready) and 503 (not-ready) branches — a
    not-ready node is a valid readiness answer, not a transport error;
    any other non-2xx still throws `ApiError`.
  - `publisherHealth()` — `GET /health/publisher` →
    `PublisherHealthResponse` (`{address, utxo_count, total_sats}`), the
    only fee-relevant figure the node exposes.
- **Read client methods**: `addresses()` (`GET /api/address`, feature-
  gated) and `inscription(txid)` (`GET /api/inscriptions/:txid`).
- **`ZkCoinsAccount.waitForIncoming(opts?)`** — an optional balance-
  polling helper for the receive pattern: reads a baseline (or an
  explicit `fromBalance`), then resolves with the updated
  `BalanceResponse` on the first observed increase. Throws on timeout
  (never returns a stale balance). Pure `getBalance()` on a timer — no
  signing, no extra trust assumption.
- **New schemas / types**: `RootResponse(Schema)`, `RootEndpoints(Schema)`,
  `ReadyResponse(Schema)`, `PublisherHealthResponse(Schema)`,
  `AddressesResponse(Schema)`, `InscriptionSummary(Schema)`,
  `InscriptionKind(Schema)`, and `WaitForIncomingOpts`.

### Documentation

- README gains a full `ZkCoinsClient` endpoint-reference table, a
  **Receiving** section (share address → poll balance/history), and a
  **Fees** section stating plainly that there is no client fee API and
  the SDK fabricates none.
- Documented the deliberately-omitted endpoints and why: `GET
/api/proof/:id` (binary bincode, not decodable in pure TS and not
  needed — the wallet reads `ash`/`ocr` from the job result),
  `POST /api/receive` (legacy plumbing), and `GET
/api/admin/r2-probe/history` (operator telemetry, out of scope).

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
