# `@zkcoins/sdk`

Pure-TypeScript wallet SDK for [zkCoins](https://zkcoins.app). One package covers BIP-39 / BIP-32 derivation, BIP-340 Schnorr signing, the typed REST client for the **Jobs API** (`/api/jobs/*`), and a high-level account adapter that wallet integrators (Cake Wallet, Layerz Wallet, the in-tree web app) consume as a drop-in `InterfaceAccountBasedWallet`-style API.

> Status: v0.3.0 — complete node-endpoint coverage (service/health probes, address list, inscription lookup, a `receive` polling helper). See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for the workflow and [`CHANGELOG.md`](./CHANGELOG.md) for the change log.

## Why pure TypeScript

Earlier iterations of the wallet primitives were compiled to WASM from `zk-coins/app/rust/client/`. That works in the browser but creates friction for every other consumer — React Native (Layerz Wallet) struggles to bundle WASM cleanly, and Cake Wallet (Dart) cannot consume a WASM blob at all. The functions involved are all standard BIP-39 / BIP-32 / secp256k1 Schnorr / SHA-256 — every audited pure-JS library can do them. `@zkcoins/sdk` is the pure-JS replacement, so the same library runs identically in Node 22+, the browser, and React Native.

## Install

```bash
npm install @zkcoins/sdk
```

## Quick start

```ts
import { ZkCoinsAccount, generateMnemonic } from '@zkcoins/sdk';

// 1. Create or restore an account. With no `apiUrl` passed the SDK
//    talks to `https://api.zkcoins.app`; pass `{ apiUrl: '...' }`
//    to point at any other node — see "Choosing a node" below.
const mnemonic = await generateMnemonic();
const account = await ZkCoinsAccount.fromMnemonic(mnemonic, /* accountIndex */ 0);

// 2. Read authoritative state from the server.
const { balance, username, num_sends } = await account.getBalance();
console.warn('balance:', balance, 'sats; username:', username, '; sends:', num_sends);

// 3. Mint (DEV faucet / authorised issuance). Mint is fully
//    server-mediated — the SDK admits the job and polls it to
//    completion for you. Throws `JobFailedError` if the job fails.
const mint = await account.mint(/* amountSats */ 10_000);
console.warn('mint proof id:', mint.proofId);

// 4. Send. `pay()` runs the whole send → commit lifecycle:
//    refresh balance → sign → admit job → poll to awaiting_signature
//    → sign the commitment → commit → poll to completed.
const result = await account.pay(/* recipient */ recipientHex, /* amountSats */ 5_000);
console.warn('send proof id:', result.proofId);

// 5. History.
const { items, total } = await account.getTransactions({ limit: 50 });
console.warn(`${items.length} of ${total} transactions`);
```

## The Jobs API

Mint / send / commit are **asynchronous jobs** on the node (`/api/jobs/*`); the old synchronous `/api/{mint,send,commit}` routes were removed node-side. A job moves through:

```
queued → proving → [awaiting_signature → broadcasting] → completed | failed | cancelled
```

`ZkCoinsAccount.mint()` / `.pay()` drive the whole lifecycle and poll for you. If you compose the lower-level `ZkCoinsClient` directly, the building blocks are:

```ts
const idem = newIdempotencyKey(); // reuse across retries of one logical op

// Admit (Idempotency-Key is mandatory on mint/send).
const { job_id } = await client.mintJob({ account_address, amount }, idem);

// Poll (respects the node's Retry-After backoff).
const { status, retryAfterMs } = await client.getJobWithRetry(job_id);

// Or stream transitions over SSE (falls back to polling where SSE
// is unavailable). The generator ends after the terminal frame.
for await (const frame of client.streamJob(job_id)) {
  console.warn(frame.status, frame.phase);
}

// Send-only: attach the wallet-signed commitment once the job parks
// in awaiting_signature, then poll to completed.
await client.commitJob(job_id, { proof_id, public_key, signature, message });

// Cancel a still-queued job.
await client.cancelJob(job_id);
```

### `asset_id` (multi-asset)

`mint(amountSats, assetId?)` and `pay(recipient, amountSats, assetId?)` take an optional 32-byte-hex `asset_id`. Omit it for the native asset. A present-but-malformed value is rejected by the node (`422`) — there is no silent fallback to native. Gate the UI on `info.capabilities.multi_asset`.

### `bitcoin_network`

`info()` returns a typed `bitcoin_network` (`'mainnet' | 'mutinynet'`) for behaviour switches — prefer it over the free-text, operator-overridable `network` label. It is optional for forward/backward compatibility: a node that predates it simply omits the field, and clients fall back to matching `network`.

## Choosing a node

`@zkcoins/sdk` is a **protocol SDK**, not a service SDK. The constructor parameter is how you tell the SDK which node to talk to:

```ts
new ZkCoinsClient({ apiUrl: 'https://...' });
ZkCoinsAccount.fromMnemonic(mnemonic, 0, { apiUrl: 'https://...' });
```

When `apiUrl` is omitted, the SDK falls back to `https://api.zkcoins.app`. The SDK does **not** read environment variables, config files, or any other ambient state — where you source the URL from (env, config-file, hardcoded, CLI arg) is your app's concern.

[zkcoins.app](https://zkcoins.app) is one such operator (one of hopefully many). It runs two public stages today:

| URL                           | Bitcoin network | Notes                                                        |
| ----------------------------- | --------------- | ------------------------------------------------------------ |
| `https://api.zkcoins.app`     | Mainnet         | Production. No faucet — mint requires real on-chain funding. |
| `https://dev-api.zkcoins.app` | Mutinynet       | DEV. Open mint faucet, signet-grade reorgs, no real value.   |

Self-hosters point `apiUrl` at their own node (`zk-coins/node` docker image). Wallet integrators typically expose a chooser in their own config; the SDK stays opinion-free on which node is "the right one".

## API surface

The `ZkCoinsAccount` class is the recommended entry point:

```ts
class ZkCoinsAccount {
  static fromMnemonic(
    mnemonic: string,
    accountIndex: number,
    opts?: { apiUrl?: string; passphrase?: string },
  ): Promise<ZkCoinsAccount>;

  readonly address: string;
  readonly client: ZkCoinsClient;

  getBalance(): Promise<{ balance: number; username?: string; num_sends: number }>;
  mint(amountSats: number, assetId?: string): Promise<MintResult>;
  pay(recipient: string, amountSats: number, assetId?: string): Promise<PayResult>;
  getTransactions(opts?: HistoryOpts): Promise<HistoryResponse>;
  // Receiving: share `address`, then poll for the credit (see "Receiving").
  waitForIncoming(opts?: WaitForIncomingOpts): Promise<BalanceResponse>;
  waitForJob(
    jobId: string,
    stopAt: ReadonlySet<JobStatus['status']>,
    opts?: WaitForJobOpts,
  ): Promise<JobStatus>;
  claimUsername(username: string): Promise<UsernameResponse>;
  resolveUsername(username: string): Promise<UsernameResponse>;

  getNumPubkeys(): number;
  setNumPubkeys(value: number): void; // e.g. setNumPubkeys(balance.num_sends)
}
```

### `ZkCoinsClient` — full endpoint reference

The lower-level `ZkCoinsClient` (also `account.client`) mirrors **every** node endpoint a wallet legitimately reads or drives. Each method validates the response against a Zod schema and maps a non-2xx onto `ApiError` (no silent fallback).

| Method                               | Node route                       | Returns                     |
| ------------------------------------ | -------------------------------- | --------------------------- |
| `root()`                             | `GET /`                          | `RootResponse`              |
| `health()`                           | `GET /health`                    | `string` (`"ok"`)           |
| `ready()`                            | `GET /health/ready`              | `ReadyResponse`¹            |
| `publisherHealth()`                  | `GET /health/publisher`          | `PublisherHealthResponse`   |
| `info()`                             | `GET /api/info`                  | `InfoResponse`              |
| `balance(address)`                   | `GET /api/balance`               | `BalanceResponse`           |
| `history(address, opts?)`            | `GET /api/history`               | `HistoryResponse`           |
| `addresses()`                        | `GET /api/address`²              | `AddressesResponse`         |
| `inscription(txid)`                  | `GET /api/inscriptions/:txid`    | `InscriptionSummary`        |
| `resolveUsername(name)`              | `GET /api/username/resolve/:u`   | `ResolveUsernameResponse`   |
| `claimUsername(signedReq)`           | `POST /api/username/claim`²      | `ClaimUsernameResponse`     |
| `mintJob(req, idem)`                 | `POST /api/jobs/mint`            | `JobAccepted`               |
| `sendJob(signedReq, idem)`           | `POST /api/jobs/send`            | `JobAccepted`               |
| `getJob(id)` / `getJobWithRetry(id)` | `GET /api/jobs/:id`              | `JobStatus` (+ retry)       |
| `commitJob(id, req)`                 | `POST /api/jobs/:id/commit`      | `void`                      |
| `cancelJob(id)`                      | `POST /api/jobs/:id/cancel`      | `void`                      |
| `streamJob(id)`                      | `GET /api/jobs/:id/stream` (SSE) | `AsyncGenerator<JobStatus>` |

¹ `ready()` returns the body for **both** the 200 (ready) and 503 (not-ready) branches — a not-ready node is a valid readiness answer, not a transport error. Read `result.ready` / `result.failures`. Any other non-2xx still throws `ApiError`.
² Feature-gated node-side (`address-list` / `username-claim` Cargo features). Gate the call on `info().capabilities.address_list` / `.username_claim`; a build without the feature 404s the route.

**Deliberately not exposed:**

- `GET /api/proof/:id` returns a **binary bincode `CoinProof`** blob. A pure-TS SDK does not decode bincode, and the wallet does not need to: it reads `account_state_hash` / `output_coins_root` from the `awaiting_signature` job result to build the commitment, never from the proof blob. Mirroring this as a method would require either a bincode decoder or a fake — neither is acceptable, so it is omitted.
- `POST /api/receive` is a legacy octet-stream route, not a wallet operation — see **Receiving** below.
- `GET /api/admin/r2-probe/history` is an operator telemetry endpoint, out of wallet-SDK scope.

Other building blocks are exported too (custom signing flows, key-derivation helpers, every Zod schema + typed error, and `newIdempotencyKey`).

## Receiving

There is **no client-initiated "receive" call**, by design. A zkCoins account receives by sharing its `address` — the sender's `pay()` credits it server-side. (The node's `POST /api/receive` is internal plumbing, not a wallet method, and is intentionally not mirrored here.)

To observe an incoming credit, poll the authoritative balance / history:

```ts
// Share this with the sender:
console.warn('my address:', account.address);

// Option A — your own loop over getBalance() / getTransactions().
// Option B — the built-in convenience helper (pure getBalance() on a
// timer; no signing, no extra trust assumption):
const updated = await account.waitForIncoming({ timeoutMs: 120_000 });
console.warn('received! new balance:', updated.balance);
```

`waitForIncoming` reads the current balance as a baseline (or takes an explicit `fromBalance`), then polls until the balance rises above it, resolving with the updated `BalanceResponse`. It **throws** on timeout rather than returning a stale balance.

## Fees

zkCoins has **no client-side fee estimation, and the SDK fabricates none.** The node exposes no fee-estimation endpoint:

- **Mint** amounts are server-controlled (DEV faucet / authorised issuance).
- **Send / inscription fees** are paid server-side from the operator-funded publisher wallet — the wallet never constructs or signs a Bitcoin fee.

The only fee-relevant figure the node surfaces is the publisher wallet's UTXO state via `client.publisherHealth()` (`{ address, utxo_count, total_sats }`); a depleting `total_sats` is the observable fee-spend signal. There is deliberately no `fees()` method — adding one would mean inventing a number the node does not provide.

## Compatibility

- Node 22+ (no native dependencies; runs in Bun, Deno, AWS Lambda, etc.).
- All evergreen browsers (Web Crypto + standard `fetch` + `ReadableStream` for SSE).
- React Native (Expo + bare workflow). `newIdempotencyKey()` uses `@noble/hashes` `randomBytes`, not `crypto.randomUUID`, so it works where the latter is absent.

## Wallet integrator notes

- **Thin-client invariant.** Before every signed request the server is the source of truth. `ZkCoinsAccount.pay()` enforces this by calling `getBalance()` first internally — replicate that if you build a flow on the lower-level client.
- **No local state.** The SDK persists nothing. Mnemonic storage, address book, transaction cache — all handled by the integrating wallet. Re-hydrate `numPubkeys` from `balance().num_sends`.
- **No silent fallback.** A malformed response hard-fails at the schema boundary (`ZodError`); a failed/cancelled job throws `JobFailedError`.

## License

MIT.

## See also

- [zk-coins/node](https://github.com/zk-coins/node) — the Rust backend serving `/api/*`.
- [zk-coins/app](https://github.com/zk-coins/app) — the reference web wallet (will migrate to `@zkcoins/sdk` as a follow-up).
- [zk-coins/docs](https://docs.zkcoins.app) — protocol documentation.
