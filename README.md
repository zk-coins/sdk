# `@zkcoins/sdk`

Pure-TypeScript wallet SDK for [zkCoins](https://zkcoins.app). One package covers BIP-39 / BIP-32 derivation, BIP-340 Schnorr signing, the typed REST client for the **Jobs API** (`/api/jobs/*`), and a high-level account adapter that wallet integrators (Cake Wallet, Layerz Wallet, the in-tree web app) consume as a drop-in `InterfaceAccountBasedWallet`-style API.

> Status: v0.2.0 — migrated to the asynchronous Jobs API. See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for the workflow and [`CHANGELOG.md`](./CHANGELOG.md) for the breaking changes.

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

Lower-level building blocks are also exported (custom signing flows, key-derivation helpers, the raw `ZkCoinsClient`, every Zod schema + typed error, and `newIdempotencyKey`).

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
