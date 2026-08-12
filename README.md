# zkCoins SDK

**Private Bitcoin payments via Shielded CSV** — no new chain, no token, no consensus change, no trusted operator. Only Bitcoin, zero-knowledge proofs, and the user's own keys.

The **thin TypeScript client** for zkCoins: on-device BIP-39/32 key derivation and BIP-340 Schnorr signing, a typed REST client to a zkCoins node/API, and a high-level account adapter. Custody stays on the device.

> Full system docs: **[docs.zkcoins.com](https://docs.zkcoins.com)** · Specification: **[docs.zkcoins.com/specification](https://docs.zkcoins.com/specification)**

## What zkCoins is

zkCoins lets you send value on Bitcoin without anyone seeing the amount, the asset, who paid, or who received. Bitcoin stores only opaque markers that a spend happened — not the coin's contents, which travel privately between sender and receiver as a small encrypted bundle. Double-spend protection is the chain's job; your seed derives every key, your wallet is the only thing that can spend, any node can serve you, and you verify everything against Bitcoin yourself. Built on the zkCoins concept (Robin Linus) and the Shielded CSV construction (Jonas Nick, Liam Eagen, Robin Linus).

## The system, end to end

| Layer                      | What it is                                                                     | Repo                                                                                                        |
| -------------------------- | ------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------- |
| **App · Explorer**         | end-user wallet (LNURL receive) · public explorer web-app                      | [`zk-coins/app`](https://github.com/zk-coins/app) · `zk-coins/explorer` _(planned)_                         |
| **SDK**                    | thin TypeScript client — on-device keys, signing, node/API calls               | **[`zk-coins/sdk`](https://github.com/zk-coins/sdk)** ← this repo                                           |
| **zkCoins API**            | public REST + LNURL, hosted-wallet service (optional)                          | currently in [`zk-coins/node`](https://github.com/zk-coins/node); a separate API layer is the target design |
| **zkCoins node**           | trustless kernel — scan · accumulator · verify · prove · store · publisher     | [`zk-coins/node`](https://github.com/zk-coins/node)                                                         |
| **bitcoind · Nostr relay** | Bitcoin L1 settlement and ordering · off-chain transport and data availability | upstream (own or external)                                                                                  |

Supporting repos: [`zk-coins/research`](https://github.com/zk-coins/research), [`zk-coins/plonky2`](https://github.com/zk-coins/plonky2), [`zk-coins/docs`](https://github.com/zk-coins/docs).

### Trust model — run your own node

zkCoins follows the **Bitcoin full-node model: your wallet trusts _your_ node, exactly as a Bitcoin wallet trusts your own `bitcoind`.** Self-hosting (the `zk-coins/node` docker image) gives you trustlessness and privacy at once; the wallet must always be able to switch nodes by changing a single configuration value. Using someone else's node is a trade-off you choose — a foreign operator can never steal, forge, or double-spend your coins (enforced cryptographically), but it can see your privacy and affect liveness, the same spectrum as an Electrum/SPV server versus your own Bitcoin node. The thin client adds no anti-node logic: anything that exists to reduce trust in the node belongs node-side, or the answer is self-hosting. See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for the full rule.

## This repository (sdk)

`@zkcoins/sdk` is the **pure-TypeScript** wallet SDK — no WASM, no native modules. It runs identically in Node 22+, modern browsers, and React Native (Expo + bare workflow), so the same package serves the in-tree web app, Cake Wallet, and Layerz Wallet. One package covers:

- **On-device key material** — BIP-39 mnemonic, BIP-32 HD derivation, BIP-340 Schnorr signing. Crypto comes from audited upstreams (`@scure/bip39`, `@scure/bip32`, `@noble/curves`, `@noble/hashes`). The sole documented rolled-crypto exception is the in-tree Poseidon-over-Goldilocks / `E(·)` / `Hc` reference (`src/poseidon/`, vector-pinned); see [`CONTRIBUTING.md`](./CONTRIBUTING.md). The private key never leaves the wallet.
- **`ZkCoinsClient`** — a typed REST client to a zkCoins node/API that mirrors every node endpoint a wallet legitimately reads or drives. Each response is validated against a Zod schema; a non-2xx maps onto a typed `ApiError` with no silent fallback.
- **`ZkCoinsAccount`** — the high-level account adapter most integrators consume. It derives the account from a mnemonic and drives the full async **Jobs API** lifecycle (`/api/jobs/*`) for mint/send, polling jobs to completion for you.

### Install

```bash
npm install @zkcoins/sdk
```

### Quick start

```ts
import { ZkCoinsAccount, generateMnemonic } from '@zkcoins/sdk';

// Create or restore an account. With no `apiUrl` the SDK talks to
// `https://api.zkcoins.app`; pass `{ apiUrl: '...' }` to point at any
// other node (your own self-hosted node, or another operator).
const mnemonic = await generateMnemonic();
const account = await ZkCoinsAccount.fromMnemonic(mnemonic, /* accountIndex */ 0);

// Read authoritative state from the node.
const { balance, username, num_sends } = await account.getBalance();

// Mint (server-mediated: DEV faucet / authorised issuance). The SDK
// admits the job and polls it to completion; throws on failure.
const mint = await account.mint(/* amountSats */ 10_000);

// Send. `pay()` runs the whole send → commit lifecycle: refresh
// balance → sign → admit job → poll to awaiting_signature → sign the
// commitment → commit → poll to completed.
const result = await account.pay(/* recipient */ recipientHex, /* amountSats */ 5_000);

// History.
const { items, total } = await account.getTransactions({ limit: 50 });
```

A runnable end-to-end example (account creation, node + health probes, mint, history, signed username claim) lives in [`examples/basic.ts`](./examples/basic.ts):

```bash
npx tsx examples/basic.ts                          # uses the fallback URL
ZKCOINS_API_URL=https://dev-api.zkcoins.app \
  npx tsx examples/basic.ts                        # point at the DEV node
```

The high-level `ZkCoinsAccount` is the recommended entry point (`getBalance`, `mint`, `pay`, `getTransactions`, `waitForIncoming`, `claimUsername`/`resolveUsername`). The lower-level `ZkCoinsClient` (also `account.client`) exposes every node route — service/health probes, `info`, `balance`, `history`, `addresses`, `inscription`, username resolve/claim, and the Jobs API (`mintJob`/`sendJob`/`getJob`/`commitJob`/`cancelJob`/`streamJob`). All exported types and helpers (Zod schemas, `ApiError`/`JobFailedError`, `newIdempotencyKey`, key-derivation and signing primitives) are listed in [`src/index.ts`](./src/index.ts).

A few design points worth knowing up front:

- **Jobs are asynchronous.** Mint/send/commit are jobs (`queued → proving → [awaiting_signature → broadcasting] → completed | failed | cancelled`); `account.mint()`/`account.pay()` poll the lifecycle for you.
- **Receiving has no client call** — share `account.address` and the sender's `pay()` credits it server-side; poll with `getBalance()`/`getTransactions()` or the `waitForIncoming()` helper.
- **No client-side fees.** Send/inscription fees are paid server-side from the operator-funded publisher wallet; the SDK fabricates no fee estimate.
- **No local state.** The SDK persists nothing — mnemonic storage, address book, and transaction cache are the integrating wallet's responsibility.

### Choosing a node

`@zkcoins/sdk` is a **protocol SDK**, not a service SDK. The constructor parameter is how you tell it which node to talk to:

```ts
new ZkCoinsClient({ apiUrl: 'https://...' });
ZkCoinsAccount.fromMnemonic(mnemonic, 0, { apiUrl: 'https://...' });
```

When `apiUrl` is omitted, the SDK falls back to `https://api.zkcoins.app`. It reads no environment variables or config files itself — where you source the URL from is your app's concern. [zkcoins.app](https://zkcoins.app) is one operator (one of hopefully many), running two public stages today:

| URL                           | Bitcoin network | Notes                                                        |
| ----------------------------- | --------------- | ------------------------------------------------------------ |
| `https://api.zkcoins.app`     | Mainnet         | Production. No faucet — mint requires real on-chain funding. |
| `https://dev-api.zkcoins.app` | Mutinynet       | DEV. Open mint faucet, signet-grade reorgs, no real value.   |

Self-hosters point `apiUrl` at their own `zk-coins/node` instance.

### Build · test · develop

```bash
npm run build           # tsup → dist/ (ESM + CJS + .d.ts)
npm run typecheck       # tsc --noEmit
npm run lint            # eslint --max-warnings 0 && prettier --check
npm run lint:fix        # eslint --fix && prettier --write

npm run test            # vitest unit tests
npm run test:coverage   # 100% lines/functions/statements/branches coverage gate on src/*
npm run test:cross      # JS-vs-Rust cross-tests — the load-bearing guarantee
                        # the pure-JS reimpl matches the protocol spec
```

### Branch flow

```
feature/* → develop → main
```

Open feature PRs against **`develop`** — there is no `staging` branch. `main` is auto-PR'd from `develop`; the maintainer merges the release PR and tags the version, which triggers `publish.yaml` to ship `@zkcoins/sdk` to npm with OIDC provenance. `develop` and `main` reject direct pushes. See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for the full workflow, test gates, and code style.

## Compatibility

- Node 22+ (no native dependencies; runs in Bun, Deno, AWS Lambda, etc.).
- All evergreen browsers (Web Crypto + standard `fetch` + `ReadableStream` for SSE).
- React Native (Expo + bare workflow). `newIdempotencyKey()` uses `@noble/hashes` `randomBytes`, not `crypto.randomUUID`, so it works where the latter is absent.

## License

MIT.

## See also

- [zk-coins/node](https://github.com/zk-coins/node) — the Rust backend serving `/api/*`.
- [zk-coins/app](https://github.com/zk-coins/app) — the reference web wallet.
- [docs.zkcoins.com](https://docs.zkcoins.com) — protocol documentation and specification.
