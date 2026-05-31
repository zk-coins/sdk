# `@zkcoins/sdk`

Pure-TypeScript wallet SDK for [zkCoins](https://zkcoins.app). One package covers BIP-39 / BIP-32 derivation, BIP-340 Schnorr signing, the typed REST client for `/api/*`, and a high-level account adapter that wallet integrators (Cake Wallet, Layerz Wallet, the in-tree web app) consume as a drop-in `InterfaceAccountBasedWallet`-style API.

> Status: v0.1.0 implementation complete, awaiting first npm publish. Tracked on the `develop` branch — see [`CONTRIBUTING.md`](./CONTRIBUTING.md) for the bootstrap workflow.

## Why pure TypeScript

Earlier iterations of the wallet primitives were compiled to WASM from `zk-coins/app/rust/client/`. That works in the browser but creates friction for every other consumer — React Native (Layerz Wallet) struggles to bundle WASM cleanly, and Cake Wallet (Dart) cannot consume a WASM blob at all. The functions involved are all standard BIP-39 / BIP-32 / secp256k1 Schnorr / SHA-256 — every audited pure-JS library can do them. `@zkcoins/sdk` is the pure-JS replacement, so the same library runs identically in Node 22+, the browser, and React Native.

Each cryptographic primitive is exercised by an internal **verify-roundtrip test**: the SDK produces a Schnorr signature, then re-verifies it under the derived x-only pubkey via the same `@noble/curves` library. This proves the signing → verifying loop is consistent within JS.

A separate **cross-test against the Rust reference** in `zk-coins/app/rust/client/` (proving the JS output is byte-equivalent to the in-tree Rust implementation for 100 randomized inputs per primitive) is planned as a v0.1.1 follow-up — see [issue #6](https://github.com/zk-coins/sdk/issues) once tracked.

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
const { balance, username } = await account.getBalance();
console.warn('balance:', balance, 'sats; username:', username);

// 3. Send.
const result = await account.pay(/* recipient */ recipientHex, /* amountSats */ 5_000);
console.warn('proof id:', result.proofId);
```

## Choosing a node

`@zkcoins/sdk` is a **protocol SDK**, not a service SDK. The constructor parameter is how you tell the SDK which node to talk to:

```ts
new ZkCoinsClient({ apiUrl: 'https://...' });
ZkCoinsAccount.fromMnemonic(mnemonic, 0, { apiUrl: 'https://...' });
```

When `apiUrl` is omitted, the SDK falls back to `https://api.zkcoins.app`. The SDK does **not** read environment variables, config files, or any other ambient state — where you source the URL from (env, config-file, hardcoded, CLI arg) is your app's concern. Example with env in your own code:

```ts
const client = new ZkCoinsClient({ apiUrl: process.env.ZKCOINS_API_URL });
// `process.env.ZKCOINS_API_URL` is `undefined` → SDK uses its fallback
```

[zkcoins.app](https://zkcoins.app) is one such operator (one of hopefully many). It runs two public stages today:

| URL                           | Bitcoin network | Notes                                                        |
| ----------------------------- | --------------- | ------------------------------------------------------------ |
| `https://api.zkcoins.app`     | Mainnet         | Production. No faucet — mint requires real on-chain funding. |
| `https://dev-api.zkcoins.app` | Mutinynet       | DEV. Open mint faucet, signet-grade reorgs, no real value.   |

Self-hosters point `apiUrl` at their own node (`zk-coins/node` docker image, see [zk-coins/node README](https://github.com/zk-coins/node)). Wallet integrators typically expose a chooser in their own config; the SDK stays opinion-free on which node is "the right one".

## API surface (preview)

The `ZkCoinsAccount` class is the recommended entry point. It composes the lower-level building blocks (derivation, signing, REST client) into a wallet-friendly shape:

```ts
class ZkCoinsAccount {
  static fromMnemonic(
    mnemonic: string,
    accountIndex: number,
    opts: { apiUrl: string; passphrase?: string },
  ): Promise<ZkCoinsAccount>;

  readonly address: string;

  getBalance(): Promise<{ balance: number; username?: string }>;
  pay(recipient: string, amountSats: number): Promise<{ txid?: string; proofId: number }>;
  getTransactions(opts?: HistoryOpts): Promise<TxItem[]>; // throws until /api/history lands
  claimUsername(username: string): Promise<void>;
  resolveUsername(username: string): Promise<{ address: string }>;
}
```

Lower-level building blocks are also exported for advanced use (custom signing flows, key-derivation helpers, raw REST client):

```ts
import {
  // BIP-39 / BIP-32
  generateMnemonic,
  validateMnemonic,
  mnemonicFromEntropy,
  generateAccountKeys,
  generateAccountKeysFromMnemonic,
  derivePublicKeys,
  deriveSigningKey,

  // BIP-340 Schnorr + commitment building
  signSchnorr,
  createCommitment,

  // Typed REST client
  ZkCoinsClient,

  // Zod schemas + typed errors
  InfoResponseSchema,
  BalanceResponseSchema,
  SendResponseSchema,
  ApiError,
  NotImplementedError,
} from '@zkcoins/sdk';
```

## Compatibility

- Node 22+ (no native dependencies; runs in Bun, Deno, AWS Lambda, etc.).
- All evergreen browsers (uses Web Crypto API + standard fetch).
- React Native (tested with Expo SDK 51+ on iOS and Android).

## Wallet integrator notes

- **Thin-client invariant.** Before every signed request, the server is the source of truth. `ZkCoinsAccount.pay()` enforces this by calling `getBalance()` first internally — but if you build your own flow on top of the lower-level `ZkCoinsClient`, replicate that pattern.
- **No local state.** The SDK does not persist anything to disk. Mnemonic storage, address book, transaction cache — all handled by the integrating wallet.
- **History endpoint pending.** `getTransactions()` will throw `NotImplementedError` until [zk-coins/node #153](https://github.com/zk-coins/node/issues/153) ships. Wallets that need a transaction list today should poll `getBalance()` and persist sends locally as a fallback.

## License

MIT.

## See also

- [zk-coins/node](https://github.com/zk-coins/node) — the Rust backend serving `/api/*`.
- [zk-coins/app](https://github.com/zk-coins/app) — the reference web wallet (will migrate to `@zkcoins/sdk` as a follow-up).
- [zk-coins/docs](https://docs.zkcoins.app) — protocol documentation.
