/**
 * Minimal end-to-end usage of `@zkcoins/sdk` against the Jobs API.
 * Run with:
 *
 *   npx tsx examples/basic.ts                    # uses the fallback URL
 *
 *   # Override — your code reads from wherever (env, config, …):
 *   ZKCOINS_API_URL=https://… npx tsx examples/basic.ts
 *
 * The example creates a brand-new account, asks the node for its
 * capabilities + network, reads the balance, runs an async mint job to
 * completion (open faucet on Mutinynet; rejected on Mainnet), reads the
 * balance again, lists recent history, and prints a Schnorr-signed
 * username claim. Everything is server-mediated: the SDK never reaches
 * a Bitcoin node directly, never stores anything on disk, never holds
 * state across calls beyond the in-memory `xpriv` + `numPubkeys`.
 *
 * `apiUrl` is passed via the constructor option. When unset, the SDK
 * falls back to `https://api.zkcoins.app`. The SDK itself does not read
 * environment variables — this example reads `process.env.ZKCOINS_API_URL`
 * in user code and passes it through.
 *
 * zkcoins.app — one of hopefully many service providers — runs two
 * public stages today:
 *
 *   - `https://api.zkcoins.app`     (Bitcoin Mainnet)
 *   - `https://dev-api.zkcoins.app` (Mutinynet — has the open faucet)
 */

import { ApiError, JobFailedError, ZkCoinsAccount, generateMnemonic } from '@zkcoins/sdk';

async function main(): Promise<void> {
  // 1. Generate a fresh BIP-39 mnemonic + derive the account.
  const mnemonic = await generateMnemonic();
  console.warn('mnemonic:', mnemonic);

  const apiUrl = process.env.ZKCOINS_API_URL;
  const account = await ZkCoinsAccount.fromMnemonic(
    mnemonic,
    /* accountIndex */ 0,
    apiUrl ? { apiUrl } : {},
  );
  console.warn('address: ', account.address);

  // 2. Inspect the node. `bitcoin_network` is the typed switch; the
  //    free-text `network` is display-only. `capabilities.multi_asset`
  //    gates the optional `asset_id` argument on mint/pay.
  const info = await account.client.info();
  console.warn('network:', info.bitcoin_network ?? info.network);
  console.warn('multi-asset:', info.capabilities?.multi_asset ?? false);

  // 2b. Service + health probes. `ready()` returns the body for both
  //     the ready (200) and not-ready (503) branches; `publisherHealth()`
  //     is the only fee-relevant figure the node exposes (the operator-
  //     funded wallet that pays inscription fees — there is no client
  //     fee API).
  const root = await account.client.root();
  console.warn('service:', root.service, root.version);
  console.warn('liveness:', await account.client.health());
  const readiness = await account.client.ready();
  console.warn('readiness:', readiness.ready ? 'ready' : `starting (${readiness.failures.join()})`);
  try {
    const pub = await account.client.publisherHealth();
    console.warn(
      'publisher sats (fee budget):',
      pub.total_sats,
      'across',
      pub.utxo_count,
      'utxo(s)',
    );
  } catch (err) {
    if (err instanceof ApiError) {
      console.warn('publisher health unavailable:', err.status, err.serverError);
    } else {
      throw err;
    }
  }

  // 3. Read the node's view of this address. Under the neutral
  //    multi-asset model there is no native/default asset, so the wallet
  //    lists every asset it holds via `getAssets()`.
  const initialAssets = await account.getAssets();
  console.warn('initial assets held:', initialAssets.assets.length);

  // 4. Create + mint a named asset to completion. The asset_id is derived
  //    node-side from `(creator_pubkey, H(name), decimals)`; the SDK
  //    drives the two-phase (admit → commit) job and throws
  //    JobFailedError if the prove/broadcast leg fails.
  try {
    const mint = await account.mint({ name: 'DemoCoin', decimals: 8, amount: 10_000 });
    console.warn('mint completed — proof_id:', mint.proofId);
  } catch (err) {
    if (err instanceof JobFailedError) {
      console.warn('mint job failed (expected on Mainnet):', err.status, err.serverError);
    } else if (err instanceof ApiError) {
      console.warn('mint rejected at admit:', err.status, err.serverError);
    } else {
      throw err;
    }
  }

  // 5. Re-read balances — the thin-client invariant in action. The first
  //    asset's id can then drive `getBalance(assetId)` / `pay(...)`.
  const post = await account.getAssets();
  for (const a of post.assets) {
    console.warn('asset', a.asset_id, '→', a.balance, '(num_sends:', a.num_sends, ')');
  }

  // 6. List recent history. Each mint/send/receive shows up as a row;
  //    a row with a `txid` can be looked up via
  //    `account.client.inscription(txid)` for its on-chain status.
  const history = await account.getTransactions({ limit: 5 });
  console.warn('recent transactions:', history.items.length, 'of', history.total);

  // 6b. Receiving: there is no "receive" call — share `account.address`
  //     and poll. `waitForIncoming` is the optional convenience helper
  //     (pure getBalance() on a timer). Not awaited here so the example
  //     stays non-blocking; in a wallet you'd await it (or run your own
  //     balance/history poll) after showing the address to the sender.
  console.warn('to receive, share this address:', account.address);

  // 7. Claim a random username. The signed-claim flow signs a fixed-
  //    prefix message with the identity key at index 0.
  const username = `demo-${Math.floor(Math.random() * 1_000_000)}`;
  try {
    const claim = await account.claimUsername(username);
    console.warn('claimed username:', claim.username, 'for address', claim.address);
  } catch (err) {
    if (err instanceof ApiError) {
      console.warn('claim rejected:', err.status, err.serverError);
    } else {
      throw err;
    }
  }
}

main().catch((err: unknown) => {
  console.error('example failed:', err);
  process.exitCode = 1;
});
