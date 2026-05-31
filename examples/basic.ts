/**
 * Minimal end-to-end usage of `@zkcoins/sdk`. Run with:
 *
 *   ZKCOINS_API_URL=https://dev-api.zkcoins.app npx tsx examples/basic.ts
 *
 * The example creates a brand-new account, asks the server for the
 * balance, mints some test coins (DEV has a faucet), reads the
 * post-mint balance, and prints a Schnorr-signed claim of a random
 * username. Everything is server-mediated: the SDK never reaches a
 * Bitcoin node directly, never stores anything on disk, never holds
 * state across function calls beyond the in-memory `xpriv` and
 * `numPubkeys` counter.
 *
 * The SDK does **not** ship endpoint constants. Pass the URL of the
 * zkCoins node you want to talk to via `ZKCOINS_API_URL` (any
 * self-hosted node works too). The DFX-operated stages are:
 *
 *   - `https://api.zkcoins.app`     (Bitcoin Mainnet)
 *   - `https://dev-api.zkcoins.app` (Mutinynet — has the open faucet)
 */

import { generateMnemonic, ZkCoinsAccount, ApiError } from '@zkcoins/sdk';

async function main(): Promise<void> {
  const apiUrl = process.env.ZKCOINS_API_URL;
  if (!apiUrl) {
    throw new Error(
      'ZKCOINS_API_URL must be set (e.g. https://dev-api.zkcoins.app for the DEV stage).',
    );
  }

  // 1. Generate a fresh BIP-39 mnemonic + derive the account.
  const mnemonic = await generateMnemonic();
  // eslint-disable-next-line no-console
  console.log('mnemonic:', mnemonic);

  const account = await ZkCoinsAccount.fromMnemonic(mnemonic, /* accountIndex */ 0, {
    apiUrl,
  });
  // eslint-disable-next-line no-console
  console.log('address: ', account.address);

  // 2. Read the server's view of this address. A brand-new account
  //    has balance 0, no username.
  const initial = await account.getBalance();
  // eslint-disable-next-line no-console
  console.log('initial balance:', initial.balance, 'sats');

  // 3. Hit the DEV faucet via `/api/mint`. On Mutinynet this is open
  //    by default. On Mainnet, mint is gated and would 4xx.
  try {
    const mint = await account.client.mint(account.address, /* amount */ 10_000);
    // eslint-disable-next-line no-console
    console.log('mint proof_id:', mint.proof_id);
  } catch (err) {
    if (err instanceof ApiError) {
      // eslint-disable-next-line no-console
      console.log('mint rejected (expected on Mainnet):', err.status, err.serverError);
    } else {
      throw err;
    }
  }

  // 4. Re-read balance — the thin-client invariant in action.
  const post = await account.getBalance();
  // eslint-disable-next-line no-console
  console.log('post-mint balance:', post.balance, 'sats');

  // 5. Claim a random username. The signed-claim flow signs a
  //    fixed-prefix message ("zkcoins:claim_username" || address ||
  //    username || timestamp_le) with the identity key at index 0.
  const username = `demo-${Math.floor(Math.random() * 1_000_000)}`;
  try {
    const claim = await account.claimUsername(username);
    // eslint-disable-next-line no-console
    console.log('claimed username:', claim.username, 'for address', claim.address);
  } catch (err) {
    if (err instanceof ApiError) {
      // eslint-disable-next-line no-console
      console.log('claim rejected:', err.status, err.serverError);
    } else {
      throw err;
    }
  }
}

main().catch((err: unknown) => {
  // eslint-disable-next-line no-console
  console.error('example failed:', err);
  process.exitCode = 1;
});
