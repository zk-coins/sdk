/**
 * Minimal end-to-end usage of `@zkcoins/sdk`. Run with:
 *
 *   npx tsx examples/basic.ts                    # uses the fallback URL
 *   ZKCOINS_API_URL=https://… npx tsx examples/basic.ts   # override
 *
 * The example creates a brand-new account, asks the server for the
 * balance, attempts a mint (rejected on Mainnet — see the stages
 * listed below for one with an open faucet), reads the balance again,
 * and prints a Schnorr-signed claim of a random username. Everything
 * is server-mediated: the SDK never reaches a Bitcoin node directly,
 * never stores anything on disk, never holds state across function
 * calls beyond the in-memory `xpriv` and `numPubkeys` counter.
 *
 * Node URL resolution order (handled inside the SDK, no boilerplate
 * needed in user code):
 *   1. explicit `{ apiUrl }` option (programmatic override)
 *   2. `ZKCOINS_API_URL` env var
 *   3. inline fallback
 *
 * zkcoins.app — one of hopefully many service providers — runs two
 * public stages today:
 *
 *   - `https://api.zkcoins.app`     (Bitcoin Mainnet)
 *   - `https://dev-api.zkcoins.app` (Mutinynet — has the open faucet)
 */

import { generateMnemonic, ZkCoinsAccount, ApiError } from '@zkcoins/sdk';

async function main(): Promise<void> {
  // 1. Generate a fresh BIP-39 mnemonic + derive the account.
  //    No `apiUrl` needed here — the SDK reads ZKCOINS_API_URL from
  //    the environment, falling back to its inline default.
  const mnemonic = await generateMnemonic();
  // eslint-disable-next-line no-console
  console.log('mnemonic:', mnemonic);

  const account = await ZkCoinsAccount.fromMnemonic(mnemonic, /* accountIndex */ 0);
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
