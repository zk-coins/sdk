/**
 * Endpoint constants for the DFX-hosted zkCoins nodes.
 *
 * Mapping reflects the live deploy as of v0.1.0:
 *
 * - **Mainnet** (`api.zkcoins.app`) runs against Bitcoin Mainnet
 *   (`electrs-mainnet` + `IS_MAINNET=true` in the node compose).
 * - **Mutinynet** (`dev-api.zkcoins.app`) runs against the
 *   Mutinynet community signet (`electrs-mutinynet` +
 *   `IS_MAINNET=false`).
 *
 * Wallet integrators should never embed these URLs directly —
 * import the constant. A future stage rename or chain repointing
 * lands here, in one place.
 *
 * Self-hosters pass their own `apiUrl` directly to the SDK; the
 * constants are conveniences for the two stages the project
 * operates itself.
 */

export interface ZkCoinsEndpoint {
  /** Base URL of the node's REST API (no trailing slash). */
  readonly apiUrl: string;
  /** Hostname the node uses for `<hex|username>@<domain>` rendering. */
  readonly usernameDomain: string;
  /** Bitcoin chain the node binds to. */
  readonly bitcoinNetwork: 'mainnet' | 'mutinynet';
}

export const ZKCOINS_ENDPOINTS = {
  mainnet: {
    apiUrl: 'https://api.zkcoins.app',
    usernameDomain: 'zkcoins.app',
    bitcoinNetwork: 'mainnet',
  },
  mutinynet: {
    apiUrl: 'https://dev-api.zkcoins.app',
    usernameDomain: 'dev.zkcoins.app',
    bitcoinNetwork: 'mutinynet',
  },
} as const satisfies Record<string, ZkCoinsEndpoint>;
