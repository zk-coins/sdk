/**
 * Per-network fixed transition message `m_state` (§1.4 / §3.2).
 *
 * Every state-advancing transition signs exactly one of these three ASCII
 * constants. The closed set is what closes on-chain cross-network replay of a
 * raw `(Pk, R, s)`: a testnet signature fails BIP-340 under mainnet's
 * `m_state` (V.9 N-19).
 *
 * There is **no default network**. Callers name the network; an unknown value
 * is a type error (or a loud runtime throw on the exhaustive fallback).
 */

/** The three networks that pin a distinct `m_state`. Closed set. */
export type Network = 'mainnet' | 'testnet' | 'regtest';

const M_STATE_MAINNET = 'zkCoins/v1/StateUpdate/mainnet';
const M_STATE_TESTNET = 'zkCoins/v1/StateUpdate/testnet';
const M_STATE_REGTEST = 'zkCoins/v1/StateUpdate/regtest';

const encoder = new TextEncoder();

const M_STATE_BYTES: Readonly<Record<Network, Uint8Array>> = {
  mainnet: encoder.encode(M_STATE_MAINNET),
  testnet: encoder.encode(M_STATE_TESTNET),
  regtest: encoder.encode(M_STATE_REGTEST),
};

/**
 * Return the fixed ASCII `m_state` bytes for `network`.
 *
 * Throws if `network` is not one of the three closed values (defensive for
 * JS call sites that bypass the type checker).
 */
export function mStateBytes(network: Network): Uint8Array {
  switch (network) {
    case 'mainnet':
    case 'testnet':
    case 'regtest': {
      const bytes = M_STATE_BYTES[network];
      // Defensive copy so callers cannot mutate the module-level constant.
      return bytes.slice();
    }
    default: {
      const _exhaustive: never = network;
      throw new Error(
        `mStateBytes: unknown network ${JSON.stringify(_exhaustive)}; expected mainnet|testnet|regtest`,
      );
    }
  }
}

/**
 * Return the fixed ASCII `m_state` string for `network` (debug / display).
 * Signing and verification use {@link mStateBytes}.
 */
export function mStateString(network: Network): string {
  switch (network) {
    case 'mainnet':
      return M_STATE_MAINNET;
    case 'testnet':
      return M_STATE_TESTNET;
    case 'regtest':
      return M_STATE_REGTEST;
    default: {
      const _exhaustive: never = network;
      throw new Error(
        `mStateString: unknown network ${JSON.stringify(_exhaustive)}; expected mainnet|testnet|regtest`,
      );
    }
  }
}
