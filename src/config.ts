/**
 * SDK-internal config defaults.
 *
 * Centralised so the next configurable value (timeouts, retry
 * counts, …) lands here rather than getting scattered across
 * `client.ts` and friends. Nothing here is part of the public API
 * — consumers configure via constructor options or env vars; this
 * module just gives those resolution chains a single endpoint to
 * fall back to.
 */

/**
 * The node URL the SDK uses when neither the explicit `apiUrl`
 * option nor the `ZKCOINS_API_URL` env var is set.
 */
export const API_URL = 'https://api.zkcoins.app';

/** Per-request abort timeout in milliseconds. */
export const REQUEST_TIMEOUT_MS = 120_000;
