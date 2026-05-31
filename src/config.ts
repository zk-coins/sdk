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
 * Inline fallback for the node URL when neither the explicit
 * `apiUrl` option nor the `ZKCOINS_API_URL` env var is set.
 */
export const FALLBACK_API_URL = 'https://api.zkcoins.app';

/** Default per-request abort timeout in milliseconds. */
export const DEFAULT_REQUEST_TIMEOUT_MS = 120_000;
