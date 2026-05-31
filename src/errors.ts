/**
 * Typed errors thrown by the SDK.
 *
 * Two flavours:
 *
 * - `ApiError` — the server returned a non-2xx with the structured
 *   failure envelope (`{success: false, error: "<string>"}` from
 *   `zk-coins/node::router::*`). Consumers catch on this class to
 *   distinguish server-side rejections from network errors or
 *   client-side validation failures.
 * - `NotImplementedError` — placeholder thrown by SDK methods whose
 *   underlying endpoint has not shipped yet (today: `getTransactions`
 *   pending on zk-coins/node issue #153). Distinct from `ApiError`
 *   so consumer code can hide the affected UI path until the gate
 *   lifts, rather than rendering a generic network error.
 */

/**
 * Thrown when the server responded with a non-2xx status.
 *
 * `serverError` is the parsed `error` string from the structured
 * failure envelope (`{success: false, error}`) when the body was
 * JSON in that shape; otherwise it falls back to the raw body. The
 * raw body is also retained on `rawBody` for diagnostics.
 */
export class ApiError extends Error {
  public readonly status: number;
  public readonly serverError: string;
  public readonly rawBody: string | undefined;

  constructor(status: number, serverError: string, rawBody?: string) {
    super(`zkCoins API error ${status}: ${serverError}`);
    this.name = 'ApiError';
    this.status = status;
    this.serverError = serverError;
    this.rawBody = rawBody;
    // Maintain proper prototype chain across class transpilation
    // — required for `instanceof ApiError` to work when the SDK is
    // consumed from a transpiled bundle.
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Thrown when an SDK method is called against a server-side endpoint
 * that has not shipped yet. Today: `ZkCoinsClient.history(...)` and
 * `ZkCoinsAccount.getTransactions(...)` while zk-coins/node #153 is
 * open.
 */
export class NotImplementedError extends Error {
  public readonly endpoint: string;
  public readonly issueUrl: string | undefined;

  constructor(endpoint: string, issueUrl?: string) {
    const tail = issueUrl ? ` (tracking: ${issueUrl})` : '';
    super(`zkCoins SDK: ${endpoint} is not implemented yet${tail}`);
    this.name = 'NotImplementedError';
    this.endpoint = endpoint;
    this.issueUrl = issueUrl;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}
