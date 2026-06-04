/**
 * Typed errors thrown by the SDK.
 *
 * - `ApiError` — the server returned a non-2xx. `serverError` is the
 *   parsed `error` string from the failure envelope (the Jobs-API
 *   `{error}` shape or the legacy `{success: false, error}` shape)
 *   when the body was JSON in either form; otherwise the raw body.
 *   Consumers catch on this class to distinguish server-side
 *   rejections from network errors or client-side validation failures.
 * - `JobFailedError` — a background job reached a terminal non-success
 *   state (`failed` or `cancelled`). Distinct from `ApiError` (the
 *   HTTP call itself succeeded — the *job* failed) so consumer code can
 *   branch on "the node rejected my request" vs. "the proof/broadcast
 *   leg failed asynchronously". No silent fallback: `waitForJob`
 *   throws this rather than returning a non-completed status.
 */

/**
 * Thrown when the server responded with a non-2xx status.
 *
 * `serverError` is the parsed `error` string from the failure envelope
 * (the Jobs-API `{error}` shape or the legacy `{success: false, error}`
 * shape) when the body was JSON in either form; otherwise it falls back
 * to the raw body. The raw body is also retained on `rawBody` for
 * diagnostics.
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
 * Thrown when a background job reaches a terminal non-success state.
 *
 * `waitForJob` / `mint` / `pay` throw this when a job ends in `failed`
 * (the prove or broadcast leg errored — `error` carries the node's
 * message) or `cancelled`. The terminal `status` is preserved so the
 * caller can branch on it; `jobId` identifies the job for follow-up.
 */
export class JobFailedError extends Error {
  public readonly jobId: string;
  public readonly status: 'failed' | 'cancelled';
  public readonly serverError: string | undefined;

  constructor(jobId: string, status: 'failed' | 'cancelled', serverError?: string) {
    const tail = serverError ? `: ${serverError}` : '';
    super(`zkCoins job ${jobId} ${status}${tail}`);
    this.name = 'JobFailedError';
    this.jobId = jobId;
    this.status = status;
    this.serverError = serverError;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}
