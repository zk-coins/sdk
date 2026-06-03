import { describe, expect, it } from 'vitest';

import { ApiError, JobFailedError } from '../src/errors.js';

describe('ApiError', () => {
  it('exposes status, serverError, rawBody', () => {
    const err = new ApiError(403, 'forbidden', '{"error":"forbidden"}');
    expect(err.status).toBe(403);
    expect(err.serverError).toBe('forbidden');
    expect(err.rawBody).toBe('{"error":"forbidden"}');
  });

  it('formats the message with status + serverError', () => {
    const err = new ApiError(503, 'service unavailable');
    expect(err.message).toBe('zkCoins API error 503: service unavailable');
  });

  it('rawBody is optional', () => {
    const err = new ApiError(500, 'oops');
    expect(err.rawBody).toBeUndefined();
  });

  it('is detectable via instanceof (prototype chain preserved across transpile)', () => {
    const err = new ApiError(400, 'bad');
    expect(err).toBeInstanceOf(ApiError);
    expect(err).toBeInstanceOf(Error);
  });

  it('has name set to ApiError', () => {
    expect(new ApiError(400, 'x').name).toBe('ApiError');
  });
});

describe('JobFailedError', () => {
  it('formats a failed job with the server error', () => {
    const err = new JobFailedError('job-1', 'failed', 'prove failed');
    expect(err.message).toBe('zkCoins job job-1 failed: prove failed');
    expect(err.jobId).toBe('job-1');
    expect(err.status).toBe('failed');
    expect(err.serverError).toBe('prove failed');
  });

  it('formats a cancelled job without a server error', () => {
    const err = new JobFailedError('job-2', 'cancelled');
    expect(err.message).toBe('zkCoins job job-2 cancelled');
    expect(err.status).toBe('cancelled');
    expect(err.serverError).toBeUndefined();
  });

  it('is detectable via instanceof', () => {
    const err = new JobFailedError('j', 'failed');
    expect(err).toBeInstanceOf(JobFailedError);
    expect(err).toBeInstanceOf(Error);
  });

  it('has name set to JobFailedError', () => {
    expect(new JobFailedError('j', 'failed').name).toBe('JobFailedError');
  });
});
