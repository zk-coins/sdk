import { describe, expect, it } from 'vitest';

import { ApiError, NotImplementedError } from '../src/errors.js';

describe('ApiError', () => {
  it('exposes status, serverError, rawBody', () => {
    const err = new ApiError(403, 'forbidden', '{"success":false,"error":"forbidden"}');
    expect(err.status).toBe(403);
    expect(err.serverError).toBe('forbidden');
    expect(err.rawBody).toBe('{"success":false,"error":"forbidden"}');
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

describe('NotImplementedError', () => {
  it('formats with endpoint name', () => {
    const err = new NotImplementedError('history');
    expect(err.message).toBe('zkCoins SDK: history is not implemented yet');
    expect(err.endpoint).toBe('history');
    expect(err.issueUrl).toBeUndefined();
  });

  it('appends tracking issue URL when provided', () => {
    const err = new NotImplementedError('history', 'https://github.com/zk-coins/node/issues/153');
    expect(err.message).toBe(
      'zkCoins SDK: history is not implemented yet (tracking: https://github.com/zk-coins/node/issues/153)',
    );
    expect(err.issueUrl).toBe('https://github.com/zk-coins/node/issues/153');
  });

  it('is detectable via instanceof', () => {
    const err = new NotImplementedError('foo');
    expect(err).toBeInstanceOf(NotImplementedError);
    expect(err).toBeInstanceOf(Error);
  });

  it('has name set to NotImplementedError', () => {
    expect(new NotImplementedError('x').name).toBe('NotImplementedError');
  });
});
