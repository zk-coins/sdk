import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';

import { ApiError, NotImplementedError } from '../src/errors.js';
import { ZkCoinsClient } from '../src/client.js';

const BASE = 'https://node.test';

const server = setupServer();

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

const newClient = () => new ZkCoinsClient({ apiUrl: BASE });

describe('ZkCoinsClient constructor', () => {
  it('rejects an apiUrl without a scheme', () => {
    expect(() => new ZkCoinsClient({ apiUrl: 'node.test' })).toThrow(/http:\/\/ or https:\/\//);
  });

  it('rejects an empty apiUrl', () => {
    expect(() => new ZkCoinsClient({ apiUrl: '' })).toThrow();
  });

  it('falls back to api.zkcoins.app when no apiUrl is passed', async () => {
    const seen: string[] = [];
    const client = new ZkCoinsClient({
      fetch: async (input) => {
        const url =
          typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
        seen.push(url);
        return new Response(JSON.stringify({ network: 'Mainnet' }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      },
    });
    expect(client.apiUrl).toBe('https://api.zkcoins.app');
    await client.info();
    expect(seen[0]).toBe('https://api.zkcoins.app/api/info');
  });

  it('also falls back when constructed with no options at all', async () => {
    // Pins the zero-arg form `new ZkCoinsClient()` as a supported
    // call shape — a regression that made `apiUrl` required again
    // would surface here.
    const origFetch = globalThis.fetch;
    const seen: string[] = [];
    globalThis.fetch = async (input) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
      seen.push(url);
      return new Response(JSON.stringify({ network: 'Mainnet' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    };
    try {
      const client = new ZkCoinsClient();
      expect(client.apiUrl).toBe('https://api.zkcoins.app');
      await client.info();
      expect(seen[0]).toBe('https://api.zkcoins.app/api/info');
    } finally {
      globalThis.fetch = origFetch;
    }
  });

  it('exposes the resolved apiUrl as a readonly instance property', () => {
    const client = new ZkCoinsClient({ apiUrl: 'https://custom.test/' });
    expect(client.apiUrl).toBe('https://custom.test'); // trailing slash stripped
  });

  it('reads ZKCOINS_API_URL env var when no apiUrl option is passed', () => {
    const orig = process.env.ZKCOINS_API_URL;
    process.env.ZKCOINS_API_URL = 'https://from-env.test/';
    try {
      const client = new ZkCoinsClient();
      expect(client.apiUrl).toBe('https://from-env.test');
    } finally {
      if (orig === undefined) delete process.env.ZKCOINS_API_URL;
      else process.env.ZKCOINS_API_URL = orig;
    }
  });

  it('explicit option wins over env var', () => {
    const orig = process.env.ZKCOINS_API_URL;
    process.env.ZKCOINS_API_URL = 'https://from-env.test';
    try {
      const client = new ZkCoinsClient({ apiUrl: 'https://from-option.test' });
      expect(client.apiUrl).toBe('https://from-option.test');
    } finally {
      if (orig === undefined) delete process.env.ZKCOINS_API_URL;
      else process.env.ZKCOINS_API_URL = orig;
    }
  });

  it('strips a trailing slash from apiUrl', async () => {
    let observed = '';
    server.use(
      http.get(`${BASE}/api/info`, ({ request }) => {
        observed = request.url;
        return HttpResponse.json({ network: 'Mainnet' });
      }),
    );
    const client = new ZkCoinsClient({ apiUrl: `${BASE}/` });
    await client.info();
    expect(observed).toBe(`${BASE}/api/info`);
  });
});

describe('ZkCoinsClient.info', () => {
  it('parses a minimal network-only response', async () => {
    server.use(http.get(`${BASE}/api/info`, () => HttpResponse.json({ network: 'Mutinynet' })));
    const info = await newClient().info();
    expect(info.network).toBe('Mutinynet');
    expect(info.capabilities).toBeUndefined();
  });

  it('parses a full info with capabilities', async () => {
    server.use(
      http.get(`${BASE}/api/info`, () =>
        HttpResponse.json({
          network: 'Mainnet',
          capabilities: { address_list: true, faucet: false, usernames: true, lnurl: false },
        }),
      ),
    );
    const info = await newClient().info();
    expect(info.capabilities?.usernames).toBe(true);
  });

  it('throws ZodError on schema-shape drift (e.g. renamed field)', async () => {
    server.use(
      http.get(
        `${BASE}/api/info`,
        () => HttpResponse.json({ chain: 'Mainnet' }), // 'chain' instead of 'network'
      ),
    );
    await expect(newClient().info()).rejects.toThrow();
  });
});

describe('ZkCoinsClient.balance', () => {
  it('URL-encodes the address', async () => {
    let observed = '';
    server.use(
      http.get(`${BASE}/api/balance`, ({ request }) => {
        observed = new URL(request.url).searchParams.get('address') ?? '';
        return HttpResponse.json({ balance: 1000 });
      }),
    );
    await newClient().balance('aa bb');
    expect(observed).toBe('aa bb');
  });

  it('parses balance + optional username', async () => {
    server.use(
      http.get(`${BASE}/api/balance`, () =>
        HttpResponse.json({ balance: 5000, username: 'alice' }),
      ),
    );
    const r = await newClient().balance('abcdef');
    expect(r.balance).toBe(5000);
    expect(r.username).toBe('alice');
  });
});

describe('ZkCoinsClient.mint', () => {
  it('defaults amount to 10000 when omitted', async () => {
    let observed: { account_address?: string; amount?: number } = {};
    server.use(
      http.post(`${BASE}/api/mint`, async ({ request }) => {
        observed = (await request.json()) as typeof observed;
        return HttpResponse.json({ success: true, proof_id: 1 });
      }),
    );
    await newClient().mint('ab');
    expect(observed).toEqual({ account_address: 'ab', amount: 10_000 });
  });

  it('passes explicit amount through', async () => {
    let observedAmount = 0;
    server.use(
      http.post(`${BASE}/api/mint`, async ({ request }) => {
        const body = (await request.json()) as { amount: number };
        observedAmount = body.amount;
        return HttpResponse.json({ success: true });
      }),
    );
    await newClient().mint('ab', 42);
    expect(observedAmount).toBe(42);
  });
});

describe('ZkCoinsClient.send / commit / claimUsername (POST methods)', () => {
  it('send: forwards the signed request body verbatim', async () => {
    let observed: unknown = null;
    server.use(
      http.post(`${BASE}/api/send`, async ({ request }) => {
        observed = await request.json();
        return HttpResponse.json({ success: true, proof_id: 99 });
      }),
    );
    const req = {
      account_address: 'aa',
      recipient: 'bb',
      amount: 100,
      public_key: 'cc',
      next_public_key: 'dd',
      signature: 'ee',
      timestamp: 12345,
    };
    const r = await newClient().send(req);
    expect(observed).toEqual(req);
    expect(r.proof_id).toBe(99);
  });

  it('commit: forwards the commit request body', async () => {
    let observed: unknown = null;
    server.use(
      http.post(`${BASE}/api/commit`, async ({ request }) => {
        observed = await request.json();
        return HttpResponse.json({ success: true });
      }),
    );
    const req = { proof_id: 5, public_key: 'aa', signature: 'bb', message: 'cc' };
    await newClient().commit(req);
    expect(observed).toEqual(req);
  });

  it('claimUsername: forwards the signed claim body', async () => {
    let observed: unknown = null;
    server.use(
      http.post(`${BASE}/api/username/claim`, async ({ request }) => {
        observed = await request.json();
        return HttpResponse.json({ username: 'satoshi', address: 'ab' });
      }),
    );
    const req = {
      username: 'satoshi',
      address: 'ab',
      public_key: 'cd',
      signature: 'ef',
      timestamp: 1,
    };
    const r = await newClient().claimUsername(req);
    expect(observed).toEqual(req);
    expect(r.username).toBe('satoshi');
  });
});

describe('ZkCoinsClient.resolveUsername', () => {
  it('URL-encodes the username in the path', async () => {
    let observed = '';
    server.use(
      http.get(`${BASE}/api/username/resolve/:name`, ({ params }) => {
        observed = params.name as string;
        return HttpResponse.json({ username: 'a b', address: 'cd' });
      }),
    );
    await newClient().resolveUsername('a b');
    expect(observed).toBe('a b');
  });
});

describe('ZkCoinsClient.history (issue #153 placeholder)', () => {
  it('throws NotImplementedError', async () => {
    await expect(newClient().history('ab')).rejects.toThrow(NotImplementedError);
  });

  it('includes the tracking issue URL in the error', async () => {
    try {
      await newClient().history('ab');
      throw new Error('expected throw');
    } catch (e) {
      expect(e).toBeInstanceOf(NotImplementedError);
      expect((e as NotImplementedError).issueUrl).toBe(
        'https://github.com/zk-coins/node/issues/153',
      );
    }
  });
});

describe('ZkCoinsClient error handling', () => {
  it('maps non-2xx with structured envelope to ApiError with serverError extracted', async () => {
    server.use(
      http.get(`${BASE}/api/balance`, () =>
        HttpResponse.json({ success: false, error: 'address not found' }, { status: 404 }),
      ),
    );
    try {
      await newClient().balance('zz');
      throw new Error('expected throw');
    } catch (e) {
      expect(e).toBeInstanceOf(ApiError);
      const err = e as ApiError;
      expect(err.status).toBe(404);
      expect(err.serverError).toBe('address not found');
      expect(err.rawBody).toContain('address not found');
    }
  });

  it('falls back to raw body when failure body is not JSON', async () => {
    server.use(
      http.get(`${BASE}/api/balance`, () => new HttpResponse('plain text 502', { status: 502 })),
    );
    try {
      await newClient().balance('zz');
      throw new Error('expected throw');
    } catch (e) {
      expect(e).toBeInstanceOf(ApiError);
      expect((e as ApiError).serverError).toBe('plain text 502');
    }
  });

  it('falls back to raw body when JSON body has no `error` string', async () => {
    server.use(
      http.get(`${BASE}/api/balance`, () => HttpResponse.json({ status: 'down' }, { status: 503 })),
    );
    try {
      await newClient().balance('zz');
      throw new Error('expected throw');
    } catch (e) {
      expect((e as ApiError).serverError).toContain('"status":"down"');
    }
  });
});

describe('ZkCoinsClient timeout + abort', () => {
  it('aborts when the per-request timeout elapses', async () => {
    server.use(
      http.get(`${BASE}/api/info`, async () => {
        // Never resolve — let the client's timeout fire.
        await new Promise(() => {});
        return HttpResponse.json({ network: 'Mainnet' });
      }),
    );
    const client = new ZkCoinsClient({ apiUrl: BASE, requestTimeoutMs: 50 });
    await expect(client.info()).rejects.toThrow();
  });

  it('aborts immediately when the caller passes an already-aborted signal', async () => {
    server.use(http.get(`${BASE}/api/info`, () => HttpResponse.json({ network: 'Mainnet' })));
    const ctrl = new AbortController();
    ctrl.abort();
    await expect(newClient().info(ctrl.signal)).rejects.toThrow();
  });

  it('aborts mid-request when the caller cancels the signal', async () => {
    server.use(
      http.get(`${BASE}/api/info`, async () => {
        await new Promise(() => {});
        return HttpResponse.json({ network: 'Mainnet' });
      }),
    );
    const ctrl = new AbortController();
    const promise = newClient().info(ctrl.signal);
    setTimeout(() => ctrl.abort(), 10);
    await expect(promise).rejects.toThrow();
  });
});

describe('ZkCoinsClient: custom fetch injection', () => {
  it('uses a caller-supplied fetch when provided', async () => {
    const fakeFetch = vi.fn<typeof fetch>(async (input) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
      expect(url).toBe(`${BASE}/api/info`);
      return new Response(JSON.stringify({ network: 'Custom' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    });
    const client = new ZkCoinsClient({ apiUrl: BASE, fetch: fakeFetch });
    const info = await client.info();
    expect(info.network).toBe('Custom');
    expect(fakeFetch).toHaveBeenCalledOnce();
  });
});
