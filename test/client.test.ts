import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';

import { API_URL } from '../src/config.js';
import { ApiError } from '../src/errors.js';
import { ZkCoinsClient, newIdempotencyKey } from '../src/client.js';

const BASE = 'https://node.test';

const server = setupServer();

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

const newClient = () => new ZkCoinsClient({ apiUrl: BASE });

describe('newIdempotencyKey', () => {
  it('produces a v4 UUID with the RFC-4122 version + variant nibbles', () => {
    const re = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
    for (let i = 0; i < 50; i += 1) {
      expect(newIdempotencyKey()).toMatch(re);
    }
  });

  it('is unique across calls', () => {
    const a = newIdempotencyKey();
    const b = newIdempotencyKey();
    expect(a).not.toBe(b);
  });
});

describe('ZkCoinsClient constructor', () => {
  it('rejects an apiUrl without a scheme', () => {
    expect(() => new ZkCoinsClient({ apiUrl: 'node.test' })).toThrow(/http:\/\/ or https:\/\//);
  });

  it('rejects an empty apiUrl', () => {
    expect(() => new ZkCoinsClient({ apiUrl: '' })).toThrow();
  });

  it('falls back to the configured API_URL when no apiUrl is passed', async () => {
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
    expect(client.apiUrl).toBe(API_URL);
    await client.info();
    expect(seen[0]).toBe(`${API_URL}/api/info`);
  });

  it('also falls back when constructed with no options at all', async () => {
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
      expect(client.apiUrl).toBe(API_URL);
      await client.info();
      expect(seen[0]).toBe(`${API_URL}/api/info`);
    } finally {
      globalThis.fetch = origFetch;
    }
  });

  it('exposes the resolved apiUrl as a readonly instance property', () => {
    const client = new ZkCoinsClient({ apiUrl: 'https://custom.test/' });
    expect(client.apiUrl).toBe('https://custom.test');
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
    expect(info.bitcoin_network).toBeUndefined();
  });

  it('parses a full info (capabilities + bitcoin_network + username_domain)', async () => {
    server.use(
      http.get(`${BASE}/api/info`, () =>
        HttpResponse.json({
          network: 'Mainnet',
          bitcoin_network: 'mainnet',
          capabilities: {
            address_list: true,
            username_claim: false,
            lnurl: false,
            multi_asset: true,
          },
          username_domain: 'api.zkcoins.app',
        }),
      ),
    );
    const info = await newClient().info();
    expect(info.capabilities?.multi_asset).toBe(true);
    expect(info.bitcoin_network).toBe('mainnet');
    expect(info.username_domain).toBe('api.zkcoins.app');
  });

  it('throws ZodError on schema-shape drift (renamed field)', async () => {
    server.use(http.get(`${BASE}/api/info`, () => HttpResponse.json({ chain: 'Mainnet' })));
    await expect(newClient().info()).rejects.toThrow();
  });
});

describe('ZkCoinsClient.balance', () => {
  it('URL-encodes the address', async () => {
    let observed = '';
    server.use(
      http.get(`${BASE}/api/balance`, ({ request }) => {
        observed = new URL(request.url).searchParams.get('address') ?? '';
        return HttpResponse.json({ balance: 1000, num_sends: 0 });
      }),
    );
    await newClient().balance('aa bb');
    expect(observed).toBe('aa bb');
  });

  it('parses balance + num_sends + optional username', async () => {
    server.use(
      http.get(`${BASE}/api/balance`, () =>
        HttpResponse.json({ balance: 5000, username: 'alice', num_sends: 4 }),
      ),
    );
    const r = await newClient().balance('abcdef');
    expect(r.balance).toBe(5000);
    expect(r.username).toBe('alice');
    expect(r.num_sends).toBe(4);
  });
});

describe('ZkCoinsClient.history', () => {
  it('forwards address + limit + offset query params', async () => {
    let params: URLSearchParams | null = null;
    server.use(
      http.get(`${BASE}/api/history`, ({ request }) => {
        params = new URL(request.url).searchParams;
        return HttpResponse.json({ items: [], total: 0, limit: 10, offset: 5 });
      }),
    );
    await newClient().history('abcd', { limit: 10, offset: 5 });
    expect(params!.get('address')).toBe('abcd');
    expect(params!.get('limit')).toBe('10');
    expect(params!.get('offset')).toBe('5');
  });

  it('omits limit / offset when not supplied', async () => {
    let params: URLSearchParams | null = null;
    server.use(
      http.get(`${BASE}/api/history`, ({ request }) => {
        params = new URL(request.url).searchParams;
        return HttpResponse.json({ items: [], total: 0, limit: 50, offset: 0 });
      }),
    );
    await newClient().history('abcd');
    expect(params!.has('limit')).toBe(false);
    expect(params!.has('offset')).toBe(false);
  });

  it('parses a populated page', async () => {
    server.use(
      http.get(`${BASE}/api/history`, () =>
        HttpResponse.json({
          items: [
            {
              id: 1,
              txid: null,
              timestamp: 0,
              direction: 'mint',
              amount: 1000,
              counterparty: null,
              status: 'confirmed',
              block_height: null,
              memo: null,
            },
          ],
          total: 1,
          limit: 50,
          offset: 0,
        }),
      ),
    );
    const r = await newClient().history('abcd');
    expect(r.items).toHaveLength(1);
    expect(r.items[0]?.direction).toBe('mint');
  });
});

describe('ZkCoinsClient.mintJob', () => {
  it('admits a mint job with the Idempotency-Key header and no asset_id', async () => {
    let body: Record<string, unknown> = {};
    let key = '';
    server.use(
      http.post(`${BASE}/api/jobs/mint`, async ({ request }) => {
        body = (await request.json()) as typeof body;
        key = request.headers.get('Idempotency-Key') ?? '';
        return HttpResponse.json({ job_id: 'job-1', status: 'queued' }, { status: 202 });
      }),
    );
    const r = await newClient().mintJob({ account_address: 'ab', amount: 10_000 }, 'idem-key-1');
    expect(body).toEqual({ account_address: 'ab', amount: 10_000 });
    expect(body).not.toHaveProperty('asset_id');
    expect(key).toBe('idem-key-1');
    expect(r.job_id).toBe('job-1');
    expect(r.status).toBe('queued');
  });

  it('passes asset_id through when supplied', async () => {
    let body: Record<string, unknown> = {};
    server.use(
      http.post(`${BASE}/api/jobs/mint`, async ({ request }) => {
        body = (await request.json()) as typeof body;
        return HttpResponse.json({ job_id: 'job-2', status: 'queued' }, { status: 202 });
      }),
    );
    await newClient().mintJob({ account_address: 'ab', amount: 5, asset_id: 'ff'.repeat(32) }, 'k');
    expect(body.asset_id).toBe('ff'.repeat(32));
  });
});

describe('ZkCoinsClient.sendJob', () => {
  it('admits a send job with the signed body verbatim + Idempotency-Key', async () => {
    let body: unknown = null;
    let key = '';
    server.use(
      http.post(`${BASE}/api/jobs/send`, async ({ request }) => {
        body = await request.json();
        key = request.headers.get('Idempotency-Key') ?? '';
        return HttpResponse.json({ job_id: 'send-1', status: 'queued' }, { status: 202 });
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
    const r = await newClient().sendJob(req, 'send-key');
    expect(body).toEqual(req);
    expect(key).toBe('send-key');
    expect(r.job_id).toBe('send-1');
  });

  it('passes asset_id through on a send', async () => {
    let body: Record<string, unknown> = {};
    server.use(
      http.post(`${BASE}/api/jobs/send`, async ({ request }) => {
        body = (await request.json()) as typeof body;
        return HttpResponse.json({ job_id: 'send-2', status: 'queued' }, { status: 202 });
      }),
    );
    await newClient().sendJob(
      {
        account_address: 'aa',
        recipient: 'bb',
        amount: 1,
        public_key: 'cc',
        next_public_key: 'dd',
        signature: 'ee',
        timestamp: 1,
        asset_id: 'ab'.repeat(32),
      },
      'k',
    );
    expect(body.asset_id).toBe('ab'.repeat(32));
  });
});

describe('ZkCoinsClient.getJob / getJobWithRetry', () => {
  it('parses the poll body and returns just the status from getJob', async () => {
    server.use(
      http.get(`${BASE}/api/jobs/:id`, () =>
        HttpResponse.json({
          job_id: 'job-1',
          kind: 'send',
          status: 'proving',
          phase: 'proving',
          progress: 50,
        }),
      ),
    );
    const r = await newClient().getJob('job-1');
    expect(r.status).toBe('proving');
    expect(r.progress).toBe(50);
  });

  it('parses Retry-After seconds into retryAfterMs', async () => {
    server.use(
      http.get(`${BASE}/api/jobs/:id`, () =>
        HttpResponse.json(
          { job_id: 'job-1', kind: 'mint', status: 'queued', phase: 'queued', progress: 0 },
          { headers: { 'Retry-After': '2' } },
        ),
      ),
    );
    const r = await newClient().getJobWithRetry('job-1');
    expect(r.retryAfterMs).toBe(2000);
    expect(r.status.status).toBe('queued');
  });

  it('returns null retryAfterMs when the header is absent (terminal poll)', async () => {
    server.use(
      http.get(`${BASE}/api/jobs/:id`, () =>
        HttpResponse.json({
          job_id: 'job-1',
          kind: 'mint',
          status: 'completed',
          phase: 'completed',
          progress: 100,
          result: { success: true, proof_id: 3 },
        }),
      ),
    );
    const r = await newClient().getJobWithRetry('job-1');
    expect(r.retryAfterMs).toBeNull();
  });

  it('ignores a malformed (non-integer) Retry-After', async () => {
    server.use(
      http.get(`${BASE}/api/jobs/:id`, () =>
        HttpResponse.json(
          { status: 'queued', phase: 'queued' },
          { headers: { 'Retry-After': 'Wed, 21 Oct 2099 07:28:00 GMT' } },
        ),
      ),
    );
    const r = await newClient().getJobWithRetry('job-1');
    expect(r.retryAfterMs).toBeNull();
  });

  it('URL-encodes the job id in the path', async () => {
    let observed = '';
    server.use(
      http.get(`${BASE}/api/jobs/:id`, ({ params }) => {
        observed = params.id as string;
        return HttpResponse.json({ status: 'queued', phase: 'queued' });
      }),
    );
    await newClient().getJob('a/b');
    expect(observed).toBe('a/b');
  });
});

describe('ZkCoinsClient.commitJob / cancelJob', () => {
  it('commitJob posts the commit body and resolves on the broadcasting accept', async () => {
    let body: unknown = null;
    let path = '';
    server.use(
      http.post(`${BASE}/api/jobs/:id/commit`, async ({ request, params }) => {
        body = await request.json();
        path = params.id as string;
        return HttpResponse.json({ status: 'broadcasting' });
      }),
    );
    const req = { proof_id: 5, public_key: 'aa', signature: 'bb', message: 'cc' };
    await expect(newClient().commitJob('send-1', req)).resolves.toBeUndefined();
    expect(body).toEqual(req);
    expect(path).toBe('send-1');
  });

  it('commitJob surfaces a 409 (not awaiting_signature) as ApiError', async () => {
    server.use(
      http.post(`${BASE}/api/jobs/:id/commit`, () =>
        HttpResponse.json({ error: 'Job is in status `completed`' }, { status: 409 }),
      ),
    );
    await expect(
      newClient().commitJob('send-1', {
        proof_id: 1,
        public_key: 'a',
        signature: 'b',
        message: 'c',
      }),
    ).rejects.toBeInstanceOf(ApiError);
  });

  it('cancelJob resolves on the cancelled accept', async () => {
    server.use(
      http.post(`${BASE}/api/jobs/:id/cancel`, () => HttpResponse.json({ status: 'cancelled' })),
    );
    await expect(newClient().cancelJob('job-1')).resolves.toBeUndefined();
  });

  it('cancelJob surfaces a 409 (no longer cancellable) as ApiError', async () => {
    server.use(
      http.post(`${BASE}/api/jobs/:id/cancel`, () =>
        HttpResponse.json({ error: 'Job is not in a cancellable state' }, { status: 409 }),
      ),
    );
    await expect(newClient().cancelJob('job-1')).rejects.toThrow(/cancellable/);
  });
});

describe('ZkCoinsClient.streamJob (SSE)', () => {
  const sse = (frames: string): Response =>
    new Response(frames, {
      status: 200,
      headers: { 'content-type': 'text/event-stream' },
    });

  it('yields each phase frame and stops after event: complete', async () => {
    const frames =
      'event: phase\ndata: {"status":"proving","phase":"proving","proof_id":null,"result":null,"error":null}\n\n' +
      ': heartbeat\n\n' +
      'event: phase\ndata: {"status":"awaiting_signature","phase":"awaiting_signature","proof_id":17,"result":null,"error":null}\n\n' +
      'event: complete\ndata: {"status":"completed","phase":"completed","proof_id":null,"result":{"success":true,"proof_id":3},"error":null}\n\n';
    const client = new ZkCoinsClient({ apiUrl: BASE, fetch: async () => sse(frames) });
    const seen: string[] = [];
    for await (const s of client.streamJob('job-1')) {
      seen.push(s.status);
    }
    expect(seen).toEqual(['proving', 'awaiting_signature', 'completed']);
  });

  it('surfaces a 404 as ApiError before yielding', async () => {
    const client = new ZkCoinsClient({
      apiUrl: BASE,
      fetch: async () => new Response('{"error":"Job not found"}', { status: 404 }),
    });
    const gen = client.streamJob('nope');
    await expect(gen.next()).rejects.toBeInstanceOf(ApiError);
  });

  it('returns when the stream ends before a complete frame (done path)', async () => {
    // A single phase frame, then the stream closes (no terminal frame).
    const client = new ZkCoinsClient({
      apiUrl: BASE,
      fetch: async () => sse('event: phase\ndata: {"status":"proving","phase":"proving"}\n\n'),
    });
    const seen: string[] = [];
    for await (const s of client.streamJob('job-1')) {
      seen.push(s.status);
    }
    expect(seen).toEqual(['proving']);
  });

  it('throws when the response has no readable body', async () => {
    const client = new ZkCoinsClient({
      apiUrl: BASE,
      // A 200 with a null body (Response with null body + ok status).
      fetch: async () => new Response(null, { status: 200 }),
    });
    const gen = client.streamJob('job-1');
    await expect(gen.next()).rejects.toThrow(/no readable body/);
  });

  it('does not start the stream when given an already-aborted signal', async () => {
    const ctrl = new AbortController();
    ctrl.abort();
    const client = new ZkCoinsClient({
      apiUrl: BASE,
      fetch: async (_input, init) => {
        // The composed controller is aborted before the fetch resolves.
        if ((init?.signal as AbortSignal | undefined)?.aborted) {
          throw new DOMException('aborted', 'AbortError');
        }
        return sse('event: complete\ndata: {"status":"completed","phase":"completed"}\n\n');
      },
    });
    const gen = client.streamJob('job-1', ctrl.signal);
    await expect(gen.next()).rejects.toThrow();
  });

  // A stream whose pending `read()` rejects when `sig` aborts — models
  // a real fetch body cancelling on AbortController.abort().
  const abortableStream = (sig: AbortSignal): ReadableStream<Uint8Array> =>
    new ReadableStream<Uint8Array>({
      start(controller) {
        sig.addEventListener(
          'abort',
          () => controller.error(new DOMException('aborted', 'AbortError')),
          {
            once: true,
          },
        );
      },
    });

  it('detaches when the caller aborts a live stream mid-flight', async () => {
    const ctrl = new AbortController();
    const client = new ZkCoinsClient({
      apiUrl: BASE,
      fetch: async (_input, init) =>
        new Response(abortableStream(init!.signal as AbortSignal), {
          status: 200,
          headers: { 'content-type': 'text/event-stream' },
        }),
    });
    const gen = client.streamJob('job-1', ctrl.signal);
    const next = gen.next();
    ctrl.abort(); // fires the addEventListener('abort') callback → controller.abort()
    await expect(next).rejects.toThrow();
  });

  it('aborts the stream when the request timeout elapses', async () => {
    const client = new ZkCoinsClient({
      apiUrl: BASE,
      requestTimeoutMs: 30,
      fetch: async (_input, init) =>
        new Response(abortableStream(init!.signal as AbortSignal), {
          status: 200,
          headers: { 'content-type': 'text/event-stream' },
        }),
    });
    const gen = client.streamJob('job-1');
    await expect(gen.next()).rejects.toThrow();
  });

  it('handles a frame split across two chunks', async () => {
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        const enc = new TextEncoder();
        controller.enqueue(enc.encode('event: complete\nda'));
        controller.enqueue(enc.encode('ta: {"status":"completed","phase":"completed"}\n\n'));
        controller.close();
      },
    });
    const client = new ZkCoinsClient({
      apiUrl: BASE,
      fetch: async () =>
        new Response(stream, { status: 200, headers: { 'content-type': 'text/event-stream' } }),
    });
    const seen: string[] = [];
    for await (const s of client.streamJob('job-1')) {
      seen.push(s.status);
    }
    expect(seen).toEqual(['completed']);
  });
});

describe('ZkCoinsClient.resolveUsername / claimUsername', () => {
  it('resolveUsername URL-encodes the username in the path', async () => {
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

  it('claimUsername forwards the signed claim body', async () => {
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

describe('ZkCoinsClient error handling', () => {
  it('maps a Jobs-API {error} envelope to ApiError with serverError extracted', async () => {
    server.use(
      http.get(`${BASE}/api/balance`, () =>
        HttpResponse.json({ error: 'address not found' }, { status: 404 }),
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

  it('falls back to raw body when the failure body is not JSON', async () => {
    server.use(
      http.get(`${BASE}/api/balance`, () => new HttpResponse('plain text 502', { status: 502 })),
    );
    await expect(newClient().balance('zz')).rejects.toMatchObject({
      serverError: 'plain text 502',
    });
  });

  it('falls back to raw body when JSON has no error string', async () => {
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

describe('ZkCoinsClient.root', () => {
  const rootBody = {
    service: 'zkcoins-node',
    version: '1.1.0',
    network: 'Mutinynet',
    endpoints: {
      info: 'GET  /api/info',
      balance: 'GET  /api/balance?address={hex}',
      history: 'GET  /api/history?address={hex}&limit={n}&offset={n}',
      receive: 'POST /api/receive',
      admit_mint: 'POST /api/jobs/mint',
      admit_send: 'POST /api/jobs/send',
      get_job: 'GET  /api/jobs/{job_id}',
      stream_job: 'GET  /api/jobs/{job_id}/stream',
      commit: 'POST /api/jobs/{job_id}/commit',
      cancel: 'POST /api/jobs/{job_id}/cancel',
      proof: 'GET  /api/proof/{id}',
      inscription: 'GET  /api/inscriptions/{txid}',
      username_resolve: 'GET  /api/username/resolve/{username}',
      health: 'GET  /health',
      health_ready: 'GET  /health/ready',
      health_publisher: 'GET  /health/publisher',
      openapi: 'GET  /openapi.json',
      docs: 'GET  /docs',
    },
    docs: 'https://docs.zkcoins.app',
  };

  it('parses the service-info envelope', async () => {
    server.use(http.get(`${BASE}/`, () => HttpResponse.json(rootBody)));
    const r = await newClient().root();
    expect(r.service).toBe('zkcoins-node');
    expect(r.network).toBe('Mutinynet');
    expect(r.endpoints.health_ready).toBe('GET  /health/ready');
    expect(r.docs).toBe('https://docs.zkcoins.app');
  });

  it('throws ZodError when a required endpoints field is missing', async () => {
    const { health_ready, ...incompleteEndpoints } = rootBody.endpoints;
    void health_ready;
    server.use(
      http.get(`${BASE}/`, () =>
        HttpResponse.json({ ...rootBody, endpoints: incompleteEndpoints }),
      ),
    );
    await expect(newClient().root()).rejects.toThrow();
  });
});

describe('ZkCoinsClient.health', () => {
  it('returns the trimmed plain-text "ok" body', async () => {
    server.use(http.get(`${BASE}/health`, () => new HttpResponse('ok\n', { status: 200 })));
    expect(await newClient().health()).toBe('ok');
  });

  it('maps a non-2xx to ApiError with the raw body', async () => {
    server.use(http.get(`${BASE}/health`, () => new HttpResponse('service down', { status: 502 })));
    await expect(newClient().health()).rejects.toMatchObject({
      status: 502,
      serverError: 'service down',
    });
  });

  it('honours an already-aborted signal', async () => {
    server.use(http.get(`${BASE}/health`, () => new HttpResponse('ok', { status: 200 })));
    const ctrl = new AbortController();
    ctrl.abort();
    await expect(newClient().health(ctrl.signal)).rejects.toThrow();
  });

  it('aborts mid-request when the caller cancels the signal', async () => {
    server.use(
      http.get(`${BASE}/health`, async () => {
        await new Promise(() => {});
        return new HttpResponse('ok', { status: 200 });
      }),
    );
    const ctrl = new AbortController();
    const promise = newClient().health(ctrl.signal);
    setTimeout(() => ctrl.abort(), 10);
    await expect(promise).rejects.toThrow();
  });

  it('aborts when the per-request timeout elapses', async () => {
    server.use(
      http.get(`${BASE}/health`, async () => {
        await new Promise(() => {});
        return new HttpResponse('ok', { status: 200 });
      }),
    );
    const client = new ZkCoinsClient({ apiUrl: BASE, requestTimeoutMs: 30 });
    await expect(client.health()).rejects.toThrow();
  });
});

describe('ZkCoinsClient.ready', () => {
  it('parses the 200 ready body', async () => {
    server.use(
      http.get(`${BASE}/health/ready`, () =>
        HttpResponse.json({ ready: true, failures: [], status: 'ready', prover: 'ready' }),
      ),
    );
    const r = await newClient().ready();
    expect(r.ready).toBe(true);
    expect(r.failures).toEqual([]);
    expect(r.prover).toBe('ready');
  });

  it('parses (does not throw on) the 503 not-ready body', async () => {
    server.use(
      http.get(`${BASE}/health/ready`, () =>
        HttpResponse.json(
          { ready: false, failures: ['db', 'prover'], status: 'starting', prover: 'warming' },
          { status: 503 },
        ),
      ),
    );
    const r = await newClient().ready();
    expect(r.ready).toBe(false);
    expect(r.failures).toEqual(['db', 'prover']);
    expect(r.status).toBe('starting');
  });

  it('still throws ApiError on a non-503 failure (e.g. 500)', async () => {
    server.use(
      http.get(`${BASE}/health/ready`, () => HttpResponse.json({ error: 'boom' }, { status: 500 })),
    );
    await expect(newClient().ready()).rejects.toBeInstanceOf(ApiError);
  });

  it('throws ZodError when the body shape drifts', async () => {
    server.use(http.get(`${BASE}/health/ready`, () => HttpResponse.json({ ready: 'yes' })));
    await expect(newClient().ready()).rejects.toThrow();
  });

  it('honours an already-aborted signal', async () => {
    server.use(
      http.get(`${BASE}/health/ready`, () =>
        HttpResponse.json({ ready: true, failures: [], status: 'ready', prover: 'ready' }),
      ),
    );
    const ctrl = new AbortController();
    ctrl.abort();
    await expect(newClient().ready(ctrl.signal)).rejects.toThrow();
  });

  it('aborts mid-request when the caller cancels the signal', async () => {
    server.use(
      http.get(`${BASE}/health/ready`, async () => {
        await new Promise(() => {});
        return HttpResponse.json({ ready: true, failures: [], status: 'ready', prover: 'ready' });
      }),
    );
    const ctrl = new AbortController();
    const promise = newClient().ready(ctrl.signal);
    setTimeout(() => ctrl.abort(), 10);
    await expect(promise).rejects.toThrow();
  });

  it('aborts when the per-request timeout elapses', async () => {
    server.use(
      http.get(`${BASE}/health/ready`, async () => {
        await new Promise(() => {});
        return HttpResponse.json({ ready: true, failures: [], status: 'ready', prover: 'ready' });
      }),
    );
    const client = new ZkCoinsClient({ apiUrl: BASE, requestTimeoutMs: 30 });
    await expect(client.ready()).rejects.toThrow();
  });
});

describe('ZkCoinsClient.publisherHealth', () => {
  it('parses the 200 publisher state', async () => {
    server.use(
      http.get(`${BASE}/health/publisher`, () =>
        HttpResponse.json({ address: 'tb1pxyz', utxo_count: 1, total_sats: 992746 }),
      ),
    );
    const r = await newClient().publisherHealth();
    expect(r.address).toBe('tb1pxyz');
    expect(r.utxo_count).toBe(1);
    expect(r.total_sats).toBe(992746);
  });

  it('maps the 503 Esplora-error shape to ApiError', async () => {
    server.use(
      http.get(`${BASE}/health/publisher`, () =>
        HttpResponse.json(
          {
            error: 'Esplora-side error fetching publisher UTXOs',
            detail: 'timeout',
            address: 'tb1p',
          },
          { status: 503 },
        ),
      ),
    );
    await expect(newClient().publisherHealth()).rejects.toMatchObject({
      status: 503,
      serverError: 'Esplora-side error fetching publisher UTXOs',
    });
  });
});

describe('ZkCoinsClient.addresses', () => {
  it('parses the address list', async () => {
    server.use(
      http.get(`${BASE}/api/address`, () => HttpResponse.json({ addresses: ['0xaa', '0xbb'] })),
    );
    const r = await newClient().addresses();
    expect(r.addresses).toEqual(['0xaa', '0xbb']);
  });

  it('maps a 404 (feature off) to ApiError', async () => {
    server.use(http.get(`${BASE}/api/address`, () => new HttpResponse('', { status: 404 })));
    await expect(newClient().addresses()).rejects.toBeInstanceOf(ApiError);
  });
});

describe('ZkCoinsClient.inscription', () => {
  it('URL-encodes the txid and parses the summary', async () => {
    let observed = '';
    server.use(
      http.get(`${BASE}/api/inscriptions/:txid`, ({ params }) => {
        observed = params.txid as string;
        return HttpResponse.json({
          commit_txid: 'ab'.repeat(32),
          reveal_txid: 'cd'.repeat(32),
          kind: 'mint',
          status: 'confirmed',
          commit_output_value: 600,
          failure_reason: null,
          created_at: '2026-06-03T00:00:00.000000Z',
          updated_at: '2026-06-03T00:00:01.000000Z',
        });
      }),
    );
    const r = await newClient().inscription('ab'.repeat(32));
    expect(observed).toBe('ab'.repeat(32));
    expect(r.kind).toBe('mint');
    expect(r.reveal_txid).toBe('cd'.repeat(32));
    expect(r.failure_reason).toBeNull();
  });

  it('parses a failed inscription with a null reveal_txid', async () => {
    server.use(
      http.get(`${BASE}/api/inscriptions/:txid`, () =>
        HttpResponse.json({
          commit_txid: 'ef'.repeat(32),
          reveal_txid: null,
          kind: 'send',
          status: 'failed',
          commit_output_value: 0,
          failure_reason: 'broadcast rejected',
          created_at: '2026-06-03T00:00:00.000000Z',
          updated_at: '2026-06-03T00:00:01.000000Z',
        }),
      ),
    );
    const r = await newClient().inscription('ef'.repeat(32));
    expect(r.status).toBe('failed');
    expect(r.reveal_txid).toBeNull();
    expect(r.failure_reason).toBe('broadcast rejected');
  });

  it('maps a 422 (malformed txid) to ApiError', async () => {
    server.use(
      http.get(`${BASE}/api/inscriptions/:txid`, () =>
        HttpResponse.json({ success: false, error: 'txid is not valid hex' }, { status: 422 }),
      ),
    );
    await expect(newClient().inscription('zz')).rejects.toMatchObject({
      status: 422,
      serverError: 'txid is not valid hex',
    });
  });

  it('maps a 404 (unknown txid) to ApiError', async () => {
    server.use(
      http.get(`${BASE}/api/inscriptions/:txid`, () =>
        HttpResponse.json(
          { success: false, error: 'No inscription found for this txid' },
          { status: 404 },
        ),
      ),
    );
    await expect(newClient().inscription('aa'.repeat(32))).rejects.toBeInstanceOf(ApiError);
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
