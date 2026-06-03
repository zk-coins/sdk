import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { schnorr } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hexToBytes } from '@noble/hashes/utils.js';

import { JobFailedError } from '../src/errors.js';
import { ZkCoinsAccount } from '../src/account.js';
import { ZkCoinsClient } from '../src/client.js';
import { buildClaimMessage, buildSendMessage } from '../src/messages.js';

const BASE = 'https://account.test';
const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

// Two valid 32-byte-hex digests for the commit message (account_state_hash
// || output_coins_root). Arbitrary but well-formed hex.
const ASH = 'aa'.repeat(32);
const OCR = 'bb'.repeat(32);

const server = setupServer();

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

const newAccount = () =>
  ZkCoinsAccount.fromMnemonic(TEST_MNEMONIC, 0, {
    apiUrl: BASE,
    client: new ZkCoinsClient({ apiUrl: BASE }),
  });

const RECIPIENT = 'cdef'.padEnd(64, '0');

describe('ZkCoinsAccount.fromMnemonic', () => {
  it('produces a 32-byte hex address', async () => {
    const account = await newAccount();
    expect(account.address).toMatch(/^[0-9a-f]{64}$/);
  });

  it('is deterministic for the same mnemonic', async () => {
    const a = await newAccount();
    const b = await newAccount();
    expect(a.address).toBe(b.address);
  });

  it('passphrase changes the derived address', async () => {
    const a = await newAccount();
    const b = await ZkCoinsAccount.fromMnemonic(TEST_MNEMONIC, 0, {
      apiUrl: BASE,
      passphrase: 'extra',
    });
    expect(a.address).not.toBe(b.address);
  });

  it('rejects a negative / non-integer accountIndex', async () => {
    await expect(ZkCoinsAccount.fromMnemonic(TEST_MNEMONIC, -1, { apiUrl: BASE })).rejects.toThrow(
      /non-negative integer/,
    );
    await expect(ZkCoinsAccount.fromMnemonic(TEST_MNEMONIC, 1.5, { apiUrl: BASE })).rejects.toThrow(
      /non-negative integer/,
    );
  });

  it('numPubkeys starts at 0', async () => {
    expect((await newAccount()).getNumPubkeys()).toBe(0);
  });

  it('constructs its own ZkCoinsClient when no override is passed', async () => {
    const account = await ZkCoinsAccount.fromMnemonic(TEST_MNEMONIC, 0, { apiUrl: BASE });
    expect(account.client).toBeInstanceOf(ZkCoinsClient);
  });
});

describe('ZkCoinsAccount.getBalance', () => {
  it('forwards to the underlying client (incl. num_sends)', async () => {
    server.use(
      http.get(`${BASE}/api/balance`, () =>
        HttpResponse.json({ balance: 12345, username: 'satoshi', num_sends: 2 }),
      ),
    );
    const r = await (await newAccount()).getBalance();
    expect(r.balance).toBe(12345);
    expect(r.num_sends).toBe(2);
  });

  it('threads through ApiError on failure', async () => {
    server.use(
      http.get(`${BASE}/api/balance`, () =>
        HttpResponse.json({ error: 'address not found' }, { status: 404 }),
      ),
    );
    await expect((await newAccount()).getBalance()).rejects.toThrow(/address not found/);
  });
});

describe('ZkCoinsAccount.mint', () => {
  it('admits a mint job and polls to completed', async () => {
    let mintBody: Record<string, unknown> = {};
    let polls = 0;
    server.use(
      http.post(`${BASE}/api/jobs/mint`, async ({ request }) => {
        mintBody = (await request.json()) as typeof mintBody;
        return HttpResponse.json({ job_id: 'mint-1', status: 'queued' }, { status: 202 });
      }),
      http.get(`${BASE}/api/jobs/mint-1`, () => {
        polls += 1;
        if (polls < 2) {
          return HttpResponse.json(
            { job_id: 'mint-1', kind: 'mint', status: 'proving', phase: 'proving', progress: 50 },
            { headers: { 'Retry-After': '0' } },
          );
        }
        return HttpResponse.json({
          job_id: 'mint-1',
          kind: 'mint',
          status: 'completed',
          phase: 'completed',
          progress: 100,
          result: { success: true, proof_id: 7 },
        });
      }),
    );
    const account = await newAccount();
    const r = await account.mint(10_000);
    expect(mintBody).toEqual({ account_address: account.address, amount: 10_000 });
    expect(mintBody).not.toHaveProperty('asset_id');
    expect(r.jobId).toBe('mint-1');
    expect(r.proofId).toBe(7);
  });

  it('passes asset_id through on a multi-asset mint', async () => {
    let mintBody: Record<string, unknown> = {};
    server.use(
      http.post(`${BASE}/api/jobs/mint`, async ({ request }) => {
        mintBody = (await request.json()) as typeof mintBody;
        return HttpResponse.json({ job_id: 'mint-2', status: 'queued' }, { status: 202 });
      }),
      http.get(`${BASE}/api/jobs/mint-2`, () =>
        HttpResponse.json({
          job_id: 'mint-2',
          kind: 'mint',
          status: 'completed',
          phase: 'completed',
          progress: 100,
          result: { success: true, proof_id: 1 },
        }),
      ),
    );
    await (await newAccount()).mint(5, 'ff'.repeat(32));
    expect(mintBody.asset_id).toBe('ff'.repeat(32));
  });

  it('throws JobFailedError when the mint job fails', async () => {
    server.use(
      http.post(`${BASE}/api/jobs/mint`, () =>
        HttpResponse.json({ job_id: 'mint-3', status: 'queued' }, { status: 202 }),
      ),
      http.get(`${BASE}/api/jobs/mint-3`, () =>
        HttpResponse.json({
          job_id: 'mint-3',
          kind: 'mint',
          status: 'failed',
          phase: 'failed',
          progress: 0,
          error: 'mint rejected on mainnet',
        }),
      ),
    );
    await expect((await newAccount()).mint(10_000)).rejects.toThrow(/mint rejected on mainnet/);
  });
});

describe('ZkCoinsAccount.pay (full send → commit lifecycle)', () => {
  // Drive a job through queued → proving → awaiting_signature (with
  // proof_id + ash/ocr on the result) → broadcasting → completed,
  // exercising the wallet's commit-message build + numPubkeys advance.
  const installSendLifecycle = (opts: { jobId: string }): { commits: unknown[] } => {
    const captured = { commits: [] as unknown[] };
    let phase: 'await' | 'committed' = 'await';
    server.use(
      http.get(`${BASE}/api/balance`, () => HttpResponse.json({ balance: 10_000, num_sends: 0 })),
      http.post(`${BASE}/api/jobs/send`, () =>
        HttpResponse.json({ job_id: opts.jobId, status: 'queued' }, { status: 202 }),
      ),
      http.post(`${BASE}/api/jobs/${opts.jobId}/commit`, async ({ request }) => {
        captured.commits.push(await request.json());
        phase = 'committed';
        return HttpResponse.json({ status: 'broadcasting' });
      }),
      http.get(`${BASE}/api/jobs/${opts.jobId}`, () => {
        if (phase === 'await') {
          return HttpResponse.json(
            {
              job_id: opts.jobId,
              kind: 'send',
              status: 'awaiting_signature',
              phase: 'awaiting_signature',
              progress: 60,
              proof_id: 99,
              result: { success: true, account_state_hash: ASH, output_coins_root: OCR },
            },
            { headers: { 'Retry-After': '0' } },
          );
        }
        return HttpResponse.json({
          job_id: opts.jobId,
          kind: 'send',
          status: 'completed',
          phase: 'completed',
          progress: 100,
          result: { success: true, proof_id: 99 },
        });
      }),
    );
    return captured;
  };

  it('refreshes balance, commits a verifying signature, completes, advances numPubkeys', async () => {
    const captured = installSendLifecycle({ jobId: 'send-1' });
    const account = await newAccount();
    expect(account.getNumPubkeys()).toBe(0);

    const r = await account.pay(RECIPIENT, 100);
    expect(r.jobId).toBe('send-1');
    expect(r.proofId).toBe(99);
    expect(account.getNumPubkeys()).toBe(1);

    // The commit body carries proof_id + the ash||ocr message + a
    // Schnorr signature that verifies under the broadcast pubkey.
    expect(captured.commits).toHaveLength(1);
    const commit = captured.commits[0] as {
      proof_id: number;
      public_key: string;
      signature: string;
      message: string;
    };
    expect(commit.proof_id).toBe(99);
    expect(commit.message).toBe(ASH + OCR);
    const digest = sha256(hexToBytes(commit.message));
    const xOnly = hexToBytes(commit.public_key).slice(1);
    expect(schnorr.verify(hexToBytes(commit.signature), digest, xOnly)).toBe(true);
  });

  it('a second pay advances numPubkeys to 2 and signs at the next index', async () => {
    installSendLifecycle({ jobId: 'send-a' });
    const account = await newAccount();
    await account.pay(RECIPIENT, 100);
    expect(account.getNumPubkeys()).toBe(1);

    const captured = installSendLifecycle({ jobId: 'send-b' });
    await account.pay(RECIPIENT, 200);
    expect(account.getNumPubkeys()).toBe(2);
    // The second commit's pubkey is derived at index 1, not 0.
    const first = await newAccount();
    const c2 = captured.commits[0] as { public_key: string };
    // pubkey at index 0 differs from the one used for send #2 (index 1)
    const idx0 = await (
      await import('../src/derivation.js')
    ).derivePublicKeys(
      (
        await (
          await import('../src/derivation.js')
        ).generateAccountKeysFromMnemonic(TEST_MNEMONIC, '')
      ).xpriv,
      0,
    );
    expect(c2.public_key).not.toBe(idx0.publicKey);
    expect(first.address).toBe(account.address);
  });

  it('hydrates numPubkeys forward from the server num_sends (lost local state / multi-device)', async () => {
    // Fresh in-memory account starts at 0, but the server reports this
    // account has already done 3 sends. The thin-client invariant means
    // pay() must derive + sign at index 3 (not 0) and advance to 4.
    let phase: 'await' | 'committed' = 'await';
    let commitBody: { public_key: string } | null = null;
    server.use(
      http.get(`${BASE}/api/balance`, () => HttpResponse.json({ balance: 10_000, num_sends: 3 })),
      http.post(`${BASE}/api/jobs/send`, () =>
        HttpResponse.json({ job_id: 'send-hyd', status: 'queued' }, { status: 202 }),
      ),
      http.post(`${BASE}/api/jobs/send-hyd/commit`, async ({ request }) => {
        commitBody = (await request.json()) as { public_key: string };
        phase = 'committed';
        return HttpResponse.json({ status: 'broadcasting' });
      }),
      http.get(`${BASE}/api/jobs/send-hyd`, () =>
        phase === 'await'
          ? HttpResponse.json(
              {
                job_id: 'send-hyd',
                kind: 'send',
                status: 'awaiting_signature',
                phase: 'awaiting_signature',
                progress: 60,
                proof_id: 7,
                result: { success: true, account_state_hash: ASH, output_coins_root: OCR },
              },
              { headers: { 'Retry-After': '0' } },
            )
          : HttpResponse.json({
              job_id: 'send-hyd',
              kind: 'send',
              status: 'completed',
              phase: 'completed',
              progress: 100,
              result: { success: true, proof_id: 7 },
            }),
      ),
    );
    const account = await newAccount();
    expect(account.getNumPubkeys()).toBe(0);

    await account.pay(RECIPIENT, 100);

    // Hydrated to 3, derived/signed at index 3, then advanced to 4.
    expect(account.getNumPubkeys()).toBe(4);
    const { generateAccountKeysFromMnemonic, derivePublicKeys } =
      await import('../src/derivation.js');
    const { xpriv } = await generateAccountKeysFromMnemonic(TEST_MNEMONIC, '');
    const idx3 = await derivePublicKeys(xpriv, 3);
    expect((commitBody as unknown as { public_key: string }).public_key).toBe(idx3.publicKey);
  });

  it('signs the send message with a signature that verifies on the server side', async () => {
    let sendBody: Record<string, unknown> | null = null;
    let phase: 'await' | 'done' = 'await';
    server.use(
      http.get(`${BASE}/api/balance`, () => HttpResponse.json({ balance: 10_000, num_sends: 0 })),
      http.post(`${BASE}/api/jobs/send`, async ({ request }) => {
        sendBody = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json({ job_id: 'send-sig', status: 'queued' }, { status: 202 });
      }),
      http.post(`${BASE}/api/jobs/send-sig/commit`, () => {
        phase = 'done';
        return HttpResponse.json({ status: 'broadcasting' });
      }),
      http.get(`${BASE}/api/jobs/send-sig`, () =>
        phase === 'await'
          ? HttpResponse.json(
              {
                status: 'awaiting_signature',
                phase: 'awaiting_signature',
                proof_id: 1,
                result: { success: true, account_state_hash: ASH, output_coins_root: OCR },
              },
              { headers: { 'Retry-After': '0' } },
            )
          : HttpResponse.json({
              status: 'completed',
              phase: 'completed',
              result: { success: true },
            }),
      ),
    );
    const account = await newAccount();
    await account.pay(RECIPIENT, 5_000);

    const body = sendBody as unknown as {
      account_address: string;
      recipient: string;
      amount: number;
      public_key: string;
      signature: string;
      timestamp: number;
    };
    const messageBytes = buildSendMessage({
      accountAddress: body.account_address,
      recipient: body.recipient,
      amount: body.amount,
      timestamp: body.timestamp,
    });
    const digest = sha256(messageBytes);
    const xOnlyPub = hexToBytes(body.public_key).slice(1);
    expect(schnorr.verify(hexToBytes(body.signature), digest, xOnlyPub)).toBe(true);
  });

  it('throws (and does NOT advance numPubkeys) when the send job fails', async () => {
    server.use(
      http.get(`${BASE}/api/balance`, () => HttpResponse.json({ balance: 10_000, num_sends: 0 })),
      http.post(`${BASE}/api/jobs/send`, () =>
        HttpResponse.json({ job_id: 'send-fail', status: 'queued' }, { status: 202 }),
      ),
      http.get(`${BASE}/api/jobs/send-fail`, () =>
        HttpResponse.json({
          status: 'failed',
          phase: 'failed',
          error: 'Insufficient funds',
        }),
      ),
    );
    const account = await newAccount();
    await expect(account.pay(RECIPIENT, 100)).rejects.toBeInstanceOf(JobFailedError);
    expect(account.getNumPubkeys()).toBe(0);
  });

  it('fails hard when the awaiting_signature job omits ash/ocr (no fabricated commit)', async () => {
    server.use(
      http.get(`${BASE}/api/balance`, () => HttpResponse.json({ balance: 10_000, num_sends: 0 })),
      http.post(`${BASE}/api/jobs/send`, () =>
        HttpResponse.json({ job_id: 'send-noash', status: 'queued' }, { status: 202 }),
      ),
      http.get(`${BASE}/api/jobs/send-noash`, () =>
        HttpResponse.json(
          { status: 'awaiting_signature', phase: 'awaiting_signature', proof_id: 5 },
          { headers: { 'Retry-After': '0' } },
        ),
      ),
    );
    const account = await newAccount();
    await expect(account.pay(RECIPIENT, 100)).rejects.toThrow(/account_state_hash/);
    expect(account.getNumPubkeys()).toBe(0);
  });

  it('throws if the send job completes before reaching awaiting_signature', async () => {
    server.use(
      http.get(`${BASE}/api/balance`, () => HttpResponse.json({ balance: 10_000, num_sends: 0 })),
      http.post(`${BASE}/api/jobs/send`, () =>
        HttpResponse.json({ job_id: 'send-skip', status: 'queued' }, { status: 202 }),
      ),
      http.get(`${BASE}/api/jobs/send-skip`, () =>
        HttpResponse.json({
          status: 'completed',
          phase: 'completed',
          result: { success: true, proof_id: 1 },
        }),
      ),
    );
    const account = await newAccount();
    await expect(account.pay(RECIPIENT, 100)).rejects.toThrow(/before commit/);
    expect(account.getNumPubkeys()).toBe(0);
  });

  it('fails when the awaiting_signature job omits proof_id', async () => {
    server.use(
      http.get(`${BASE}/api/balance`, () => HttpResponse.json({ balance: 10_000, num_sends: 0 })),
      http.post(`${BASE}/api/jobs/send`, () =>
        HttpResponse.json({ job_id: 'send-nopid', status: 'queued' }, { status: 202 }),
      ),
      http.get(`${BASE}/api/jobs/send-nopid`, () =>
        HttpResponse.json(
          { status: 'awaiting_signature', phase: 'awaiting_signature' },
          { headers: { 'Retry-After': '0' } },
        ),
      ),
    );
    await expect((await newAccount()).pay(RECIPIENT, 100)).rejects.toThrow(/proof_id/);
  });
});

describe('ZkCoinsAccount.waitForJob', () => {
  it('invokes onPhase once per distinct phase transition', async () => {
    let polls = 0;
    server.use(
      http.get(`${BASE}/api/jobs/wj-1`, () => {
        polls += 1;
        const body =
          polls === 1
            ? { status: 'queued', phase: 'queued' }
            : polls === 2
              ? { status: 'proving', phase: 'proving' }
              : { status: 'completed', phase: 'completed', result: { success: true } };
        return HttpResponse.json(body, { headers: { 'Retry-After': '0' } });
      }),
    );
    const account = await newAccount();
    const phases: string[] = [];
    const terminal = await account.waitForJob(
      'wj-1',
      new Set(['completed', 'failed', 'cancelled']),
      {
        onPhase: (s) => phases.push(s.phase),
        pollIntervalMs: 0,
      },
    );
    expect(terminal.status).toBe('completed');
    expect(phases).toEqual(['queued', 'proving', 'completed']);
  });

  it('throws JobFailedError on a cancelled terminal', async () => {
    server.use(
      http.get(`${BASE}/api/jobs/wj-2`, () =>
        HttpResponse.json({ status: 'cancelled', phase: 'cancelled' }),
      ),
    );
    const account = await newAccount();
    await expect(
      account.waitForJob('wj-2', new Set(['completed', 'failed', 'cancelled'])),
    ).rejects.toBeInstanceOf(JobFailedError);
  });

  it('times out if the job never reaches a stop status', async () => {
    server.use(
      http.get(`${BASE}/api/jobs/wj-3`, () =>
        HttpResponse.json(
          { status: 'proving', phase: 'proving' },
          { headers: { 'Retry-After': '0' } },
        ),
      ),
    );
    const account = await newAccount();
    await expect(
      account.waitForJob('wj-3', new Set(['completed']), { pollIntervalMs: 0, timeoutMs: 30 }),
    ).rejects.toThrow(/timed out/);
  });

  it('rejects immediately when given an already-aborted signal (loop-top guard)', async () => {
    const account = await newAccount();
    const ctrl = new AbortController();
    ctrl.abort();
    await expect(
      account.waitForJob('wj-pre', new Set(['completed']), { signal: ctrl.signal }),
    ).rejects.toThrow(/aborted/);
  });

  it('rejects when the signal aborts between a poll and the next delay', async () => {
    server.use(
      http.get(`${BASE}/api/jobs/wj-mid`, () =>
        HttpResponse.json(
          { status: 'proving', phase: 'proving' },
          { headers: { 'Retry-After': '0' } },
        ),
      ),
    );
    const account = await newAccount();
    const ctrl = new AbortController();
    // Abort from onPhase: this runs after the poll resolves but before
    // `delay` is reached, so the loop-top guard already passed and the
    // delay sees an already-aborted signal.
    await expect(
      account.waitForJob('wj-mid', new Set(['completed']), {
        signal: ctrl.signal,
        pollIntervalMs: 1_000,
        onPhase: () => ctrl.abort(),
      }),
    ).rejects.toThrow(/aborted/);
  });

  it('aborts when the supplied signal fires during a delay', async () => {
    server.use(
      http.get(`${BASE}/api/jobs/wj-4`, () =>
        HttpResponse.json(
          { status: 'proving', phase: 'proving' },
          { headers: { 'Retry-After': '0' } },
        ),
      ),
    );
    const account = await newAccount();
    const ctrl = new AbortController();
    setTimeout(() => ctrl.abort(), 10);
    await expect(
      account.waitForJob('wj-4', new Set(['completed']), {
        pollIntervalMs: 50,
        signal: ctrl.signal,
      }),
    ).rejects.toThrow(/aborted/);
  });
});

describe('ZkCoinsAccount.getTransactions', () => {
  it('delegates to client.history with this.address', async () => {
    let observedAddress = '';
    server.use(
      http.get(`${BASE}/api/history`, ({ request }) => {
        observedAddress = new URL(request.url).searchParams.get('address') ?? '';
        return HttpResponse.json({ items: [], total: 0, limit: 50, offset: 0 });
      }),
    );
    const account = await newAccount();
    const r = await account.getTransactions({ limit: 5 });
    expect(observedAddress).toBe(account.address);
    expect(r.total).toBe(0);
  });
});

describe('ZkCoinsAccount.claimUsername / resolveUsername', () => {
  it('claimUsername signs a verifying Schnorr signature over sha256(claim message)', async () => {
    let body: { public_key: string; signature: string; timestamp: number } | null = null;
    server.use(
      http.post(`${BASE}/api/username/claim`, async ({ request }) => {
        body = (await request.json()) as typeof body;
        return HttpResponse.json({ username: 'satoshi', address: 'ab' });
      }),
    );
    const account = await newAccount();
    await account.claimUsername('satoshi');
    const b = body as unknown as { public_key: string; signature: string; timestamp: number };
    const msg = buildClaimMessage({
      address: account.address,
      username: 'satoshi',
      timestamp: b.timestamp,
    });
    const digest = sha256(msg);
    const xOnly = hexToBytes(b.public_key).slice(1);
    expect(schnorr.verify(hexToBytes(b.signature), digest, xOnly)).toBe(true);
  });

  it('resolveUsername passes through (no signing)', async () => {
    server.use(
      http.get(`${BASE}/api/username/resolve/:name`, ({ params }) =>
        HttpResponse.json({ username: params.name, address: 'aa' }),
      ),
    );
    const r = await (await newAccount()).resolveUsername('bob');
    expect(r).toEqual({ username: 'bob', address: 'aa' });
  });
});

describe('ZkCoinsAccount numPubkeys persistence', () => {
  it('setNumPubkeys advances the counter (restore-from-num_sends)', async () => {
    const account = await newAccount();
    account.setNumPubkeys(7);
    expect(account.getNumPubkeys()).toBe(7);
  });

  it('setNumPubkeys refuses to go backwards', async () => {
    const account = await newAccount();
    account.setNumPubkeys(5);
    expect(() => account.setNumPubkeys(3)).toThrow(/≥ current/);
  });

  it('setNumPubkeys refuses non-integers', async () => {
    const account = await newAccount();
    expect(() => account.setNumPubkeys(1.5)).toThrow();
  });
});

describe('ZkCoinsAccount.client property', () => {
  it('is the same client passed in', async () => {
    const client = new ZkCoinsClient({ apiUrl: BASE });
    const account = await ZkCoinsAccount.fromMnemonic(TEST_MNEMONIC, 0, { apiUrl: BASE, client });
    expect(account.client).toBe(client);
  });
});
