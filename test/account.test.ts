import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

import { NotImplementedError } from '../src/errors.js';
import { ZkCoinsAccount } from '../src/account.js';
import { ZkCoinsClient } from '../src/client.js';
import { buildClaimMessage, buildSendMessage } from '../src/messages.js';

const BASE = 'https://account.test';
const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const server = setupServer();

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

const newAccount = () =>
  ZkCoinsAccount.fromMnemonic(TEST_MNEMONIC, 0, {
    apiUrl: BASE,
    client: new ZkCoinsClient({ apiUrl: BASE }),
  });

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

  it('rejects a negative accountIndex', async () => {
    await expect(ZkCoinsAccount.fromMnemonic(TEST_MNEMONIC, -1, { apiUrl: BASE })).rejects.toThrow(
      /non-negative integer/,
    );
  });

  it('rejects a non-integer accountIndex', async () => {
    await expect(ZkCoinsAccount.fromMnemonic(TEST_MNEMONIC, 1.5, { apiUrl: BASE })).rejects.toThrow(
      /non-negative integer/,
    );
  });

  it('numPubkeys starts at 0', async () => {
    const account = await newAccount();
    expect(account.getNumPubkeys()).toBe(0);
  });

  it('constructs its own ZkCoinsClient when no override is passed', async () => {
    const account = await ZkCoinsAccount.fromMnemonic(TEST_MNEMONIC, 0, { apiUrl: BASE });
    expect(account.client).toBeInstanceOf(ZkCoinsClient);
  });
});

describe('ZkCoinsAccount.getBalance', () => {
  it('forwards to the underlying client', async () => {
    server.use(
      http.get(`${BASE}/api/balance`, () =>
        HttpResponse.json({ balance: 12345, username: 'satoshi' }),
      ),
    );
    const account = await newAccount();
    const r = await account.getBalance();
    expect(r.balance).toBe(12345);
    expect(r.username).toBe('satoshi');
  });

  it('threads through ApiError on failure', async () => {
    server.use(
      http.get(`${BASE}/api/balance`, () =>
        HttpResponse.json({ success: false, error: 'address not found' }, { status: 404 }),
      ),
    );
    const account = await newAccount();
    await expect(account.getBalance()).rejects.toThrow(/address not found/);
  });
});

describe('ZkCoinsAccount.pay', () => {
  it('refreshes balance before constructing the send (thin-client invariant)', async () => {
    const calls: string[] = [];
    server.use(
      http.get(`${BASE}/api/balance`, () => {
        calls.push('balance');
        return HttpResponse.json({ balance: 10_000 });
      }),
      http.post(`${BASE}/api/send`, () => {
        calls.push('send');
        return HttpResponse.json({ success: true, proof_id: 1 });
      }),
    );
    const account = await newAccount();
    await account.pay('cdef'.padEnd(64, '0'), 100);
    expect(calls).toEqual(['balance', 'send']);
  });

  it('increments numPubkeys on a successful send', async () => {
    server.use(
      http.get(`${BASE}/api/balance`, () => HttpResponse.json({ balance: 10_000 })),
      http.post(`${BASE}/api/send`, () => HttpResponse.json({ success: true, proof_id: 42 })),
    );
    const account = await newAccount();
    expect(account.getNumPubkeys()).toBe(0);
    await account.pay('cdef'.padEnd(64, '0'), 100);
    expect(account.getNumPubkeys()).toBe(1);
    await account.pay('cdef'.padEnd(64, '0'), 200);
    expect(account.getNumPubkeys()).toBe(2);
  });

  it('produces a verifying Schnorr signature against the SHA-256 of the send message', async () => {
    let receivedBody: Record<string, unknown> | null = null;
    server.use(
      http.get(`${BASE}/api/balance`, () => HttpResponse.json({ balance: 10_000 })),
      http.post(`${BASE}/api/send`, async ({ request }) => {
        receivedBody = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json({ success: true });
      }),
    );
    const account = await newAccount();
    const recipient = 'cdef'.padEnd(64, '0');
    await account.pay(recipient, 5_000);

    expect(receivedBody).not.toBeNull();
    const body = receivedBody as unknown as {
      account_address: string;
      recipient: string;
      amount: number;
      public_key: string;
      signature: string;
      timestamp: number;
    };

    // Reconstruct the digest the same way pay() would, and verify
    // against the x-only form of the broadcast pubkey.
    const messageBytes = buildSendMessage({
      accountAddress: body.account_address,
      recipient: body.recipient,
      amount: body.amount,
      timestamp: body.timestamp,
    });
    const digest = sha256(messageBytes);
    const xOnlyPub = hexToBytes(body.public_key).slice(1);
    const ok = schnorr.verify(hexToBytes(body.signature), digest, xOnlyPub);
    expect(ok).toBe(true);
  });

  it('returns PayResult with proof_id and the optional ash/ocr fields', async () => {
    server.use(
      http.get(`${BASE}/api/balance`, () => HttpResponse.json({ balance: 10_000 })),
      http.post(`${BASE}/api/send`, () =>
        HttpResponse.json({
          success: true,
          proof_id: 7,
          account_state_hash: 'aa',
          output_coins_root: 'bb',
        }),
      ),
    );
    const account = await newAccount();
    const r = await account.pay('cdef'.padEnd(64, '0'), 500);
    expect(r.proofId).toBe(7);
    expect(r.accountStateHash).toBe('aa');
    expect(r.outputCoinsRoot).toBe('bb');
  });

  it('does not advance numPubkeys on a failed send', async () => {
    server.use(
      http.get(`${BASE}/api/balance`, () => HttpResponse.json({ balance: 10_000 })),
      http.post(`${BASE}/api/send`, () =>
        HttpResponse.json({ success: false, error: 'insufficient' }, { status: 400 }),
      ),
    );
    const account = await newAccount();
    await expect(account.pay('cdef'.padEnd(64, '0'), 100)).rejects.toThrow(/insufficient/);
    expect(account.getNumPubkeys()).toBe(0);
  });
});

describe('ZkCoinsAccount.claimUsername', () => {
  it('produces a verifying Schnorr signature over sha256(claim message)', async () => {
    let body: { public_key: string; signature: string; timestamp: number } | null = null;
    server.use(
      http.post(`${BASE}/api/username/claim`, async ({ request }) => {
        body = (await request.json()) as typeof body;
        return HttpResponse.json({ username: 'satoshi', address: 'ab' });
      }),
    );
    const account = await newAccount();
    await account.claimUsername('satoshi');

    expect(body).not.toBeNull();
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

  it('returns the parsed UsernameResponse', async () => {
    server.use(
      http.post(`${BASE}/api/username/claim`, () =>
        HttpResponse.json({ username: 'alice', address: 'cd' }),
      ),
    );
    const account = await newAccount();
    const r = await account.claimUsername('alice');
    expect(r).toEqual({ username: 'alice', address: 'cd' });
  });
});

describe('ZkCoinsAccount.resolveUsername', () => {
  it('pass-through; no signing', async () => {
    server.use(
      http.get(`${BASE}/api/username/resolve/:name`, ({ params }) =>
        HttpResponse.json({ username: params.name, address: 'aa' }),
      ),
    );
    const account = await newAccount();
    const r = await account.resolveUsername('bob');
    expect(r).toEqual({ username: 'bob', address: 'aa' });
  });
});

describe('ZkCoinsAccount.getTransactions (issue #153 placeholder)', () => {
  it('throws NotImplementedError', async () => {
    const account = await newAccount();
    await expect(account.getTransactions()).rejects.toThrow(NotImplementedError);
  });

  it('includes the tracking URL', async () => {
    const account = await newAccount();
    try {
      await account.getTransactions();
      throw new Error('expected throw');
    } catch (e) {
      expect((e as NotImplementedError).issueUrl).toBe(
        'https://github.com/zk-coins/node/issues/153',
      );
    }
  });
});

describe('ZkCoinsAccount numPubkeys persistence', () => {
  it('setNumPubkeys advances the counter for restore-from-storage flows', async () => {
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
  it('is the same client passed in (if any)', async () => {
    const client = new ZkCoinsClient({ apiUrl: BASE });
    const account = await ZkCoinsAccount.fromMnemonic(TEST_MNEMONIC, 0, {
      apiUrl: BASE,
      client,
    });
    expect(account.client).toBe(client);
  });
});

describe('ZkCoinsAccount address derivation parity', () => {
  it('address equals sha256(publicKey at index 0) — same contract as Rust', async () => {
    const account = await newAccount();
    // The address is set in the ctor from accountFromSeed(); re-derive
    // the same way as a parity check.
    const recomputed = bytesToHex(
      sha256(
        hexToBytes(
          (
            await (
              await import('../src/derivation.js')
            ).derivePublicKeys(
              // We don't have direct access to the xpriv here; derive
              // again via the helper using the same mnemonic.
              (
                await (
                  await import('../src/derivation.js')
                ).generateAccountKeysFromMnemonic(TEST_MNEMONIC, '')
              ).xpriv,
              0,
            )
          ).publicKey,
        ),
      ),
    );
    expect(account.address).toBe(recomputed);
  });
});
