/**
 * v1 transition client + three pre-sign refusals + pull session.
 *
 * No network: MSW (same pattern as test/client.test.ts). Crypto is real —
 * every signature is verified with verify/commVerify.
 */

import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { hexToBytes } from '@noble/hashes/utils.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { schnorr } from '@noble/curves/secp256k1.js';

import {
  KeyBindingRefusalError,
  ProofDataHashRefusalError,
  NetworkMismatchRefusalError,
  CsprngUnavailableError,
  V1ApiError,
  ZkCoinsV1Client,
  encodeHexLower,
  hashProofData,
  verify,
  commVerify,
  freshNpkRand,
  computeNpkCommit,
  refuseOrSignTransition,
  signBodyFromSignature,
  deriveSpendKey,
  seedFromMnemonicV1,
  encodeZkAddress,
  chanBindForHost,
  pullChallengeMessage,
  PULL_CHALLENGE_DOMAIN,
  buildOwnershipProof,
  transitionRequestToJson,
  assertTransitionRequest,
  type TransitionRequest,
  type AwaitingSignature,
  type ProofData,
  type ZkCoinsV1ClientOptions,
} from '../../src/v1/index.js';

const BASE = 'https://node.test';
const server = setupServer();

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

const newClient = (network: 'testnet' | 'mainnet' | 'regtest' = 'testnet') =>
  new ZkCoinsV1Client({ apiUrl: BASE, network });

function isJsonRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * Prefer the abort signal's own `reason` when it is already an `Error`
 * (what `AbortController.abort()` and the Fetch timeout path produce).
 * Never replace a missing/unknown reason with a generic "aborted" stand-in
 * that would discard the value under test — wrap non-Error reasons so the
 * promise still rejects with an `Error` (prefer-promise-reject-errors).
 */
function abortReasonAsError(signal: AbortSignal): Error {
  const reason: unknown = signal.reason;
  if (reason instanceof Error) {
    return reason;
  }
  return new Error(
    `AbortSignal.reason is not an Error (got ${reason === null ? 'null' : typeof reason}: ${String(reason)})`,
  );
}

// V.8 Signer 1 material — real key that verify/commVerify accept.
const V8_SK1 = hexToBytes('22f508c0a93b29fa87ca8d9abcec996f01620656cd7a7e4ab5418b2e76beccf4');
const V8_PK1 = hexToBytes('e7f2a98e7b45e9424e3e0cb1d937a1698ebd339c6d8344906db979642cf20474');

const V8_PD: ProofData = {
  newAccountStateHash: hexToBytes(
    'f882df3ef57d11032e01c2214525060766250b110b09586cd6cecbed8e3ed4f7',
  ),
  outputCoinsRoot: hexToBytes('0852ae9e41b56cb6320977d06df0b11463919fda0364a5b1cfd3d22358211f24'),
  inputNullifiersRoot: hexToBytes(
    '25af2581385ea1e3688958c7e915c2b46b426daf62536945caaeecc8e3c3a6c6',
  ),
  coinHistoryRoot: hexToBytes('7014c090cbf7eeb37519e4ff815a747384f46943a2b0cc3f4a0094e62cdfaaba'),
  navCommitment: hexToBytes('4dcf2ab90710006a8fe0c9fb0363e5465100858fc0d69155f69db53468e6af7c'),
  npkCommit: hexToBytes('23461051f1c23cf0660eab775049d51ea90bd08c31dabe5cc3d1a0e4767fe259'),
};

function awaitingFromProofData(
  pd: ProofData,
  overrides: Partial<AwaitingSignature> = {},
): AwaitingSignature {
  const base: AwaitingSignature = {
    new_account_state_hash: encodeHexLower(pd.newAccountStateHash),
    output_coins_root: encodeHexLower(pd.outputCoinsRoot),
    input_nullifiers_root: encodeHexLower(pd.inputNullifiersRoot),
    coin_history_root: encodeHexLower(pd.coinHistoryRoot),
    nav_commitment: encodeHexLower(pd.navCommitment),
    npk_commit: encodeHexLower(pd.npkCommit),
    proof_data_hash: encodeHexLower(hashProofData(pd)),
    txn_pubkey: encodeHexLower(V8_PK1),
    send_counter: 0,
  };
  return { ...base, ...overrides };
}

// ---------------------------------------------------------------------------
// Keys (V.2-ext pin)
// ---------------------------------------------------------------------------

describe('v1 SPEND derivation (V.2-ext)', () => {
  it("derives sk₀ / sk₁ at m/1798'/0'/0'/i'", () => {
    const seed = seedFromMnemonicV1(
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
    );
    const sk0 = deriveSpendKey(seed, 0, 0);
    expect(encodeHexLower(sk0.secretKey)).toBe(
      '4a8e3a83404f1aa99e89af57179dcf033820b816c0d78ac94fcb322d6ee85649',
    );
    expect(encodeHexLower(sk0.publicKey)).toBe(
      '7c9cdde9b8cb1e33a48a5c2b6ab1fa6fd753fa1762f56c0b3e8169e4f2d54630',
    );
    const sk1 = deriveSpendKey(seed, 0, 1);
    expect(encodeHexLower(sk1.secretKey)).toBe(
      'c09b2a6301bdc0fef9adb1bd9de4ff77e5a30a28fb11a0dd7a76831708cea7ee',
    );
    expect(encodeHexLower(sk1.publicKey)).toBe(
      '3b471e208d280506b20476e64c1478741bc3a71244d4a3099501f639d54afa6c',
    );
  });
});

// ---------------------------------------------------------------------------
// Presence matrix
// ---------------------------------------------------------------------------

describe('TransitionRequest presence matrix', () => {
  const base = {
    subject: 'zk1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq6gtw5c',
    next_pubkey: 'aa'.repeat(32),
    npk_rand: 'bb'.repeat(32),
  };

  it('serialises a legal send (case a — no publisher)', () => {
    const req: TransitionRequest = {
      kind: 'send',
      ...base,
      input_coins: ['cc'.repeat(32)],
      output_templates: [{ recipient: base.subject, asset_id: 'dd'.repeat(32), amount: '1' }],
    };
    const json = transitionRequestToJson(req);
    expect(json.kind).toBe('send');
    expect(json).not.toHaveProperty('fee_address');
    expect(json).not.toHaveProperty('fold_coin_ids');
    expect(json).not.toHaveProperty('issuance');
  });

  it('serialises a legal send (case c — publisher, no fee)', () => {
    const req: TransitionRequest = {
      kind: 'send',
      ...base,
      publisher_pubkey: 'ee'.repeat(32),
      input_coins: ['cc'.repeat(32)],
      output_templates: [{ recipient: base.subject, asset_id: 'dd'.repeat(32), amount: '1' }],
    };
    const json = transitionRequestToJson(req);
    expect(json.publisher_pubkey).toBe('ee'.repeat(32));
    expect(json).not.toHaveProperty('fee_address');
  });

  it('runtime-rejects fee_address even if forced through a plain object', () => {
    const sneaky: Record<string, unknown> = {
      kind: 'send',
      ...base,
      input_coins: ['cc'.repeat(32)],
      output_templates: [{ recipient: base.subject, asset_id: 'dd'.repeat(32), amount: '1' }],
      fee_address: 'zk1fee',
    };
    expect(() => assertTransitionRequest(sneaky)).toThrow(/fee_address/);
  });

  it('runtime-rejects send with empty input_coins', () => {
    expect(() =>
      assertTransitionRequest({
        kind: 'send',
        ...base,
        input_coins: [],
        output_templates: [{ recipient: base.subject, asset_id: 'dd'.repeat(32), amount: '1' }],
      }),
    ).toThrow(/input_coins/);
  });

  it('runtime-rejects mint without issuance', () => {
    expect(() =>
      assertTransitionRequest({
        kind: 'mint',
        ...base,
        output_templates: [{ recipient: base.subject, asset_id: 'dd'.repeat(32), amount: '1' }],
      }),
    ).toThrow(/issuance/);
  });

  it('runtime-rejects receive without fold_coin_ids', () => {
    expect(() =>
      assertTransitionRequest({
        kind: 'receive',
        ...base,
        fold_coin_ids: [],
      }),
    ).toThrow(/fold_coin_ids/);
  });
});

// Note on typecheck-only matrix cells (not runtime-testable without casts):
//   - fee_address?: never blocks legal construction of case (b)
//   - kind=send forbids fold_coin_ids / issuance at the type level
//   - kind=mint forbids input_coins / fold_coin_ids
//   - kind=receive forbids input_coins / output_templates / issuance

// ---------------------------------------------------------------------------
// npk_rand
// ---------------------------------------------------------------------------

describe('npk_rand CSPRNG', () => {
  it('two draws yield distinct 32-byte values', () => {
    const a = freshNpkRand();
    const b = freshNpkRand();
    expect(a.length).toBe(32);
    expect(b.length).toBe(32);
    expect(encodeHexLower(a)).not.toBe(encodeHexLower(b));
  });

  it('fails closed when getRandomValues is unavailable', () => {
    const orig = globalThis.crypto;
    // Remove CSPRNG for this test only.
    Object.defineProperty(globalThis, 'crypto', {
      configurable: true,
      value: undefined,
    });
    try {
      expect(() => freshNpkRand()).toThrow(CsprngUnavailableError);
    } finally {
      Object.defineProperty(globalThis, 'crypto', {
        configurable: true,
        value: orig,
      });
    }
  });

  it('fails closed when crypto exists but getRandomValues is not a function', () => {
    const orig = globalThis.crypto;
    Object.defineProperty(globalThis, 'crypto', {
      configurable: true,
      value: {},
    });
    try {
      expect(() => freshNpkRand()).toThrow(CsprngUnavailableError);
    } finally {
      Object.defineProperty(globalThis, 'crypto', {
        configurable: true,
        value: orig,
      });
    }
  });
});

// ---------------------------------------------------------------------------
// Three refusals
// ---------------------------------------------------------------------------

describe('pre-sign refusals', () => {
  const nextPubkey = new Uint8Array(32).fill(0x11);
  const npkRand = new Uint8Array(32).fill(0x22);
  // Align V8_PD.npkCommit with the wallet material for the happy/refusal tests
  // that do not specifically target npk_commit.
  const npkCommit = computeNpkCommit(nextPubkey, npkRand);
  const pd: ProofData = { ...V8_PD, npkCommit };
  const accountState = {
    current_pubkey: encodeHexLower(V8_PK1),
    send_counter: 0,
  };

  it('refuses on wrong txn_pubkey (KeyBindingRefusalError)', () => {
    const awaiting = awaitingFromProofData(pd, {
      txn_pubkey: 'ff'.repeat(32),
      npk_commit: encodeHexLower(npkCommit),
      proof_data_hash: encodeHexLower(hashProofData(pd)),
    });
    expect(() =>
      refuseOrSignTransition({
        localPubkey: V8_PK1,
        secretKey: V8_SK1,
        accountState,
        awaiting,
        walletNetwork: 'testnet',
        nextPubkey,
        npkRand,
      }),
    ).toThrow(KeyBindingRefusalError);
  });

  it('refuses when proof_data_hash does not match the six fields', () => {
    const awaiting = awaitingFromProofData(pd, {
      npk_commit: encodeHexLower(npkCommit),
      proof_data_hash: 'aa'.repeat(32), // wrong
    });
    expect(() =>
      refuseOrSignTransition({
        localPubkey: V8_PK1,
        secretKey: V8_SK1,
        accountState,
        awaiting,
        walletNetwork: 'testnet',
        nextPubkey,
        npkRand,
      }),
    ).toThrow(ProofDataHashRefusalError);
  });

  it('refuses on network conflict (wallet testnet vs node mainnet)', () => {
    const awaiting = awaitingFromProofData(pd, {
      npk_commit: encodeHexLower(npkCommit),
      proof_data_hash: encodeHexLower(hashProofData(pd)),
    });
    expect(() =>
      refuseOrSignTransition({
        localPubkey: V8_PK1,
        secretKey: V8_SK1,
        accountState,
        awaiting,
        walletNetwork: 'testnet',
        nodeNetwork: 'mainnet',
        nextPubkey,
        npkRand,
      }),
    ).toThrow(NetworkMismatchRefusalError);
  });

  it('happy path: real signature verifies and opens under CommVerify', () => {
    const awaiting = awaitingFromProofData(pd, {
      npk_commit: encodeHexLower(npkCommit),
      proof_data_hash: encodeHexLower(hashProofData(pd)),
    });
    const sig = refuseOrSignTransition({
      localPubkey: V8_PK1,
      secretKey: V8_SK1,
      accountState,
      awaiting,
      walletNetwork: 'testnet',
      nodeNetwork: 'testnet',
      nextPubkey,
      npkRand,
    });
    expect(sig.signature.length).toBe(64);
    expect(sig.s2cNonce.length).toBe(32);
    expect(
      verify({
        publicKey: V8_PK1,
        signature: sig.signature,
        network: 'testnet',
      }),
    ).toBe(true);
    expect(
      commVerify({
        r: sig.signature.subarray(0, 32),
        mSc: hashProofData(pd),
        rPrime: sig.s2cNonce,
      }),
    ).toBe(true);
    // Wire body uses exact lowercase hex lengths (node signature.rs).
    const body = signBodyFromSignature(sig);
    expect(body.signature).toMatch(/^[0-9a-f]{128}$/);
    expect(body.s2c_nonce).toMatch(/^[0-9a-f]{64}$/);
  });
});

// ---------------------------------------------------------------------------
// End-to-end happy path with MSW
// ---------------------------------------------------------------------------

describe('v1 transition flow (msw)', () => {
  const nextPubkey = new Uint8Array(32).fill(0x11);
  const npkRand = new Uint8Array(32).fill(0x22);
  const npkCommit = computeNpkCommit(nextPubkey, npkRand);
  const pd: ProofData = { ...V8_PD, npkCommit };
  const mSc = hashProofData(pd);
  const awaiting = awaitingFromProofData(pd, {
    npk_commit: encodeHexLower(npkCommit),
    proof_data_hash: encodeHexLower(mSc),
  });

  it('POST /v1/tx → poll Retry-After → awaiting_signature → sign → completed; signature verifies', async () => {
    let signBody: { signature: string; s2c_nonce: string } | undefined;
    let polls = 0;

    server.use(
      http.post(`${BASE}/v1/tx`, async ({ request }) => {
        const raw: unknown = await request.json();
        if (!isJsonRecord(raw)) {
          throw new Error('tx body: expected object');
        }
        expect(raw).not.toHaveProperty('fee_address');
        expect(raw['kind']).toBe('send');
        return HttpResponse.json({ job_id: 'job-1', status: 'accepted' }, { status: 202 });
      }),
      http.get(`${BASE}/v1/jobs/job-1`, () => {
        polls += 1;
        if (polls === 1) {
          return HttpResponse.json(
            {
              job_id: 'job-1',
              kind: 'send',
              status: 'proving',
              progress: 0.4,
            },
            { headers: { 'Retry-After': '0' } },
          );
        }
        return HttpResponse.json(
          {
            job_id: 'job-1',
            kind: 'send',
            status: 'awaiting_signature',
            progress: 0.7,
            awaiting_signature: awaiting,
          },
          { headers: { 'Retry-After': '0' } },
        );
      }),
      http.post(`${BASE}/v1/jobs/job-1/sign`, async ({ request }) => {
        // Runtime check — request.json() is `any`; the assertion below is the
        // load-bearing wire contract (lowercase hex signature + s2c_nonce).
        const raw: unknown = await request.json();
        if (!isJsonRecord(raw)) {
          throw new Error('sign body: expected object');
        }
        const signature = raw['signature'];
        const s2c_nonce = raw['s2c_nonce'];
        if (typeof signature !== 'string' || typeof s2c_nonce !== 'string') {
          throw new Error('sign body: signature and s2c_nonce must be strings');
        }
        signBody = { signature, s2c_nonce };
        return HttpResponse.json({
          job_id: 'job-1',
          kind: 'send',
          status: 'completed',
          progress: 1,
          result: {
            new_account_state_hash: awaiting.new_account_state_hash,
            output_coins_root: awaiting.output_coins_root,
            input_nullifiers_root: awaiting.input_nullifiers_root,
            output_coin_ids: [],
          },
        });
      }),
    );

    const client = newClient('testnet');
    const accepted = await client.submitTransition({
      kind: 'send',
      subject: 'zk1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq6gtw5c',
      next_pubkey: encodeHexLower(nextPubkey),
      npk_rand: encodeHexLower(npkRand),
      input_coins: ['ab'.repeat(32)],
      output_templates: [
        {
          recipient: 'zk1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq6gtw5c',
          asset_id: 'cd'.repeat(32),
          amount: '10',
        },
      ],
    });
    expect(accepted.job_id).toBe('job-1');

    const waited = await client.waitForAwaitingSignature('job-1', {
      sleep: async () => {},
    });
    expect(waited.status).toBe('awaiting_signature');
    expect(waited.awaiting_signature).toBeDefined();

    const { signature, job } = await client.refuseOrSignAndSubmit({
      jobId: 'job-1',
      localPubkey: V8_PK1,
      secretKey: V8_SK1,
      accountState: { current_pubkey: encodeHexLower(V8_PK1), send_counter: 0 },
      awaiting: waited.awaiting_signature!,
      nextPubkey,
      npkRand,
      nodeNetwork: 'testnet',
    });

    expect(job.status).toBe('completed');
    // THE load-bearing assertion: not "looks like 128 hex chars" but Verify + CommVerify.
    expect(
      verify({ publicKey: V8_PK1, signature: signature.signature, network: 'testnet' }),
      'end-to-end signature must Verify under testnet m_state',
    ).toBe(true);
    expect(
      commVerify({
        r: signature.signature.subarray(0, 32),
        mSc,
        rPrime: signature.s2cNonce,
      }),
      'end-to-end S2C opening must CommVerify against pinned ProofData',
    ).toBe(true);
    if (signBody === undefined) {
      throw new Error('sign handler never captured a body');
    }
    expect(signBody.signature).toBe(encodeHexLower(signature.signature));
    expect(signBody.s2c_nonce).toBe(encodeHexLower(signature.s2cNonce));
    expect(polls).toBeGreaterThanOrEqual(2);
  });

  it('SSE yields status (not phase) and ignores diagnostic phase labels', async () => {
    const frames =
      'event: phase\ndata: {"status":"proving","phase":"witness_build","progress":0.2}\n\n' +
      'event: phase\ndata: {"status":"awaiting_signature","phase":"ready_for_wallet","progress":0.5,"awaiting_signature":' +
      JSON.stringify(awaiting) +
      '}\n\n' +
      'event: complete\ndata: {"job_id":"job-s","kind":"send","status":"completed","progress":1,"result":{"output_coin_ids":[]}}\n\n';

    server.use(
      http.get(`${BASE}/v1/jobs/job-s/stream`, () => {
        return new HttpResponse(frames, {
          status: 200,
          headers: { 'Content-Type': 'text/event-stream' },
        });
      }),
    );

    const client = newClient();
    const seen: string[] = [];
    for await (const frame of client.streamJob('job-s')) {
      // Control flow is on status only.
      seen.push(frame.status);
      // phase may be present on the payload but we never require it.
      if (frame.status === 'awaiting_signature') {
        expect(frame.event).toBe('phase'); // event name is structural
      }
    }
    expect(seen).toEqual(['proving', 'awaiting_signature', 'completed']);
  });

  it('cancel posts to /v1/jobs/<id>/cancel', async () => {
    server.use(
      http.post(`${BASE}/v1/jobs/job-c/cancel`, () =>
        HttpResponse.json({
          job_id: 'job-c',
          kind: 'send',
          status: 'cancelled',
          progress: 0,
          error: { error: 'cancelled', message: 'cancelled by client' },
        }),
      ),
    );
    const job = await newClient().cancelJob('job-c');
    expect(job.status).toBe('cancelled');
  });
});

// ---------------------------------------------------------------------------
// Ownership + pull session
// ---------------------------------------------------------------------------

describe('OwnershipProof + pull session', () => {
  // Build a consistent subject = H(Pk0 ‖ nk_commit) with all-zero nk_commit
  // (canonical Goldilocks limbs — same as api ownership tests).
  const seed = seedFromMnemonicV1(
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
  );
  const sk0 = deriveSpendKey(seed, 0, 0);
  const nkCommit = new Uint8Array(32); // zeros
  const subjectRaw = sha256(
    (() => {
      const pre = new Uint8Array(64);
      pre.set(sk0.publicKey, 0);
      pre.set(nkCommit, 32);
      return pre;
    })(),
  );
  const subject = encodeZkAddress(subjectRaw);
  const SESSION_TOKEN = 'opaque-session-secret-do-not-leak-me-please-32b';

  it('chan_bind matches api composition H(PullHost ‖ host)', () => {
    const cb = chanBindForHost('node.test');
    const expected = sha256(new TextEncoder().encode('zkCoins/v1/PullHost' + 'node.test'));
    expect(encodeHexLower(cb)).toBe(encodeHexLower(expected));
  });

  it('OwnershipProof verifies under BIP-340 over pull chal', () => {
    const nonce = new Uint8Array(32).fill(0xaa);
    const expiry = 1_700_000_060n;
    const host = 'node.test';
    const challenge = {
      nonce: encodeHexLower(nonce),
      expiry: expiry.toString(),
      domain: PULL_CHALLENGE_DOMAIN,
    };
    const proof = buildOwnershipProof({
      subject,
      sk0: sk0.secretKey,
      nkCommit,
      challenge,
      host,
    });
    const chal = pullChallengeMessage({
      domain: PULL_CHALLENGE_DOMAIN,
      nonce,
      chanBind: chanBindForHost(host),
      subjectRaw,
      expiry,
    });
    expect(schnorr.verify(hexToBytes(proof.signature), chal, hexToBytes(proof.public_key))).toBe(
      true,
    );
    expect(proof.type).toBe('ownership');
  });

  it('openOwnershipPullSession posts challenge then pull; token never in errors', async () => {
    const nonce = 'aa'.repeat(32);
    const expiry = '1700000060';

    server.use(
      http.post(`${BASE}/v1/pull/challenge`, async ({ request }) => {
        const raw: unknown = await request.json();
        if (!isJsonRecord(raw) || typeof raw['subject'] !== 'string') {
          throw new Error('pull/challenge body: expected { subject: string }');
        }
        expect(raw['subject']).toBe(subject);
        return HttpResponse.json({
          nonce,
          expiry,
          domain: PULL_CHALLENGE_DOMAIN,
        });
      }),
      http.post(`${BASE}/v1/pull`, async ({ request }) => {
        const raw: unknown = await request.json();
        if (!isJsonRecord(raw)) {
          throw new Error('pull body: expected object');
        }
        const proofRaw = raw['proof'];
        if (!isJsonRecord(proofRaw) || typeof proofRaw['signature'] !== 'string') {
          throw new Error('pull body: expected proof.signature string');
        }
        expect(raw['nonce']).toBe(nonce);
        expect(raw['expiry']).toBe(expiry);
        expect(proofRaw['type']).toBe('ownership');
        // Signature must be real hex64.
        expect(proofRaw['signature']).toMatch(/^[0-9a-f]{128}$/);
        return HttpResponse.json({
          records: [],
          session: SESSION_TOKEN,
          session_expiry: '1700001000',
        });
      }),
      http.get(`${BASE}/v1/account/state`, ({ request }) => {
        const auth = request.headers.get('Authorization');
        expect(auth).toBe(`Bearer ${SESSION_TOKEN}`);
        // Simulate session_expired with a body that would leak the token if
        // the client echoed the Authorization header into the error.
        return HttpResponse.json(
          {
            error: 'session_expired',
            message: `session unknown (presented Authorization would be Bearer ${SESSION_TOKEN})`,
          },
          { status: 410 },
        );
      }),
    );

    const client = newClient();
    const pull = await client.openOwnershipPullSession({
      subject,
      sk0: sk0.secretKey,
      nkCommit,
    });
    expect(pull.session).toBe(SESSION_TOKEN);

    try {
      await client.getAccountState(SESSION_TOKEN);
      expect.unreachable('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(V1ApiError);
      const e = err as V1ApiError;
      expect(e.isSessionExpired()).toBe(true);
      expect(e.isUnauthorized()).toBe(false);
      expect(e.isChallengeExpired()).toBe(false);
      // Token must not appear in the error surface.
      expect(e.message).not.toContain(SESSION_TOKEN);
      expect(e.rawBody ?? '').not.toContain(SESSION_TOKEN);
      expect(String(e)).not.toContain(SESSION_TOKEN);
    }
  });

  it('distinguishes 401 unauthorized from 410 challenge_expired', async () => {
    server.use(
      http.get(`${BASE}/v1/account/state`, () =>
        HttpResponse.json(
          { error: 'unauthorized', message: 'missing Authorization bearer token' },
          { status: 401 },
        ),
      ),
      http.post(`${BASE}/v1/pull`, () =>
        HttpResponse.json(
          { error: 'challenge_expired', message: 'nonce unknown or expired' },
          { status: 410 },
        ),
      ),
    );
    const client = newClient();
    try {
      await client.getAccountState('some-token');
      expect.unreachable('expected 401');
    } catch (err) {
      expect(err).toBeInstanceOf(V1ApiError);
      expect((err as V1ApiError).isUnauthorized()).toBe(true);
      expect((err as V1ApiError).isSessionExpired()).toBe(false);
      expect((err as V1ApiError).isChallengeExpired()).toBe(false);
      expect((err as V1ApiError).message).not.toContain('some-token');
    }
    try {
      await client.openPullSession({
        challenge: {
          nonce: 'aa'.repeat(32),
          expiry: '1',
          domain: PULL_CHALLENGE_DOMAIN,
        },
        proof: {
          type: 'ownership',
          subject,
          public_key: encodeHexLower(sk0.publicKey),
          nk_commit: encodeHexLower(nkCommit),
          signature: 'ab'.repeat(64),
        },
      });
      expect.unreachable('expected 410 challenge_expired');
    } catch (err) {
      expect(err).toBeInstanceOf(V1ApiError);
      expect((err as V1ApiError).isChallengeExpired()).toBe(true);
      expect((err as V1ApiError).isSessionExpired()).toBe(false);
      expect((err as V1ApiError).isUnauthorized()).toBe(false);
    }
  });

  it('410 session_expired is not challenge_expired and not unauthorized', async () => {
    server.use(
      http.get(`${BASE}/v1/account/state`, () =>
        HttpResponse.json(
          { error: 'session_expired', message: 'pull session unknown' },
          { status: 410 },
        ),
      ),
    );
    try {
      await newClient().getAccountState('tok-session');
      expect.unreachable('expected 410 session_expired');
    } catch (err) {
      expect(err).toBeInstanceOf(V1ApiError);
      if (!(err instanceof V1ApiError)) throw err;
      expect(err.status).toBe(410);
      expect(err.machineCode).toBe('session_expired');
      expect(err.isSessionExpired()).toBe(true);
      expect(err.isChallengeExpired()).toBe(false);
      expect(err.isUnauthorized()).toBe(false);
    }
  });

  it('401 with a non-unauthorized machine code is not isUnauthorized()', async () => {
    // Status alone is not enough — machineCode must match too.
    server.use(
      http.get(`${BASE}/v1/account/state`, () =>
        HttpResponse.json({ error: 'forbidden', message: 'nope' }, { status: 401 }),
      ),
    );
    try {
      await newClient().getAccountState('tok');
      expect.unreachable('expected 401');
    } catch (err) {
      expect(err).toBeInstanceOf(V1ApiError);
      if (!(err instanceof V1ApiError)) throw err;
      expect(err.status).toBe(401);
      expect(err.machineCode).toBe('forbidden');
      expect(err.isUnauthorized()).toBe(false);
    }
  });
});

// ---------------------------------------------------------------------------
// Constructor fail-closed
// ---------------------------------------------------------------------------

describe('ZkCoinsV1Client constructor', () => {
  it('requires apiUrl with scheme and a closed network', () => {
    expect(() => new ZkCoinsV1Client({ apiUrl: '', network: 'testnet' })).toThrow(/apiUrl/);
    expect(() => new ZkCoinsV1Client({ apiUrl: 'node.test', network: 'testnet' })).toThrow(
      /http:\/\/ or https:\/\//,
    );
    // Plain-JS callers can put any string in `network`; overwrite at runtime
    // without widening the TypeScript type to `any`.
    const opts: ZkCoinsV1ClientOptions = { apiUrl: BASE, network: 'testnet' };
    const raw: unknown = JSON.parse('"mutinynet"');
    if (typeof raw !== 'string') {
      throw new Error('fixture: expected JSON string for bad network');
    }
    Reflect.set(opts, 'network', raw);
    expect(() => new ZkCoinsV1Client(opts)).toThrow(/network/);
  });

  it('derives host for chan_bind from apiUrl', () => {
    const c = new ZkCoinsV1Client({ apiUrl: 'https://node.example.com:8443/', network: 'regtest' });
    expect(c.host).toBe('node.example.com:8443');
    expect(c.apiUrl).toBe('https://node.example.com:8443');
  });
});

// ---------------------------------------------------------------------------
// Client parsers, empty ids, SSE errors, info, account state
// ---------------------------------------------------------------------------

describe('ZkCoinsV1Client request surface', () => {
  it('info() parses a closed network and features list', async () => {
    server.use(
      http.get(`${BASE}/v1/info`, () =>
        HttpResponse.json({
          network: 'testnet',
          protocol_version: '1',
          features: ['pull', 'half_agg'],
          extra: true,
        }),
      ),
    );
    const info = await newClient().info();
    expect(info.network).toBe('testnet');
    expect(info.protocol_version).toBe('1');
    expect(info.features).toEqual(['pull', 'half_agg']);
    expect(info.extra).toBe(true);
  });

  it('info() rejects network outside the closed set and non-string features', async () => {
    server.use(
      http.get(`${BASE}/v1/info`, () =>
        HttpResponse.json({ network: 'mutinynet', protocol_version: '1', features: [] }),
      ),
    );
    await expect(newClient().info()).rejects.toThrow(/Info\.network outside closed set/);

    server.use(
      http.get(`${BASE}/v1/info`, () =>
        HttpResponse.json({ network: 'testnet', protocol_version: '1', features: [1] }),
      ),
    );
    await expect(newClient().info()).rejects.toThrow(/Info\.features\[0\]: expected string/);

    server.use(
      http.get(`${BASE}/v1/info`, () =>
        HttpResponse.json({ network: 'testnet', protocol_version: '1', features: 'nope' }),
      ),
    );
    await expect(newClient().info()).rejects.toThrow(/Info\.features: expected array/);
  });

  it('submitTransition forwards Idempotency-Key when provided', async () => {
    let seen: string | null = null;
    server.use(
      http.post(`${BASE}/v1/tx`, ({ request }) => {
        seen = request.headers.get('Idempotency-Key');
        return HttpResponse.json({ job_id: 'j', status: 'accepted' }, { status: 202 });
      }),
    );
    await newClient().submitTransition(
      {
        kind: 'receive',
        subject: 'zk1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq6gtw5c',
        next_pubkey: 'aa'.repeat(32),
        npk_rand: 'bb'.repeat(32),
        fold_coin_ids: ['cc'.repeat(32)],
      },
      { idempotencyKey: 'idem-1' },
    );
    expect(seen).toBe('idem-1');
  });

  it('getJob / signJob / cancelJob / streamJob reject empty job_id', async () => {
    const c = newClient();
    await expect(c.getJob('')).rejects.toThrow(/job_id must not be empty/);
    await expect(
      c.signJob('', { signature: 'aa'.repeat(64), s2c_nonce: 'bb'.repeat(32) }),
    ).rejects.toThrow(/job_id must not be empty/);
    await expect(c.cancelJob('')).rejects.toThrow(/job_id must not be empty/);
    await expect(async () => {
      for await (const _ of c.streamJob('')) {
        // never
      }
    }).rejects.toThrow(/job_id must not be empty/);
  });

  it('getJob rejects a non-canonical Retry-After header', async () => {
    server.use(
      http.get(`${BASE}/v1/jobs/j1`, () =>
        HttpResponse.json(
          { job_id: 'j1', kind: 'send', status: 'proving', progress: 0.1 },
          { headers: { 'Retry-After': '1.5' } },
        ),
      ),
    );
    await expect(newClient().getJob('j1')).rejects.toThrow(/non-canonical Retry-After/);
  });

  it('getJob parses phase, completed result fields, and failed error body', async () => {
    server.use(
      http.get(`${BASE}/v1/jobs/done`, () =>
        HttpResponse.json({
          job_id: 'done',
          kind: 'send',
          status: 'completed',
          phase: 'published',
          progress: 1,
          result: {
            new_account_state_hash: '11'.repeat(32),
            output_coins_root: '22'.repeat(32),
            input_nullifiers_root: '33'.repeat(32),
            publisher_pubkey: '44'.repeat(32),
            attestation: 'att',
            output_coin_ids: ['55'.repeat(32)],
          },
        }),
      ),
      http.get(`${BASE}/v1/jobs/fail`, () =>
        HttpResponse.json({
          job_id: 'fail',
          kind: 'send',
          status: 'failed',
          progress: 0,
          error: { error: 'prove_failed', message: 'circuit rejected' },
        }),
      ),
    );
    const done = await newClient().getJob('done');
    expect(done.job.phase).toBe('published');
    expect(done.job.result?.output_coin_ids).toEqual(['55'.repeat(32)]);
    expect(done.job.result?.publisher_pubkey).toBe('44'.repeat(32));
    expect(done.job.result?.attestation).toBe('att');
    expect(done.retryAfterMs).toBeNull();

    const fail = await newClient().getJob('fail');
    expect(fail.job.status).toBe('failed');
    expect(fail.job.error).toEqual({ error: 'prove_failed', message: 'circuit rejected' });
  });

  it('getJob rejects awaiting_signature without payload and unknown status', async () => {
    server.use(
      http.get(`${BASE}/v1/jobs/bad-await`, () =>
        HttpResponse.json({
          job_id: 'bad-await',
          kind: 'send',
          status: 'awaiting_signature',
          progress: 0.5,
        }),
      ),
    );
    await expect(newClient().getJob('bad-await')).rejects.toThrow(
      /awaiting_signature but payload is absent/,
    );

    server.use(
      http.get(`${BASE}/v1/jobs/weird`, () =>
        HttpResponse.json({
          job_id: 'weird',
          kind: 'send',
          status: 'queued',
          progress: 0,
        }),
      ),
    );
    await expect(newClient().getJob('weird')).rejects.toThrow(/job\.status outside closed set/);
  });

  it('getJob rejects non-string coin ids and non-object result', async () => {
    server.use(
      http.get(`${BASE}/v1/jobs/bad-coins`, () =>
        HttpResponse.json({
          job_id: 'bad-coins',
          kind: 'send',
          status: 'completed',
          progress: 1,
          result: { output_coin_ids: [1] },
        }),
      ),
    );
    await expect(newClient().getJob('bad-coins')).rejects.toThrow(
      /output_coin_ids\[0\]: expected string/,
    );
  });

  it('waitForAwaitingSignature returns terminal jobs and fails closed without Retry-After', async () => {
    server.use(
      http.get(`${BASE}/v1/jobs/term`, () =>
        HttpResponse.json({
          job_id: 'term',
          kind: 'send',
          status: 'cancelled',
          progress: 0,
          error: { error: 'cancelled', message: 'bye' },
        }),
      ),
    );
    const term = await newClient().waitForAwaitingSignature('term', { sleep: async () => {} });
    expect(term.status).toBe('cancelled');

    server.use(
      http.get(`${BASE}/v1/jobs/stuck`, () =>
        HttpResponse.json({
          job_id: 'stuck',
          kind: 'send',
          status: 'proving',
          progress: 0.2,
        }),
      ),
    );
    await expect(
      newClient().waitForAwaitingSignature('stuck', { sleep: async () => {} }),
    ).rejects.toThrow(/without Retry-After/);
  });

  it('waitForAwaitingSignature aborts when the signal is already aborted', async () => {
    const ac = new AbortController();
    ac.abort();
    await expect(
      newClient().waitForAwaitingSignature('x', { signal: ac.signal, sleep: async () => {} }),
    ).rejects.toThrow(/aborted/);
  });

  it('streamJob fails closed on HTTP error and missing body', async () => {
    server.use(
      http.get(`${BASE}/v1/jobs/sse-err/stream`, () =>
        HttpResponse.json({ error: 'not_found', message: 'no job' }, { status: 404 }),
      ),
    );
    await expect(async () => {
      for await (const _ of newClient().streamJob('sse-err')) {
        // never
      }
    }).rejects.toBeInstanceOf(V1ApiError);

    // Node's Response always exposes a body stream for empty payloads; force
    // body === null so the streamJob guard is exercised.
    const client = new ZkCoinsV1Client({
      apiUrl: BASE,
      network: 'testnet',
      fetch: async () => {
        const res = new Response('', {
          status: 200,
          headers: { 'Content-Type': 'text/event-stream' },
        });
        Object.defineProperty(res, 'body', { configurable: true, get: () => null });
        return res;
      },
    });
    await expect(async () => {
      for await (const _ of client.streamJob('sse-nobody')) {
        // never
      }
    }).rejects.toThrow(/no readable body for SSE/);
  });

  it("streamJob aborts when the caller's signal is already aborted", async () => {
    const ac = new AbortController();
    ac.abort();
    await expect(async () => {
      for await (const _ of newClient().streamJob('x', ac.signal)) {
        // never
      }
    }).rejects.toThrow();
  });

  it('streamJob skips comment/empty frames and stops on failed', async () => {
    const frames =
      ': keep-alive\n\n' +
      'event: phase\ndata: {"status":"proving","progress":0.1}\n\n' +
      'event: error\ndata: {"job_id":"f","kind":"send","status":"failed","progress":0,"error":{"error":"x","message":"y"}}\n\n';
    server.use(
      http.get(
        `${BASE}/v1/jobs/f/stream`,
        () =>
          new HttpResponse(frames, {
            status: 200,
            headers: { 'Content-Type': 'text/event-stream' },
          }),
      ),
    );
    const seen: string[] = [];
    for await (const frame of newClient().streamJob('f')) {
      seen.push(frame.status);
    }
    expect(seen).toEqual(['proving', 'failed']);
  });

  it('openPullChallenge rejects empty subject and wrong domain', async () => {
    await expect(newClient().openPullChallenge('')).rejects.toThrow(/subject is required/);
    server.use(
      http.post(`${BASE}/v1/pull/challenge`, () =>
        HttpResponse.json({
          nonce: 'aa'.repeat(32),
          expiry: '1',
          domain: 'zkCoins/v1/Wrong',
        }),
      ),
    );
    await expect(newClient().openPullChallenge('zk1x')).rejects.toThrow(/PullChallenge\.domain/);
  });

  it('getAccountState requires a token and parses optional fields', async () => {
    await expect(newClient().getAccountState('')).rejects.toThrow(/session token is required/);
    server.use(
      http.get(`${BASE}/v1/account/state`, () =>
        HttpResponse.json({
          account_state: 'aa'.repeat(32),
          state_head: 'bb'.repeat(32),
          head_record_id: 'rec-1',
          send_counter: 3,
          current_pubkey: 'cc'.repeat(32),
          last_nullifier: { pubkey: 'dd'.repeat(32), r: 'ee'.repeat(32) },
        }),
      ),
    );
    const state = await newClient().getAccountState('tok');
    expect(state.send_counter).toBe(3);
    expect(state.head_record_id).toBe('rec-1');
    expect(state.last_nullifier).toEqual({ pubkey: 'dd'.repeat(32), r: 'ee'.repeat(32) });
  });

  it('getAccountState rejects a malformed last_nullifier', async () => {
    server.use(
      http.get(`${BASE}/v1/account/state`, () =>
        HttpResponse.json({
          account_state: 'aa'.repeat(32),
          state_head: 'bb'.repeat(32),
          send_counter: 0,
          current_pubkey: 'cc'.repeat(32),
          last_nullifier: 'nope',
        }),
      ),
    );
    await expect(newClient().getAccountState('tok')).rejects.toThrow(
      /last_nullifier: expected object/,
    );
  });

  it('openPullSession rejects empty session and non-array records', async () => {
    server.use(
      http.post(`${BASE}/v1/pull`, () =>
        HttpResponse.json({
          records: [],
          session: '',
          session_expiry: '1',
        }),
      ),
    );
    await expect(
      newClient().openPullSession({
        challenge: { nonce: 'aa'.repeat(32), expiry: '1', domain: PULL_CHALLENGE_DOMAIN },
        proof: {
          type: 'ownership',
          subject: 'zk1x',
          public_key: 'aa'.repeat(32),
          nk_commit: 'bb'.repeat(32),
          signature: 'cc'.repeat(64),
        },
      }),
    ).rejects.toThrow(/session is empty/);

    server.use(
      http.post(`${BASE}/v1/pull`, () =>
        HttpResponse.json({
          records: 'nope',
          session: 'tok',
          session_expiry: '1',
        }),
      ),
    );
    await expect(
      newClient().openPullSession({
        challenge: { nonce: 'aa'.repeat(32), expiry: '1', domain: PULL_CHALLENGE_DOMAIN },
        proof: {
          type: 'ownership',
          subject: 'zk1x',
          public_key: 'aa'.repeat(32),
          nk_commit: 'bb'.repeat(32),
          signature: 'cc'.repeat(64),
        },
      }),
    ).rejects.toThrow(/records: expected array/);
  });

  it('openPullSession parses records with optional transition_kind', async () => {
    server.use(
      http.post(`${BASE}/v1/pull`, () =>
        HttpResponse.json({
          records: [
            {
              record_id: 'r1',
              record_type: 'transition',
              transition_kind: 'send',
              blob_id: 'b1',
              occurred_at: '2020-01-01T00:00:00Z',
            },
          ],
          session: 'session-tok',
          session_expiry: '99',
        }),
      ),
    );
    const pull = await newClient().openPullSession({
      challenge: { nonce: 'aa'.repeat(32), expiry: '1', domain: PULL_CHALLENGE_DOMAIN },
      proof: {
        type: 'ownership',
        subject: 'zk1x',
        public_key: 'aa'.repeat(32),
        nk_commit: 'bb'.repeat(32),
        signature: 'cc'.repeat(64),
      },
    });
    expect(pull.records[0]?.transition_kind).toBe('send');
    expect(pull.session).toBe('session-tok');
  });

  it('non-JSON error bodies keep the raw text and default machineCode', async () => {
    server.use(
      http.get(`${BASE}/v1/info`, () => new HttpResponse('upstream blew up', { status: 502 })),
    );
    try {
      await newClient().info();
      expect.unreachable('expected 502');
    } catch (err) {
      expect(err).toBeInstanceOf(V1ApiError);
      if (!(err instanceof V1ApiError)) throw err;
      expect(err.status).toBe(502);
      expect(err.machineCode).toBe('internal_error');
      expect(err.message).toMatch(/upstream blew up/);
    }
  });

  it('empty 2xx body parses as an empty object (JobAccepted then fails on fields)', async () => {
    server.use(http.post(`${BASE}/v1/tx`, () => new HttpResponse('', { status: 202 })));
    await expect(
      newClient().submitTransition({
        kind: 'receive',
        subject: 'zk1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq6gtw5c',
        next_pubkey: 'aa'.repeat(32),
        npk_rand: 'bb'.repeat(32),
        fold_coin_ids: ['cc'.repeat(32)],
      }),
    ).rejects.toThrow(/response\.job_id: expected string/);
  });

  it('getAccountState rethrows non-V1ApiError from fetch', async () => {
    const client = new ZkCoinsV1Client({
      apiUrl: BASE,
      network: 'testnet',
      fetch: async () => {
        throw new TypeError('network down');
      },
    });
    await expect(client.getAccountState('tok')).rejects.toThrow(/network down/);
  });

  it('JobAccepted rejects a non-accepted status', async () => {
    server.use(
      http.post(`${BASE}/v1/tx`, () =>
        HttpResponse.json({ job_id: 'j', status: 'proving' }, { status: 202 }),
      ),
    );
    await expect(
      newClient().submitTransition({
        kind: 'receive',
        subject: 'zk1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq6gtw5c',
        next_pubkey: 'aa'.repeat(32),
        npk_rand: 'bb'.repeat(32),
        fold_coin_ids: ['cc'.repeat(32)],
      }),
    ).rejects.toThrow(/JobAccepted\.status must be "accepted"/);
  });

  it('request paths honour an already-aborted AbortSignal', async () => {
    const ac = new AbortController();
    ac.abort();
    await expect(newClient().info(ac.signal)).rejects.toThrow();
  });

  it('SSE frame with multi-line data is concatenated before JSON parse', async () => {
    // Two data: lines in one frame (SSE multi-line data) still yield one event.
    const frames =
      'event: phase\n' +
      'data: {"status":"completed","job_id":"m","kind":"send","progress":1,\n' +
      'data: "result":{"output_coin_ids":[]}}\n\n';
    server.use(
      http.get(
        `${BASE}/v1/jobs/m/stream`,
        () =>
          new HttpResponse(frames, {
            status: 200,
            headers: { 'Content-Type': 'text/event-stream' },
          }),
      ),
    );
    const seen: string[] = [];
    for await (const frame of newClient().streamJob('m')) {
      seen.push(frame.status);
    }
    expect(seen).toEqual(['completed']);
  });

  it('SSE rejects a payload without a status string', async () => {
    server.use(
      http.get(
        `${BASE}/v1/jobs/nostatus/stream`,
        () =>
          new HttpResponse('data: {"progress":0.1}\n\n', {
            status: 200,
            headers: { 'Content-Type': 'text/event-stream' },
          }),
      ),
    );
    await expect(async () => {
      for await (const _ of newClient().streamJob('nostatus')) {
        // never
      }
    }).rejects.toThrow(/missing status string/);
  });

  it('openPullSession rejects a non-object record entry', async () => {
    server.use(
      http.post(`${BASE}/v1/pull`, () =>
        HttpResponse.json({
          records: [null],
          session: 'tok',
          session_expiry: '1',
        }),
      ),
    );
    await expect(
      newClient().openPullSession({
        challenge: { nonce: 'aa'.repeat(32), expiry: '1', domain: PULL_CHALLENGE_DOMAIN },
        proof: {
          type: 'ownership',
          subject: 'zk1x',
          public_key: 'aa'.repeat(32),
          nk_commit: 'bb'.repeat(32),
          signature: 'cc'.repeat(64),
        },
      }),
    ).rejects.toThrow(/records\[0\]: expected object/);
  });

  it('info rejects a non-object body', async () => {
    server.use(http.get(`${BASE}/v1/info`, () => HttpResponse.json([1, 2, 3])));
    await expect(newClient().info()).rejects.toThrow(/Info: expected object/);
  });

  it('requireNumber rejects non-finite progress', async () => {
    server.use(
      http.get(`${BASE}/v1/jobs/bad-progress`, () =>
        HttpResponse.json({
          job_id: 'bad-progress',
          kind: 'send',
          status: 'proving',
          progress: 'half',
        }),
      ),
    );
    await expect(newClient().getJob('bad-progress')).rejects.toThrow(
      /response\.progress: expected finite number/,
    );

    // Raw body so the wire carries a JSON null (JSON.stringify(NaN) → null).
    server.use(
      http.get(
        `${BASE}/v1/jobs/null-progress`,
        () =>
          new HttpResponse(
            JSON.stringify({
              job_id: 'null-progress',
              kind: 'send',
              status: 'proving',
              progress: null,
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          ),
      ),
    );
    await expect(newClient().getJob('null-progress')).rejects.toThrow(
      /response\.progress: expected finite number/,
    );
  });

  it('getJob rejects completed result without an output_coin_ids array', async () => {
    server.use(
      http.get(`${BASE}/v1/jobs/no-coins`, () =>
        HttpResponse.json({
          job_id: 'no-coins',
          kind: 'send',
          status: 'completed',
          progress: 1,
          result: { new_account_state_hash: '11'.repeat(32) },
        }),
      ),
    );
    await expect(newClient().getJob('no-coins')).rejects.toThrow(/output_coin_ids: expected array/);
  });

  it('requestJsonWithHeaders registers a live AbortSignal and aborts in flight', async () => {
    server.use(
      http.get(`${BASE}/v1/info`, async () => {
        await new Promise<void>((resolve) => setTimeout(resolve, 80));
        return HttpResponse.json({
          network: 'testnet',
          protocol_version: '1',
          features: [],
        });
      }),
    );
    const ac = new AbortController();
    const pending = newClient().info(ac.signal);
    // Non-aborted signal at call time → addEventListener branch; then abort.
    await new Promise<void>((resolve) => setTimeout(resolve, 10));
    ac.abort();
    await expect(pending).rejects.toThrow();
  });

  it('streamJob registers a live AbortSignal and aborts mid-stream', async () => {
    // Real fetch cancels the response body when the request AbortSignal fires
    // after the Response is already handed back. A mock that ignores
    // `init.signal` and later enqueues a frame measures delivery timing, not
    // abort. Wire the body to the signal the client passes into fetch.
    const abortableStream = (sig: AbortSignal): ReadableStream<Uint8Array> =>
      new ReadableStream<Uint8Array>({
        start(controller) {
          if (sig.aborted) {
            controller.error(abortReasonAsError(sig));
            return;
          }
          sig.addEventListener(
            'abort',
            () => {
              controller.error(abortReasonAsError(sig));
            },
            { once: true },
          );
        },
      });

    const client = new ZkCoinsV1Client({
      apiUrl: BASE,
      network: 'testnet',
      fetch: async (_input, init) => {
        const signal = init?.signal;
        if (signal === undefined || signal === null) {
          throw new Error('streamJob fetch expected AbortSignal');
        }
        return new Response(abortableStream(signal), {
          status: 200,
          headers: { 'Content-Type': 'text/event-stream' },
        });
      },
    });
    const ac = new AbortController();
    const iter = client.streamJob('live-abort', ac.signal);
    const pending = iter.next();
    // Generator has attached the abort listener and is awaiting reader.read().
    await new Promise<void>((resolve) => setTimeout(resolve, 10));
    ac.abort();
    await expect(pending).rejects.toThrow();
  });

  it('request timeout aborts a hung fetch (covers timeout callbacks)', async () => {
    const hangUntilAbort = async (init: RequestInit | undefined): Promise<never> => {
      await new Promise<void>((_resolve, reject) => {
        const signal = init?.signal;
        if (signal === undefined || signal === null) {
          reject(new Error('expected AbortSignal on hung fetch'));
          return;
        }
        const rejectAborted = (): void => {
          reject(abortReasonAsError(signal));
        };
        if (signal.aborted) {
          rejectAborted();
          return;
        }
        signal.addEventListener('abort', rejectAborted, { once: true });
      });
      throw new Error('unreachable');
    };

    const jsonClient = new ZkCoinsV1Client({
      apiUrl: BASE,
      network: 'testnet',
      requestTimeoutMs: 20,
      fetch: async (_input, init) => hangUntilAbort(init),
    });
    await expect(jsonClient.info()).rejects.toThrow();

    // Same timeout arm on the SSE path (streamJob's setTimeout callback).
    const streamClient = new ZkCoinsV1Client({
      apiUrl: BASE,
      network: 'testnet',
      requestTimeoutMs: 20,
      fetch: async (_input, init) => hangUntilAbort(init),
    });
    await expect(async () => {
      for await (const _ of streamClient.streamJob('timeout-sse')) {
        // never
      }
    }).rejects.toThrow();
  });

  it('waitForAwaitingSignature uses the default sleep when Retry-After is present', async () => {
    let polls = 0;
    server.use(
      http.get(`${BASE}/v1/jobs/sleep-default`, () => {
        polls += 1;
        if (polls === 1) {
          return HttpResponse.json(
            {
              job_id: 'sleep-default',
              kind: 'send',
              status: 'proving',
              progress: 0.1,
            },
            { headers: { 'Retry-After': '0' } },
          );
        }
        return HttpResponse.json({
          job_id: 'sleep-default',
          kind: 'send',
          status: 'awaiting_signature',
          progress: 0.9,
          awaiting_signature: {
            new_account_state_hash: '11'.repeat(32),
            output_coins_root: '22'.repeat(32),
            input_nullifiers_root: '33'.repeat(32),
            coin_history_root: '44'.repeat(32),
            nav_commitment: '55'.repeat(32),
            npk_commit: '66'.repeat(32),
            proof_data_hash: '77'.repeat(32),
            txn_pubkey: '88'.repeat(32),
            send_counter: 0,
          },
        });
      }),
    );
    // No custom `sleep` — exercises the default setTimeout path.
    const job = await newClient().waitForAwaitingSignature('sleep-default');
    expect(job.status).toBe('awaiting_signature');
    expect(polls).toBeGreaterThanOrEqual(2);
  });
});

// ---------------------------------------------------------------------------
// Defensive parser arms — non-object 2xx bodies + truncated SSE
// ---------------------------------------------------------------------------

/**
 * Assert that `run` rejects with a plain `Error` whose message is exactly
 * `message`. Checks type and cause — not a bare `toThrow()` regex match.
 */
async function expectExactError(run: () => Promise<unknown>, message: string): Promise<void> {
  try {
    await run();
    expect.unreachable(`expected Error(${JSON.stringify(message)})`);
  } catch (err) {
    expect(err).toBeInstanceOf(Error);
    if (!(err instanceof Error)) throw err;
    expect(err.name).toBe('Error');
    expect(err.message).toBe(message);
  }
}

const RECEIVE_TX: TransitionRequest = {
  kind: 'receive',
  subject: 'zk1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq6gtw5c',
  next_pubkey: 'aa'.repeat(32),
  npk_rand: 'bb'.repeat(32),
  fold_coin_ids: ['cc'.repeat(32)],
};

const DUMMY_OWNERSHIP_PROOF = {
  type: 'ownership' as const,
  subject: 'zk1x',
  public_key: 'aa'.repeat(32),
  nk_commit: 'bb'.repeat(32),
  signature: 'cc'.repeat(64),
};

const DUMMY_CHALLENGE = {
  nonce: 'aa'.repeat(32),
  expiry: '1',
  domain: PULL_CHALLENGE_DOMAIN,
};

describe('ZkCoinsV1Client fail-closed parsers (non-object wire bodies)', () => {
  it('parseJobAccepted: array body (proxy/malformed 202)', async () => {
    // JSON array is valid JSON but not a job-accepted object — a broken edge
    // or intermediate proxy might wrap the payload this way.
    server.use(http.post(`${BASE}/v1/tx`, () => HttpResponse.json(['accepted'])));
    await expectExactError(
      () => newClient().submitTransition(RECEIVE_TX),
      'JobAccepted: expected object',
    );
  });

  it('parseJob: null body on GET job', async () => {
    server.use(
      http.get(
        `${BASE}/v1/jobs/null-job`,
        () =>
          new HttpResponse('null', {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          }),
      ),
    );
    await expectExactError(() => newClient().getJob('null-job'), 'job: expected object');
  });

  it('parseAwaitingSignature: awaiting_signature is a string, not an object', async () => {
    server.use(
      http.get(`${BASE}/v1/jobs/await-str`, () =>
        HttpResponse.json({
          job_id: 'await-str',
          kind: 'send',
          status: 'awaiting_signature',
          progress: 0.5,
          // Real corruption: field present but wrong JSON type (string instead of object).
          awaiting_signature: 'not-an-object',
        }),
      ),
    );
    await expectExactError(
      () => newClient().getJob('await-str'),
      'awaiting_signature: expected object',
    );
  });

  it('parseJob result: completed.result is an array, not an object', async () => {
    server.use(
      http.get(`${BASE}/v1/jobs/result-arr`, () =>
        HttpResponse.json({
          job_id: 'result-arr',
          kind: 'send',
          status: 'completed',
          progress: 1,
          result: ['coin-a'],
        }),
      ),
    );
    await expectExactError(() => newClient().getJob('result-arr'), 'job.result: expected object');
  });

  it('parseJob error: failed.error is a number, not an object', async () => {
    server.use(
      http.get(`${BASE}/v1/jobs/err-num`, () =>
        HttpResponse.json({
          job_id: 'err-num',
          kind: 'send',
          status: 'failed',
          progress: 0,
          error: 500,
        }),
      ),
    );
    await expectExactError(() => newClient().getJob('err-num'), 'job.error: expected object');
  });

  it('parsePullChallenge: string body on challenge endpoint', async () => {
    server.use(
      http.post(
        `${BASE}/v1/pull/challenge`,
        () =>
          new HttpResponse(JSON.stringify('challenge-please'), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          }),
      ),
    );
    await expectExactError(
      () => newClient().openPullChallenge('zk1x'),
      'PullChallenge: expected object',
    );
  });

  it('parsePullResult: null body on pull redeem', async () => {
    server.use(
      http.post(
        `${BASE}/v1/pull`,
        () =>
          new HttpResponse('null', {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          }),
      ),
    );
    await expectExactError(
      () =>
        newClient().openPullSession({
          challenge: DUMMY_CHALLENGE,
          proof: DUMMY_OWNERSHIP_PROOF,
        }),
      'PullResult: expected object',
    );
  });

  it('parseAccountState: number body on account/state', async () => {
    server.use(
      http.get(
        `${BASE}/v1/account/state`,
        () =>
          new HttpResponse('42', {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          }),
      ),
    );
    await expectExactError(
      () => newClient().getAccountState('tok'),
      'AccountState: expected object',
    );
  });

  it('streamJob: peer closes without a terminal status frame (truncated SSE)', async () => {
    // Realistic cut: one non-terminal phase frame, then the connection ends.
    // Client must not invent completed/failed/cancelled — the generator just
    // returns when the readable stream signals done.
    const frames = 'event: phase\ndata: {"status":"proving","progress":0.1}\n\n';
    server.use(
      http.get(
        `${BASE}/v1/jobs/cut/stream`,
        () =>
          new HttpResponse(frames, {
            status: 200,
            headers: { 'Content-Type': 'text/event-stream' },
          }),
      ),
    );
    const seen: string[] = [];
    for await (const frame of newClient().streamJob('cut')) {
      seen.push(frame.status);
    }
    expect(seen).toEqual(['proving']);
  });
});
