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
  ATTEST_BALANCE_CHALLENGE_DOMAIN,
  ceilingEncoding,
  attestRequestHash,
  attestChallengeMessage,
  buildAttestOwnershipProof,
  ISSUE_GRANT_CHALLENGE_DOMAIN,
  ISSUE_GRANT_REQUEST_TAG,
  SCOPE_NOT_AFTER_UNBOUNDED,
  encodeGrantAssetIds,
  issueGrantRequestHash,
  buildIssueGrantOwnershipProof,
  grantScopeToJsonBody,
  buildGrantProof,
  transitionRequestToJson,
  assertTransitionRequest,
  type TransitionRequest,
  type AwaitingSignature,
  type GrantScopeInput,
  type ProofData,
  type ZkCoinsV1ClientOptions,
  type PullChallenge,
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

/**
 * Valid Bech32m zk-address for request fixtures that need a real checksum
 * (assertOutputDeliveries decodes subject/recipient before any other check).
 * Payload is the all-zero 32-byte address — encoded, never hand-invented.
 */
const FIXTURE_ZK_ADDRESS = encodeZkAddress(new Uint8Array(32));

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
    subject: FIXTURE_ZK_ADDRESS,
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

  it('accepts issuance decimals at the u8 maximum and rejects overflow', () => {
    const mint = {
      kind: 'mint',
      ...base,
      output_templates: [{ recipient: base.subject, asset_id: 'dd'.repeat(32), amount: '1' }],
      issuance: {
        name: 'Boundary asset',
        decimals: 255,
        issuance_version: 1,
        amount: '1',
        creator_pubkey: 'ee'.repeat(32),
      },
    };

    expect(assertTransitionRequest(mint)).toMatchObject({ issuance: { decimals: 255 } });
    expect(() =>
      assertTransitionRequest({
        ...mint,
        issuance: { ...mint.issuance, decimals: 256 },
      }),
    ).toThrow(/decimals must be a non-negative integer <= 255/);
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
    const accepted = await client.submitTransition(
      {
        kind: 'send',
        subject: FIXTURE_ZK_ADDRESS,
        next_pubkey: encodeHexLower(nextPubkey),
        npk_rand: encodeHexLower(npkRand),
        input_coins: ['ab'.repeat(32)],
        output_templates: [
          {
            recipient: FIXTURE_ZK_ADDRESS,
            asset_id: 'cd'.repeat(32),
            amount: '10',
          },
        ],
      },
      {
        confirmPinMismatch: false,
        pinOnFirstUse: false,
        signal: new AbortController().signal,
      },
    );
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
      signal: new AbortController().signal,
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

  it('signJob posts and parses a job without an AbortSignal', async () => {
    const body = { signature: 'aa'.repeat(64), s2c_nonce: 'bb'.repeat(32) };
    let received: unknown;
    server.use(
      http.post(`${BASE}/v1/jobs/job-sign/sign`, async ({ request }) => {
        received = await request.json();
        return HttpResponse.json({
          job_id: 'job-sign',
          kind: 'send',
          status: 'publishing',
          progress: 0.9,
        });
      }),
    );

    const job = await newClient().signJob('job-sign', body);
    expect(received).toEqual(body);
    expect(job).toMatchObject({ job_id: 'job-sign', status: 'publishing' });
  });

  it('signAwaiting accepts an explicit matching node network', () => {
    const signature = newClient('testnet').signAwaiting({
      localPubkey: V8_PK1,
      secretKey: V8_SK1,
      accountState: { current_pubkey: encodeHexLower(V8_PK1), send_counter: 0 },
      awaiting,
      nextPubkey,
      npkRand,
      nodeNetwork: 'testnet',
    });

    expect(verify({ publicKey: V8_PK1, signature: signature.signature, network: 'testnet' })).toBe(
      true,
    );
  });

  it('refuseOrSignAndSubmit accepts an explicit matching node network', async () => {
    server.use(
      http.post(`${BASE}/v1/jobs/job-network/sign`, () =>
        HttpResponse.json({
          job_id: 'job-network',
          kind: 'send',
          status: 'completed',
          progress: 1,
          result: {
            new_account_state_hash: awaiting.new_account_state_hash,
            output_coins_root: awaiting.output_coins_root,
            input_nullifiers_root: awaiting.input_nullifiers_root,
            output_coin_ids: [],
          },
        }),
      ),
    );

    const { signature, job } = await newClient('testnet').refuseOrSignAndSubmit({
      jobId: 'job-network',
      localPubkey: V8_PK1,
      secretKey: V8_SK1,
      accountState: { current_pubkey: encodeHexLower(V8_PK1), send_counter: 0 },
      awaiting,
      nextPubkey,
      npkRand,
      nodeNetwork: 'testnet',
    });

    expect(job.status).toBe('completed');
    expect(verify({ publicKey: V8_PK1, signature: signature.signature, network: 'testnet' })).toBe(
      true,
    );
  });

  it('SSE yields status (not phase) and ignores diagnostic phase labels', async () => {
    const completeResult = {
      new_account_state_hash: '11'.repeat(32),
      output_coins_root: '22'.repeat(32),
      input_nullifiers_root: '33'.repeat(32),
      output_coin_ids: [] as string[],
    };
    const frames =
      'event: phase\ndata: {"status":"proving","phase":"witness_build","progress":0.2}\n\n' +
      'event: phase\ndata: {"status":"awaiting_signature","phase":"ready_for_wallet","progress":0.5,"awaiting_signature":' +
      JSON.stringify(awaiting) +
      '}\n\n' +
      `event: complete\ndata: ${JSON.stringify({
        job_id: 'job-s',
        kind: 'send',
        status: 'completed',
        progress: 1,
        result: completeResult,
      })}\n\n`;

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
    const job = await newClient().cancelJob('job-c', new AbortController().signal);
    expect(job.status).toBe('cancelled');
  });

  it('cancelJob posts and parses a job without an AbortSignal', async () => {
    server.use(
      http.post(`${BASE}/v1/jobs/job-c-no-signal/cancel`, () =>
        HttpResponse.json({
          job_id: 'job-c-no-signal',
          kind: 'send',
          status: 'cancelled',
          progress: 0,
          error: { error: 'cancelled', message: 'cancelled by client' },
        }),
      ),
    );

    const job = await newClient().cancelJob('job-c-no-signal');
    expect(job).toMatchObject({
      job_id: 'job-c-no-signal',
      status: 'cancelled',
      error: { error: 'cancelled', message: 'cancelled by client' },
    });
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
    const pull = await client.openOwnershipPullSession(
      {
        subject,
        sk0: sk0.secretKey,
        nkCommit,
      },
      new AbortController().signal,
    );
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
        subject: FIXTURE_ZK_ADDRESS,
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

  it('getJob parses an accepted job status', async () => {
    server.use(
      http.get(`${BASE}/v1/jobs/j1`, () =>
        HttpResponse.json({ job_id: 'j1', kind: 'send', status: 'accepted', progress: 0 }),
      ),
    );

    const { job } = await newClient().getJob('j1');
    expect(job).toMatchObject({ job_id: 'j1', status: 'accepted', progress: 0 });
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
    const done = await newClient().getJob('done', new AbortController().signal);
    expect(done.job.phase).toBe('published');
    expect(done.job.result?.output_coin_ids).toEqual(['55'.repeat(32)]);
    expect(done.job.result?.publisher_pubkey).toBe('44'.repeat(32));
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
          result: {
            new_account_state_hash: '11'.repeat(32),
            output_coins_root: '22'.repeat(32),
            input_nullifiers_root: '33'.repeat(32),
            output_coin_ids: [1],
          },
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
      'event: phase\nunknown-field: ignored\ndata: {"status":"proving","progress":0.1}\n\n' +
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

  it('openPullChallenge rejects non-canonical nonce and expiry', async () => {
    const badCases: Array<{ nonce: string; expiry: string; re: RegExp }> = [
      { nonce: '', expiry: '1', re: /PullChallenge\.nonce.*expected 64 hex chars/ },
      { nonce: 'a'.repeat(63), expiry: '1', re: /PullChallenge\.nonce.*expected 64 hex chars/ },
      { nonce: 'AA'.repeat(32), expiry: '1', re: /PullChallenge\.nonce.*non-canonical hex/ },
      { nonce: 'aa'.repeat(16), expiry: '1', re: /PullChallenge\.nonce.*expected 64 hex chars/ },
      { nonce: 'aa'.repeat(32), expiry: '01', re: /leading zeros are not allowed/ },
      { nonce: 'aa'.repeat(32), expiry: '12a', re: /not a canonical u64 decimal/ },
    ];
    for (const c of badCases) {
      server.use(
        http.post(`${BASE}/v1/pull/challenge`, () =>
          HttpResponse.json({
            nonce: c.nonce,
            expiry: c.expiry,
            domain: PULL_CHALLENGE_DOMAIN,
          }),
        ),
      );
      await expect(newClient().openPullChallenge('zk1x')).rejects.toThrow(c.re);
    }
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
    const state = await newClient().getAccountState('tok', new AbortController().signal);
    expect(state.send_counter).toBe(3);
    expect(state.head_record_id).toBe('rec-1');
    expect(state.last_nullifier).toEqual({ pubkey: 'dd'.repeat(32), r: 'ee'.repeat(32) });
  });

  it('getAccountState accepts a state without optional head fields', async () => {
    server.use(
      http.get(`${BASE}/v1/account/state`, () =>
        HttpResponse.json({
          account_state: 'aa'.repeat(32),
          state_head: 'bb'.repeat(32),
          send_counter: 0,
          current_pubkey: 'cc'.repeat(32),
        }),
      ),
    );
    const state = await newClient().getAccountState('tok');
    expect(state.head_record_id).toBeUndefined();
    expect(state.last_nullifier).toBeUndefined();
  });

  it('rejects out-of-range awaiting_signature send_counter values', async () => {
    for (const [suffix, sendCounter] of [
      ['negative', -1],
      ['fractional', 1.5],
      ['above-i32-max', 0x80000000],
      ['non-safe-integer', Number.MAX_SAFE_INTEGER + 1],
    ] as const) {
      const jobId = `bad-await-counter-${suffix}`;
      server.use(
        http.get(`${BASE}/v1/jobs/${jobId}`, () =>
          HttpResponse.json({
            job_id: jobId,
            kind: 'send',
            status: 'awaiting_signature',
            progress: 0.5,
            awaiting_signature: {
              ...awaitingFromProofData(V8_PD),
              send_counter: sendCounter,
            },
          }),
        ),
      );
      await expect(newClient().getJob(jobId)).rejects.toThrow(/expected integer in \[0, 2\^31-1\]/);
    }
  });

  it('rejects out-of-range account-state send_counter values', async () => {
    for (const sendCounter of [-1, 1.5, 0x80000000, Number.MAX_SAFE_INTEGER + 1]) {
      server.use(
        http.get(`${BASE}/v1/account/state`, () =>
          HttpResponse.json({
            account_state: 'aa'.repeat(32),
            state_head: 'bb'.repeat(32),
            send_counter: sendCounter,
            current_pubkey: 'cc'.repeat(32),
          }),
        ),
      );
      await expect(newClient().getAccountState('tok')).rejects.toThrow(
        /expected integer in \[0, 2\^31-1\]/,
      );
    }
  });

  it('getAccountState accepts send_counter at 2^31-1', async () => {
    server.use(
      http.get(`${BASE}/v1/account/state`, () =>
        HttpResponse.json({
          account_state: 'aa'.repeat(32),
          state_head: 'bb'.repeat(32),
          send_counter: 0x7fffffff,
          current_pubkey: 'cc'.repeat(32),
        }),
      ),
    );
    const state = await newClient().getAccountState('tok');
    expect(state.send_counter).toBe(0x7fffffff);
  });

  it('accepts fractional progress while send_counter remains integer-only', async () => {
    server.use(
      http.get(`${BASE}/v1/jobs/fractional-progress`, () =>
        HttpResponse.json({
          job_id: 'fractional-progress',
          kind: 'send',
          status: 'proving',
          progress: 0.5,
        }),
      ),
    );
    const { job } = await newClient().getJob('fractional-progress');
    expect(job.progress).toBe(0.5);
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
            {
              record_id: 'r2',
              record_type: 'snapshot',
              blob_id: 'b2',
              occurred_at: '2020-01-02T00:00:00Z',
            },
          ],
          session: 'session-tok',
          session_expiry: '99',
        }),
      ),
    );
    const pull = await newClient().openPullSession(
      {
        challenge: { nonce: 'aa'.repeat(32), expiry: '1', domain: PULL_CHALLENGE_DOMAIN },
        proof: {
          type: 'ownership',
          subject: 'zk1x',
          public_key: 'aa'.repeat(32),
          nk_commit: 'bb'.repeat(32),
          signature: 'cc'.repeat(64),
        },
      },
      new AbortController().signal,
    );
    expect(pull.records[0]?.transition_kind).toBe('send');
    expect(pull.records[1]?.transition_kind).toBeUndefined();
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
      expect(err.machineCode).toBe('unparseable_error_body');
      expect(err.message).toMatch(/upstream blew up/);
    }
  });

  it('JSON error bodies independently default missing error and message fields', async () => {
    server.use(
      http.get(`${BASE}/v1/info`, () =>
        HttpResponse.json({ message: 'human only' }, { status: 502 }),
      ),
    );
    const err1 = await newClient()
      .info()
      .then(
        () => {
          throw new Error('expected reject');
        },
        (e: unknown) => e,
      );
    expect(err1).toBeInstanceOf(V1ApiError);
    if (!(err1 instanceof V1ApiError)) throw err1;
    expect(err1.status).toBe(502);
    expect(err1.machineCode).toBe('unparseable_error_body');
    expect(err1.message).toContain('human only');

    server.use(
      http.get(`${BASE}/v1/info`, () => HttpResponse.json({ error: 'code_only' }, { status: 503 })),
    );
    const err2 = await newClient()
      .info()
      .then(
        () => {
          throw new Error('expected reject');
        },
        (e: unknown) => e,
      );
    expect(err2).toBeInstanceOf(V1ApiError);
    if (!(err2 instanceof V1ApiError)) throw err2;
    expect(err2.status).toBe(503);
    expect(err2.machineCode).toBe('code_only');
    expect(err2.message).toContain('{"error":"code_only"}');
  });

  it('redacts a caught V1ApiError with a non-standard message and no raw body', async () => {
    const token = 'secret-session';
    const source = new V1ApiError(401, 'unauthorized', 'placeholder');
    source.message = `upstream leaked ${token} without the SDK prefix`;
    const client = new ZkCoinsV1Client({
      apiUrl: BASE,
      network: 'testnet',
      fetch: async () => {
        throw source;
      },
    });
    const err = await client.getAccountState(token).then(
      () => {
        throw new Error('expected reject');
      },
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(V1ApiError);
    if (!(err instanceof V1ApiError)) throw err;
    expect(err.rawBody).toBeUndefined();
    expect(err.message).not.toContain(token);
  });

  it('empty 2xx body parses as an empty object (JobAccepted then fails on fields)', async () => {
    server.use(http.post(`${BASE}/v1/tx`, () => new HttpResponse('', { status: 202 })));
    await expect(
      newClient().submitTransition({
        kind: 'receive',
        subject: FIXTURE_ZK_ADDRESS,
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
        subject: FIXTURE_ZK_ADDRESS,
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
      'data: "result":{"new_account_state_hash":"' +
      '11'.repeat(32) +
      '","output_coins_root":"' +
      '22'.repeat(32) +
      '","input_nullifiers_root":"' +
      '33'.repeat(32) +
      '","output_coin_ids":[]}}\n\n';
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

  // ---------------------------------------------------------------------------
  // §7.5 terminal payload fail-closed (poll + SSE share one parser)
  // Without the parseJob / parseSseJobPayload tighten-up these cases returned
  // a "successful" V1Job with status completed/failed/cancelled and no
  // result/error — a half-success the wallet would treat as valid.
  // ---------------------------------------------------------------------------

  /** Base job envelope shared by terminal fail-closed fixtures. */
  function terminalJobBase(
    status: 'completed' | 'failed' | 'cancelled',
    extra: Record<string, unknown> = {},
  ): Record<string, unknown> {
    return {
      job_id: `term-${status}`,
      kind: 'send',
      status,
      progress: status === 'completed' ? 1 : 0,
      ...extra,
    };
  }

  async function expectGetJobMessage(jobId: string, message: string): Promise<void> {
    try {
      await newClient().getJob(jobId);
      expect.unreachable(`getJob(${jobId}) should have thrown`);
    } catch (err) {
      expect(err).toBeInstanceOf(Error);
      if (!(err instanceof Error)) throw err;
      expect(err.message).toBe(message);
    }
  }

  async function expectStreamJobMessage(jobId: string, message: string): Promise<void> {
    try {
      for await (const _ of newClient().streamJob(jobId)) {
        // drain
      }
      expect.unreachable(`streamJob(${jobId}) should have thrown`);
    } catch (err) {
      expect(err).toBeInstanceOf(Error);
      if (!(err instanceof Error)) throw err;
      expect(err.message).toBe(message);
    }
  }

  it('completed without result → error, not silent success (poll)', async () => {
    // Without the fix: parseJob left result undefined and returned status completed.
    server.use(
      http.get(`${BASE}/v1/jobs/term-completed`, () =>
        HttpResponse.json(terminalJobBase('completed')),
      ),
    );
    await expectGetJobMessage('term-completed', 'job status is completed but result is absent');
  });

  it('failed without error → error (poll)', async () => {
    server.use(
      http.get(`${BASE}/v1/jobs/term-failed`, () => HttpResponse.json(terminalJobBase('failed'))),
    );
    await expectGetJobMessage('term-failed', 'job status is failed but error is absent');
  });

  it('cancelled without error → error (poll)', async () => {
    server.use(
      http.get(`${BASE}/v1/jobs/term-cancelled`, () =>
        HttpResponse.json(terminalJobBase('cancelled')),
      ),
    );
    await expectGetJobMessage('term-cancelled', 'job status is cancelled but error is absent');
  });

  it('same half-successful terminal jobs over SSE yield the same errors as poll', async () => {
    // Closes the bypass: before the fix, streamJob yielded the raw object and
    // stopped on terminal status without ever calling parseJob.
    const cases: Array<{
      id: string;
      body: Record<string, unknown>;
      message: string;
    }> = [
      {
        id: 'sse-no-result',
        body: terminalJobBase('completed'),
        message: 'job status is completed but result is absent',
      },
      {
        id: 'sse-no-fail-err',
        body: { ...terminalJobBase('failed'), job_id: 'sse-no-fail-err' },
        message: 'job status is failed but error is absent',
      },
      {
        id: 'sse-no-cancel-err',
        body: { ...terminalJobBase('cancelled'), job_id: 'sse-no-cancel-err' },
        message: 'job status is cancelled but error is absent',
      },
    ];

    for (const c of cases) {
      // Poll path — pin the expected message.
      server.use(http.get(`${BASE}/v1/jobs/${c.id}`, () => HttpResponse.json(c.body)));
      await expectGetJobMessage(c.id, c.message);

      // SSE complete/error frame with the identical JSON body.
      const eventName = c.body.status === 'completed' ? 'complete' : 'error';
      const frames = `event: ${eventName}\ndata: ${JSON.stringify(c.body)}\n\n`;
      server.use(
        http.get(
          `${BASE}/v1/jobs/${c.id}/stream`,
          () =>
            new HttpResponse(frames, {
              status: 200,
              headers: { 'Content-Type': 'text/event-stream' },
            }),
        ),
      );
      await expectStreamJobMessage(c.id, c.message);
    }
  });

  it('well-formed jobs per status are still accepted (poll + SSE)', async () => {
    const ash = '11'.repeat(32);
    const ocr = '22'.repeat(32);
    const inr = '33'.repeat(32);
    const awaiting: AwaitingSignature = {
      new_account_state_hash: ash,
      output_coins_root: ocr,
      input_nullifiers_root: inr,
      coin_history_root: '44'.repeat(32),
      nav_commitment: '55'.repeat(32),
      npk_commit: '66'.repeat(32),
      proof_data_hash: '77'.repeat(32),
      txn_pubkey: '88'.repeat(32),
      send_counter: 1,
    };

    const wellFormed: Array<{ id: string; body: Record<string, unknown> }> = [
      {
        id: 'ok-proving',
        body: { job_id: 'ok-proving', kind: 'send', status: 'proving', progress: 0.3 },
      },
      {
        id: 'ok-publishing',
        body: { job_id: 'ok-publishing', kind: 'send', status: 'publishing', progress: 0.9 },
      },
      {
        id: 'ok-await',
        body: {
          job_id: 'ok-await',
          kind: 'send',
          status: 'awaiting_signature',
          progress: 0.5,
          awaiting_signature: awaiting,
        },
      },
      {
        id: 'ok-completed',
        body: {
          job_id: 'ok-completed',
          kind: 'send',
          status: 'completed',
          progress: 1,
          result: {
            new_account_state_hash: ash,
            output_coins_root: ocr,
            input_nullifiers_root: inr,
            output_coin_ids: ['aa'.repeat(32)],
            publisher_pubkey: 'bb'.repeat(32),
          },
        },
      },
      {
        id: 'ok-failed',
        body: {
          job_id: 'ok-failed',
          kind: 'send',
          status: 'failed',
          progress: 0,
          error: { error: 'proving_failed', message: 'witness build failed' },
        },
      },
      {
        id: 'ok-cancelled',
        body: {
          job_id: 'ok-cancelled',
          kind: 'send',
          status: 'cancelled',
          progress: 0,
          error: { error: 'cancelled', message: 'client cancel' },
        },
      },
      {
        // attest_balance completed: wire form is exclusively { attestation }.
        id: 'ok-attest',
        body: {
          job_id: 'ok-attest',
          kind: 'attest_balance',
          status: 'completed',
          progress: 1,
          result: { attestation: 'ff'.repeat(16) },
        },
      },
    ];

    for (const w of wellFormed) {
      server.use(http.get(`${BASE}/v1/jobs/${w.id}`, () => HttpResponse.json(w.body)));
      const { job } = await newClient().getJob(w.id);
      expect(job.status).toBe(w.body.status);
      expect(job.job_id).toBe(w.id);
      if (job.status === 'completed') {
        expect(job.result).toBeDefined();
        if (w.body.kind === 'attest_balance') {
          expect(typeof job.result?.attestation).toBe('string');
          expect(job.result?.output_coin_ids).toBeUndefined();
        } else {
          expect(Array.isArray(job.result?.output_coin_ids)).toBe(true);
        }
      }
      if (job.status === 'failed' || job.status === 'cancelled') {
        expect(job.error).toEqual(w.body.error);
      }
      if (job.status === 'awaiting_signature') {
        expect(job.awaiting_signature?.send_counter).toBe(1);
      }
    }

    // SSE well-formed terminal frames still yield and stop.
    const completedBody = wellFormed.find((w) => w.id === 'ok-completed');
    if (completedBody === undefined) {
      throw new Error('fixture ok-completed missing');
    }
    server.use(
      http.get(
        `${BASE}/v1/jobs/ok-completed/stream`,
        () =>
          new HttpResponse(`event: complete\ndata: ${JSON.stringify(completedBody.body)}\n\n`, {
            status: 200,
            headers: { 'Content-Type': 'text/event-stream' },
          }),
      ),
    );
    const seen: string[] = [];
    let lastJob: unknown;
    for await (const frame of newClient().streamJob('ok-completed')) {
      seen.push(frame.status);
      lastJob = frame.job;
    }
    expect(seen).toEqual(['completed']);
    expect(lastJob).toMatchObject({
      status: 'completed',
      result: {
        new_account_state_hash: ash,
        output_coins_root: ocr,
        input_nullifiers_root: inr,
        output_coin_ids: ['aa'.repeat(32)],
      },
    });
  });

  it('completed mint/send/receive without a required digest fails closed (per kind)', async () => {
    // Without kind-strict digests a completed send with only output_coin_ids
    // would parse as success — the wallet would treat a half-result as final.
    const ash = '11'.repeat(32);
    const ocr = '22'.repeat(32);
    const inr = '33'.repeat(32);
    const coins = ['aa'.repeat(32)];

    const cases: Array<{
      id: string;
      kind: 'mint' | 'send' | 'receive';
      result: Record<string, unknown>;
      message: RegExp;
    }> = [
      {
        id: 'digest-send-missing-ash',
        kind: 'send',
        result: {
          output_coins_root: ocr,
          input_nullifiers_root: inr,
          output_coin_ids: coins,
        },
        message: /new_account_state_hash: required 32-byte hex for completed kind=send/,
      },
      {
        id: 'digest-mint-missing-ocr',
        kind: 'mint',
        result: {
          new_account_state_hash: ash,
          input_nullifiers_root: inr,
          output_coin_ids: coins,
        },
        message: /output_coins_root: required 32-byte hex for completed kind=mint/,
      },
      {
        id: 'digest-recv-missing-inr',
        kind: 'receive',
        result: {
          new_account_state_hash: ash,
          output_coins_root: ocr,
          output_coin_ids: coins,
        },
        message: /input_nullifiers_root: required 32-byte hex for completed kind=receive/,
      },
    ];

    for (const c of cases) {
      server.use(
        http.get(`${BASE}/v1/jobs/${c.id}`, () =>
          HttpResponse.json({
            job_id: c.id,
            kind: c.kind,
            status: 'completed',
            progress: 1,
            result: c.result,
          }),
        ),
      );
      await expect(newClient().getJob(c.id)).rejects.toThrow(c.message);
    }

    // attest_balance wire form is exclusively { attestation } (no digests).
    server.use(
      http.get(`${BASE}/v1/jobs/digest-attest-ok`, () =>
        HttpResponse.json({
          job_id: 'digest-attest-ok',
          kind: 'attest_balance',
          status: 'completed',
          progress: 1,
          result: { attestation: 'ff'.repeat(16) },
        }),
      ),
    );
    const { job } = await newClient().getJob('digest-attest-ok');
    expect(job.kind).toBe('attest_balance');
    expect(job.result?.attestation).toBe('ff'.repeat(16));
    expect(job.result?.new_account_state_hash).toBeUndefined();
  });

  it('SSE frames delimited by CRLF are processed (not only LF)', async () => {
    // Without CRLF support a standard-conformant `\r\n\r\n` stream never yields.
    const body = {
      job_id: 'sse-crlf',
      kind: 'send',
      status: 'completed',
      progress: 1,
      result: {
        new_account_state_hash: '11'.repeat(32),
        output_coins_root: '22'.repeat(32),
        input_nullifiers_root: '33'.repeat(32),
        output_coin_ids: ['aa'.repeat(32)],
      },
    };
    const frames = 'event: complete\r\n' + `data: ${JSON.stringify(body)}\r\n` + '\r\n';
    server.use(
      http.get(
        `${BASE}/v1/jobs/sse-crlf/stream`,
        () =>
          new HttpResponse(frames, {
            status: 200,
            headers: { 'Content-Type': 'text/event-stream' },
          }),
      ),
    );
    const seen: string[] = [];
    let last: unknown;
    for await (const frame of newClient().streamJob('sse-crlf')) {
      seen.push(frame.status);
      last = frame.job;
    }
    expect(seen).toEqual(['completed']);
    expect(last).toMatchObject({
      job_id: 'sse-crlf',
      status: 'completed',
      result: { output_coin_ids: ['aa'.repeat(32)] },
    });
  });

  it('SSE chooses the earliest boundary when LF and CRLF frames share a buffer', async () => {
    const completed = {
      job_id: 'mixed',
      kind: 'send',
      status: 'completed',
      progress: 1,
      result: {
        new_account_state_hash: '11'.repeat(32),
        output_coins_root: '22'.repeat(32),
        input_nullifiers_root: '33'.repeat(32),
        output_coin_ids: [] as string[],
      },
    };
    const lfFrame = 'event: phase\ndata: {"status":"proving","progress":0.1}\n\n';
    const crlfFrame = `event: complete\r\ndata: ${JSON.stringify(completed)}\r\n\r\n`;

    for (const [id, frames] of [
      ['mixed-lf-first', lfFrame + crlfFrame],
      ['mixed-crlf-first', crlfFrame + lfFrame],
    ] as const) {
      server.use(
        http.get(
          `${BASE}/v1/jobs/${id}/stream`,
          () =>
            new HttpResponse(frames, {
              status: 200,
              headers: { 'Content-Type': 'text/event-stream' },
            }),
        ),
      );
      const seen: string[] = [];
      for await (const frame of newClient().streamJob(id)) {
        seen.push(frame.status);
      }
      if (id === 'mixed-lf-first') {
        expect(seen).toEqual(['proving', 'completed']);
      } else {
        // Terminal first: streamJob returns before the trailing proving frame.
        expect(seen).toEqual(['completed']);
      }
    }
  });

  it('SSE frames delimited by CRLF then CR blank line are processed', async () => {
    // Blank line is `\r\n` + `\r` (not in the homogeneous pair set).
    const completed = {
      job_id: 'sse-crlf-cr',
      kind: 'send',
      status: 'completed',
      progress: 1,
      result: {
        new_account_state_hash: '11'.repeat(32),
        output_coins_root: '22'.repeat(32),
        input_nullifiers_root: '33'.repeat(32),
        output_coin_ids: [] as string[],
      },
    };
    const frames =
      `event: complete\r\ndata: ${JSON.stringify(completed)}\r\n\r` +
      'event: phase\ndata: {"status":"proving","progress":0.1}\n';
    server.use(
      http.get(
        `${BASE}/v1/jobs/sse-crlf-cr/stream`,
        () =>
          new HttpResponse(frames, {
            status: 200,
            headers: { 'Content-Type': 'text/event-stream' },
          }),
      ),
    );
    const seen: string[] = [];
    for await (const frame of newClient().streamJob('sse-crlf-cr')) {
      seen.push(frame.status);
    }
    expect(seen).toEqual(['completed']);
  });

  it('SSE frames delimited by LF then CRLF blank line are processed', async () => {
    // Blank line is `\n` + `\r\n` (not in the homogeneous pair set).
    const completed = {
      job_id: 'sse-lf-crlf',
      kind: 'send',
      status: 'completed',
      progress: 1,
      result: {
        new_account_state_hash: '11'.repeat(32),
        output_coins_root: '22'.repeat(32),
        input_nullifiers_root: '33'.repeat(32),
        output_coin_ids: [] as string[],
      },
    };
    const frames =
      `event: complete\ndata: ${JSON.stringify(completed)}\n\r\n` +
      'event: phase\ndata: {"status":"proving","progress":0.1}\n';
    server.use(
      http.get(
        `${BASE}/v1/jobs/sse-lf-crlf/stream`,
        () =>
          new HttpResponse(frames, {
            status: 200,
            headers: { 'Content-Type': 'text/event-stream' },
          }),
      ),
    );
    const seen: string[] = [];
    for await (const frame of newClient().streamJob('sse-lf-crlf')) {
      seen.push(frame.status);
    }
    expect(seen).toEqual(['completed']);
  });

  it('SSE flushes a terminal frame split across two ReadableStream chunks', async () => {
    // First enqueue leaves the frame incomplete; the second closes the blank
    // line on the normal done=false path. Chunk-boundary test, not a done=true
    // drain (those use a custom getReader further below).
    const body = {
      job_id: 'sse-eof-bound',
      kind: 'send',
      status: 'completed',
      progress: 1,
      result: {
        new_account_state_hash: '11'.repeat(32),
        output_coins_root: '22'.repeat(32),
        input_nullifiers_root: '33'.repeat(32),
        output_coin_ids: ['aa'.repeat(32)],
      },
    };
    const full = `event: complete\ndata: ${JSON.stringify(body)}\n\n`;
    const enc = new TextEncoder();
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(enc.encode(full.slice(0, 24)));
        controller.enqueue(enc.encode(full.slice(24)));
        controller.close();
      },
    });
    server.use(
      http.get(
        `${BASE}/v1/jobs/sse-eof-bound/stream`,
        () =>
          new HttpResponse(stream, {
            status: 200,
            headers: { 'Content-Type': 'text/event-stream' },
          }),
      ),
    );
    const seen: string[] = [];
    for await (const frame of newClient().streamJob('sse-eof-bound')) {
      seen.push(frame.status);
    }
    expect(seen).toEqual(['completed']);
  });

  it('SSE flushes a terminal frame without a trailing blank line at EOF', async () => {
    // No closing blank line → only the trailing-buffer flush on done yields.
    const body = {
      job_id: 'sse-eof-trail',
      kind: 'send',
      status: 'completed',
      progress: 1,
      result: {
        new_account_state_hash: '11'.repeat(32),
        output_coins_root: '22'.repeat(32),
        input_nullifiers_root: '33'.repeat(32),
        output_coin_ids: ['bb'.repeat(32)],
      },
    };
    const frames = `event: complete\ndata: ${JSON.stringify(body)}\n`;
    server.use(
      http.get(
        `${BASE}/v1/jobs/sse-eof-trail/stream`,
        () =>
          new HttpResponse(frames, {
            status: 200,
            headers: { 'Content-Type': 'text/event-stream' },
          }),
      ),
    );
    const seen: string[] = [];
    for await (const frame of newClient().streamJob('sse-eof-trail')) {
      seen.push(frame.status);
    }
    expect(seen).toEqual(['completed']);
  });

  it('SSE phase frame with awaiting_signature but no payload fails closed', async () => {
    // Phase frames are not full job objects; status-specific payload still
    // required so the stream path cannot surface awaiting_signature empty.
    const frames = 'event: phase\ndata: {"status":"awaiting_signature","progress":0.5}\n\n';
    server.use(
      http.get(
        `${BASE}/v1/jobs/sse-await-empty/stream`,
        () =>
          new HttpResponse(frames, {
            status: 200,
            headers: { 'Content-Type': 'text/event-stream' },
          }),
      ),
    );
    await expectStreamJobMessage(
      'sse-await-empty',
      'job status is awaiting_signature but payload is absent',
    );
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
  subject: FIXTURE_ZK_ADDRESS,
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
    // Client must not invent completed/failed/cancelled — fail closed instead.
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
    await expect(async () => {
      for await (const frame of newClient().streamJob('cut')) {
        seen.push(frame.status);
      }
    }).rejects.toThrow(/stream ended without terminal status/);
    expect(seen).toEqual(['proving']);
  });

  it('streamJob: empty body ends without terminal status', async () => {
    server.use(
      http.get(
        `${BASE}/v1/jobs/empty-sse/stream`,
        () =>
          new HttpResponse('', {
            status: 200,
            headers: { 'Content-Type': 'text/event-stream' },
          }),
      ),
    );
    await expect(async () => {
      for await (const _ of newClient().streamJob('empty-sse')) {
        // never
      }
    }).rejects.toThrow(/stream ended without terminal status/);
  });

  it('streamJob: trailing frame without blank line is still consumed', async () => {
    const completed = {
      job_id: 'trail',
      kind: 'send',
      status: 'completed',
      progress: 1,
      result: {
        new_account_state_hash: '11'.repeat(32),
        output_coins_root: '22'.repeat(32),
        input_nullifiers_root: '33'.repeat(32),
        output_coin_ids: ['aa'.repeat(32)],
      },
    };
    // No trailing \n\n — final incomplete-looking buffer is still one frame.
    const body = `event: complete\ndata: ${JSON.stringify(completed)}`;
    server.use(
      http.get(
        `${BASE}/v1/jobs/trail/stream`,
        () =>
          new HttpResponse(body, {
            status: 200,
            headers: { 'Content-Type': 'text/event-stream' },
          }),
      ),
    );
    const seen: string[] = [];
    for await (const frame of newClient().streamJob('trail')) {
      seen.push(frame.status);
    }
    expect(seen).toEqual(['completed']);
  });

  it('streamJob: single read with done=true still drains two SSE frames', async () => {
    // Real ReadableStreams typically split final bytes ({value, done:false}) from
    // EOF ({done:true}). Some runtimes hand both in one read — exercise that path.
    const completed = {
      job_id: 'done-value',
      kind: 'send',
      status: 'completed',
      progress: 1,
      result: {
        new_account_state_hash: '11'.repeat(32),
        output_coins_root: '22'.repeat(32),
        input_nullifiers_root: '33'.repeat(32),
        output_coin_ids: ['aa'.repeat(32)],
      },
    };
    const frames =
      'event: phase\ndata: {"status":"proving","progress":0.1}\n\n' +
      `event: complete\ndata: ${JSON.stringify(completed)}\n\n`;
    const chunk = new TextEncoder().encode(frames);

    const client = new ZkCoinsV1Client({
      apiUrl: BASE,
      network: 'testnet',
      fetch: async () => {
        let delivered = false;
        const body = {
          getReader() {
            return {
              async read() {
                if (delivered) {
                  return { value: undefined, done: true as const };
                }
                delivered = true;
                return { value: chunk, done: true as const };
              },
              releaseLock() {},
              cancel: async () => {},
            };
          },
        };
        const res = new Response(null, {
          status: 200,
          headers: { 'Content-Type': 'text/event-stream' },
        });
        Object.defineProperty(res, 'body', {
          configurable: true,
          get: () => body,
        });
        return res;
      },
    });

    const seen: string[] = [];
    for await (const frame of client.streamJob('done-value')) {
      seen.push(frame.status);
    }
    expect(seen).toEqual(['proving', 'completed']);
  });

  it('streamJob: done=true completed frame after a non-done proving chunk returns in the drain loop', async () => {
    // First read: non-done proving frame (normal path). Second: done=true with a
    // completed frame so the drain while-loop yields terminal and returns (line 488).
    const completed = {
      job_id: 'done-drain',
      kind: 'send',
      status: 'completed',
      progress: 1,
      result: {
        new_account_state_hash: '11'.repeat(32),
        output_coins_root: '22'.repeat(32),
        input_nullifiers_root: '33'.repeat(32),
        output_coin_ids: ['aa'.repeat(32)],
      },
    };
    const provingChunk = new TextEncoder().encode(
      'event: phase\ndata: {"status":"proving","progress":0.1}\n\n',
    );
    const completedChunk = new TextEncoder().encode(
      `event: complete\ndata: ${JSON.stringify(completed)}\n\n`,
    );

    const client = new ZkCoinsV1Client({
      apiUrl: BASE,
      network: 'testnet',
      fetch: async () => {
        let step = 0;
        const body = {
          getReader() {
            return {
              async read() {
                if (step === 0) {
                  step = 1;
                  return { value: provingChunk, done: false as const };
                }
                if (step === 1) {
                  step = 2;
                  return { value: completedChunk, done: true as const };
                }
                return { value: undefined, done: true as const };
              },
              releaseLock() {},
              cancel: async () => {},
            };
          },
        };
        const res = new Response(null, {
          status: 200,
          headers: { 'Content-Type': 'text/event-stream' },
        });
        Object.defineProperty(res, 'body', {
          configurable: true,
          get: () => body,
        });
        return res;
      },
    });

    const seen: string[] = [];
    for await (const frame of client.streamJob('done-drain')) {
      seen.push(frame.status);
    }
    expect(seen).toEqual(['proving', 'completed']);
  });

  it('streamJob: trailing non-terminal frame without blank line yields then throws', async () => {
    // done=true with a proving fragment that has no blank-line boundary — the
    // while over findSseFrameBoundary finds nothing; trailing buffer consume
    // yields proving (non-terminal), then throws (lines 499–501 + throw).
    const fragment = new TextEncoder().encode(
      'event: job\ndata: {"status":"proving","progress":0.1}\n',
    );

    const client = new ZkCoinsV1Client({
      apiUrl: BASE,
      network: 'testnet',
      fetch: async () => {
        let delivered = false;
        const body = {
          getReader() {
            return {
              async read() {
                if (delivered) {
                  return { value: undefined, done: true as const };
                }
                delivered = true;
                return { value: fragment, done: true as const };
              },
              releaseLock() {},
              cancel: async () => {},
            };
          },
        };
        const res = new Response(null, {
          status: 200,
          headers: { 'Content-Type': 'text/event-stream' },
        });
        Object.defineProperty(res, 'body', {
          configurable: true,
          get: () => body,
        });
        return res;
      },
    });

    const seen: string[] = [];
    await expect(async () => {
      for await (const frame of client.streamJob('trail-nonterm')) {
        seen.push(frame.status);
      }
    }).rejects.toThrow(/stream ended without terminal status/);
    expect(seen).toEqual(['proving']);
  });

  it('streamJob: done=true single complete SSE frame returns in the drain while-loop', async () => {
    // One complete frame (with blank-line boundary) on the first read with done=true
    // — drain while-loop yields terminal and returns cleanly.
    const completed = {
      job_id: 'done-while-term',
      kind: 'send',
      status: 'completed',
      progress: 1,
      result: {
        new_account_state_hash: '11'.repeat(32),
        output_coins_root: '22'.repeat(32),
        input_nullifiers_root: '33'.repeat(32),
        output_coin_ids: ['aa'.repeat(32)],
      },
    };
    const sseText = `event: complete\ndata: ${JSON.stringify(completed)}\n\n`;
    const chunk = new TextEncoder().encode(sseText);

    const client = new ZkCoinsV1Client({
      apiUrl: BASE,
      network: 'testnet',
      fetch: async () => {
        let delivered = false;
        const body = {
          getReader() {
            return {
              async read() {
                if (delivered) {
                  return { value: undefined, done: true as const };
                }
                delivered = true;
                return { value: chunk, done: true as const };
              },
              releaseLock() {},
              cancel: async () => {},
            };
          },
        };
        const res = new Response(null, {
          status: 200,
          headers: { 'Content-Type': 'text/event-stream' },
        });
        Object.defineProperty(res, 'body', {
          configurable: true,
          get: () => body,
        });
        return res;
      },
    });

    const seen: string[] = [];
    for await (const sseFrame of client.streamJob('done-while-term')) {
      seen.push(sseFrame.status);
    }
    expect(seen).toEqual(['completed']);
  });

  it('streamJob: done=true trailing completed frame without blank line returns cleanly', async () => {
    // done=true with a completed frame that has no blank-line boundary — while finds
    // nothing; trailing buffer consume yields terminal and returns (no throw).
    const completed = {
      job_id: 'done-trail-term',
      kind: 'send',
      status: 'completed',
      progress: 1,
      result: {
        new_account_state_hash: '11'.repeat(32),
        output_coins_root: '22'.repeat(32),
        input_nullifiers_root: '33'.repeat(32),
        output_coin_ids: ['aa'.repeat(32)],
      },
    };
    const fragment = new TextEncoder().encode(
      `event: complete\ndata: ${JSON.stringify(completed)}\n`,
    );

    const client = new ZkCoinsV1Client({
      apiUrl: BASE,
      network: 'testnet',
      fetch: async () => {
        let delivered = false;
        const body = {
          getReader() {
            return {
              async read() {
                if (delivered) {
                  return { value: undefined, done: true as const };
                }
                delivered = true;
                return { value: fragment, done: true as const };
              },
              releaseLock() {},
              cancel: async () => {},
            };
          },
        };
        const res = new Response(null, {
          status: 200,
          headers: { 'Content-Type': 'text/event-stream' },
        });
        Object.defineProperty(res, 'body', {
          configurable: true,
          get: () => body,
        });
        return res;
      },
    });

    const seen: string[] = [];
    for await (const frame of client.streamJob('done-trail-term')) {
      seen.push(frame.status);
    }
    expect(seen).toEqual(['completed']);
  });

  it('streamJob: done=true comment frame then completed skips yieldFrame-null in drain while', async () => {
    // done=true with a comment frame (no data) then terminal complete — drain while
    // hits yieldFrame===null (line 489 false) then yields completed and returns.
    const completed = {
      job_id: 'done-keep-then-term',
      kind: 'send',
      status: 'completed',
      progress: 1,
      result: {
        new_account_state_hash: '11'.repeat(32),
        output_coins_root: '22'.repeat(32),
        input_nullifiers_root: '33'.repeat(32),
        output_coin_ids: ['aa'.repeat(32)],
      },
    };
    const frames = ': keepalive\n\n' + `event: complete\ndata: ${JSON.stringify(completed)}\n\n`;
    const chunk = new TextEncoder().encode(frames);

    const client = new ZkCoinsV1Client({
      apiUrl: BASE,
      network: 'testnet',
      fetch: async () => {
        let delivered = false;
        const body = {
          getReader() {
            return {
              async read() {
                if (delivered) {
                  return { value: undefined, done: true as const };
                }
                delivered = true;
                return { value: chunk, done: true as const };
              },
              releaseLock() {},
              cancel: async () => {},
            };
          },
        };
        const res = new Response(null, {
          status: 200,
          headers: { 'Content-Type': 'text/event-stream' },
        });
        Object.defineProperty(res, 'body', {
          configurable: true,
          get: () => body,
        });
        return res;
      },
    });

    const seen: string[] = [];
    for await (const frame of client.streamJob('done-keep-then-term')) {
      seen.push(frame.status);
    }
    expect(seen).toEqual(['completed']);
  });

  it('streamJob: done=true trailing comment without blank line throws without yielding', async () => {
    // done=true trailing comment-only fragment (no \n\n) — while finds no boundary;
    // trailing consume yields null (line 501 false); sawTerminal stays false → throw.
    const fragment = new TextEncoder().encode(': keepalive\n');

    const client = new ZkCoinsV1Client({
      apiUrl: BASE,
      network: 'testnet',
      fetch: async () => {
        let delivered = false;
        const body = {
          getReader() {
            return {
              async read() {
                if (delivered) {
                  return { value: undefined, done: true as const };
                }
                delivered = true;
                return { value: fragment, done: true as const };
              },
              releaseLock() {},
              cancel: async () => {},
            };
          },
        };
        const res = new Response(null, {
          status: 200,
          headers: { 'Content-Type': 'text/event-stream' },
        });
        Object.defineProperty(res, 'body', {
          configurable: true,
          get: () => body,
        });
        return res;
      },
    });

    const seen: string[] = [];
    await expect(async () => {
      for await (const frame of client.streamJob('done-trail-nodata')) {
        seen.push(frame.status);
      }
    }).rejects.toThrow(/stream ended without terminal status/);
    expect(seen).toEqual([]);
  });

  it('redacts machineCode when the JSON error field is the session token', async () => {
    const token = 'tok-in-code-9f3a';
    server.use(
      http.get(`${BASE}/v1/account/state`, () =>
        HttpResponse.json({ error: token, message: 'denied' }, { status: 401 }),
      ),
    );
    try {
      await newClient().getAccountState(token);
      expect.unreachable('expected V1ApiError');
    } catch (err) {
      expect(err).toBeInstanceOf(V1ApiError);
      if (!(err instanceof V1ApiError)) throw err;
      expect(err.machineCode).not.toContain(token);
      expect(err.machineCode).toBe('<redacted-session-token>');
      expect(err.message).not.toContain(token);
      expect(err.rawBody).toEqual(expect.any(String));
      expect(err.rawBody).not.toContain(token);
    }
  });
});

// ---------------------------------------------------------------------------
// Attest balance (§7.5 request-side: challenge + OwnershipProof + POST)
// ---------------------------------------------------------------------------

describe('AttestBalance request surface', () => {
  const seed = seedFromMnemonicV1(
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
  );
  const sk0 = deriveSpendKey(seed, 0, 0);
  const nkCommit = new Uint8Array(32);
  const subjectRaw = sha256(
    (() => {
      const pre = new Uint8Array(64);
      pre.set(sk0.publicKey, 0);
      pre.set(nkCommit, 32);
      return pre;
    })(),
  );
  const subject = encodeZkAddress(subjectRaw);
  const assetId = new Uint8Array(32).fill(0x02);
  const host = 'node.test';

  // ---- 1. Known-answer vectors (Python hashlib.sha256; fixed values) ----

  it('ceilingEncoding: both absent → single 0x00 byte', () => {
    expect(Array.from(ceilingEncoding(undefined, undefined))).toEqual([0x00]);
    expect(Array.from(ceilingEncoding())).toEqual([0x00]);
  });

  it('ceilingEncoding: both present → 0x01 ‖ nav(32) ‖ u64-be(size)', () => {
    const enc = ceilingEncoding(new Uint8Array(32).fill(0x03), 9);
    expect(encodeHexLower(enc)).toBe(
      '0103030303030303030303030303030303030303030303030303030303030303030000000000000009',
    );
    expect(enc.length).toBe(41);
  });

  it('attestRequestHash KAT: subject=[1;32], asset=[2;32], ceiling=0x00', () => {
    const h = attestRequestHash(
      new Uint8Array(32).fill(1),
      new Uint8Array(32).fill(2),
      ceilingEncoding(undefined, undefined),
    );
    expect(encodeHexLower(h)).toBe(
      '18d6a5c4d891c9984be2602b7afd18d32dffb2ff3667b9c946352c41bfea4c63',
    );
  });

  it('attestRequestHash KAT: subject=[1;32], asset=[2;32], nav=[3;32], size=9', () => {
    const h = attestRequestHash(
      new Uint8Array(32).fill(1),
      new Uint8Array(32).fill(2),
      ceilingEncoding(new Uint8Array(32).fill(3), 9),
    );
    expect(encodeHexLower(h)).toBe(
      'b1d282624c49c552c8e31ec16424c2cfcbbc2fb18f82e8608111838284b0a349',
    );
  });

  it('attestChallengeMessage KAT: fixed domain/nonce/chanBind/subject/expiry/requestHash', () => {
    const chal = attestChallengeMessage({
      domain: ATTEST_BALANCE_CHALLENGE_DOMAIN,
      nonce: new Uint8Array(32).fill(0x11),
      chanBind: new Uint8Array(32).fill(0x22),
      subjectRaw: new Uint8Array(32).fill(0x33),
      expiry: 1700000000n,
      requestHash: new Uint8Array(32).fill(0x44),
    });
    expect(encodeHexLower(chal)).toBe(
      'dcbd51dc183e10cde9fdf57e94a5ff054f270535bb4434085a0b06932b41f734',
    );
  });

  // ---- 2. Error paths / no-silent-fallback ----

  it('ceilingEncoding rejects mixed presence and invalid field sizes', () => {
    const nav = new Uint8Array(32).fill(0x03);
    expect(() => ceilingEncoding(nav, undefined)).toThrow(/both be present or both omitted/);
    expect(() => ceilingEncoding(undefined, 9)).toThrow(/both be present or both omitted/);
    expect(() => ceilingEncoding(new Uint8Array(16), 9)).toThrow(/nav_ceiling must be 32 bytes/);
    expect(() => ceilingEncoding(nav, -1)).toThrow(/out of u64 range/);
    expect(() => ceilingEncoding(nav, -1n)).toThrow(/out of u64 range/);
    expect(() => ceilingEncoding(nav, 0x1_0000_0000_0000_0000n)).toThrow(/out of u64 range/);
    expect(() => ceilingEncoding(nav, 1.5)).toThrow(/safe integer/);
  });

  it('attestChallengeMessage / attestRequestHash reject wrong 32-byte field lengths', () => {
    const ok32 = new Uint8Array(32);
    expect(() =>
      attestChallengeMessage({
        domain: '',
        nonce: ok32,
        chanBind: ok32,
        subjectRaw: ok32,
        expiry: 1n,
        requestHash: ok32,
      }),
    ).toThrow(/domain is required/);
    expect(() =>
      attestChallengeMessage({
        domain: ATTEST_BALANCE_CHALLENGE_DOMAIN,
        nonce: new Uint8Array(31),
        chanBind: ok32,
        subjectRaw: ok32,
        expiry: 1n,
        requestHash: ok32,
      }),
    ).toThrow(/nonce must be 32 bytes/);
    expect(() =>
      attestChallengeMessage({
        domain: ATTEST_BALANCE_CHALLENGE_DOMAIN,
        nonce: ok32,
        chanBind: new Uint8Array(16),
        subjectRaw: ok32,
        expiry: 1n,
        requestHash: ok32,
      }),
    ).toThrow(/chan_bind must be 32 bytes/);
    expect(() =>
      attestChallengeMessage({
        domain: ATTEST_BALANCE_CHALLENGE_DOMAIN,
        nonce: ok32,
        chanBind: ok32,
        subjectRaw: new Uint8Array(8),
        expiry: 1n,
        requestHash: ok32,
      }),
    ).toThrow(/subject must be 32 bytes/);
    expect(() =>
      attestChallengeMessage({
        domain: ATTEST_BALANCE_CHALLENGE_DOMAIN,
        nonce: ok32,
        chanBind: ok32,
        subjectRaw: ok32,
        expiry: -1n,
        requestHash: ok32,
      }),
    ).toThrow(/expiry out of u64 range/);
    expect(() =>
      attestChallengeMessage({
        domain: ATTEST_BALANCE_CHALLENGE_DOMAIN,
        nonce: ok32,
        chanBind: ok32,
        subjectRaw: ok32,
        expiry: 1n,
        requestHash: new Uint8Array(33),
      }),
    ).toThrow(/request_hash must be 32 bytes/);
    expect(() => attestRequestHash(new Uint8Array(31), ok32, new Uint8Array([0x00]))).toThrow(
      /subject must be 32 bytes/,
    );
    expect(() => attestRequestHash(ok32, new Uint8Array(31), new Uint8Array([0x00]))).toThrow(
      /asset_id must be 32 bytes/,
    );
  });

  it('buildAttestOwnershipProof rejects wrong domain and bad field lengths', () => {
    const challenge: PullChallenge = {
      nonce: 'aa'.repeat(32),
      expiry: '1700000000',
      domain: PULL_CHALLENGE_DOMAIN,
    };
    expect(() =>
      buildAttestOwnershipProof({
        subject,
        sk0: sk0.secretKey,
        nkCommit,
        challenge,
        host,
        assetId,
      }),
    ).toThrow(/unexpected challenge domain/);

    const goodChallenge: PullChallenge = {
      nonce: 'aa'.repeat(32),
      expiry: '1700000000',
      domain: ATTEST_BALANCE_CHALLENGE_DOMAIN,
    };
    expect(() =>
      buildAttestOwnershipProof({
        subject,
        sk0: sk0.secretKey,
        nkCommit: new Uint8Array(16),
        challenge: goodChallenge,
        host,
        assetId,
      }),
    ).toThrow(/nk_commit must be 32 bytes/);
    expect(() =>
      buildAttestOwnershipProof({
        subject,
        sk0: sk0.secretKey,
        nkCommit,
        challenge: goodChallenge,
        host,
        assetId: new Uint8Array(8),
      }),
    ).toThrow(/asset_id must be 32 bytes/);
  });

  it('buildAttestOwnershipProof rejects subject that does not match Pk0||nk_commit', () => {
    const foreignSubject = encodeZkAddress(sha256(new Uint8Array(64)));
    const goodChallenge: PullChallenge = {
      nonce: 'aa'.repeat(32),
      expiry: '1700000000',
      domain: ATTEST_BALANCE_CHALLENGE_DOMAIN,
    };
    expect(() =>
      buildAttestOwnershipProof({
        subject: foreignSubject,
        sk0: sk0.secretKey,
        nkCommit,
        challenge: goodChallenge,
        host,
        assetId,
      }),
    ).toThrow(/subject does not match/);
  });

  // ---- 3. Signature round-trip (with and without ceilings) ----

  it('OwnershipProof verifies under BIP-340 over attest chal (no ceilings)', () => {
    const nonce = new Uint8Array(32).fill(0xbb);
    const expiry = 1_700_000_060n;
    const challenge = {
      nonce: encodeHexLower(nonce),
      expiry: expiry.toString(),
      domain: ATTEST_BALANCE_CHALLENGE_DOMAIN,
    };
    const proof = buildAttestOwnershipProof({
      subject,
      sk0: sk0.secretKey,
      nkCommit,
      challenge,
      host,
      assetId,
    });
    const ceilingEnc = ceilingEncoding(undefined, undefined);
    const requestHash = attestRequestHash(subjectRaw, assetId, ceilingEnc);
    const chal = attestChallengeMessage({
      domain: ATTEST_BALANCE_CHALLENGE_DOMAIN,
      nonce,
      chanBind: chanBindForHost(host),
      subjectRaw,
      expiry,
      requestHash,
    });
    expect(schnorr.verify(hexToBytes(proof.signature), chal, hexToBytes(proof.public_key))).toBe(
      true,
    );
    expect(proof.public_key).toBe(encodeHexLower(sk0.publicKey));
    expect(proof.subject).toBe(subject);
    expect(proof.nk_commit).toBe(encodeHexLower(nkCommit));
    expect(proof.type).toBe('ownership');
  });

  it('OwnershipProof verifies under BIP-340 over attest chal (with ceilings)', () => {
    const nonce = new Uint8Array(32).fill(0xcc);
    const expiry = 1_700_000_070n;
    const navCeiling = new Uint8Array(32).fill(0x05);
    const sizeCeiling = 42n;
    const challenge = {
      nonce: encodeHexLower(nonce),
      expiry: expiry.toString(),
      domain: ATTEST_BALANCE_CHALLENGE_DOMAIN,
    };
    const proof = buildAttestOwnershipProof({
      subject,
      sk0: sk0.secretKey,
      nkCommit,
      challenge,
      host,
      assetId,
      navCeiling,
      sizeCeiling,
    });
    const ceilingEnc = ceilingEncoding(navCeiling, sizeCeiling);
    const requestHash = attestRequestHash(subjectRaw, assetId, ceilingEnc);
    const chal = attestChallengeMessage({
      domain: ATTEST_BALANCE_CHALLENGE_DOMAIN,
      nonce,
      chanBind: chanBindForHost(host),
      subjectRaw,
      expiry,
      requestHash,
    });
    expect(schnorr.verify(hexToBytes(proof.signature), chal, hexToBytes(proof.public_key))).toBe(
      true,
    );
    expect(proof.public_key).toBe(encodeHexLower(sk0.publicKey));
    expect(proof.subject).toBe(subject);
    expect(proof.nk_commit).toBe(encodeHexLower(nkCommit));
  });

  // ---- 4. HTTP-level (msw) ----

  it('openAttestBalanceChallenge posts subject and rejects mismatched domain', async () => {
    const nonce = 'dd'.repeat(32);
    const expiry = '1700000080';
    server.use(
      http.post(`${BASE}/v1/attest/balance/challenge`, async ({ request }) => {
        const raw: unknown = await request.json();
        if (!isJsonRecord(raw) || typeof raw['subject'] !== 'string') {
          throw new Error('attest/balance/challenge body: expected { subject: string }');
        }
        expect(raw['subject']).toBe(subject);
        return HttpResponse.json({
          nonce,
          expiry,
          domain: ATTEST_BALANCE_CHALLENGE_DOMAIN,
        });
      }),
    );
    const challenge = await newClient().openAttestBalanceChallenge(
      subject,
      new AbortController().signal,
    );
    expect(challenge.nonce).toBe(nonce);
    expect(challenge.expiry).toBe(expiry);
    expect(challenge.domain).toBe(ATTEST_BALANCE_CHALLENGE_DOMAIN);

    await expect(newClient().openAttestBalanceChallenge('')).rejects.toThrow(/subject is required/);

    server.use(
      http.post(`${BASE}/v1/attest/balance/challenge`, () =>
        HttpResponse.json({
          nonce,
          expiry,
          domain: PULL_CHALLENGE_DOMAIN,
        }),
      ),
    );
    await expect(newClient().openAttestBalanceChallenge(subject)).rejects.toThrow(
      /AttestBalanceChallenge\.domain/,
    );

    server.use(
      http.post(
        `${BASE}/v1/attest/balance/challenge`,
        () =>
          new HttpResponse(JSON.stringify('not-an-object'), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          }),
      ),
    );
    await expect(newClient().openAttestBalanceChallenge(subject)).rejects.toThrow(
      /AttestBalanceChallenge: expected object/,
    );
  });

  it('openAttestBalanceChallenge rejects non-canonical nonce and expiry', async () => {
    const badCases: Array<{ nonce: string; expiry: string; re: RegExp }> = [
      {
        nonce: '',
        expiry: '1700000080',
        re: /AttestBalanceChallenge\.nonce.*expected 64 hex chars/,
      },
      {
        nonce: 'a'.repeat(63),
        expiry: '1700000080',
        re: /AttestBalanceChallenge\.nonce.*expected 64 hex chars/,
      },
      {
        nonce: 'AA'.repeat(32),
        expiry: '1700000080',
        re: /AttestBalanceChallenge\.nonce.*non-canonical hex/,
      },
      {
        nonce: 'aa'.repeat(16),
        expiry: '1700000080',
        re: /AttestBalanceChallenge\.nonce.*expected 64 hex chars/,
      },
      { nonce: 'dd'.repeat(32), expiry: '01', re: /leading zeros are not allowed/ },
      { nonce: 'dd'.repeat(32), expiry: '12a', re: /not a canonical u64 decimal/ },
    ];
    for (const c of badCases) {
      server.use(
        http.post(`${BASE}/v1/attest/balance/challenge`, () =>
          HttpResponse.json({
            nonce: c.nonce,
            expiry: c.expiry,
            domain: ATTEST_BALANCE_CHALLENGE_DOMAIN,
          }),
        ),
      );
      await expect(newClient().openAttestBalanceChallenge(subject)).rejects.toThrow(c.re);
    }
  });

  it('attestBalance full flow without ceilings: body omits ceilings, 202 { job_id } only', async () => {
    const nonce = 'ee'.repeat(32);
    const expiry = '1700000090';
    let posted: Record<string, unknown> | undefined;

    server.use(
      http.post(`${BASE}/v1/attest/balance/challenge`, async ({ request }) => {
        const raw: unknown = await request.json();
        if (!isJsonRecord(raw)) throw new Error('challenge body: expected object');
        expect(raw['subject']).toBe(subject);
        return HttpResponse.json({
          nonce,
          expiry,
          domain: ATTEST_BALANCE_CHALLENGE_DOMAIN,
        });
      }),
      http.post(`${BASE}/v1/attest/balance`, async ({ request }) => {
        const raw: unknown = await request.json();
        if (!isJsonRecord(raw)) throw new Error('attest body: expected object');
        posted = raw;
        const proofRaw = raw['ownership_proof'];
        if (!isJsonRecord(proofRaw) || typeof proofRaw['signature'] !== 'string') {
          throw new Error('attest body: expected ownership_proof.signature string');
        }
        expect(raw['subject']).toBe(subject);
        expect(raw['asset_id']).toBe(encodeHexLower(assetId));
        expect(raw['nav_ceiling']).toBeUndefined();
        expect(raw['size_ceiling']).toBeUndefined();
        expect('nav_ceiling' in raw).toBe(false);
        expect('size_ceiling' in raw).toBe(false);
        const ch = raw['challenge'];
        if (!isJsonRecord(ch)) throw new Error('challenge: expected object');
        expect(ch['nonce']).toBe(nonce);
        expect(ch['expiry']).toBe(expiry);
        expect(ch['domain']).toBeUndefined();
        expect('domain' in ch).toBe(false);
        expect(proofRaw['type']).toBe('ownership');
        expect(proofRaw['signature']).toMatch(/^[0-9a-f]{128}$/);
        // No status field — only job_id (api/src/attest.rs L174–188).
        return HttpResponse.json({ job_id: 'attest-job-1' }, { status: 202 });
      }),
    );

    const result = await newClient().attestBalance({
      subject,
      sk0: sk0.secretKey,
      nkCommit,
      assetId,
    });
    expect(result.job_id).toBe('attest-job-1');
    expect(posted).toBeDefined();
  });

  it('attestBalance full flow with ceilings: nav_ceiling hex + size_ceiling decimal string', async () => {
    const nonce = 'ff'.repeat(32);
    const expiry = '1700000100';
    const navCeiling = new Uint8Array(32).fill(0x07);
    const sizeCeiling = 99;

    server.use(
      http.post(`${BASE}/v1/attest/balance/challenge`, () =>
        HttpResponse.json({
          nonce,
          expiry,
          domain: ATTEST_BALANCE_CHALLENGE_DOMAIN,
        }),
      ),
      http.post(`${BASE}/v1/attest/balance`, async ({ request }) => {
        const raw: unknown = await request.json();
        if (!isJsonRecord(raw)) throw new Error('attest body: expected object');
        expect(raw['nav_ceiling']).toBe(encodeHexLower(navCeiling));
        // §7.1: size_ceiling is a decimal *string*, not a JSON number.
        expect(raw['size_ceiling']).toBe('99');
        expect(typeof raw['size_ceiling']).toBe('string');
        const proofRaw = raw['ownership_proof'];
        if (!isJsonRecord(proofRaw) || typeof proofRaw['signature'] !== 'string') {
          throw new Error('attest body: expected ownership_proof.signature string');
        }
        expect(proofRaw['signature']).toMatch(/^[0-9a-f]{128}$/);
        return HttpResponse.json({ job_id: 'attest-job-ceil' }, { status: 202 });
      }),
    );

    const result = await newClient().attestBalance(
      {
        subject,
        sk0: sk0.secretKey,
        nkCommit,
        assetId,
        navCeiling,
        sizeCeiling,
      },
      new AbortController().signal,
    );
    expect(result.job_id).toBe('attest-job-ceil');
  });

  it('attestBalance rejects mixed ceilings before any network call', async () => {
    // No handlers registered: msw onUnhandledRequest: 'error' would fail if
    // a request were attempted.
    await expect(
      newClient().attestBalance({
        subject,
        sk0: sk0.secretKey,
        nkCommit,
        assetId,
        navCeiling: new Uint8Array(32).fill(1),
      }),
    ).rejects.toThrow(/both be present or both omitted/);

    await expect(
      newClient().attestBalance({
        subject,
        sk0: sk0.secretKey,
        nkCommit,
        assetId,
        sizeCeiling: 1n,
      }),
    ).rejects.toThrow(/both be present or both omitted/);
  });

  it('parseAttestBalanceAccepted rejects non-object body', async () => {
    server.use(
      http.post(`${BASE}/v1/attest/balance/challenge`, () =>
        HttpResponse.json({
          nonce: '11'.repeat(32),
          expiry: '1',
          domain: ATTEST_BALANCE_CHALLENGE_DOMAIN,
        }),
      ),
      http.post(
        `${BASE}/v1/attest/balance`,
        () =>
          new HttpResponse(JSON.stringify('accepted-please'), {
            status: 202,
            headers: { 'Content-Type': 'application/json' },
          }),
      ),
    );
    await expect(
      newClient().attestBalance({
        subject,
        sk0: sk0.secretKey,
        nkCommit,
        assetId,
      }),
    ).rejects.toThrow(/AttestBalanceAccepted: expected object/);
  });

  it('parseAttestBalanceAccepted rejects an empty job_id', async () => {
    server.use(
      http.post(`${BASE}/v1/attest/balance/challenge`, () =>
        HttpResponse.json({
          nonce: '12'.repeat(32),
          expiry: '1',
          domain: ATTEST_BALANCE_CHALLENGE_DOMAIN,
        }),
      ),
      http.post(`${BASE}/v1/attest/balance`, () =>
        HttpResponse.json({ job_id: '' }, { status: 202 }),
      ),
    );
    await expect(
      newClient().attestBalance({
        subject,
        sk0: sk0.secretKey,
        nkCommit,
        assetId,
      }),
    ).rejects.toThrow(/AttestBalanceAccepted\.job_id is empty/);
  });
});

describe('ViewGrant request surface', () => {
  const seed = seedFromMnemonicV1(
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
  );
  const sk0 = deriveSpendKey(seed, 0, 0);
  const grantee = deriveSpendKey(seed, 0, 1);
  const nkCommit = new Uint8Array(32);
  const subjectRaw = sha256(
    (() => {
      const pre = new Uint8Array(64);
      pre.set(sk0.publicKey, 0);
      pre.set(nkCommit, 32);
      return pre;
    })(),
  );
  const subject = encodeZkAddress(subjectRaw);
  const host = 'node.test';
  const granteePk = grantee.publicKey;
  const grantExpiry = 1700000000n;
  // Opaque blob — SDK never decodes zkgrant payloads.
  const OPAQUE_GRANT = 'zkgrant1qptestopaque-test-grant';

  // ---- 1. Known-answer vectors ----

  it('encodeGrantAssetIds: allAssets → single 0x00 byte', () => {
    expect(Array.from(encodeGrantAssetIds(true, []))).toEqual([0x00]);
  });

  it('encodeGrantAssetIds: explicit list → 0x01 ‖ u32-be count ‖ ascending ids', () => {
    const enc = encodeGrantAssetIds(false, [
      new Uint8Array(32).fill(0x03),
      new Uint8Array(32).fill(0x04),
    ]);
    expect(encodeHexLower(enc)).toBe(
      '010000000203030303030303030303030303030303030303030303030303030303030303030404040404040404040404040404040404040404040404040404040404040404',
    );
    expect(enc.length).toBe(69);
  });

  it('issueGrantRequestHash KAT: subject=[1;32], grantee=[2;32], asset=0x00, defaults, expiry=1700000000', () => {
    const h = issueGrantRequestHash(
      new Uint8Array(32).fill(0x01),
      new Uint8Array(32).fill(0x02),
      encodeGrantAssetIds(true, []),
      0n,
      SCOPE_NOT_AFTER_UNBOUNDED,
      1700000000n,
    );
    expect(encodeHexLower(h)).toBe(
      'a288dab5ad9f25eb3328a3d502b93b51ead04e9417857e035eb4ffb7541383dc',
    );
  });

  it('issueGrantRequestHash KAT: subject=[1;32], grantee=[2;32], two assets, not_before=100, not_after=200', () => {
    const h = issueGrantRequestHash(
      new Uint8Array(32).fill(0x01),
      new Uint8Array(32).fill(0x02),
      encodeGrantAssetIds(false, [new Uint8Array(32).fill(0x03), new Uint8Array(32).fill(0x04)]),
      100n,
      200n,
      1700000000n,
    );
    expect(encodeHexLower(h)).toBe(
      '02a753abd0f7368ac1498bdeeed58ee5fe10501c3395d18b1990f708f60981d8',
    );
  });

  it('grantScopeToJsonBody: allAssets emits "*" and resolved bounds', () => {
    expect(grantScopeToJsonBody({ allAssets: true })).toEqual({
      asset_ids: '*',
      not_before: '0',
      not_after: SCOPE_NOT_AFTER_UNBOUNDED.toString(),
    });
    expect(grantScopeToJsonBody({ allAssets: true, notBefore: 10n, notAfter: 20n })).toEqual({
      asset_ids: '*',
      not_before: '10',
      not_after: '20',
    });
  });

  it('grantScopeToJsonBody: explicit assetIds as lowercase hex32 in caller order', () => {
    const a = new Uint8Array(32).fill(0x0a);
    const b = new Uint8Array(32).fill(0x0b);
    expect(grantScopeToJsonBody({ assetIds: [a, b], notBefore: 1n })).toEqual({
      asset_ids: [encodeHexLower(a), encodeHexLower(b)],
      not_before: '1',
      not_after: SCOPE_NOT_AFTER_UNBOUNDED.toString(),
    });
  });

  // ---- 2. Error paths / no-silent-fallback ----

  it('encodeGrantAssetIds rejects empty list, non-empty under "*", wrong length, non-ascending', () => {
    expect(() => encodeGrantAssetIds(true, [new Uint8Array(32)])).toThrow(
      /must be empty when asset_ids is "\*"/,
    );
    expect(() => encodeGrantAssetIds(false, [])).toThrow(/must be non-empty when not "\*"/);
    expect(() => encodeGrantAssetIds(false, [new Uint8Array(16)])).toThrow(
      /asset_ids\[0\] must be 32 bytes/,
    );
    const id = new Uint8Array(32).fill(0x05);
    expect(() => encodeGrantAssetIds(false, [id, id])).toThrow(/strictly ascending/);
    const high = new Uint8Array(32).fill(0x09);
    const low = new Uint8Array(32).fill(0x01);
    expect(() => encodeGrantAssetIds(false, [high, low])).toThrow(/strictly ascending/);
  });

  it('grantScopeToJsonBody rejects contradictory and malformed asset scopes', () => {
    const id = new Uint8Array(32).fill(0x05);
    // runtime-invalid shape: allAssets true with non-empty assetIds — static GrantScopeInput forbids it
    const contradictoryScope = {
      allAssets: true,
      assetIds: [id],
    } as unknown as GrantScopeInput;
    expect(() => grantScopeToJsonBody(contradictoryScope)).toThrow(/allAssets.*assetIds/);
    expect(() => grantScopeToJsonBody({ assetIds: [] })).toThrow(/must be non-empty when not "\*"/);
    expect(() => grantScopeToJsonBody({ assetIds: [new Uint8Array(16)] })).toThrow(
      /asset_ids\[0\] must be 32 bytes/,
    );
    expect(() => grantScopeToJsonBody({ assetIds: [id, id] })).toThrow(/strictly ascending/);
    expect(() =>
      grantScopeToJsonBody({
        assetIds: [new Uint8Array(32).fill(0x09), new Uint8Array(32).fill(0x01)],
      }),
    ).toThrow(/strictly ascending/);
  });

  it('issueGrantRequestHash rejects wrong 32-byte fields and out-of-range u64', () => {
    const ok32 = new Uint8Array(32);
    const assetEnc = encodeGrantAssetIds(true, []);
    expect(() => issueGrantRequestHash(new Uint8Array(31), ok32, assetEnc, 0n, 1n, 1n)).toThrow(
      /subject must be 32 bytes/,
    );
    expect(() => issueGrantRequestHash(ok32, new Uint8Array(31), assetEnc, 0n, 1n, 1n)).toThrow(
      /grantee_pk must be 32 bytes/,
    );
    expect(() => issueGrantRequestHash(ok32, ok32, assetEnc, -1n, 1n, 1n)).toThrow(
      /not_before out of u64 range/,
    );
    expect(() => issueGrantRequestHash(ok32, ok32, assetEnc, 0n, -1n, 1n)).toThrow(
      /not_after out of u64 range/,
    );
    expect(() =>
      issueGrantRequestHash(ok32, ok32, assetEnc, 0n, 1n, 0x1_0000_0000_0000_0000n),
    ).toThrow(/grant_expiry out of u64 range/);
  });

  it('grantScopeToJsonBody rejects out-of-range not_before / not_after', () => {
    expect(() => grantScopeToJsonBody({ allAssets: true, notBefore: -1n })).toThrow(
      /not_before out of u64 range/,
    );
    expect(() =>
      grantScopeToJsonBody({ allAssets: true, notAfter: 0x1_0000_0000_0000_0000n }),
    ).toThrow(/not_after out of u64 range/);
  });

  it('buildIssueGrantOwnershipProof rejects wrong domain and bad field lengths', () => {
    const challenge: PullChallenge = {
      nonce: 'aa'.repeat(32),
      expiry: '1700000000',
      domain: PULL_CHALLENGE_DOMAIN,
    };
    expect(() =>
      buildIssueGrantOwnershipProof({
        subject,
        sk0: sk0.secretKey,
        nkCommit,
        challenge,
        host,
        granteePk,
        scope: { allAssets: true },
        grantExpiry,
      }),
    ).toThrow(/unexpected challenge domain/);

    const goodChallenge: PullChallenge = {
      nonce: 'aa'.repeat(32),
      expiry: '1700000000',
      domain: ISSUE_GRANT_CHALLENGE_DOMAIN,
    };
    expect(() =>
      buildIssueGrantOwnershipProof({
        subject,
        sk0: sk0.secretKey,
        nkCommit: new Uint8Array(16),
        challenge: goodChallenge,
        host,
        granteePk,
        scope: { allAssets: true },
        grantExpiry,
      }),
    ).toThrow(/nk_commit must be 32 bytes/);
    expect(() =>
      buildIssueGrantOwnershipProof({
        subject,
        sk0: sk0.secretKey,
        nkCommit,
        challenge: goodChallenge,
        host,
        granteePk: new Uint8Array(8),
        scope: { allAssets: true },
        grantExpiry,
      }),
    ).toThrow(/grantee_pk must be 32 bytes/);
  });

  it('buildIssueGrantOwnershipProof rejects subject that does not match Pk0||nk_commit', () => {
    const foreignSubject = encodeZkAddress(sha256(new Uint8Array(64)));
    const goodChallenge: PullChallenge = {
      nonce: 'aa'.repeat(32),
      expiry: '1700000000',
      domain: ISSUE_GRANT_CHALLENGE_DOMAIN,
    };
    expect(() =>
      buildIssueGrantOwnershipProof({
        subject: foreignSubject,
        sk0: sk0.secretKey,
        nkCommit,
        challenge: goodChallenge,
        host,
        granteePk,
        scope: { allAssets: true },
        grantExpiry,
      }),
    ).toThrow(/subject does not match/);
  });

  it('buildIssueGrantOwnershipProof rejects a contradictory asset scope', () => {
    const challenge: PullChallenge = {
      nonce: 'aa'.repeat(32),
      expiry: '1700000000',
      domain: ISSUE_GRANT_CHALLENGE_DOMAIN,
    };
    // runtime-invalid shape: allAssets true with non-empty assetIds — static GrantScopeInput forbids it
    const contradictoryScope = {
      allAssets: true,
      assetIds: [new Uint8Array(32)],
    } as unknown as GrantScopeInput;
    expect(() =>
      buildIssueGrantOwnershipProof({
        subject,
        sk0: sk0.secretKey,
        nkCommit,
        challenge,
        host,
        granteePk,
        scope: contradictoryScope,
        grantExpiry,
      }),
    ).toThrow(/allAssets.*assetIds/);
  });

  it('buildGrantProof rejects wrong domain, empty grant, and bad subject length', () => {
    const goodChallenge: PullChallenge = {
      nonce: 'aa'.repeat(32),
      expiry: '1700000000',
      domain: PULL_CHALLENGE_DOMAIN,
    };
    expect(() =>
      buildGrantProof({
        grant: OPAQUE_GRANT,
        granteeSecret: grantee.secretKey,
        subjectRaw,
        challenge: {
          nonce: 'aa'.repeat(32),
          expiry: '1700000000',
          domain: ISSUE_GRANT_CHALLENGE_DOMAIN,
        },
        host,
      }),
    ).toThrow(/unexpected challenge domain/);
    expect(() =>
      buildGrantProof({
        grant: '',
        granteeSecret: grantee.secretKey,
        subjectRaw,
        challenge: goodChallenge,
        host,
      }),
    ).toThrow(/grant is required/);
    expect(() =>
      buildGrantProof({
        grant: OPAQUE_GRANT,
        granteeSecret: grantee.secretKey,
        subjectRaw: new Uint8Array(16),
        challenge: goodChallenge,
        host,
      }),
    ).toThrow(/subject must be 32 bytes/);
  });

  // ---- 3. Signature round-trips ----

  it('OwnershipProof verifies under BIP-340 over issue-grant chal (allAssets)', () => {
    const nonce = new Uint8Array(32).fill(0xbb);
    const expiry = 1_700_000_060n;
    const challenge = {
      nonce: encodeHexLower(nonce),
      expiry: expiry.toString(),
      domain: ISSUE_GRANT_CHALLENGE_DOMAIN,
    };
    const scope = { allAssets: true as const };
    const proof = buildIssueGrantOwnershipProof({
      subject,
      sk0: sk0.secretKey,
      nkCommit,
      challenge,
      host,
      granteePk,
      scope,
      grantExpiry,
    });
    const assetEnc = encodeGrantAssetIds(true, []);
    const requestHash = issueGrantRequestHash(
      subjectRaw,
      granteePk,
      assetEnc,
      0n,
      SCOPE_NOT_AFTER_UNBOUNDED,
      grantExpiry,
    );
    const chal = attestChallengeMessage({
      domain: ISSUE_GRANT_CHALLENGE_DOMAIN,
      nonce,
      chanBind: chanBindForHost(host),
      subjectRaw,
      expiry,
      requestHash,
    });
    expect(schnorr.verify(hexToBytes(proof.signature), chal, hexToBytes(proof.public_key))).toBe(
      true,
    );
    expect(proof.public_key).toBe(encodeHexLower(sk0.publicKey));
    expect(proof.subject).toBe(subject);
    expect(proof.nk_commit).toBe(encodeHexLower(nkCommit));
    expect(proof.type).toBe('ownership');
  });

  it('OwnershipProof verifies under BIP-340 over issue-grant chal (explicit assetIds)', () => {
    const nonce = new Uint8Array(32).fill(0xcc);
    const expiry = 1_700_000_070n;
    const assetIds = [new Uint8Array(32).fill(0x03), new Uint8Array(32).fill(0x04)];
    const challenge = {
      nonce: encodeHexLower(nonce),
      expiry: expiry.toString(),
      domain: ISSUE_GRANT_CHALLENGE_DOMAIN,
    };
    const scope = { assetIds, notBefore: 100n, notAfter: 200n };
    const proof = buildIssueGrantOwnershipProof({
      subject,
      sk0: sk0.secretKey,
      nkCommit,
      challenge,
      host,
      granteePk,
      scope,
      grantExpiry,
    });
    const assetEnc = encodeGrantAssetIds(false, assetIds);
    const requestHash = issueGrantRequestHash(
      subjectRaw,
      granteePk,
      assetEnc,
      100n,
      200n,
      grantExpiry,
    );
    const chal = attestChallengeMessage({
      domain: ISSUE_GRANT_CHALLENGE_DOMAIN,
      nonce,
      chanBind: chanBindForHost(host),
      subjectRaw,
      expiry,
      requestHash,
    });
    expect(schnorr.verify(hexToBytes(proof.signature), chal, hexToBytes(proof.public_key))).toBe(
      true,
    );
    expect(proof.public_key).toBe(encodeHexLower(sk0.publicKey));
    expect(proof.subject).toBe(subject);
    expect(proof.nk_commit).toBe(encodeHexLower(nkCommit));
  });

  it('GrantProof verifies under BIP-340 over plain pull chal', () => {
    const nonce = new Uint8Array(32).fill(0xdd);
    const expiry = 1_700_000_080n;
    const challenge: PullChallenge = {
      nonce: encodeHexLower(nonce),
      expiry: expiry.toString(),
      domain: PULL_CHALLENGE_DOMAIN,
    };
    const proof = buildGrantProof({
      grant: OPAQUE_GRANT,
      granteeSecret: grantee.secretKey,
      subjectRaw,
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
    expect(schnorr.verify(hexToBytes(proof.signature), chal, hexToBytes(proof.grantee_pk))).toBe(
      true,
    );
    expect(proof.type).toBe('grant');
    expect(proof.grant).toBe(OPAQUE_GRANT);
    expect(proof.grantee_pk).toBe(encodeHexLower(grantee.publicKey));
  });

  // ---- 4. HTTP-level (msw) ----

  it('openGrantsChallenge posts subject and rejects mismatched domain', async () => {
    const nonce = 'ee'.repeat(32);
    const expiry = '1700000080';
    server.use(
      http.post(`${BASE}/v1/grants/challenge`, async ({ request }) => {
        const raw: unknown = await request.json();
        if (!isJsonRecord(raw) || typeof raw['subject'] !== 'string') {
          throw new Error('grants/challenge body: expected { subject: string }');
        }
        expect(raw['subject']).toBe(subject);
        return HttpResponse.json({
          nonce,
          expiry,
          domain: ISSUE_GRANT_CHALLENGE_DOMAIN,
        });
      }),
    );
    const challenge = await newClient().openGrantsChallenge(subject, new AbortController().signal);
    expect(challenge.nonce).toBe(nonce);
    expect(challenge.expiry).toBe(expiry);
    expect(challenge.domain).toBe(ISSUE_GRANT_CHALLENGE_DOMAIN);

    await expect(newClient().openGrantsChallenge('')).rejects.toThrow(/subject is required/);

    server.use(
      http.post(`${BASE}/v1/grants/challenge`, () =>
        HttpResponse.json({
          nonce,
          expiry,
          domain: PULL_CHALLENGE_DOMAIN,
        }),
      ),
    );
    await expect(newClient().openGrantsChallenge(subject)).rejects.toThrow(
      /GrantsChallenge\.domain/,
    );

    server.use(
      http.post(
        `${BASE}/v1/grants/challenge`,
        () =>
          new HttpResponse(JSON.stringify('not-an-object'), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          }),
      ),
    );
    await expect(newClient().openGrantsChallenge(subject)).rejects.toThrow(
      /GrantsChallenge: expected object/,
    );
  });

  it('openGrantsChallenge rejects non-canonical nonce and expiry', async () => {
    const badCases: Array<{ nonce: string; expiry: string; re: RegExp }> = [
      { nonce: '', expiry: '1700000080', re: /GrantsChallenge\.nonce.*expected 64 hex chars/ },
      {
        nonce: 'a'.repeat(63),
        expiry: '1700000080',
        re: /GrantsChallenge\.nonce.*expected 64 hex chars/,
      },
      {
        nonce: 'AA'.repeat(32),
        expiry: '1700000080',
        re: /GrantsChallenge\.nonce.*non-canonical hex/,
      },
      {
        nonce: 'aa'.repeat(16),
        expiry: '1700000080',
        re: /GrantsChallenge\.nonce.*expected 64 hex chars/,
      },
      { nonce: 'ee'.repeat(32), expiry: '01', re: /leading zeros are not allowed/ },
      { nonce: 'ee'.repeat(32), expiry: '12a', re: /not a canonical u64 decimal/ },
    ];
    for (const c of badCases) {
      server.use(
        http.post(`${BASE}/v1/grants/challenge`, () =>
          HttpResponse.json({
            nonce: c.nonce,
            expiry: c.expiry,
            domain: ISSUE_GRANT_CHALLENGE_DOMAIN,
          }),
        ),
      );
      await expect(newClient().openGrantsChallenge(subject)).rejects.toThrow(c.re);
    }
  });

  it('issueViewGrant full flow with allAssets: scope "*", explicit not_before/not_after', async () => {
    const nonce = '11'.repeat(32);
    const expiry = '1700000090';
    let posted: Record<string, unknown> | undefined;

    server.use(
      http.post(`${BASE}/v1/grants/challenge`, async ({ request }) => {
        const raw: unknown = await request.json();
        if (!isJsonRecord(raw)) throw new Error('challenge body: expected object');
        expect(raw['subject']).toBe(subject);
        return HttpResponse.json({
          nonce,
          expiry,
          domain: ISSUE_GRANT_CHALLENGE_DOMAIN,
        });
      }),
      http.post(`${BASE}/v1/grants`, async ({ request }) => {
        const raw: unknown = await request.json();
        if (!isJsonRecord(raw)) throw new Error('grants body: expected object');
        posted = raw;
        const proofRaw = raw['ownership_proof'];
        if (!isJsonRecord(proofRaw) || typeof proofRaw['signature'] !== 'string') {
          throw new Error('grants body: expected ownership_proof.signature string');
        }
        expect(raw['subject']).toBe(subject);
        expect(raw['grantee_pk']).toBe(encodeHexLower(granteePk));
        expect(raw['expiry']).toBe(grantExpiry.toString());
        const scope = raw['scope'];
        if (!isJsonRecord(scope)) throw new Error('scope: expected object');
        expect(scope['asset_ids']).toBe('*');
        expect(scope['not_before']).toBe('0');
        expect(scope['not_after']).toBe(SCOPE_NOT_AFTER_UNBOUNDED.toString());
        const ch = raw['challenge'];
        if (!isJsonRecord(ch)) throw new Error('challenge: expected object');
        expect(ch['nonce']).toBe(nonce);
        expect(ch['expiry']).toBe(expiry);
        expect(ch['domain']).toBeUndefined();
        expect('domain' in ch).toBe(false);
        expect(proofRaw['type']).toBe('ownership');
        expect(proofRaw['signature']).toMatch(/^[0-9a-f]{128}$/);
        return HttpResponse.json({ grant: OPAQUE_GRANT });
      }),
    );

    const result = await newClient().issueViewGrant({
      subject,
      sk0: sk0.secretKey,
      nkCommit,
      granteePk,
      scope: { allAssets: true },
      grantExpiry,
    });
    expect(result.grant).toBe(OPAQUE_GRANT);
    expect(posted).toBeDefined();
  });

  it('issueViewGrant full flow with explicit assetIds and custom bounds', async () => {
    const nonce = '22'.repeat(32);
    const expiry = '1700000100';
    const assetIds = [new Uint8Array(32).fill(0x03), new Uint8Array(32).fill(0x04)];

    server.use(
      http.post(`${BASE}/v1/grants/challenge`, () =>
        HttpResponse.json({
          nonce,
          expiry,
          domain: ISSUE_GRANT_CHALLENGE_DOMAIN,
        }),
      ),
      http.post(`${BASE}/v1/grants`, async ({ request }) => {
        const raw: unknown = await request.json();
        if (!isJsonRecord(raw)) throw new Error('grants body: expected object');
        const scope = raw['scope'];
        if (!isJsonRecord(scope)) throw new Error('scope: expected object');
        expect(scope['asset_ids']).toEqual([
          encodeHexLower(assetIds[0]!),
          encodeHexLower(assetIds[1]!),
        ]);
        expect(scope['not_before']).toBe('100');
        expect(scope['not_after']).toBe('200');
        const proofRaw = raw['ownership_proof'];
        if (!isJsonRecord(proofRaw) || typeof proofRaw['signature'] !== 'string') {
          throw new Error('grants body: expected ownership_proof.signature string');
        }
        expect(proofRaw['signature']).toMatch(/^[0-9a-f]{128}$/);
        return HttpResponse.json({ grant: 'zkgrant1explicit' });
      }),
    );

    const result = await newClient().issueViewGrant(
      {
        subject,
        sk0: sk0.secretKey,
        nkCommit,
        granteePk,
        scope: { assetIds, notBefore: 100n, notAfter: 200n },
        grantExpiry,
      },
      new AbortController().signal,
    );
    expect(result.grant).toBe('zkgrant1explicit');
  });

  it('issueViewGrant rejects bad scope before any network call', async () => {
    // No handlers registered: msw onUnhandledRequest: 'error' would fail if
    // a request were attempted.
    await expect(
      newClient().issueViewGrant({
        subject,
        sk0: sk0.secretKey,
        nkCommit,
        granteePk,
        scope: { assetIds: [] },
        grantExpiry,
      }),
    ).rejects.toThrow(/must be non-empty when not "\*"/);

    const unsorted = [new Uint8Array(32).fill(0x09), new Uint8Array(32).fill(0x01)];
    await expect(
      newClient().issueViewGrant({
        subject,
        sk0: sk0.secretKey,
        nkCommit,
        granteePk,
        scope: { assetIds: unsorted },
        grantExpiry,
      }),
    ).rejects.toThrow(/strictly ascending/);
  });

  it('parseIssueGrantResult rejects non-object body', async () => {
    server.use(
      http.post(`${BASE}/v1/grants/challenge`, () =>
        HttpResponse.json({
          nonce: '33'.repeat(32),
          expiry: '1',
          domain: ISSUE_GRANT_CHALLENGE_DOMAIN,
        }),
      ),
      http.post(
        `${BASE}/v1/grants`,
        () =>
          new HttpResponse(JSON.stringify('not-a-grant'), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          }),
      ),
    );
    await expect(
      newClient().issueViewGrant({
        subject,
        sk0: sk0.secretKey,
        nkCommit,
        granteePk,
        scope: { allAssets: true },
        grantExpiry,
      }),
    ).rejects.toThrow(/IssueGrantResult: expected object/);
  });

  it('parseIssueGrantResult rejects an empty grant', async () => {
    server.use(
      http.post(`${BASE}/v1/grants/challenge`, () =>
        HttpResponse.json({
          nonce: '34'.repeat(32),
          expiry: '1',
          domain: ISSUE_GRANT_CHALLENGE_DOMAIN,
        }),
      ),
      http.post(`${BASE}/v1/grants`, () => HttpResponse.json({ grant: '' })),
    );
    await expect(
      newClient().issueViewGrant({
        subject,
        sk0: sk0.secretKey,
        nkCommit,
        granteePk,
        scope: { allAssets: true },
        grantExpiry,
      }),
    ).rejects.toThrow(/IssueGrantResult\.grant is empty/);
  });

  it('openGrantPullSession posts challenge then pull with GrantProof; no scope when omitted', async () => {
    const nonce = '44'.repeat(32);
    const expiry = '1700000110';
    let pullBody: Record<string, unknown> | undefined;

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
        if (!isJsonRecord(raw)) throw new Error('pull body: expected object');
        pullBody = raw;
        const proofRaw = raw['proof'];
        if (!isJsonRecord(proofRaw) || typeof proofRaw['signature'] !== 'string') {
          throw new Error('pull body: expected proof.signature string');
        }
        expect(raw['nonce']).toBe(nonce);
        expect(raw['expiry']).toBe(expiry);
        expect(proofRaw['type']).toBe('grant');
        expect(proofRaw['grant']).toBe(OPAQUE_GRANT);
        expect(proofRaw['grantee_pk']).toBe(encodeHexLower(grantee.publicKey));
        expect(proofRaw['signature']).toMatch(/^[0-9a-f]{128}$/);
        expect(raw['scope']).toBeUndefined();
        expect('scope' in raw).toBe(false);
        return HttpResponse.json({
          records: [],
          session: 'grant-session-tok',
          session_expiry: '1700001000',
        });
      }),
    );

    const pull = await newClient().openGrantPullSession({
      subject,
      grant: OPAQUE_GRANT,
      granteeSecret: grantee.secretKey,
    });
    expect(pull.session).toBe('grant-session-tok');
    expect(pullBody).toBeDefined();
  });

  it('openGrantPullSession with scope echoes resolved scope on pull body', async () => {
    const nonce = '55'.repeat(32);
    const expiry = '1700000120';
    const assetIds = [new Uint8Array(32).fill(0x03)];

    server.use(
      http.post(`${BASE}/v1/pull/challenge`, () =>
        HttpResponse.json({
          nonce,
          expiry,
          domain: PULL_CHALLENGE_DOMAIN,
        }),
      ),
      http.post(`${BASE}/v1/pull`, async ({ request }) => {
        const raw: unknown = await request.json();
        if (!isJsonRecord(raw)) throw new Error('pull body: expected object');
        const scope = raw['scope'];
        if (!isJsonRecord(scope)) throw new Error('scope: expected object');
        expect(scope['asset_ids']).toEqual([encodeHexLower(assetIds[0]!)]);
        expect(scope['not_before']).toBe('0');
        expect(scope['not_after']).toBe(SCOPE_NOT_AFTER_UNBOUNDED.toString());
        const proofRaw = raw['proof'];
        if (!isJsonRecord(proofRaw)) throw new Error('proof: expected object');
        expect(proofRaw['type']).toBe('grant');
        return HttpResponse.json({
          records: [],
          session: 'grant-scope-session',
          session_expiry: '1700002000',
        });
      }),
    );

    const pull = await newClient().openGrantPullSession(
      {
        subject,
        grant: OPAQUE_GRANT,
        granteeSecret: grantee.secretKey,
      },
      { assetIds },
    );
    expect(pull.session).toBe('grant-scope-session');
  });

  it('openPullSession rejects a malformed scope before any network call', async () => {
    // No handlers registered: the validation error must occur before fetch.
    const badScope = {
      assetIds: [new Uint8Array(32).fill(0x09), new Uint8Array(32).fill(0x01)],
    };
    await expect(
      newClient().openPullSession({
        challenge: DUMMY_CHALLENGE,
        proof: DUMMY_OWNERSHIP_PROOF,
        scope: badScope,
      }),
    ).rejects.toThrow(/strictly ascending/);
  });

  it('openGrantPullSession rejects a malformed scope before any network call', async () => {
    // No handlers registered: even the challenge endpoint must not be called.
    const badScope = {
      assetIds: [new Uint8Array(32).fill(0x09), new Uint8Array(32).fill(0x01)],
    };
    await expect(
      newClient().openGrantPullSession(
        {
          subject,
          grant: OPAQUE_GRANT,
          granteeSecret: grantee.secretKey,
        },
        badScope,
      ),
    ).rejects.toThrow(/strictly ascending/);
  });

  it('constants match Rust ownership.rs literals', () => {
    expect(ISSUE_GRANT_CHALLENGE_DOMAIN).toBe('zkCoins/v1/IssueGrantChallenge');
    expect(ISSUE_GRANT_REQUEST_TAG).toBe('zkCoins/v1/IssueGrant');
    expect(SCOPE_NOT_AFTER_UNBOUNDED).toBe(9223372036854775807n);
  });

  // ---------------------------------------------------------------------------
  // parseJob completed-result kind branching (attest_balance vs transition)
  // ---------------------------------------------------------------------------

  it('getJob parses completed attest_balance wire form without output_coin_ids', async () => {
    // Live wire: node completed_attest_result is exclusively { attestation }.
    // Previously parseJob always required output_coin_ids and threw for every
    // successful attest_balance job.
    const attestation = 'ab'.repeat(40);
    server.use(
      http.get(`${BASE}/v1/jobs/attest-done`, () =>
        HttpResponse.json({
          job_id: 'attest-done',
          kind: 'attest_balance',
          status: 'completed',
          progress: 1,
          result: { attestation },
        }),
      ),
    );
    const { job } = await newClient().getJob('attest-done');
    expect(job.status).toBe('completed');
    expect(job.kind).toBe('attest_balance');
    expect(job.result?.attestation).toBe(attestation);
    expect(job.result?.output_coin_ids).toBeUndefined();
    expect(job.result?.new_account_state_hash).toBeUndefined();
    expect(job.result?.publisher_pubkey).toBeUndefined();
  });

  it('getJob rejects attest_balance results mixed with transition fields', async () => {
    server.use(
      http.get(`${BASE}/v1/jobs/attest-mixed`, () =>
        HttpResponse.json({
          job_id: 'attest-mixed',
          kind: 'attest_balance',
          status: 'completed',
          progress: 1,
          result: {
            attestation: 'ab'.repeat(40),
            output_coin_ids: [],
          },
        }),
      ),
    );
    await expect(newClient().getJob('attest-mixed')).rejects.toThrow(
      /mixed completed result.*output_coin_ids/,
    );
  });

  it('getJob rejects transition results mixed with an attestation', async () => {
    server.use(
      http.get(`${BASE}/v1/jobs/mint-mixed`, () =>
        HttpResponse.json({
          job_id: 'mint-mixed',
          kind: 'mint',
          status: 'completed',
          progress: 1,
          result: {
            new_account_state_hash: '11'.repeat(32),
            output_coins_root: '22'.repeat(32),
            input_nullifiers_root: '33'.repeat(32),
            output_coin_ids: [],
            attestation: 'ab'.repeat(40),
          },
        }),
      ),
    );
    await expect(newClient().getJob('mint-mixed')).rejects.toThrow(
      /mixed completed result.*attestation/,
    );
  });

  it('getJob rejects completed job with unknown kind', async () => {
    server.use(
      http.get(`${BASE}/v1/jobs/kind-foo`, () =>
        HttpResponse.json({
          job_id: 'kind-foo',
          kind: 'foo',
          status: 'completed',
          progress: 1,
          result: { attestation: 'aa' },
        }),
      ),
    );
    await expect(newClient().getJob('kind-foo')).rejects.toThrow(
      /unsupported completed job kind.*"foo"/,
    );
  });

  it('getJob rejects invalid attest_balance attestation forms', async () => {
    const cases: Array<{ id: string; result: Record<string, unknown>; message: RegExp }> = [
      {
        id: 'attest-missing',
        result: {},
        message: /job\.result\.attestation: expected non-empty hex string/,
      },
      {
        id: 'attest-empty',
        result: { attestation: '' },
        message: /job\.result\.attestation: expected non-empty hex string/,
      },
      {
        id: 'attest-upper',
        result: { attestation: 'AA' },
        message: /job\.result\.attestation: non-canonical hex/,
      },
      {
        id: 'attest-odd',
        result: { attestation: 'abc' },
        message: /job\.result\.attestation: non-canonical hex/,
      },
      {
        id: 'attest-not-string',
        result: { attestation: 42 },
        message: /job\.result\.attestation: expected non-empty hex string/,
      },
    ];

    for (const c of cases) {
      server.use(
        http.get(`${BASE}/v1/jobs/${c.id}`, () =>
          HttpResponse.json({
            job_id: c.id,
            kind: 'attest_balance',
            status: 'completed',
            progress: 1,
            result: c.result,
          }),
        ),
      );
      await expect(newClient().getJob(c.id)).rejects.toThrow(c.message);
    }
  });
});
