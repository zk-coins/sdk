import { describe, expect, it } from 'vitest';

import {
  AddressesResponseSchema,
  BalanceResponseSchema,
  BitcoinNetworkSchema,
  CapabilitiesSchema,
  ClaimUsernameResponseSchema,
  HistoryResponseSchema,
  InfoResponseSchema,
  InscriptionKindSchema,
  InscriptionSummarySchema,
  JobAcceptedSchema,
  JobKindSchema,
  JobResultSchema,
  JobStatusSchema,
  JobStatusValueSchema,
  PublisherHealthResponseSchema,
  ReadyResponseSchema,
  ResolveUsernameResponseSchema,
  RootResponseSchema,
  TxItemSchema,
  UsernameResponseSchema,
} from '../src/schemas.js';

describe('BalanceResponseSchema', () => {
  it('requires balance + num_sends, allows username', () => {
    expect(BalanceResponseSchema.parse({ balance: 0, num_sends: 0 })).toEqual({
      balance: 0,
      num_sends: 0,
    });
    expect(BalanceResponseSchema.parse({ balance: 5, username: 'alice', num_sends: 3 })).toEqual({
      balance: 5,
      username: 'alice',
      num_sends: 3,
    });
  });

  it('rejects a missing num_sends (authoritative counter must be present)', () => {
    expect(() => BalanceResponseSchema.parse({ balance: 5 })).toThrow();
  });

  it('rejects missing balance', () => {
    expect(() => BalanceResponseSchema.parse({ num_sends: 0 })).toThrow();
  });

  it('rejects wrong-type balance', () => {
    expect(() => BalanceResponseSchema.parse({ balance: '5', num_sends: 0 })).toThrow();
  });
});

describe('UsernameResponseSchema (also Claim, Resolve aliases)', () => {
  it('requires both fields', () => {
    expect(UsernameResponseSchema.parse({ username: 'a', address: 'ab' })).toEqual({
      username: 'a',
      address: 'ab',
    });
    expect(() => UsernameResponseSchema.parse({ username: 'a' })).toThrow();
    expect(() => UsernameResponseSchema.parse({ address: 'a' })).toThrow();
  });

  it('claim and resolve aliases share the same parsed shape', () => {
    const env = { username: 'bob', address: 'cd' };
    expect(ClaimUsernameResponseSchema.parse(env)).toEqual(UsernameResponseSchema.parse(env));
    expect(ResolveUsernameResponseSchema.parse(env)).toEqual(UsernameResponseSchema.parse(env));
  });
});

describe('CapabilitiesSchema', () => {
  it('parses all four boolean flags', () => {
    expect(
      CapabilitiesSchema.parse({
        address_list: true,
        username_claim: false,
        lnurl: true,
        multi_asset: false,
      }),
    ).toEqual({ address_list: true, username_claim: false, lnurl: true, multi_asset: false });
  });

  it('rejects a missing flag (the node always emits all four)', () => {
    expect(() =>
      CapabilitiesSchema.parse({ address_list: true, username_claim: false, lnurl: true }),
    ).toThrow();
  });

  it('rejects a non-boolean flag', () => {
    expect(() =>
      CapabilitiesSchema.parse({
        address_list: true,
        username_claim: false,
        lnurl: true,
        multi_asset: 'yes',
      }),
    ).toThrow();
  });
});

describe('BitcoinNetworkSchema', () => {
  it('accepts the two normalized values', () => {
    expect(BitcoinNetworkSchema.parse('mainnet')).toBe('mainnet');
    expect(BitcoinNetworkSchema.parse('mutinynet')).toBe('mutinynet');
  });

  it('rejects the human-readable label', () => {
    expect(() => BitcoinNetworkSchema.parse('Mainnet')).toThrow();
  });
});

describe('InfoResponseSchema', () => {
  it('parses a full info (network, bitcoin_network, capabilities, username_domain)', () => {
    const r = InfoResponseSchema.parse({
      network: 'Mainnet',
      bitcoin_network: 'mainnet',
      capabilities: {
        address_list: false,
        username_claim: true,
        lnurl: false,
        multi_asset: true,
      },
      username_domain: 'api.zkcoins.app',
    });
    expect(r.network).toBe('Mainnet');
    expect(r.bitcoin_network).toBe('mainnet');
    expect(r.capabilities?.multi_asset).toBe(true);
    expect(r.username_domain).toBe('api.zkcoins.app');
  });

  it('parses with bitcoin_network ABSENT (fail-open for nodes pre-#193)', () => {
    const r = InfoResponseSchema.parse({
      network: 'Mutinynet',
      username_domain: 'dev-api.zkcoins.app',
    });
    expect(r.bitcoin_network).toBeUndefined();
    expect(r.username_domain).toBe('dev-api.zkcoins.app');
  });

  it('parses with username_domain ABSENT (legacy self-host fallback)', () => {
    const r = InfoResponseSchema.parse({ network: 'Mutinynet' });
    expect(r.username_domain).toBeUndefined();
    expect(r.capabilities).toBeUndefined();
  });

  it('rejects a malformed bitcoin_network rather than coercing', () => {
    expect(() =>
      InfoResponseSchema.parse({ network: 'Mainnet', bitcoin_network: 'signet' }),
    ).toThrow();
  });

  it('rejects missing network', () => {
    expect(() => InfoResponseSchema.parse({ capabilities: {} })).toThrow();
  });
});

describe('TxItemSchema + HistoryResponseSchema', () => {
  it('parses a confirmed receive with all nullables present', () => {
    const r = TxItemSchema.parse({
      id: 42,
      txid: 'abcdef',
      timestamp: 1717081234,
      direction: 'receive',
      amount: 10000,
      counterparty: null,
      status: 'confirmed',
      block_height: 871234,
      memo: null,
    });
    expect(r.id).toBe(42);
    expect(r.direction).toBe('receive');
    expect(r.block_height).toBe(871234);
    expect(r.counterparty).toBeNull();
    expect(r.memo).toBeNull();
  });

  it('parses a pending send with null txid / block_height', () => {
    const r = TxItemSchema.parse({
      id: 7,
      txid: null,
      timestamp: 1717082000,
      direction: 'send',
      amount: 500,
      counterparty: null,
      status: 'pending',
      block_height: null,
      memo: null,
    });
    expect(r.status).toBe('pending');
    expect(r.txid).toBeNull();
    expect(r.block_height).toBeNull();
  });

  it('rejects a missing id (always set server-side)', () => {
    expect(() =>
      TxItemSchema.parse({
        txid: null,
        timestamp: 0,
        direction: 'mint',
        amount: 1,
        counterparty: null,
        status: 'confirmed',
        block_height: null,
        memo: null,
      }),
    ).toThrow();
  });

  it('rejects a nullable field that is omitted (the node emits explicit null)', () => {
    expect(() =>
      TxItemSchema.parse({
        id: 1,
        timestamp: 0,
        direction: 'mint',
        amount: 1,
        counterparty: null,
        status: 'confirmed',
        block_height: null,
        memo: null,
        // txid omitted
      }),
    ).toThrow();
  });

  it('rejects an unknown direction / status', () => {
    const base = {
      id: 1,
      txid: null,
      timestamp: 0,
      amount: 0,
      counterparty: null,
      block_height: null,
      memo: null,
    };
    expect(() =>
      TxItemSchema.parse({ ...base, direction: 'whatever', status: 'pending' }),
    ).toThrow();
    expect(() => TxItemSchema.parse({ ...base, direction: 'send', status: 'maybe' })).toThrow();
  });

  it('HistoryResponseSchema parses a populated page', () => {
    const r = HistoryResponseSchema.parse({
      items: [
        {
          id: 1,
          txid: 'a',
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
    });
    expect(r.items).toHaveLength(1);
    expect(r.total).toBe(1);
  });
});

describe('Jobs schemas', () => {
  it('JobStatusValueSchema covers the seven states', () => {
    for (const s of [
      'queued',
      'proving',
      'awaiting_signature',
      'broadcasting',
      'completed',
      'failed',
      'cancelled',
    ]) {
      expect(JobStatusValueSchema.parse(s)).toBe(s);
    }
    expect(() => JobStatusValueSchema.parse('unknown')).toThrow();
  });

  it('JobKindSchema covers mint + send', () => {
    expect(JobKindSchema.parse('mint')).toBe('mint');
    expect(JobKindSchema.parse('send')).toBe('send');
    expect(() => JobKindSchema.parse('commit')).toThrow();
  });

  it('JobAcceptedSchema parses the 202 admit body', () => {
    const r = JobAcceptedSchema.parse({ job_id: 'uuid-1', status: 'queued' });
    expect(r.job_id).toBe('uuid-1');
    expect(r.status).toBe('queued');
  });

  it('JobResultSchema parses a completed mint/commit result body', () => {
    const r = JobResultSchema.parse({
      success: true,
      proof_id: 17,
      account_state_hash: 'aa',
      output_coins_root: 'bb',
    });
    expect(r.success).toBe(true);
    expect(r.proof_id).toBe(17);
    expect(r.account_state_hash).toBe('aa');
  });

  it('JobResultSchema accepts a null proof_id', () => {
    expect(JobResultSchema.parse({ success: true, proof_id: null }).proof_id).toBeNull();
  });

  it('JobStatusSchema parses a poll body (job_id, kind, progress present; optionals elided)', () => {
    const r = JobStatusSchema.parse({
      job_id: 'uuid-1',
      kind: 'send',
      status: 'proving',
      phase: 'proving',
      progress: 40,
    });
    expect(r.job_id).toBe('uuid-1');
    expect(r.kind).toBe('send');
    expect(r.progress).toBe(40);
    expect(r.proof_id).toBeUndefined();
  });

  it('JobStatusSchema parses an awaiting_signature poll body with proof_id', () => {
    const r = JobStatusSchema.parse({
      job_id: 'uuid-1',
      kind: 'send',
      status: 'awaiting_signature',
      phase: 'awaiting_signature',
      progress: 60,
      proof_id: 17,
    });
    expect(r.status).toBe('awaiting_signature');
    expect(r.proof_id).toBe(17);
  });

  it('JobStatusSchema parses an SSE frame (no job_id/kind/progress; explicit nulls)', () => {
    const r = JobStatusSchema.parse({
      status: 'proving',
      phase: 'proving',
      proof_id: null,
      result: null,
      error: null,
    });
    expect(r.job_id).toBeUndefined();
    expect(r.kind).toBeUndefined();
    expect(r.progress).toBeUndefined();
    expect(r.proof_id).toBeNull();
    expect(r.result).toBeNull();
  });

  it('JobStatusSchema parses a completed frame carrying a result', () => {
    const r = JobStatusSchema.parse({
      status: 'completed',
      phase: 'completed',
      proof_id: null,
      result: { success: true, proof_id: 3, account_state_hash: 'aa', output_coins_root: 'bb' },
      error: null,
    });
    expect(r.result?.account_state_hash).toBe('aa');
  });

  it('JobStatusSchema rejects an unknown status (contract drift)', () => {
    expect(() => JobStatusSchema.parse({ status: 'paused', phase: 'x' })).toThrow();
  });
});

describe('ReadyResponseSchema', () => {
  it('parses a ready body', () => {
    const r = ReadyResponseSchema.parse({
      ready: true,
      failures: [],
      status: 'ready',
      prover: 'ready',
    });
    expect(r.ready).toBe(true);
    expect(r.failures).toEqual([]);
  });

  it('parses a not-ready body with failures', () => {
    const r = ReadyResponseSchema.parse({
      ready: false,
      failures: ['db', 'esplora', 'prover'],
      status: 'starting',
      prover: 'warming',
    });
    expect(r.failures).toEqual(['db', 'esplora', 'prover']);
    expect(r.prover).toBe('warming');
  });

  it('rejects a missing failures array', () => {
    expect(() =>
      ReadyResponseSchema.parse({ ready: true, status: 'ready', prover: 'ready' }),
    ).toThrow();
  });

  it('rejects a non-boolean ready', () => {
    expect(() =>
      ReadyResponseSchema.parse({ ready: 'yes', failures: [], status: 'ready', prover: 'ready' }),
    ).toThrow();
  });
});

describe('PublisherHealthResponseSchema', () => {
  it('parses the publisher wallet state', () => {
    const r = PublisherHealthResponseSchema.parse({
      address: 'tb1pl79',
      utxo_count: 1,
      total_sats: 992746,
    });
    expect(r.address).toBe('tb1pl79');
    expect(r.utxo_count).toBe(1);
    expect(r.total_sats).toBe(992746);
  });

  it('rejects a missing total_sats', () => {
    expect(() => PublisherHealthResponseSchema.parse({ address: 'tb1p', utxo_count: 0 })).toThrow();
  });
});

describe('RootResponseSchema', () => {
  const endpoints = {
    info: 'GET  /api/info',
    balance: 'GET  /api/balance?address={hex}',
    history: 'GET  /api/history',
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
  };

  it('parses the service-info envelope', () => {
    const r = RootResponseSchema.parse({
      service: 'zkcoins-node',
      version: '1.1.0',
      network: 'Mutinynet',
      endpoints,
      docs: 'https://docs.zkcoins.app',
    });
    expect(r.service).toBe('zkcoins-node');
    expect(r.endpoints.health_publisher).toBe('GET  /health/publisher');
  });

  it('rejects an endpoints map missing a required key', () => {
    const { docs, ...incomplete } = endpoints;
    void docs;
    expect(() =>
      RootResponseSchema.parse({
        service: 'zkcoins-node',
        version: '1.1.0',
        network: 'Mutinynet',
        endpoints: incomplete,
        docs: 'https://docs.zkcoins.app',
      }),
    ).toThrow();
  });
});

describe('AddressesResponseSchema', () => {
  it('parses an address list', () => {
    expect(AddressesResponseSchema.parse({ addresses: ['0xaa', '0xbb'] }).addresses).toEqual([
      '0xaa',
      '0xbb',
    ]);
  });

  it('parses an empty list', () => {
    expect(AddressesResponseSchema.parse({ addresses: [] }).addresses).toEqual([]);
  });

  it('rejects a non-array addresses', () => {
    expect(() => AddressesResponseSchema.parse({ addresses: 'nope' })).toThrow();
  });
});

describe('InscriptionKindSchema + InscriptionSummarySchema', () => {
  it('InscriptionKindSchema covers mint + send', () => {
    expect(InscriptionKindSchema.parse('mint')).toBe('mint');
    expect(InscriptionKindSchema.parse('send')).toBe('send');
    expect(() => InscriptionKindSchema.parse('reveal')).toThrow();
  });

  it('parses a confirmed inscription summary', () => {
    const r = InscriptionSummarySchema.parse({
      commit_txid: 'ab'.repeat(32),
      reveal_txid: 'cd'.repeat(32),
      kind: 'mint',
      status: 'confirmed',
      commit_output_value: 600,
      failure_reason: null,
      created_at: '2026-06-03T00:00:00.000000Z',
      updated_at: '2026-06-03T00:00:01.000000Z',
    });
    expect(r.kind).toBe('mint');
    expect(r.reveal_txid).toBe('cd'.repeat(32));
    expect(r.failure_reason).toBeNull();
  });

  it('parses a failed inscription with null reveal_txid + a failure_reason', () => {
    const r = InscriptionSummarySchema.parse({
      commit_txid: 'ef'.repeat(32),
      reveal_txid: null,
      kind: 'send',
      status: 'failed',
      commit_output_value: 0,
      failure_reason: 'broadcast rejected',
      created_at: '2026-06-03T00:00:00.000000Z',
      updated_at: '2026-06-03T00:00:01.000000Z',
    });
    expect(r.reveal_txid).toBeNull();
    expect(r.failure_reason).toBe('broadcast rejected');
  });

  it('rejects an omitted reveal_txid (node emits explicit null)', () => {
    expect(() =>
      InscriptionSummarySchema.parse({
        commit_txid: 'ab'.repeat(32),
        kind: 'mint',
        status: 'confirmed',
        commit_output_value: 600,
        failure_reason: null,
        created_at: '2026-06-03T00:00:00.000000Z',
        updated_at: '2026-06-03T00:00:01.000000Z',
      }),
    ).toThrow();
  });

  it('rejects an unknown kind', () => {
    expect(() =>
      InscriptionSummarySchema.parse({
        commit_txid: 'ab'.repeat(32),
        reveal_txid: null,
        kind: 'transfer',
        status: 'confirmed',
        commit_output_value: 600,
        failure_reason: null,
        created_at: '2026-06-03T00:00:00.000000Z',
        updated_at: '2026-06-03T00:00:01.000000Z',
      }),
    ).toThrow();
  });
});
