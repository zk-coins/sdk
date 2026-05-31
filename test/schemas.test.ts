import { describe, expect, it } from 'vitest';

import {
  BalanceResponseSchema,
  CapabilitiesSchema,
  ClaimUsernameResponseSchema,
  CommitResponseSchema,
  HistoryResponseSchema,
  InfoResponseSchema,
  MintResponseSchema,
  ResolveUsernameResponseSchema,
  SendResponseSchema,
  TxItemSchema,
  UsernameResponseSchema,
} from '../src/schemas.js';

describe('SendResponseSchema (also MintResponseSchema, CommitResponseSchema)', () => {
  it('parses a minimal success envelope', () => {
    expect(SendResponseSchema.parse({ success: true })).toEqual({ success: true });
  });

  it('parses a full envelope with proof_id, ash, ocr', () => {
    const r = SendResponseSchema.parse({
      success: true,
      proof_id: 42,
      account_state_hash: 'aa',
      output_coins_root: 'bb',
    });
    expect(r.proof_id).toBe(42);
    expect(r.account_state_hash).toBe('aa');
    expect(r.output_coins_root).toBe('bb');
  });

  it('accepts null for proof_id (server emits null on success without proof)', () => {
    expect(SendResponseSchema.parse({ success: true, proof_id: null }).proof_id).toBeNull();
  });

  it('parses a failure envelope', () => {
    const r = SendResponseSchema.parse({ success: false, error: 'insufficient balance' });
    expect(r.success).toBe(false);
    expect(r.error).toBe('insufficient balance');
  });

  it('strips unknown keys silently (forward-compat policy)', () => {
    const parsed = SendResponseSchema.parse({ success: true, future_field: 'whatever' });
    expect(parsed).not.toHaveProperty('future_field');
  });

  it('rejects when `success` is missing (renamed-required-field is the failure mode we want)', () => {
    expect(() => SendResponseSchema.parse({ proof_id: 1 })).toThrow();
  });

  it('mint and commit aliases share the same parsed shape', () => {
    const env = { success: true, proof_id: 7 };
    expect(MintResponseSchema.parse(env)).toEqual(SendResponseSchema.parse(env));
    expect(CommitResponseSchema.parse(env)).toEqual(SendResponseSchema.parse(env));
  });
});

describe('BalanceResponseSchema', () => {
  it('requires balance, allows username', () => {
    expect(BalanceResponseSchema.parse({ balance: 0 })).toEqual({ balance: 0 });
    expect(BalanceResponseSchema.parse({ balance: 5, username: 'alice' })).toEqual({
      balance: 5,
      username: 'alice',
    });
  });

  it('rejects missing balance', () => {
    expect(() => BalanceResponseSchema.parse({ username: 'alice' })).toThrow();
  });

  it('rejects wrong-type balance', () => {
    expect(() => BalanceResponseSchema.parse({ balance: '5' })).toThrow();
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
  it('parses all four boolean fields', () => {
    expect(
      CapabilitiesSchema.parse({
        address_list: true,
        faucet: false,
        usernames: true,
        lnurl: false,
      }),
    ).toEqual({ address_list: true, faucet: false, usernames: true, lnurl: false });
  });

  it('rejects missing any field', () => {
    expect(() =>
      CapabilitiesSchema.parse({ address_list: true, faucet: false, usernames: true }),
    ).toThrow();
  });
});

describe('InfoResponseSchema', () => {
  it('parses with capabilities present', () => {
    const r = InfoResponseSchema.parse({
      network: 'Mainnet',
      capabilities: { address_list: false, faucet: false, usernames: true, lnurl: false },
    });
    expect(r.network).toBe('Mainnet');
    expect(r.capabilities?.usernames).toBe(true);
  });

  it('parses without capabilities (legacy server fallback)', () => {
    const r = InfoResponseSchema.parse({ network: 'Mutinynet' });
    expect(r.capabilities).toBeUndefined();
  });

  it('rejects missing network', () => {
    expect(() => InfoResponseSchema.parse({ capabilities: {} })).toThrow();
  });
});

describe('TxItemSchema + HistoryResponseSchema (pending issue #153)', () => {
  it('parses a confirmed receive', () => {
    const r = TxItemSchema.parse({
      txid: 'abcdef',
      timestamp: 1717081234,
      direction: 'receive',
      amount: 10000,
      counterparty: 'cd',
      status: 'confirmed',
      block_height: 871234,
    });
    expect(r.direction).toBe('receive');
    expect(r.status).toBe('confirmed');
    expect(r.block_height).toBe(871234);
  });

  it('parses a pending send (no block_height)', () => {
    const r = TxItemSchema.parse({
      txid: 'cdef',
      timestamp: 1717082000,
      direction: 'send',
      amount: 500,
      status: 'pending',
    });
    expect(r.status).toBe('pending');
    expect(r.block_height).toBeUndefined();
  });

  it('rejects an unknown direction', () => {
    expect(() =>
      TxItemSchema.parse({
        txid: 'a',
        timestamp: 0,
        direction: 'whatever',
        amount: 0,
        status: 'pending',
      }),
    ).toThrow();
  });

  it('rejects an unknown status', () => {
    expect(() =>
      TxItemSchema.parse({
        txid: 'a',
        timestamp: 0,
        direction: 'send',
        amount: 0,
        status: 'maybe',
      }),
    ).toThrow();
  });

  it('HistoryResponseSchema parses a populated list', () => {
    const r = HistoryResponseSchema.parse({
      items: [{ txid: 'a', timestamp: 0, direction: 'mint', amount: 1000, status: 'confirmed' }],
      total: 1,
      limit: 50,
      offset: 0,
    });
    expect(r.items).toHaveLength(1);
    expect(r.total).toBe(1);
  });
});
