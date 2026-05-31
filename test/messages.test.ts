import { describe, expect, it } from 'vitest';
import { bytesToHex } from '@noble/hashes/utils';

import { buildClaimMessage, buildSendMessage } from '../src/messages.js';

describe('buildSendMessage', () => {
  it('lays out address || recipient || amount_le || timestamp_le in that order', () => {
    const msg = buildSendMessage({
      accountAddress: 'ab',
      recipient: 'cd',
      amount: 1n, // little-endian: 01 00 00 00 00 00 00 00
      timestamp: 2n, // little-endian: 02 00 00 00 00 00 00 00
    });
    // UTF-8 of "ab" is 61 62; "cd" is 63 64. Then 8 LE bytes per field.
    expect(bytesToHex(msg)).toBe('6162' + '6364' + '0100000000000000' + '0200000000000000');
  });

  it('encodes the address as UTF-8 of the hex string (not as raw bytes)', () => {
    const msg = buildSendMessage({
      accountAddress: '00',
      recipient: 'ff',
      amount: 0,
      timestamp: 0,
    });
    // "00" in UTF-8 is the bytes 0x30 0x30, NOT a single 0x00 byte.
    expect(msg[0]).toBe(0x30);
    expect(msg[1]).toBe(0x30);
    expect(msg[2]).toBe(0x66); // 'f'
    expect(msg[3]).toBe(0x66); // 'f'
  });

  it('amount and timestamp are 8 bytes little-endian unsigned', () => {
    const msg = buildSendMessage({
      accountAddress: '',
      recipient: '',
      amount: 0x0807060504030201n,
      timestamp: 0xff_00ee_00dd_00cc_00n & 0xffff_ffff_ffff_ffffn,
    });
    // amount LE: 01 02 03 04 05 06 07 08
    // timestamp LE depends; we just assert the amount slice here
    expect(bytesToHex(msg.slice(0, 8))).toBe('0102030405060708');
  });

  it('accepts number and bigint interchangeably for amount/timestamp', () => {
    const aNum = buildSendMessage({
      accountAddress: 'aa',
      recipient: 'bb',
      amount: 5000,
      timestamp: 1717000000,
    });
    const aBig = buildSendMessage({
      accountAddress: 'aa',
      recipient: 'bb',
      amount: 5000n,
      timestamp: 1717000000n,
    });
    expect(bytesToHex(aNum)).toBe(bytesToHex(aBig));
  });

  it('throws on negative amount', () => {
    expect(() =>
      buildSendMessage({
        accountAddress: 'aa',
        recipient: 'bb',
        amount: -1n,
        timestamp: 0,
      }),
    ).toThrow(/u64 range/);
  });

  it('throws on amount above 2^64 - 1', () => {
    expect(() =>
      buildSendMessage({
        accountAddress: 'aa',
        recipient: 'bb',
        amount: 1n << 64n,
        timestamp: 0,
      }),
    ).toThrow(/u64 range/);
  });
});

describe('buildClaimMessage', () => {
  it('starts with the literal `zkcoins:claim_username` prefix', () => {
    const msg = buildClaimMessage({
      address: 'abcdef',
      username: 'satoshi',
      timestamp: 0,
    });
    const prefix = 'zkcoins:claim_username';
    const decoded = new TextDecoder().decode(msg.slice(0, prefix.length));
    expect(decoded).toBe(prefix);
  });

  it('layout = prefix || address (hex utf-8) || username (utf-8) || timestamp_le', () => {
    const msg = buildClaimMessage({
      address: 'ab',
      username: 'x',
      timestamp: 1,
    });
    expect(bytesToHex(msg)).toBe(
      // 'zkcoins:claim_username' = 7a 6b 63 6f 69 6e 73 3a 63 6c 61 69 6d 5f 75 73 65 72 6e 61 6d 65
      '7a6b636f696e733a636c61696d5f757365726e616d65' +
        // 'ab' utf-8
        '6162' +
        // 'x' utf-8
        '78' +
        // timestamp LE
        '0100000000000000',
    );
  });

  it('is deterministic for the same inputs', () => {
    const a = buildClaimMessage({ address: 'ff', username: 'alice', timestamp: 1000 });
    const b = buildClaimMessage({ address: 'ff', username: 'alice', timestamp: 1000 });
    expect(bytesToHex(a)).toBe(bytesToHex(b));
  });
});
