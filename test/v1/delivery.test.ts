/**
 * §7.5 delivery credential + sender-side §4.3 checks.
 *
 * Fixtures build on the pinned V.2-ext key chain and V.2 address preimage
 * samples from the specification — not on values invented by this suite.
 */

import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { HDKey } from '@scure/bip32';
import { schnorr } from '@noble/curves/secp256k1.js';

import { sha256 } from '@noble/hashes/sha2.js';

import {
  addressFromParts,
  assertOutputDeliveries,
  assertTransitionRequest,
  computeNip01EventId,
  DeliveryCredentialError,
  encodeHexLower,
  encodeZkAddress,
  escapeNip01String,
  invoiceMessage,
  parseDeliveryCredential,
  parseU128Decimal,
  PaymentIdentityPinMismatchError,
  PaymentIdentityPinStore,
  placeDeliveryCredential,
  profileInvoiceMessage,
  seedFromMnemonicV1,
  serializeNip01IdPreimage,
  signNip01Event,
  transitionRequestToJson,
  verifyDeliveryCredential,
  verifyNip01Event,
  ZkCoinsV1Client,
  type DeliveryCredential,
  type InvoiceJson,
  type TransitionRequest,
} from '../../src/v1/index.js';
import { nkCommit } from '../../src/poseidon/hashes.js';
import { digestToBytes } from '../../src/poseidon/hc.js';
import { bip340NormaliseSecret } from '../../src/v1/transitionSignature.js';

// ---------------------------------------------------------------------------
// V.2-ext / V.2 pinned values (specification)
// ---------------------------------------------------------------------------

const MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const SK0_HEX = '4a8e3a83404f1aa99e89af57179dcf033820b816c0d78ac94fcb322d6ee85649';
const PK0_HEX = '7c9cdde9b8cb1e33a48a5c2b6ab1fa6fd753fa1762f56c0b3e8169e4f2d54630';
const OP_SECRET_HEX = '6516c985b442d51f1e91760c9327a593ddcb7fe06b363aa5b2b8547cc61d7395';
/** V.12 name_message pin: x-only(op·G) for V.2-ext `op`. */
const OP_PUBKEY_HEX = '6424b41eea59c6a3aa6169b802c96ff5194962d3bf5f941130e4ebc86de3b485';
/** V.10 pin: x-only(ivk·G) for V.2-ext `ivk`. */
const IVPK_HEX = 'cf8c205c48c67816489375cb1c03f09cee718999b4a97a90e8aef80c72fb6c17';

const V2_PK0_SAMPLE = '5dcffebb708081e3cc78b22f54d260467022c095a67da835f50713a36ee40746';
const V2_NK_COMMIT_SAMPLE = '444981ebd6edc1116dc1a13d51e7ed2c47988cc66ad5fb95c12de4f2efa4456e';
const V2_ADDRESS_HEX = 'e38121742a22e04e51175eb3e38a66df7e7e691c0041c169bc3a2592696f803d';
const V2_BECH32 = 'zk1uwqjzap2ytsyu5ght6e78znxmal8u6guqpquz6du8gjey6t0sq7st3s86p';

const RELAY = 'wss://relay.example.com';
const ASSET_ID = 'aa'.repeat(32);
const AMOUNT = '100';
/** Self-output subject: pinned V.2 Bech32m address (valid checksum). */
const SELF_SUBJECT = V2_BECH32;

function hex32(h: string): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function hex64(h: string): Uint8Array {
  const out = new Uint8Array(64);
  for (let i = 0; i < 64; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** V.2-ext nk → Poseidon nk_commit (Hc — real, not a hand sample). */
function v2extNkCommit(): Uint8Array {
  const seed = seedFromMnemonicV1(MNEMONIC);
  const master = HDKey.fromMasterSeed(seed);
  const nkChild = master.derive("m/1798'/0'/3'");
  const nk = nkChild.privateKey;
  if (nk === null) throw new Error('nk missing');
  return digestToBytes(nkCommit(nk));
}

function signMsg(secret: Uint8Array, msg: Uint8Array): string {
  return encodeHexLower(schnorr.sign(msg, secret, new Uint8Array(32)));
}

function buildValidInvoice(overrides: Partial<InvoiceJson> = {}): {
  invoice: InvoiceJson;
  recipient: string;
} {
  const pk0 = hex32(PK0_HEX);
  const nk = v2extNkCommit();
  const recipientRaw = addressFromParts(pk0, nk);
  const recipient = encodeZkAddress(recipientRaw);

  const amount = overrides.amount ?? AMOUNT;
  const assetId = overrides.asset_id ?? ASSET_ID;
  const relays = overrides.relays ?? [RELAY];
  const ivpkHex = overrides.ivpk ?? IVPK_HEX;
  const opPubkeyHex = overrides.op_pubkey ?? OP_PUBKEY_HEX;
  const memo = 'memo' in overrides ? overrides.memo : undefined;

  const msg = invoiceMessage({
    amount: BigInt(amount),
    recipient: recipientRaw,
    pk0,
    nkCommit: nk,
    assetId: hex32(assetId),
    ...(memo !== undefined ? { memo } : {}),
    ivpk: hex32(ivpkHex),
    opPubkey: hex32(opPubkeyHex),
    relays,
  });

  const invoice: InvoiceJson = {
    amount,
    recipient: overrides.recipient ?? recipient,
    asset_id: assetId,
    pk0: overrides.pk0 ?? PK0_HEX,
    nk_commit: overrides.nk_commit ?? encodeHexLower(nk),
    ivpk: ivpkHex,
    op_pubkey: opPubkeyHex,
    relays: [...relays],
    addr_sig: overrides.addr_sig ?? signMsg(hex32(SK0_HEX), msg),
    sig: overrides.sig ?? signMsg(hex32(OP_SECRET_HEX), msg),
  };
  if (memo !== undefined) invoice.memo = memo;
  return { invoice, recipient: invoice.recipient };
}

function buildValidProfile(
  opts: {
    network?: 'mainnet' | 'testnet' | 'regtest';
    badEventSig?: boolean;
    version?: number;
    emptyRelays?: boolean;
  } = {},
): { event: ReturnType<typeof signNip01Event>; address: string } {
  const pk0 = hex32(PK0_HEX);
  const nk = v2extNkCommit();
  const addressRaw = addressFromParts(pk0, nk);
  const address = encodeZkAddress(addressRaw);
  const network = opts.network ?? 'regtest';
  const relays = opts.emptyRelays ? [] : [RELAY];

  const msg = profileInvoiceMessage({
    address: addressRaw,
    pk0,
    nkCommit: nk,
    ivpk: hex32(IVPK_HEX),
    opPubkey: hex32(OP_PUBKEY_HEX),
    relays,
  });
  const addrSig = signMsg(hex32(SK0_HEX), msg);

  const content = JSON.stringify({
    name: 'Alice',
    nip05: 'alice@example.com',
    zkcoins: {
      version: opts.version ?? 1,
      network,
      address,
      pk0: PK0_HEX,
      nk_commit: encodeHexLower(nk),
      ivpk: IVPK_HEX,
      relays,
      addr_sig: addrSig,
      name_sig: 'ab'.repeat(64),
    },
  });

  const event = signNip01Event({
    secretKey: hex32(OP_SECRET_HEX),
    createdAt: 1_700_000_000,
    kind: 0,
    tags: [],
    content,
  });

  if (opts.badEventSig) {
    const sigBytes = hex64(event.sig);
    sigBytes[0] = (sigBytes[0]! ^ 0xff) & 0xff;
    event.sig = encodeHexLower(sigBytes);
  }

  return { event, address };
}

// ---------------------------------------------------------------------------
// V.2 address preimage pin
// ---------------------------------------------------------------------------

describe('addressFromParts (V.2 pin)', () => {
  it('matches the pinned H(Pk₀_sample ‖ nk_commit_sample) and Bech32m', () => {
    const addr = addressFromParts(hex32(V2_PK0_SAMPLE), hex32(V2_NK_COMMIT_SAMPLE));
    expect(encodeHexLower(addr)).toBe(V2_ADDRESS_HEX);
    expect(encodeZkAddress(addr)).toBe(V2_BECH32);
  });
});

// ---------------------------------------------------------------------------
// invoice_message framing
// ---------------------------------------------------------------------------

describe('invoiceMessage framing', () => {
  it('is order-sensitive (memo changes the digest)', () => {
    const z = new Uint8Array(32);
    const a = invoiceMessage({
      amount: 1n,
      recipient: z,
      pk0: hex32(PK0_HEX),
      nkCommit: hex32(V2_NK_COMMIT_SAMPLE),
      assetId: hex32(ASSET_ID),
      ivpk: hex32(IVPK_HEX),
      opPubkey: hex32(OP_PUBKEY_HEX),
      relays: [RELAY],
    });
    const b = invoiceMessage({
      amount: 1n,
      recipient: z,
      pk0: hex32(PK0_HEX),
      nkCommit: hex32(V2_NK_COMMIT_SAMPLE),
      assetId: hex32(ASSET_ID),
      memo: 'x',
      ivpk: hex32(IVPK_HEX),
      opPubkey: hex32(OP_PUBKEY_HEX),
      relays: [RELAY],
    });
    expect(encodeHexLower(a)).not.toBe(encodeHexLower(b));
  });

  it('parseU128Decimal rejects leading zeros and non-digits', () => {
    expect(() => parseU128Decimal('01', 'a')).toThrow(DeliveryCredentialError);
    expect(() => parseU128Decimal('', 'a')).toThrow(DeliveryCredentialError);
    expect(() => parseU128Decimal('1a', 'a')).toThrow(DeliveryCredentialError);
    expect(parseU128Decimal('0', 'a')).toBe(0n);
    expect(parseU128Decimal('100', 'a')).toBe(100n);
  });
});

// ---------------------------------------------------------------------------
// Invoice positives / negatives
// ---------------------------------------------------------------------------

describe('invoice delivery credential', () => {
  it('accepts a valid invoice and places delivery at output position i', () => {
    const { invoice, recipient } = buildValidInvoice();
    const placed = placeDeliveryCredential(
      { recipient, asset_id: ASSET_ID, amount: AMOUNT },
      { type: 'invoice', invoice },
      { network: 'regtest' },
    );
    expect(placed.delivery.type).toBe('invoice');
    if (placed.delivery.type === 'invoice') {
      expect(placed.delivery.invoice.recipient).toBe(recipient);
      expect(placed.delivery.invoice.amount).toBe(AMOUNT);
    }
  });

  it('rejects forged addr_sig (check ii)', () => {
    const { invoice, recipient } = buildValidInvoice({ addr_sig: '00'.repeat(64) });
    expect(() =>
      verifyDeliveryCredential(
        { type: 'invoice', invoice },
        { recipient, asset_id: ASSET_ID, amount: AMOUNT },
        { network: 'regtest' },
      ),
    ).toThrow(/addr_sig|check \(ii\)/);
  });

  it('rejects swapped ivpk while keeping signatures over the honest preimage', () => {
    const { invoice, recipient } = buildValidInvoice();
    invoice.ivpk = '11'.repeat(32);
    expect(() =>
      verifyDeliveryCredential(
        { type: 'invoice', invoice },
        { recipient, asset_id: ASSET_ID, amount: AMOUNT },
        { network: 'regtest' },
      ),
    ).toThrow(/addr_sig|check \(ii\)/);
  });

  it('rejects credential values ≠ output values', () => {
    const { invoice, recipient } = buildValidInvoice();
    expect(() =>
      verifyDeliveryCredential(
        { type: 'invoice', invoice },
        { recipient, asset_id: ASSET_ID, amount: '999' },
        { network: 'regtest' },
      ),
    ).toThrow(/amount must equal/);
    expect(() =>
      verifyDeliveryCredential(
        { type: 'invoice', invoice },
        { recipient, asset_id: 'bb'.repeat(32), amount: AMOUNT },
        { network: 'regtest' },
      ),
    ).toThrow(/asset_id must equal/);
    expect(() =>
      verifyDeliveryCredential(
        { type: 'invoice', invoice },
        { recipient: V2_BECH32, asset_id: ASSET_ID, amount: AMOUNT },
        { network: 'regtest' },
      ),
    ).toThrow(/recipient must equal/);
  });

  it('rejects unknown delivery.type (closed union)', () => {
    expect(() => parseDeliveryCredential({ type: 'email', invoice: {} })).toThrow(
      /unknown|invoice.*profile/i,
    );
  });

  it('rejects check (i) when H(pk0 ‖ nk_commit) ≠ recipient', () => {
    const { invoice } = buildValidInvoice();
    invoice.recipient = V2_BECH32;
    expect(() =>
      verifyDeliveryCredential(
        { type: 'invoice', invoice },
        { recipient: V2_BECH32, asset_id: ASSET_ID, amount: AMOUNT },
        { network: 'regtest' },
      ),
    ).toThrow(/check \(i\)|H\(pk0/);
  });

  it('rejects check (iii) when op sig is forged', () => {
    const { invoice, recipient } = buildValidInvoice({ sig: '00'.repeat(64) });
    expect(() =>
      verifyDeliveryCredential(
        { type: 'invoice', invoice },
        { recipient, asset_id: ASSET_ID, amount: AMOUNT },
        { network: 'regtest' },
      ),
    ).toThrow(/check \(iii\)|op_pubkey/);
  });
});

// ---------------------------------------------------------------------------
// Profile positives / negatives
// ---------------------------------------------------------------------------

describe('profile delivery credential', () => {
  it('accepts a valid kind-0 profile and places delivery at position i', () => {
    const { event, address } = buildValidProfile({ network: 'regtest' });
    const placed = placeDeliveryCredential(
      { recipient: address, asset_id: ASSET_ID, amount: AMOUNT },
      { type: 'profile', event },
      { network: 'regtest' },
    );
    expect(placed.delivery.type).toBe('profile');
    expect(placed.recipient).toBe(address);
  });

  it('rejects a profile event with a broken event signature', () => {
    const { event, address } = buildValidProfile({ network: 'regtest', badEventSig: true });
    expect(() =>
      verifyDeliveryCredential(
        { type: 'profile', event },
        { recipient: address, asset_id: ASSET_ID, amount: AMOUNT },
        { network: 'regtest' },
      ),
    ).toThrow(/event signature|BIP-340/);
  });

  it('rejects profile when zkcoins.address ≠ output.recipient', () => {
    const { event, address } = buildValidProfile({ network: 'regtest' });
    expect(address).not.toBe(V2_BECH32);
    expect(() =>
      verifyDeliveryCredential(
        { type: 'profile', event },
        { recipient: V2_BECH32, asset_id: ASSET_ID, amount: AMOUNT },
        { network: 'regtest' },
      ),
    ).toThrow(/address must equal output\.recipient/);
  });

  it('rejects wrong network / version / empty relays', () => {
    const wrongNet = buildValidProfile({ network: 'mainnet' });
    expect(() =>
      verifyDeliveryCredential(
        { type: 'profile', event: wrongNet.event },
        { recipient: wrongNet.address, asset_id: ASSET_ID, amount: AMOUNT },
        { network: 'regtest' },
      ),
    ).toThrow(/network/);

    const badVer = buildValidProfile({ network: 'regtest', version: 2 });
    expect(() =>
      verifyDeliveryCredential(
        { type: 'profile', event: badVer.event },
        { recipient: badVer.address, asset_id: ASSET_ID, amount: AMOUNT },
        { network: 'regtest' },
      ),
    ).toThrow(/version/);

    const empty = buildValidProfile({ network: 'regtest', emptyRelays: true });
    expect(() =>
      verifyDeliveryCredential(
        { type: 'profile', event: empty.event },
        { recipient: empty.address, asset_id: ASSET_ID, amount: AMOUNT },
        { network: 'regtest' },
      ),
    ).toThrow(/relays/);
  });

  it('requires name_sig as 64-byte hex (undefined/null/number refuse)', () => {
    // Without requireStringField, undefined/null/number name_sig slipped through.
    const cases: unknown[] = [undefined, null, 1, true, { hex: 'ab' }];
    for (const name_sig of cases) {
      const { event, address } = buildValidProfile({ network: 'regtest' });
      const content = JSON.parse(event.content) as {
        zkcoins: Record<string, unknown>;
      };
      if (name_sig === undefined) {
        delete content.zkcoins.name_sig;
      } else {
        content.zkcoins.name_sig = name_sig;
      }
      // Re-sign so event id/sig stay consistent with content (shape check runs after sig).
      const resigned = signNip01Event({
        secretKey: hex32(OP_SECRET_HEX),
        createdAt: event.created_at,
        kind: 0,
        tags: event.tags,
        content: JSON.stringify(content),
      });
      expect(() =>
        verifyDeliveryCredential(
          { type: 'profile', event: resigned },
          { recipient: address, asset_id: ASSET_ID, amount: AMOUNT },
          { network: 'regtest' },
        ),
      ).toThrow(/name_sig must be a string/);
    }

    // Wrong hex width is also refused (string present but not 64-byte).
    const { event, address } = buildValidProfile({ network: 'regtest' });
    const content = JSON.parse(event.content) as { zkcoins: Record<string, unknown> };
    content.zkcoins.name_sig = 'ab'.repeat(32); // 32 bytes, not 64
    const resigned = signNip01Event({
      secretKey: hex32(OP_SECRET_HEX),
      createdAt: event.created_at,
      kind: 0,
      tags: event.tags,
      content: JSON.stringify(content),
    });
    expect(() =>
      verifyDeliveryCredential(
        { type: 'profile', event: resigned },
        { recipient: address, asset_id: ASSET_ID, amount: AMOUNT },
        { network: 'regtest' },
      ),
    ).toThrow(/name_sig/);
  });
});

// ---------------------------------------------------------------------------
// Pin mismatch warn path
// ---------------------------------------------------------------------------

describe('payment-identity pin', () => {
  it('first contact (no pin) is not an error', () => {
    const store = new PaymentIdentityPinStore();
    const { invoice, recipient } = buildValidInvoice();
    expect(() =>
      verifyDeliveryCredential(
        { type: 'invoice', invoice },
        { recipient, asset_id: ASSET_ID, amount: AMOUNT },
        { network: 'regtest', pinStore: store },
      ),
    ).not.toThrow();
    expect(store.get(OP_PUBKEY_HEX)).toBeUndefined();
  });

  it('pin mismatch refuses silent payment (warn path)', () => {
    const store = new PaymentIdentityPinStore();
    store.set(OP_PUBKEY_HEX, {
      address: V2_BECH32,
      pk0: V2_PK0_SAMPLE,
      nk_commit: V2_NK_COMMIT_SAMPLE,
      ivpk: '22'.repeat(32),
    });
    const { invoice, recipient } = buildValidInvoice();
    expect(() =>
      verifyDeliveryCredential(
        { type: 'invoice', invoice },
        { recipient, asset_id: ASSET_ID, amount: AMOUNT },
        { network: 'regtest', pinStore: store },
      ),
    ).toThrow(PaymentIdentityPinMismatchError);
  });

  it('pin mismatch proceeds only with confirmPinMismatch', () => {
    const store = new PaymentIdentityPinStore();
    store.set(OP_PUBKEY_HEX, {
      address: V2_BECH32,
      pk0: V2_PK0_SAMPLE,
      nk_commit: V2_NK_COMMIT_SAMPLE,
      ivpk: '22'.repeat(32),
    });
    const { invoice, recipient } = buildValidInvoice();
    expect(() =>
      verifyDeliveryCredential(
        { type: 'invoice', invoice },
        { recipient, asset_id: ASSET_ID, amount: AMOUNT },
        { network: 'regtest', pinStore: store, confirmPinMismatch: true },
      ),
    ).not.toThrow();
  });

  it('pinOnFirstUse records the pin after a successful check', () => {
    const store = new PaymentIdentityPinStore();
    const { invoice, recipient } = buildValidInvoice();
    verifyDeliveryCredential(
      { type: 'invoice', invoice },
      { recipient, asset_id: ASSET_ID, amount: AMOUNT },
      { network: 'regtest', pinStore: store, pinOnFirstUse: true },
    );
    const pin = store.get(OP_PUBKEY_HEX);
    expect(pin).toBeDefined();
    expect(pin!.pk0).toBe(PK0_HEX);
    expect(pin!.ivpk).toBe(IVPK_HEX);
  });

  it('matching pin succeeds', () => {
    const store = new PaymentIdentityPinStore();
    const { invoice, recipient } = buildValidInvoice();
    store.set(OP_PUBKEY_HEX, {
      address: recipient,
      pk0: invoice.pk0,
      nk_commit: invoice.nk_commit,
      ivpk: invoice.ivpk,
    });
    expect(() =>
      verifyDeliveryCredential(
        { type: 'invoice', invoice },
        { recipient, asset_id: ASSET_ID, amount: AMOUNT },
        { network: 'regtest', pinStore: store },
      ),
    ).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Request JSON placement (position i) + presence
// ---------------------------------------------------------------------------

describe('TransitionRequest delivery placement', () => {
  it('serialises delivery at output_templates[i] for a valid invoice send', () => {
    const { invoice, recipient } = buildValidInvoice();
    const req: TransitionRequest = {
      kind: 'send',
      subject: SELF_SUBJECT,
      next_pubkey: 'aa'.repeat(32),
      npk_rand: 'bb'.repeat(32),
      input_coins: ['cc'.repeat(32)],
      output_templates: [
        { recipient: SELF_SUBJECT, asset_id: ASSET_ID, amount: '1' },
        {
          recipient,
          asset_id: ASSET_ID,
          amount: AMOUNT,
          delivery: { type: 'invoice', invoice },
        },
      ],
    };
    assertTransitionRequest(req);
    const json = transitionRequestToJson(req);
    const outs = json.output_templates as Array<Record<string, unknown>>;
    expect(outs).toHaveLength(2);
    expect(outs[0]).not.toHaveProperty('delivery');
    expect(outs[1]!.delivery).toEqual({ type: 'invoice', invoice });
  });

  it('serialises profile delivery at position i for mint to third party', () => {
    const { event, address } = buildValidProfile({ network: 'regtest' });
    const req: TransitionRequest = {
      kind: 'mint',
      subject: SELF_SUBJECT,
      next_pubkey: 'aa'.repeat(32),
      npk_rand: 'bb'.repeat(32),
      issuance: { name: 'X', decimals: 0, issuance_version: 1, amount: AMOUNT },
      output_templates: [
        {
          recipient: address,
          asset_id: ASSET_ID,
          amount: AMOUNT,
          delivery: { type: 'profile', event },
        },
      ],
    };
    const json = transitionRequestToJson(req);
    const outs = json.output_templates as Array<Record<string, unknown>>;
    expect((outs[0]!.delivery as { type: string }).type).toBe('profile');
  });

  it('assertTransitionRequest rejects unknown delivery.type', () => {
    expect(() =>
      assertTransitionRequest({
        kind: 'send',
        subject: SELF_SUBJECT,
        next_pubkey: 'aa'.repeat(32),
        npk_rand: 'bb'.repeat(32),
        input_coins: ['cc'.repeat(32)],
        output_templates: [
          {
            recipient: SELF_SUBJECT,
            asset_id: ASSET_ID,
            amount: '1',
            delivery: { type: 'mystery', invoice: {} },
          },
        ],
      }),
    ).toThrow(/unknown|invoice.*profile/i);
  });

  it('assertOutputDeliveries requires delivery on non-self outputs', () => {
    const { recipient } = buildValidInvoice();
    expect(() =>
      assertOutputDeliveries(SELF_SUBJECT, [{ recipient, asset_id: ASSET_ID, amount: AMOUNT }], {
        network: 'regtest',
      }),
    ).toThrow(/delivery is required/);
  });

  it('assertOutputDeliveries allows self-output without delivery', () => {
    expect(() =>
      assertOutputDeliveries(
        SELF_SUBJECT,
        [{ recipient: SELF_SUBJECT, asset_id: ASSET_ID, amount: '1' }],
        { network: 'regtest' },
      ),
    ).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Client submitTransition wires pin + delivery
// ---------------------------------------------------------------------------

const BASE = 'https://node.delivery.test';
const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

describe('ZkCoinsV1Client.submitTransition delivery gate', () => {
  it('posts a send with invoice delivery at position 0', async () => {
    const { invoice, recipient } = buildValidInvoice();
    let posted: unknown;
    server.use(
      http.post(`${BASE}/v1/tx`, async ({ request }) => {
        posted = await request.json();
        return HttpResponse.json({ job_id: 'job-d', status: 'accepted' }, { status: 202 });
      }),
    );
    const client = new ZkCoinsV1Client({ apiUrl: BASE, network: 'regtest' });
    await client.submitTransition({
      kind: 'send',
      subject: SELF_SUBJECT,
      next_pubkey: 'aa'.repeat(32),
      npk_rand: 'bb'.repeat(32),
      input_coins: ['cc'.repeat(32)],
      output_templates: [
        {
          recipient,
          asset_id: ASSET_ID,
          amount: AMOUNT,
          delivery: { type: 'invoice', invoice },
        },
      ],
    });
    const body = posted as {
      output_templates: Array<{ delivery?: DeliveryCredential }>;
    };
    expect(body.output_templates[0]!.delivery?.type).toBe('invoice');
  });

  it('refuses submit when pin mismatches without confirmation', async () => {
    const store = new PaymentIdentityPinStore();
    store.set(OP_PUBKEY_HEX, {
      address: V2_BECH32,
      pk0: V2_PK0_SAMPLE,
      nk_commit: V2_NK_COMMIT_SAMPLE,
      ivpk: '22'.repeat(32),
    });
    const { invoice, recipient } = buildValidInvoice();
    const client = new ZkCoinsV1Client({ apiUrl: BASE, network: 'regtest', pinStore: store });
    await expect(
      client.submitTransition({
        kind: 'send',
        subject: SELF_SUBJECT,
        next_pubkey: 'aa'.repeat(32),
        npk_rand: 'bb'.repeat(32),
        input_coins: ['cc'.repeat(32)],
        output_templates: [
          {
            recipient,
            asset_id: ASSET_ID,
            amount: AMOUNT,
            delivery: { type: 'invoice', invoice },
          },
        ],
      }),
    ).rejects.toBeInstanceOf(PaymentIdentityPinMismatchError);
  });
});

// ---------------------------------------------------------------------------
// NIP-01 + V.2-ext key pins
// ---------------------------------------------------------------------------

describe('NIP-01 event id and V.2-ext key pins', () => {
  it('verifyNip01Event accepts a self-signed event and rejects id tampering', () => {
    const event = signNip01Event({
      secretKey: hex32(OP_SECRET_HEX),
      createdAt: 42,
      kind: 0,
      tags: [],
      content: '{}',
    });
    expect(event.pubkey).toBe(OP_PUBKEY_HEX);
    expect(() => verifyNip01Event(event)).not.toThrow();
    expect(() => verifyNip01Event({ ...event, id: '00'.repeat(32) })).toThrow(/id mismatch/);
  });

  it('escapeNip01String escapes remaining control characters as \\u00xx', () => {
    // Independent of self-sign/self-verify: preimage bytes differ when U+0001
    // is left raw vs escaped — event ids must match the escaped form.
    expect(escapeNip01String('a\u0001b')).toBe('"a\\u0001b"');
    expect(escapeNip01String('a\u0000b')).toBe('"a\\u0000b"');
    expect(escapeNip01String('a\u001fb')).toBe('"a\\u001fb"');
    // Classical short escapes still preferred over \\u00xx.
    expect(escapeNip01String('a\nb\tc')).toBe('"a\\nb\\tc"');
    // Non-ASCII stays raw UTF-8 (no \\u00e4).
    expect(escapeNip01String('ä')).toBe('"ä"');
    expect(escapeNip01String('ä').includes('\\u')).toBe(false);

    const pubkey = hex32(OP_PUBKEY_HEX);
    const content = 'ctrl\u0001end';
    const preimage = serializeNip01IdPreimage({
      pubkey,
      createdAt: 1_700_000_000,
      kind: 0,
      tags: [['t', 'x\u0002y']],
      content,
    });
    expect(preimage).toContain('\\u0001');
    expect(preimage).toContain('\\u0002');
    // Raw U+0001 byte must not appear in the preimage.
    expect(preimage.includes('\u0001')).toBe(false);

    const id = computeNip01EventId({
      pubkey,
      createdAt: 1_700_000_000,
      kind: 0,
      tags: [['t', 'x\u0002y']],
      content,
    });
    // Independent vector: recompute SHA-256 of the preimage outside the helper.
    const expected = sha256(new TextEncoder().encode(preimage));
    expect(encodeHexLower(id)).toBe(encodeHexLower(expected));
    // Distinct from the unescaped (non-JSON) preimage id.
    const rawBad = `[0,"${OP_PUBKEY_HEX}",1700000000,0,[["t","x\u0002y"]],"ctrl\u0001end"]`;
    const rawId = sha256(new TextEncoder().encode(rawBad));
    expect(encodeHexLower(id)).not.toBe(encodeHexLower(rawId));
  });

  it('op_pubkey and sk₀ match the V.2-ext / V.12 pins', () => {
    const pk = schnorr.getPublicKey(hex32(OP_SECRET_HEX));
    expect(encodeHexLower(pk)).toBe(OP_PUBKEY_HEX);
    const { pkBytes } = bip340NormaliseSecret(hex32(SK0_HEX));
    expect(encodeHexLower(pkBytes)).toBe(PK0_HEX);
  });
});
