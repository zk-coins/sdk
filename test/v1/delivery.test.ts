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
  issueInvoice,
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
      issuance: {
        name: 'X',
        decimals: 0,
        issuance_version: 1,
        amount: AMOUNT,
        creator_pubkey: PK0_HEX,
      },
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

// ---------------------------------------------------------------------------
// Delivery rejection / edge paths (coverage for fail-closed branches)
// ---------------------------------------------------------------------------

describe('PaymentIdentityPinStore edge paths', () => {
  it('delete removes a pin and returns false when absent', () => {
    const store = new PaymentIdentityPinStore();
    expect(store.delete(OP_PUBKEY_HEX)).toBe(false);
    store.set(OP_PUBKEY_HEX, {
      address: V2_BECH32,
      pk0: V2_PK0_SAMPLE,
      nk_commit: V2_NK_COMMIT_SAMPLE,
      ivpk: IVPK_HEX,
    });
    expect(store.delete(OP_PUBKEY_HEX)).toBe(true);
    expect(store.get(OP_PUBKEY_HEX)).toBeUndefined();
  });

  it('rejects empty op_pubkey for pin lookup', () => {
    const store = new PaymentIdentityPinStore();
    expect(() => store.get('')).toThrow(DeliveryCredentialError);
    expect(() => store.get('')).toThrow(/op_pubkey is required/);
    expect(() =>
      store.set('', {
        address: V2_BECH32,
        pk0: PK0_HEX,
        nk_commit: V2_NK_COMMIT_SAMPLE,
        ivpk: IVPK_HEX,
      }),
    ).toThrow(/op_pubkey is required/);
  });

  it('pin check treats undecodable address or bad hex fields as mismatch', () => {
    const store = new PaymentIdentityPinStore();
    const { invoice, recipient } = buildValidInvoice();
    // Empty address → decodeAddressField throws → pinsEqual catch → mismatch.
    store.set(OP_PUBKEY_HEX, {
      address: '',
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
    ).toThrow(PaymentIdentityPinMismatchError);

    // Garbage non-Bech32 address that fails hex decode → first catch.
    store.set(OP_PUBKEY_HEX, {
      address: 'not-zk1-and-not-hex',
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
    ).toThrow(PaymentIdentityPinMismatchError);

    // Hex address form is accepted; bad pk0 hex on the pin → second catch → mismatch.
    store.set(OP_PUBKEY_HEX, {
      address: encodeHexLower(addressFromParts(hex32(invoice.pk0), hex32(invoice.nk_commit))),
      pk0: 'zz'.repeat(32),
      nk_commit: invoice.nk_commit,
      ivpk: invoice.ivpk,
    });
    expect(() =>
      verifyDeliveryCredential(
        { type: 'invoice', invoice },
        { recipient, asset_id: ASSET_ID, amount: AMOUNT },
        { network: 'regtest', pinStore: store },
      ),
    ).toThrow(PaymentIdentityPinMismatchError);
  });

  it('matching pin accepts raw 32-byte hex address spelling', () => {
    const store = new PaymentIdentityPinStore();
    const { invoice, recipient } = buildValidInvoice();
    const rawAddr = encodeHexLower(addressFromParts(hex32(invoice.pk0), hex32(invoice.nk_commit)));
    store.set(OP_PUBKEY_HEX, {
      address: rawAddr,
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

describe('addressFromParts / invoiceMessage bounds', () => {
  it('rejects non-32-byte pk0 and nk_commit', () => {
    expect(() => addressFromParts(new Uint8Array(16), new Uint8Array(32))).toThrow(
      /pk0 must be 32 bytes, got 16/,
    );
    expect(() => addressFromParts(new Uint8Array(32), new Uint8Array(31))).toThrow(
      /nk_commit must be 32 bytes, got 31/,
    );
  });

  it('rejects amount outside u128 and oversized relay count', () => {
    const z = new Uint8Array(32);
    const base = {
      recipient: z,
      pk0: z,
      nkCommit: z,
      assetId: z,
      ivpk: z,
      opPubkey: z,
      relays: [RELAY] as string[],
    };
    expect(() => invoiceMessage({ ...base, amount: -1n })).toThrow(/amount out of u128 range/);
    expect(() => invoiceMessage({ ...base, amount: 1n << 128n })).toThrow(
      /amount out of u128 range/,
    );
    expect(() =>
      invoiceMessage({
        ...base,
        amount: 1n,
        relays: Array.from({ length: 0x10000 }, () => 'wss://r.example'),
      }),
    ).toThrow(/relay count exceeds u16/);
  });

  it('rejects non-32-byte fields via require32', () => {
    const z = new Uint8Array(32);
    expect(() =>
      invoiceMessage({
        amount: 1n,
        recipient: new Uint8Array(16),
        pk0: z,
        nkCommit: z,
        assetId: z,
        ivpk: z,
        opPubkey: z,
        relays: [],
      }),
    ).toThrow(/recipient must be 32 bytes/);
  });
});

describe('parseDeliveryCredential shape rejections', () => {
  it('rejects non-object delivery, invoice, and event', () => {
    expect(() => parseDeliveryCredential(null)).toThrow(/delivery must be an object/);
    expect(() => parseDeliveryCredential('invoice')).toThrow(/delivery must be an object/);
    expect(() => parseDeliveryCredential({ type: 'invoice', invoice: null })).toThrow(
      /invoice must be an object/,
    );
    expect(() => parseDeliveryCredential({ type: 'invoice', invoice: [] })).toThrow(
      /invoice must be an object/,
    );
    expect(() => parseDeliveryCredential({ type: 'profile', event: null })).toThrow(
      /event must be an object/,
    );
  });

  it('rejects non-string relays and non-string memo', () => {
    const { invoice } = buildValidInvoice();
    expect(() =>
      parseDeliveryCredential({
        type: 'invoice',
        invoice: { ...invoice, relays: 'wss://x' },
      }),
    ).toThrow(/relays must be an array of strings/);
    expect(() =>
      parseDeliveryCredential({
        type: 'invoice',
        invoice: { ...invoice, relays: [1, 2] },
      }),
    ).toThrow(/relays must be an array of strings/);
    expect(() =>
      parseDeliveryCredential({
        type: 'invoice',
        invoice: { ...invoice, memo: 42 },
      }),
    ).toThrow(/memo must be a string when present/);
  });

  it('accepts string memo and copies it onto the invoice', () => {
    const { invoice } = buildValidInvoice({ memo: 'hello' });
    const parsed = parseDeliveryCredential({ type: 'invoice', invoice });
    expect(parsed.type).toBe('invoice');
    if (parsed.type === 'invoice') {
      expect(parsed.invoice.memo).toBe('hello');
    }
  });

  it('rejects event.tags shape and non-integer created_at/kind', () => {
    const { event } = buildValidProfile({ network: 'regtest' });
    expect(() =>
      parseDeliveryCredential({
        type: 'profile',
        event: { ...event, created_at: -1 },
      }),
    ).toThrow(/created_at must be a non-negative integer/);
    expect(() =>
      parseDeliveryCredential({
        type: 'profile',
        event: { ...event, kind: 1.5 },
      }),
    ).toThrow(/kind must be a non-negative integer/);
    expect(() =>
      parseDeliveryCredential({
        type: 'profile',
        event: { ...event, tags: 'nope' },
      }),
    ).toThrow(/event\.tags must be an array/);
    expect(() =>
      parseDeliveryCredential({
        type: 'profile',
        event: { ...event, tags: [['ok'], [1, 2]] },
      }),
    ).toThrow(/each event tag must be an array of strings/);
    // Happy path with a real tag array so the copy arm runs.
    const withTags = parseDeliveryCredential({
      type: 'profile',
      event: { ...event, tags: [['p', 'aa'.repeat(32)]] },
    });
    expect(withTags.type).toBe('profile');
    if (withTags.type === 'profile') {
      expect(withTags.event.tags).toEqual([['p', 'aa'.repeat(32)]]);
      // Defensive copy: mutating the input must not alter the parsed value.
      (event as { tags: string[][] }).tags = [];
      expect(withTags.event.tags).toEqual([['p', 'aa'.repeat(32)]]);
    }
  });
});

describe('verifyDeliveryCredential remaining refusals', () => {
  it('rejects empty invoice.relays and non-ws relay URLs', () => {
    const { invoice, recipient } = buildValidInvoice({ relays: [] });
    expect(() =>
      verifyDeliveryCredential(
        { type: 'invoice', invoice },
        { recipient, asset_id: ASSET_ID, amount: AMOUNT },
        { network: 'regtest' },
      ),
    ).toThrow(/relays must be non-empty/);

    const badUrl = buildValidInvoice({ relays: ['https://not-a-relay.example'] });
    // Signatures were built over the bad relay list; validation fails on URL form first.
    expect(() =>
      verifyDeliveryCredential(
        { type: 'invoice', invoice: badUrl.invoice },
        { recipient: badUrl.recipient, asset_id: ASSET_ID, amount: AMOUNT },
        { network: 'regtest' },
      ),
    ).toThrow(/relay URL must start with ws:\/\/ or wss:\/\//);
  });

  it('rejects profile kind ≠ 0, non-JSON content, non-object content, missing zkcoins', () => {
    const { event, address } = buildValidProfile({ network: 'regtest' });

    const wrongKind = signNip01Event({
      secretKey: hex32(OP_SECRET_HEX),
      createdAt: event.created_at,
      kind: 1,
      tags: [],
      content: event.content,
    });
    expect(() =>
      verifyDeliveryCredential(
        { type: 'profile', event: wrongKind },
        { recipient: address, asset_id: ASSET_ID, amount: AMOUNT },
        { network: 'regtest' },
      ),
    ).toThrow(/kind must be 0/);

    const notJson = signNip01Event({
      secretKey: hex32(OP_SECRET_HEX),
      createdAt: event.created_at,
      kind: 0,
      tags: [],
      content: 'not-json{',
    });
    expect(() =>
      verifyDeliveryCredential(
        { type: 'profile', event: notJson },
        { recipient: address, asset_id: ASSET_ID, amount: AMOUNT },
        { network: 'regtest' },
      ),
    ).toThrow(/content is not JSON/);

    const notObj = signNip01Event({
      secretKey: hex32(OP_SECRET_HEX),
      createdAt: event.created_at,
      kind: 0,
      tags: [],
      content: '["array"]',
    });
    expect(() =>
      verifyDeliveryCredential(
        { type: 'profile', event: notObj },
        { recipient: address, asset_id: ASSET_ID, amount: AMOUNT },
        { network: 'regtest' },
      ),
    ).toThrow(/content must be a JSON object/);

    const noZk = signNip01Event({
      secretKey: hex32(OP_SECRET_HEX),
      createdAt: event.created_at,
      kind: 0,
      tags: [],
      content: JSON.stringify({ name: 'Alice' }),
    });
    expect(() =>
      verifyDeliveryCredential(
        { type: 'profile', event: noZk },
        { recipient: address, asset_id: ASSET_ID, amount: AMOUNT },
        { network: 'regtest' },
      ),
    ).toThrow(/zkcoins object is required/);
  });

  it('rejects zkcoins.op_pubkey duplicate and unknown zkcoins fields', () => {
    const { event, address } = buildValidProfile({ network: 'regtest' });
    const content = JSON.parse(event.content) as { zkcoins: Record<string, unknown> };

    content.zkcoins.op_pubkey = OP_PUBKEY_HEX;
    const withOp = signNip01Event({
      secretKey: hex32(OP_SECRET_HEX),
      createdAt: event.created_at,
      kind: 0,
      tags: [],
      content: JSON.stringify(content),
    });
    expect(() =>
      verifyDeliveryCredential(
        { type: 'profile', event: withOp },
        { recipient: address, asset_id: ASSET_ID, amount: AMOUNT },
        { network: 'regtest' },
      ),
    ).toThrow(/must not duplicate op_pubkey/);

    delete content.zkcoins.op_pubkey;
    content.zkcoins.extra_field = true;
    const withExtra = signNip01Event({
      secretKey: hex32(OP_SECRET_HEX),
      createdAt: event.created_at,
      kind: 0,
      tags: [],
      content: JSON.stringify(content),
    });
    expect(() =>
      verifyDeliveryCredential(
        { type: 'profile', event: withExtra },
        { recipient: address, asset_id: ASSET_ID, amount: AMOUNT },
        { network: 'regtest' },
      ),
    ).toThrow(/unknown field/);
  });

  it('rejects non-string relays entries, address preimage mismatch, and bad addr_sig', () => {
    const { event, address } = buildValidProfile({ network: 'regtest' });
    const content = JSON.parse(event.content) as { zkcoins: Record<string, unknown> };

    content.zkcoins.relays = [1, 2];
    const badRelayTypes = signNip01Event({
      secretKey: hex32(OP_SECRET_HEX),
      createdAt: event.created_at,
      kind: 0,
      tags: [],
      content: JSON.stringify(content),
    });
    expect(() =>
      verifyDeliveryCredential(
        { type: 'profile', event: badRelayTypes },
        { recipient: address, asset_id: ASSET_ID, amount: AMOUNT },
        { network: 'regtest' },
      ),
    ).toThrow(/relays entries must be strings/);

    // Restore valid relays; break address preimage by swapping address to V.2 pin.
    content.zkcoins.relays = [RELAY];
    content.zkcoins.address = V2_BECH32;
    const badAddr = signNip01Event({
      secretKey: hex32(OP_SECRET_HEX),
      createdAt: event.created_at,
      kind: 0,
      tags: [],
      content: JSON.stringify(content),
    });
    expect(() =>
      verifyDeliveryCredential(
        { type: 'profile', event: badAddr },
        { recipient: V2_BECH32, asset_id: ASSET_ID, amount: AMOUNT },
        { network: 'regtest' },
      ),
    ).toThrow(/H\(pk0 ‖ nk_commit\) != address/);

    // Valid address preimage, forged addr_sig.
    const good = buildValidProfile({ network: 'regtest' });
    const goodContent = JSON.parse(good.event.content) as { zkcoins: Record<string, unknown> };
    goodContent.zkcoins.addr_sig = '00'.repeat(64);
    const forgedSig = signNip01Event({
      secretKey: hex32(OP_SECRET_HEX),
      createdAt: good.event.created_at,
      kind: 0,
      tags: [],
      content: JSON.stringify(goodContent),
    });
    expect(() =>
      verifyDeliveryCredential(
        { type: 'profile', event: forgedSig },
        { recipient: good.address, asset_id: ASSET_ID, amount: AMOUNT },
        { network: 'regtest' },
      ),
    ).toThrow(/addr_sig invalid under pk0/);
  });

  it('exhaustiveness arm rejects a runtime-only unknown delivery variant', () => {
    // parseDeliveryCredential never returns this shape; cast forces the never branch.
    const bogus = { type: 'carrier-pigeon' } as unknown as DeliveryCredential;
    expect(() =>
      verifyDeliveryCredential(
        bogus,
        { recipient: V2_BECH32, asset_id: ASSET_ID, amount: AMOUNT },
        { network: 'regtest' },
      ),
    ).toThrow(/unreachable delivery variant/);
  });
});

describe('assertOutputDeliveries address and verify error paths', () => {
  it('rejects invalid subject and invalid recipient addresses', () => {
    expect(() => assertOutputDeliveries('not-an-address', [], { network: 'regtest' })).toThrow(
      /invalid subject address/,
    );

    expect(() =>
      assertOutputDeliveries(
        SELF_SUBJECT,
        [{ recipient: 'also-not-an-address', asset_id: ASSET_ID, amount: '1' }],
        { network: 'regtest' },
      ),
    ).toThrow(/recipient invalid/);
  });

  it('propagates DeliveryCredentialError from nested verify', () => {
    const { invoice, recipient } = buildValidInvoice({ addr_sig: '00'.repeat(64) });
    expect(() =>
      assertOutputDeliveries(
        SELF_SUBJECT,
        [
          {
            recipient,
            asset_id: ASSET_ID,
            amount: AMOUNT,
            delivery: { type: 'invoice', invoice },
          },
        ],
        { network: 'regtest' },
      ),
    ).toThrow(/addr_sig|check \(ii\)/);
  });

  it('rewraps plain Error from nested hex decode as DeliveryCredentialError', () => {
    // parseDeliveryCredential only checks string shapes; wrong-length pk0 is a
    // plain Error from decodeHexExact inside verify — assertOutputDeliveries
    // must re-emit it under code "verify".
    const { invoice, recipient } = buildValidInvoice();
    invoice.pk0 = 'aa'.repeat(16); // 16 bytes, not 32
    try {
      assertOutputDeliveries(
        SELF_SUBJECT,
        [
          {
            recipient,
            asset_id: ASSET_ID,
            amount: AMOUNT,
            delivery: { type: 'invoice', invoice },
          },
        ],
        { network: 'regtest' },
      );
      expect.unreachable('expected DeliveryCredentialError');
    } catch (err) {
      expect(err).toBeInstanceOf(DeliveryCredentialError);
      if (!(err instanceof DeliveryCredentialError)) throw err;
      expect(err.code).toBe('verify');
      expect(err.message).toMatch(/output_templates\[0\]\.delivery:/);
    }
  });
});

describe('verifyBip340 malformed-key path via invoice', () => {
  /**
   * 32-byte x-only with x ≥ field prime p (all 0xFF). Length is valid; the
   * point is not. `@noble/curves` `schnorr.verify` returns false for this
   * (it does not throw) — `verifyBip340` therefore rejects via `false`.
   */
  const X_GE_P = 'ff'.repeat(32);

  it('rejects addr_sig check when pk0 is off-curve (verify returns false)', () => {
    // BIP-340 invalid x-only key (same probe as half-agg tests). Address is
    // still H(pk0‖nk) so check (i) passes; BIP-340 under pk0 is the gate.
    const OFF_CURVE = 'eefdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34';
    const nk = v2extNkCommit();
    const recipientRaw = addressFromParts(hex32(OFF_CURVE), nk);
    const recipient = encodeZkAddress(recipientRaw);
    const msg = invoiceMessage({
      amount: BigInt(AMOUNT),
      recipient: recipientRaw,
      pk0: hex32(OFF_CURVE),
      nkCommit: nk,
      assetId: hex32(ASSET_ID),
      ivpk: hex32(IVPK_HEX),
      opPubkey: hex32(OP_PUBKEY_HEX),
      relays: [RELAY],
    });
    const invoice: InvoiceJson = {
      amount: AMOUNT,
      recipient,
      asset_id: ASSET_ID,
      pk0: OFF_CURVE,
      nk_commit: encodeHexLower(nk),
      ivpk: IVPK_HEX,
      op_pubkey: OP_PUBKEY_HEX,
      relays: [RELAY],
      addr_sig: signMsg(hex32(SK0_HEX), msg),
      sig: signMsg(hex32(OP_SECRET_HEX), msg),
    };
    expect(() =>
      verifyDeliveryCredential(
        { type: 'invoice', invoice },
        { recipient, asset_id: ASSET_ID, amount: AMOUNT },
        { network: 'regtest' },
      ),
    ).toThrow(/addr_sig|check \(ii\)/);
  });

  it('rejects addr_sig check when pk0 x ≥ p (32×0xFF, verify returns false)', () => {
    const nk = v2extNkCommit();
    const pk0 = hex32(X_GE_P);
    const recipientRaw = addressFromParts(pk0, nk);
    const recipient = encodeZkAddress(recipientRaw);
    const msg = invoiceMessage({
      amount: BigInt(AMOUNT),
      recipient: recipientRaw,
      pk0,
      nkCommit: nk,
      assetId: hex32(ASSET_ID),
      ivpk: hex32(IVPK_HEX),
      opPubkey: hex32(OP_PUBKEY_HEX),
      relays: [RELAY],
    });
    const invoice: InvoiceJson = {
      amount: AMOUNT,
      recipient,
      asset_id: ASSET_ID,
      pk0: X_GE_P,
      nk_commit: encodeHexLower(nk),
      ivpk: IVPK_HEX,
      op_pubkey: OP_PUBKEY_HEX,
      relays: [RELAY],
      addr_sig: signMsg(hex32(SK0_HEX), msg),
      sig: signMsg(hex32(OP_SECRET_HEX), msg),
    };
    expect(() =>
      verifyDeliveryCredential(
        { type: 'invoice', invoice },
        { recipient, asset_id: ASSET_ID, amount: AMOUNT },
        { network: 'regtest' },
      ),
    ).toThrow(/addr_sig|check \(ii\)/);
  });
});

describe('parseU128Decimal bounds', () => {
  it('rejects non-canonical decimals via the regex guard (before BigInt)', () => {
    expect(() => parseU128Decimal('01', 'field')).toThrow(/non-canonical decimal string/);
    expect(() => parseU128Decimal('-1', 'field')).toThrow(/non-canonical decimal string/);
    expect(() => parseU128Decimal('1.0', 'field')).toThrow(/non-canonical decimal string/);
    expect(() => parseU128Decimal('1e2', 'field')).toThrow(/non-canonical decimal string/);
    expect(() => parseU128Decimal(' ', 'field')).toThrow(/non-canonical decimal string/);
  });

  it('rejects values outside u128 after successful BigInt parse', () => {
    // Canonical decimal longer than u128 max (2^128 − 1 ≈ 39 digits).
    const over = '1' + '0'.repeat(40);
    expect(() => parseU128Decimal(over, 'field')).toThrow(/out of u128 range/);
  });
});

describe('issueInvoice', () => {
  const baseParams = () => ({
    amount: AMOUNT,
    assetId: ASSET_ID,
    relays: [RELAY],
    sk0Secret: hex32(SK0_HEX),
    nkCommit: v2extNkCommit(),
    ivpk: hex32(IVPK_HEX),
    opSecret: hex32(OP_SECRET_HEX),
  });

  it('issues a valid invoice that round-trips through verifyDeliveryCredential', async () => {
    const invoice = await issueInvoice(baseParams());
    expect(invoice.pk0).toBe(PK0_HEX);
    expect(invoice.op_pubkey).toBe(OP_PUBKEY_HEX);
    expect(invoice.amount).toBe(AMOUNT);
    expect(invoice.asset_id).toBe(ASSET_ID);
    expect(invoice.relays).toEqual([RELAY]);
    expect(invoice.memo).toBeUndefined();
    expect(() =>
      verifyDeliveryCredential(
        { type: 'invoice', invoice },
        {
          recipient: invoice.recipient,
          asset_id: invoice.asset_id,
          amount: invoice.amount,
        },
        { network: 'regtest' },
      ),
    ).not.toThrow();
  });

  it('includes memo on the wire and changes both signatures vs no-memo', async () => {
    const noMemo = await issueInvoice(baseParams());
    const withMemo = await issueInvoice({ ...baseParams(), memo: 'payment for goods' });
    expect(withMemo.memo).toBe('payment for goods');
    expect(withMemo.addr_sig).not.toBe(noMemo.addr_sig);
    expect(withMemo.sig).not.toBe(noMemo.sig);
    expect(() =>
      verifyDeliveryCredential(
        { type: 'invoice', invoice: withMemo },
        {
          recipient: withMemo.recipient,
          asset_id: withMemo.asset_id,
          amount: withMemo.amount,
        },
        { network: 'regtest' },
      ),
    ).not.toThrow();
  });

  it('rejects empty relays', async () => {
    await expect(issueInvoice({ ...baseParams(), relays: [] })).rejects.toThrow(
      DeliveryCredentialError,
    );
    await expect(issueInvoice({ ...baseParams(), relays: [] })).rejects.toThrow(/relays/);
  });

  it('rejects a non-ws(s) relay URL', async () => {
    await expect(
      issueInvoice({ ...baseParams(), relays: ['https://not-a-relay.example'] }),
    ).rejects.toThrow(DeliveryCredentialError);
    await expect(
      issueInvoice({ ...baseParams(), relays: ['https://not-a-relay.example'] }),
    ).rejects.toThrow(/ws:\/\/|wss:\/\//);
  });

  it('rejects wrong-length nkCommit / ivpk', async () => {
    await expect(
      issueInvoice({ ...baseParams(), nkCommit: new Uint8Array(31) }),
    ).rejects.toThrow(/nk_commit/);
    await expect(issueInvoice({ ...baseParams(), ivpk: new Uint8Array(16) })).rejects.toThrow(
      /ivpk/,
    );
  });
});
