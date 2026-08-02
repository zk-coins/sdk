/**
 * §7.5 `OutputTemplate.delivery` credential + sender-side §4.3 checks.
 *
 * The kernel alone verifies delivery for admission; the wallet **also**
 * verifies before placing a credential into a request — that is the
 * counterparty-object check §4.3 requires of the sender, not anti-node
 * logic. Crypto reused from existing SDK primitives:
 *   - SHA-256 address preimage `H(pk0 ‖ nk_commit)` (§1.4)
 *   - BIP-340 via `@noble/curves` (same path as ownership proofs)
 *   - NIP-01 event id + verify (`nostrEvent.ts`)
 *   - Bech32m decode (`bech32m.ts`) / hex helpers (`hex.ts`)
 *
 * Pinning (§4.3 *Payment-identity pinning*) lives in
 * {@link PaymentIdentityPinStore}: first contact is not an error; a pin
 * mismatch warns and refuses silent payment.
 */

import { schnorr } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';

import { decodeZkAddress } from './bech32m.js';
import { bytesEqual, decodeHexExact, encodeHexLower } from './hex.js';
import type { Network } from './mstate.js';
import { verifyNip01Event, type NostrEventJson } from './nostrEvent.js';

// ---------------------------------------------------------------------------
// Wire types (§7.5 closed tagged union)
// ---------------------------------------------------------------------------

/** Domain tag for `invoice_message` (§4.3). */
export const INVOICE_MESSAGE_DOMAIN = 'zkCoins/v1/Invoice';

/**
 * Full §1.5 / §4.3 `Invoice` on the REST surface (§7.1 hex + decimal-string).
 * Binary fields are lowercase hex; `recipient` is Bech32m `zk1…`.
 */
export interface InvoiceJson {
  /** Decimal-string u128. */
  amount: string;
  /** Bech32m zk-address. */
  recipient: string;
  /** 32-byte asset id, lowercase hex. */
  asset_id: string;
  /** Optional memo (UTF-8). Absent or empty both contribute length-0 to the preimage. */
  memo?: string;
  /** 32-byte recipient Pk₀, lowercase hex. */
  pk0: string;
  /** 32-byte nk_commit, lowercase hex. */
  nk_commit: string;
  /** 32-byte IVPK, lowercase hex. */
  ivpk: string;
  /** 32-byte recipient op pubkey, lowercase hex. */
  op_pubkey: string;
  /** Non-empty advertised relay set. */
  relays: string[];
  /** 64-byte BIP-340 under pk0 over invoice_message. */
  addr_sig: string;
  /** 64-byte BIP-340 under op_pubkey over invoice_message. */
  sig: string;
}

/** Closed tagged union. Any other `type` is malformed. */
export type DeliveryCredential =
  | { type: 'invoice'; invoice: InvoiceJson }
  | { type: 'profile'; event: NostrEventJson };

/** Payment-identity pin fields (§4.3). Keyed by `op_pubkey` at the store. */
export interface PaymentIdentityPin {
  /** Bech32m address (or any string form the caller stored; compared decoded). */
  address: string;
  /** 32-byte lowercase hex. */
  pk0: string;
  /** 32-byte lowercase hex. */
  nk_commit: string;
  /** 32-byte lowercase hex. */
  ivpk: string;
}

export type PinCheckResult =
  | { status: 'absent' }
  | { status: 'match' }
  | { status: 'mismatch'; pin: PaymentIdentityPin; credential: PaymentIdentityPin };

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export class DeliveryCredentialError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = 'DeliveryCredentialError';
    this.code = code;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * §4.3 pin mismatch: credential values differ from the stored pin for this
 * `op_pubkey`. Silent payment is forbidden; the caller must obtain explicit
 * user confirmation and pass `confirmPinMismatch: true` to proceed.
 */
export class PaymentIdentityPinMismatchError extends Error {
  readonly opPubkey: string;
  readonly pin: PaymentIdentityPin;
  readonly credential: PaymentIdentityPin;

  constructor(input: {
    opPubkey: string;
    pin: PaymentIdentityPin;
    credential: PaymentIdentityPin;
  }) {
    super(
      `payment-identity pin mismatch for op_pubkey=${input.opPubkey}: ` +
        `refusing silent payment (confirmPinMismatch required to proceed)`,
    );
    this.name = 'PaymentIdentityPinMismatchError';
    this.opPubkey = input.opPubkey;
    this.pin = input.pin;
    this.credential = input.credential;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

// ---------------------------------------------------------------------------
// Pin store
// ---------------------------------------------------------------------------

/**
 * Local §4.3 payment-identity pin set, keyed by `op_pubkey` (lowercase hex).
 *
 * Not seed-derivable — lost on node switch / emergency recovery unless the
 * deployment transfers it. First contact (`get` returns undefined) is not an
 * error.
 */
export class PaymentIdentityPinStore {
  private readonly pins = new Map<string, PaymentIdentityPin>();

  /** Lookup by lowercase-hex `op_pubkey`. */
  get(opPubkey: string): PaymentIdentityPin | undefined {
    return this.pins.get(normalizeOpKey(opPubkey));
  }

  /**
   * Record or replace a pin after first successful verification or after
   * explicit user confirmation of a changed identity.
   */
  set(opPubkey: string, pin: PaymentIdentityPin): void {
    this.pins.set(normalizeOpKey(opPubkey), {
      address: pin.address,
      pk0: pin.pk0,
      nk_commit: pin.nk_commit,
      ivpk: pin.ivpk,
    });
  }

  /** Remove a pin (e.g. user discards a contact). */
  delete(opPubkey: string): boolean {
    return this.pins.delete(normalizeOpKey(opPubkey));
  }

  /**
   * Compare a credential's payment identity against any pin held for
   * `opPubkey`. Absent pin → first contact.
   */
  check(opPubkey: string, candidate: PaymentIdentityPin): PinCheckResult {
    const pin = this.get(opPubkey);
    if (pin === undefined) {
      return { status: 'absent' };
    }
    if (pinsEqual(pin, candidate)) {
      return { status: 'match' };
    }
    return { status: 'mismatch', pin, credential: candidate };
  }
}

function normalizeOpKey(opPubkey: string): string {
  if (typeof opPubkey !== 'string' || opPubkey.length === 0) {
    throw new DeliveryCredentialError('pin_key', 'op_pubkey is required for pin lookup');
  }
  // Fail-closed: only accept canonical 32-byte lowercase hex as map keys.
  decodeHexExact(opPubkey, 32, 'op_pubkey');
  return opPubkey;
}

function pinsEqual(a: PaymentIdentityPin, b: PaymentIdentityPin): boolean {
  // Address compared on the 32-byte payload so Bech32m spelling variants match.
  let addrA: Uint8Array;
  let addrB: Uint8Array;
  try {
    addrA = decodeAddressField(a.address);
    addrB = decodeAddressField(b.address);
  } catch {
    return false;
  }
  if (!bytesEqual(addrA, addrB)) return false;
  try {
    return (
      bytesEqual(decodeHexExact(a.pk0, 32, 'pin.pk0'), decodeHexExact(b.pk0, 32, 'pin.pk0')) &&
      bytesEqual(
        decodeHexExact(a.nk_commit, 32, 'pin.nk_commit'),
        decodeHexExact(b.nk_commit, 32, 'pin.nk_commit'),
      ) &&
      bytesEqual(decodeHexExact(a.ivpk, 32, 'pin.ivpk'), decodeHexExact(b.ivpk, 32, 'pin.ivpk'))
    );
  } catch {
    return false;
  }
}

/** Accept Bech32m `zk1…` or raw 32-byte lowercase hex for address fields. */
function decodeAddressField(address: string): Uint8Array {
  if (typeof address !== 'string' || address.length === 0) {
    throw new DeliveryCredentialError('address', 'address is required');
  }
  if (address.startsWith('zk1') || address.startsWith('ZK1')) {
    return decodeZkAddress(address);
  }
  return decodeHexExact(address, 32, 'address');
}

// ---------------------------------------------------------------------------
// invoice_message / address preimage
// ---------------------------------------------------------------------------

/** `address = SHA-256(pk0 ‖ nk_commit)` — 64-byte preimage, no domain tag (§1.4). */
export function addressFromParts(pk0: Uint8Array, nkCommit: Uint8Array): Uint8Array {
  if (pk0.length !== 32) {
    throw new DeliveryCredentialError(
      'pk0',
      `addressFromParts: pk0 must be 32 bytes, got ${pk0.length}`,
    );
  }
  if (nkCommit.length !== 32) {
    throw new DeliveryCredentialError(
      'nk_commit',
      `addressFromParts: nk_commit must be 32 bytes, got ${nkCommit.length}`,
    );
  }
  const pre = new Uint8Array(64);
  pre.set(pk0, 0);
  pre.set(nkCommit, 32);
  return sha256(pre);
}

export interface InvoiceMessageParts {
  amount: bigint;
  /** 32-byte address payload (not Bech32m). */
  recipient: Uint8Array;
  pk0: Uint8Array;
  nkCommit: Uint8Array;
  assetId: Uint8Array;
  /** Absent or empty both encode as u32-be length 0. */
  memo?: string;
  ivpk: Uint8Array;
  opPubkey: Uint8Array;
  relays: readonly string[];
}

/**
 * `invoice_message = H("zkCoins/v1/Invoice" ‖ amount ‖ recipient ‖ pk0 ‖
 * nk_commit ‖ asset_id ‖ memo ‖ ivpk ‖ op_pubkey ‖ relays)` (§4.3).
 *
 * Framing: amount 16-byte BE u128; memo = u32-be len ‖ UTF-8; relays =
 * u16-be count ‖ each (u32-be len ‖ UTF-8). Order is the formula.
 */
export function invoiceMessage(parts: InvoiceMessageParts): Uint8Array {
  require32(parts.recipient, 'recipient');
  require32(parts.pk0, 'pk0');
  require32(parts.nkCommit, 'nk_commit');
  require32(parts.assetId, 'asset_id');
  require32(parts.ivpk, 'ivpk');
  require32(parts.opPubkey, 'op_pubkey');
  if (parts.amount < 0n || parts.amount >= 1n << 128n) {
    throw new DeliveryCredentialError(
      'amount',
      `invoiceMessage: amount out of u128 range: ${parts.amount.toString()}`,
    );
  }
  if (parts.relays.length > 0xffff) {
    throw new DeliveryCredentialError('relays', 'invoiceMessage: relay count exceeds u16');
  }

  const memoBytes = new TextEncoder().encode(parts.memo ?? '');
  if (memoBytes.length > 0xffff_ffff) {
    throw new DeliveryCredentialError('memo', 'invoiceMessage: memo length exceeds u32');
  }

  const tag = new TextEncoder().encode(INVOICE_MESSAGE_DOMAIN);
  let relayBytesLen = 0;
  for (const r of parts.relays) {
    const b = new TextEncoder().encode(r);
    if (b.length > 0xffff_ffff) {
      throw new DeliveryCredentialError('relays', 'invoiceMessage: relay URL length exceeds u32');
    }
    relayBytesLen += 4 + b.length;
  }

  const preimage = new Uint8Array(
    tag.length + 16 + 32 + 32 + 32 + 32 + 4 + memoBytes.length + 32 + 32 + 2 + relayBytesLen,
  );
  let o = 0;
  preimage.set(tag, o);
  o += tag.length;
  preimage.set(u128Be(parts.amount), o);
  o += 16;
  preimage.set(parts.recipient, o);
  o += 32;
  preimage.set(parts.pk0, o);
  o += 32;
  preimage.set(parts.nkCommit, o);
  o += 32;
  preimage.set(parts.assetId, o);
  o += 32;
  preimage.set(u32Be(memoBytes.length), o);
  o += 4;
  preimage.set(memoBytes, o);
  o += memoBytes.length;
  preimage.set(parts.ivpk, o);
  o += 32;
  preimage.set(parts.opPubkey, o);
  o += 32;
  preimage.set(u16Be(parts.relays.length), o);
  o += 2;
  for (const r of parts.relays) {
    const b = new TextEncoder().encode(r);
    preimage.set(u32Be(b.length), o);
    o += 4;
    preimage.set(b, o);
    o += b.length;
  }
  return sha256(preimage);
}

/** Profile-fixed invoice_message: amount=0, all-zero asset_id, empty memo. */
export function profileInvoiceMessage(input: {
  address: Uint8Array;
  pk0: Uint8Array;
  nkCommit: Uint8Array;
  ivpk: Uint8Array;
  opPubkey: Uint8Array;
  relays: readonly string[];
}): Uint8Array {
  return invoiceMessage({
    amount: 0n,
    recipient: input.address,
    pk0: input.pk0,
    nkCommit: input.nkCommit,
    assetId: new Uint8Array(32),
    ivpk: input.ivpk,
    opPubkey: input.opPubkey,
    relays: input.relays,
  });
}

// ---------------------------------------------------------------------------
// Parse / shape helpers
// ---------------------------------------------------------------------------

/** Object (not null, not array) — same guard as `client.ts` response parsers. */
function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function requireStringField(obj: Record<string, unknown>, key: string): string {
  const v = obj[key];
  if (typeof v !== 'string') {
    throw new DeliveryCredentialError(key, `${key} must be a string`);
  }
  return v;
}

function requireNonNegativeIntegerField(
  obj: Record<string, unknown>,
  key: string,
  message: string,
): number {
  const v = obj[key];
  if (typeof v !== 'number' || !Number.isInteger(v) || v < 0) {
    throw new DeliveryCredentialError(key, message);
  }
  return v;
}

/** Fail-closed string-array parse; copies so callers cannot mutate wire input. */
function requireStringArray(raw: unknown, code: string, message: string): string[] {
  if (!Array.isArray(raw) || !raw.every((r): r is string => typeof r === 'string')) {
    throw new DeliveryCredentialError(code, message);
  }
  return raw.slice();
}

/** Closed delivery union. Unknown `type` is an error — never passed through. */
export function parseDeliveryCredential(raw: unknown): DeliveryCredential {
  if (!isRecord(raw)) {
    throw new DeliveryCredentialError('shape', 'delivery must be an object');
  }
  const type = raw.type;
  if (type === 'invoice') {
    return { type: 'invoice', invoice: parseInvoiceJson(raw.invoice) };
  }
  if (type === 'profile') {
    return { type: 'profile', event: parseNostrEventJson(raw.event) };
  }
  throw new DeliveryCredentialError(
    'unknown_type',
    `delivery.type must be "invoice" or "profile", got ${JSON.stringify(type)}`,
  );
}

function parseInvoiceJson(raw: unknown): InvoiceJson {
  if (!isRecord(raw)) {
    throw new DeliveryCredentialError('shape', 'invoice must be an object');
  }
  const amount = requireStringField(raw, 'amount');
  const recipient = requireStringField(raw, 'recipient');
  const asset_id = requireStringField(raw, 'asset_id');
  const pk0 = requireStringField(raw, 'pk0');
  const nk_commit = requireStringField(raw, 'nk_commit');
  const ivpk = requireStringField(raw, 'ivpk');
  const op_pubkey = requireStringField(raw, 'op_pubkey');
  const addr_sig = requireStringField(raw, 'addr_sig');
  const sig = requireStringField(raw, 'sig');
  const relays = requireStringArray(
    raw.relays,
    'relays',
    'invoice.relays must be an array of strings',
  );
  const memoVal = raw.memo;
  const out: InvoiceJson = {
    amount,
    recipient,
    asset_id,
    pk0,
    nk_commit,
    ivpk,
    op_pubkey,
    relays,
    addr_sig,
    sig,
  };
  if (memoVal !== undefined) {
    if (typeof memoVal !== 'string') {
      throw new DeliveryCredentialError('memo', 'invoice.memo must be a string when present');
    }
    out.memo = memoVal;
  }
  return out;
}

function parseNostrEventJson(raw: unknown): NostrEventJson {
  if (!isRecord(raw)) {
    throw new DeliveryCredentialError('shape', 'event must be an object');
  }
  const id = requireStringField(raw, 'id');
  const pubkey = requireStringField(raw, 'pubkey');
  const content = requireStringField(raw, 'content');
  const sig = requireStringField(raw, 'sig');
  const created_at = requireNonNegativeIntegerField(
    raw,
    'created_at',
    'event.created_at must be a non-negative integer',
  );
  const kind = requireNonNegativeIntegerField(
    raw,
    'kind',
    'event.kind must be a non-negative integer',
  );
  const tagsRaw = raw.tags;
  if (!Array.isArray(tagsRaw)) {
    throw new DeliveryCredentialError('tags', 'event.tags must be an array');
  }
  const tags: string[][] = [];
  for (const tag of tagsRaw) {
    if (!Array.isArray(tag) || !tag.every((e): e is string => typeof e === 'string')) {
      throw new DeliveryCredentialError('tags', 'each event tag must be an array of strings');
    }
    tags.push(tag.slice());
  }
  return {
    id,
    pubkey,
    created_at,
    kind,
    tags,
    content,
    sig,
  };
}

// ---------------------------------------------------------------------------
// Verification (sender-side §4.3 + §7.5 field equality)
// ---------------------------------------------------------------------------

export interface VerifyDeliveryOptions {
  /** Expected network for profile credentials (`zkcoins.network`). */
  network: Network;
  /** Optional pin store for §4.3 payment-identity pin check. */
  pinStore?: PaymentIdentityPinStore;
  /**
   * When true, a pin mismatch does not abort — the caller has obtained
   * explicit user confirmation. Default false (refuse silent payment).
   */
  confirmPinMismatch?: boolean;
  /**
   * When true and verification succeeds with no existing pin, record a
   * first-use pin for the credential's `op_pubkey`. Default false — the
   * wallet decides when to pin.
   */
  pinOnFirstUse?: boolean;
}

/**
 * Verify a delivery credential against its enclosing output template and
 * (when supplied) the pin store. Throws {@link DeliveryCredentialError} or
 * {@link PaymentIdentityPinMismatchError}.
 *
 * Invoice order (§4.3): (i) address preimage, (ii) addr_sig, (iii) op sig,
 * then byte-exact recipient/asset_id/amount equality with the output.
 *
 * Profile order (§4.3 sender chain + §7.5 shape): event signature, address
 * preimage, profile-fixed addr_sig, version/network/hex/relays, then
 * `zkcoins.address == output.recipient`.
 */
export function verifyDeliveryCredential(
  delivery: DeliveryCredential,
  output: { recipient: string; asset_id: string; amount: string },
  opts: VerifyDeliveryOptions,
): void {
  if (delivery.type === 'invoice') {
    verifyInvoiceAgainstOutput(delivery.invoice, output, opts);
    return;
  }
  if (delivery.type === 'profile') {
    verifyProfileAgainstOutput(delivery.event, output, opts);
    return;
  }
  // Exhaustiveness — parseDeliveryCredential already rejects unknown types.
  const _never: never = delivery;
  throw new DeliveryCredentialError(
    'unknown_type',
    `unreachable delivery variant ${JSON.stringify(_never)}`,
  );
}

/**
 * Place a verified delivery credential onto an output template at the
 * caller's chosen slot (position binding is the array index in
 * `output_templates[]`). Returns a new template object.
 */
export function placeDeliveryCredential(
  output: { recipient: string; asset_id: string; amount: string },
  delivery: DeliveryCredential,
  opts: VerifyDeliveryOptions,
): { recipient: string; asset_id: string; amount: string; delivery: DeliveryCredential } {
  const parsed = parseDeliveryCredential(delivery);
  verifyDeliveryCredential(parsed, output, opts);
  return {
    recipient: output.recipient,
    asset_id: output.asset_id,
    amount: output.amount,
    delivery: parsed,
  };
}

function verifyInvoiceAgainstOutput(
  invoice: InvoiceJson,
  output: { recipient: string; asset_id: string; amount: string },
  opts: VerifyDeliveryOptions,
): void {
  if (invoice.relays.length === 0) {
    throw new DeliveryCredentialError('relays', 'invoice.relays must be non-empty');
  }
  for (const url of invoice.relays) {
    validateRelayUrl(url);
  }

  const pk0 = decodeHexExact(invoice.pk0, 32, 'invoice.pk0');
  const nkCommit = decodeHexExact(invoice.nk_commit, 32, 'invoice.nk_commit');
  const ivpk = decodeHexExact(invoice.ivpk, 32, 'invoice.ivpk');
  const opPubkey = decodeHexExact(invoice.op_pubkey, 32, 'invoice.op_pubkey');
  const assetId = decodeHexExact(invoice.asset_id, 32, 'invoice.asset_id');
  const addrSig = decodeHexExact(invoice.addr_sig, 64, 'invoice.addr_sig');
  const opSig = decodeHexExact(invoice.sig, 64, 'invoice.sig');
  const recipientRaw = decodeZkAddress(invoice.recipient);
  const amount = parseU128Decimal(invoice.amount, 'invoice.amount');

  // (i) H(pk0 ‖ nk_commit) == recipient
  const computed = addressFromParts(pk0, nkCommit);
  if (!bytesEqual(computed, recipientRaw)) {
    throw new DeliveryCredentialError(
      'check_i_address',
      `invoice check (i): H(pk0 ‖ nk_commit) != recipient — computed=${encodeHexLower(computed)}`,
    );
  }

  const msg = invoiceMessage({
    amount,
    recipient: recipientRaw,
    pk0,
    nkCommit,
    assetId,
    ...(invoice.memo !== undefined ? { memo: invoice.memo } : {}),
    ivpk,
    opPubkey,
    relays: invoice.relays,
  });

  // (ii) addr_sig under pk0
  if (!verifyBip340(pk0, msg, addrSig)) {
    throw new DeliveryCredentialError(
      'check_ii_addr_sig',
      'invoice check (ii): addr_sig invalid under pk0 over invoice_message',
    );
  }

  // (iii) sig under op_pubkey
  if (!verifyBip340(opPubkey, msg, opSig)) {
    throw new DeliveryCredentialError(
      'check_iii_op_sig',
      'invoice check (iii): sig invalid under op_pubkey over invoice_message',
    );
  }

  // Byte-exact equality with enclosing output (wire strings).
  if (invoice.recipient !== output.recipient) {
    throw new DeliveryCredentialError(
      'output_recipient',
      'invoice.recipient must equal output.recipient exactly',
    );
  }
  if (invoice.asset_id !== output.asset_id) {
    throw new DeliveryCredentialError(
      'output_asset_id',
      'invoice.asset_id must equal output.asset_id exactly',
    );
  }
  if (invoice.amount !== output.amount) {
    throw new DeliveryCredentialError(
      'output_amount',
      'invoice.amount must equal output.amount exactly',
    );
  }

  applyPinCheck(
    encodeHexLower(opPubkey),
    {
      address: invoice.recipient,
      pk0: invoice.pk0,
      nk_commit: invoice.nk_commit,
      ivpk: invoice.ivpk,
    },
    opts,
  );
}

function verifyProfileAgainstOutput(
  event: NostrEventJson,
  output: { recipient: string; asset_id: string; amount: string },
  opts: VerifyDeliveryOptions,
): void {
  // Event signature under author (profile check that binds op_pubkey).
  if (event.kind !== 0) {
    throw new DeliveryCredentialError(
      'kind',
      `profile event kind must be 0, got ${String(event.kind)}`,
    );
  }
  try {
    verifyNip01Event(event);
  } catch (cause) {
    throw new DeliveryCredentialError(
      'event_sig',
      `profile event signature failed: ${cause instanceof Error ? cause.message : String(cause)}`,
    );
  }

  const opPubkey = decodeHexExact(event.pubkey, 32, 'event.pubkey');
  let contentJson: unknown;
  try {
    // JSON.parse returns `any`; narrow via isRecord below — never trust the payload.
    contentJson = JSON.parse(event.content) as unknown;
  } catch {
    throw new DeliveryCredentialError('content', 'profile event content is not JSON');
  }
  if (!isRecord(contentJson)) {
    throw new DeliveryCredentialError('content', 'profile event content must be a JSON object');
  }
  const zkRaw = contentJson.zkcoins;
  if (!isRecord(zkRaw)) {
    throw new DeliveryCredentialError('zkcoins', 'profile content.zkcoins object is required');
  }

  // Closed field set — reject duplicated op_pubkey and unknown keys.
  const allowed = new Set([
    'version',
    'network',
    'address',
    'pk0',
    'nk_commit',
    'ivpk',
    'relays',
    'addr_sig',
    'name_sig',
  ]);
  for (const key of Object.keys(zkRaw)) {
    if (key === 'op_pubkey') {
      throw new DeliveryCredentialError(
        'op_pubkey',
        'zkcoins must not duplicate op_pubkey (it is the kind-0 author)',
      );
    }
    if (!allowed.has(key)) {
      throw new DeliveryCredentialError(
        'zkcoins',
        `zkcoins has unknown field ${JSON.stringify(key)}`,
      );
    }
  }

  const version = zkRaw.version;
  if (version !== 1) {
    throw new DeliveryCredentialError(
      'version',
      `zkcoins.version must be 1, got ${JSON.stringify(version)}`,
    );
  }
  const network = zkRaw.network;
  if (network !== opts.network) {
    throw new DeliveryCredentialError(
      'network',
      `zkcoins.network must be ${JSON.stringify(opts.network)}, got ${JSON.stringify(network)}`,
    );
  }
  const addressStr = requireStringField(zkRaw, 'address');
  const pk0Hex = requireStringField(zkRaw, 'pk0');
  const nkHex = requireStringField(zkRaw, 'nk_commit');
  const ivpkHex = requireStringField(zkRaw, 'ivpk');
  const addrSigHex = requireStringField(zkRaw, 'addr_sig');
  // name_sig is required in the object shape for served accounts; we only
  // require the field present as hex — payment does not depend on it when
  // the consumer did not arrive via a name.
  const nameSigHex = zkRaw.name_sig;
  if (typeof nameSigHex === 'string') {
    decodeHexExact(nameSigHex, 64, 'zkcoins.name_sig');
  }
  const relaysRaw = zkRaw.relays;
  if (!Array.isArray(relaysRaw) || relaysRaw.length === 0) {
    throw new DeliveryCredentialError('relays', 'zkcoins.relays must be a non-empty array');
  }
  if (!relaysRaw.every((r): r is string => typeof r === 'string')) {
    throw new DeliveryCredentialError('relays', 'zkcoins.relays entries must be strings');
  }
  const relays = relaysRaw.slice();
  for (const url of relays) {
    validateRelayUrl(url);
  }

  const pk0 = decodeHexExact(pk0Hex, 32, 'zkcoins.pk0');
  const nkCommit = decodeHexExact(nkHex, 32, 'zkcoins.nk_commit');
  const ivpk = decodeHexExact(ivpkHex, 32, 'zkcoins.ivpk');
  const addrSig = decodeHexExact(addrSigHex, 64, 'zkcoins.addr_sig');
  const addressRaw = decodeZkAddress(addressStr);

  // Address preimage.
  const computed = addressFromParts(pk0, nkCommit);
  if (!bytesEqual(computed, addressRaw)) {
    throw new DeliveryCredentialError(
      'check_address',
      `profile: H(pk0 ‖ nk_commit) != address — computed=${encodeHexLower(computed)}`,
    );
  }

  // addr_sig under pk0 over profile-fixed invoice_message (op = event author).
  const msg = profileInvoiceMessage({
    address: addressRaw,
    pk0,
    nkCommit,
    ivpk,
    opPubkey,
    relays,
  });
  if (!verifyBip340(pk0, msg, addrSig)) {
    throw new DeliveryCredentialError(
      'check_addr_sig',
      'profile: addr_sig invalid under pk0 over profile-fixed invoice_message',
    );
  }

  // Addressing credential: address == output.recipient (wire string equality).
  if (addressStr !== output.recipient) {
    throw new DeliveryCredentialError(
      'output_recipient',
      'zkcoins.address must equal output.recipient exactly',
    );
  }
  // Silence unused amount/asset — profile deliberately does not bind them.
  void output.asset_id;
  void output.amount;

  applyPinCheck(
    encodeHexLower(opPubkey),
    {
      address: addressStr,
      pk0: pk0Hex,
      nk_commit: nkHex,
      ivpk: ivpkHex,
    },
    opts,
  );
}

function applyPinCheck(
  opPubkeyHex: string,
  candidate: PaymentIdentityPin,
  opts: VerifyDeliveryOptions,
): void {
  const store = opts.pinStore;
  if (store === undefined) {
    return;
  }
  const result = store.check(opPubkeyHex, candidate);
  if (result.status === 'mismatch') {
    if (opts.confirmPinMismatch === true) {
      return;
    }
    throw new PaymentIdentityPinMismatchError({
      opPubkey: opPubkeyHex,
      pin: result.pin,
      credential: result.credential,
    });
  }
  if (result.status === 'absent' && opts.pinOnFirstUse === true) {
    store.set(opPubkeyHex, candidate);
  }
}

// ---------------------------------------------------------------------------
// Output-template presence (sender-side presence rule)
// ---------------------------------------------------------------------------

/**
 * For every non-self output, `delivery` is required. Self-output ≜
 * `decoded(recipient) == decoded(subject)`. When delivery is present it is
 * verified against the enclosing output.
 */
export function assertOutputDeliveries(
  subject: string,
  outputs: readonly {
    recipient: string;
    asset_id: string;
    amount: string;
    delivery?: DeliveryCredential;
  }[],
  opts: VerifyDeliveryOptions,
): void {
  let subjectRaw: Uint8Array;
  try {
    subjectRaw = decodeZkAddress(subject);
  } catch (cause) {
    throw new DeliveryCredentialError(
      'subject',
      `invalid subject address: ${cause instanceof Error ? cause.message : String(cause)}`,
    );
  }

  for (let i = 0; i < outputs.length; i++) {
    const out = outputs[i]!;
    let recipientRaw: Uint8Array;
    try {
      recipientRaw = decodeZkAddress(out.recipient);
    } catch (cause) {
      throw new DeliveryCredentialError(
        'recipient',
        `output_templates[${i}].recipient invalid: ${cause instanceof Error ? cause.message : String(cause)}`,
      );
    }
    const isSelf = bytesEqual(recipientRaw, subjectRaw);
    if (out.delivery === undefined) {
      if (!isSelf) {
        throw new DeliveryCredentialError(
          'delivery_required',
          `output_templates[${i}]: delivery is required for non-self outputs`,
        );
      }
      continue;
    }
    const parsed = parseDeliveryCredential(out.delivery);
    try {
      verifyDeliveryCredential(parsed, out, opts);
    } catch (err) {
      if (
        err instanceof DeliveryCredentialError ||
        err instanceof PaymentIdentityPinMismatchError
      ) {
        throw err;
      }
      throw new DeliveryCredentialError(
        'verify',
        `output_templates[${i}].delivery: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

function verifyBip340(pubkey: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean {
  try {
    return schnorr.verify(sig, msg, pubkey);
  } catch {
    return false;
  }
}

function validateRelayUrl(url: string): void {
  if (url.length === 0 || !(url.startsWith('ws://') || url.startsWith('wss://'))) {
    throw new DeliveryCredentialError(
      'relays',
      `relay URL must start with ws:// or wss://, got ${JSON.stringify(url)}`,
    );
  }
}

/** §7.1 canonical decimal-string u128: `0|[1-9][0-9]*`. */
export function parseU128Decimal(s: string, field: string): bigint {
  if (typeof s !== 'string' || s.length === 0) {
    throw new DeliveryCredentialError(field, `${field}: empty decimal string`);
  }
  if (!/^(0|[1-9][0-9]*)$/.test(s)) {
    throw new DeliveryCredentialError(
      field,
      `${field}: non-canonical decimal string (expected 0|[1-9][0-9]*)`,
    );
  }
  let n: bigint;
  try {
    n = BigInt(s);
  } catch {
    throw new DeliveryCredentialError(field, `${field}: not a valid integer`);
  }
  if (n < 0n || n >= 1n << 128n) {
    throw new DeliveryCredentialError(field, `${field}: out of u128 range`);
  }
  return n;
}

function require32(bytes: Uint8Array, label: string): void {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) {
    throw new DeliveryCredentialError(
      label,
      `${label} must be 32 bytes, got ${bytes?.length ?? 'invalid'}`,
    );
  }
}

function u128Be(n: bigint): Uint8Array {
  const out = new Uint8Array(16);
  let x = n;
  for (let i = 15; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

function u32Be(n: number): Uint8Array {
  const out = new Uint8Array(4);
  out[0] = (n >>> 24) & 0xff;
  out[1] = (n >>> 16) & 0xff;
  out[2] = (n >>> 8) & 0xff;
  out[3] = n & 0xff;
  return out;
}

function u16Be(n: number): Uint8Array {
  const out = new Uint8Array(2);
  out[0] = (n >>> 8) & 0xff;
  out[1] = n & 0xff;
  return out;
}
