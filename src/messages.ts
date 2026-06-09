/**
 * SHA-256 message construction for the signed-request endpoints.
 *
 * Extracts the message-bytes layout from the inline implementation
 * in `zk-coins/app/src/lib/api/client.ts::signSendRequest` and
 * `signClaimRequest`. Server side does the same construction in
 * `zk-coins/node` and verifies the signature against this exact
 * byte layout — drift here breaks every signed request.
 *
 * **Layout invariants** (matched 1:1 against the in-tree app):
 *
 * - All variable-length strings are encoded as **UTF-8 of the hex
 *   string**, not as raw bytes. So a 32-byte address becomes a
 *   64-character hex string which becomes 64 UTF-8 bytes. The
 *   choice predates the SDK; we mirror it.
 * - The `amount` and `timestamp` fields are **8-byte little-endian
 *   unsigned 64-bit integers**.
 * - Concatenation order matters; no separator, no length prefix.
 *
 * Tested independently from signing so byte-layout regressions
 * surface in their own test (not buried inside a Schnorr failure).
 */

import { hexToBytes } from '@noble/hashes/utils.js';

/** Inputs to a send signature — mirrors the wire types in the API. */
export interface SendMessageParams {
  /** Sender address, hex-encoded (will be UTF-8 encoded here). */
  accountAddress: string;
  /** Recipient address, hex-encoded. */
  recipient: string;
  /** Amount in satoshis. */
  amount: number | bigint;
  /** Unix timestamp in seconds. */
  timestamp: number | bigint;
}

/** Inputs to a username-claim signature. */
export interface ClaimMessageParams {
  /** Sender address, hex-encoded. */
  address: string;
  /** Username to claim. */
  username: string;
  /** Unix timestamp in seconds. */
  timestamp: number | bigint;
}

/**
 * Inputs to a creator-signed mint signature (neutral multi-asset
 * model: anyone mints their own asset; nobody can mint a foreign one).
 *
 * Mirrors `verify_mint_signature_pub` in `zk-coins/node`'s
 * `router.rs`. Unlike the send / claim layouts — which UTF-8-encode
 * the *hex string* of each address — the mint layout commits to the
 * **raw bytes** of the compressed creator pubkey (33 bytes,
 * hex-decoded here) and the raw UTF-8 of the asset `name`. The node
 * re-derives the owner (`H(creator_pubkey)`) and the `asset_id`
 * (`calculate_asset_id(creator_pubkey, H(name), decimals)`) from the
 * same fields, so the signature binds the mint to one
 * `(creator, name, decimals, amount)` tuple.
 */
export interface MintMessageParams {
  /** Compressed secp256k1 creator pubkey — 33 bytes hex (66 chars). */
  creatorPubkey: string;
  /** Raw asset name (UTF-8); folded into the asset_id by the node. */
  name: string;
  /** Asset decimals — a single byte (`u8`). */
  decimals: number;
  /** Amount to mint into the creator's own balance, atomic units. */
  amount: number | bigint;
  /** Unix timestamp in seconds. */
  timestamp: number | bigint;
}

const CLAIM_PREFIX = 'zkcoins:claim_username';

/**
 * Concatenate the send-message bytes — sender address, recipient
 * address, amount LE64, timestamp LE64 — in that order.
 *
 * Does **not** hash. The caller hashes the result and signs the
 * digest; keeping the two steps separate is what makes a bad layout
 * visible in a per-vector test instead of as "the signature didn't
 * verify on the server".
 */
export function buildSendMessage(params: SendMessageParams): Uint8Array {
  const encoder = new TextEncoder();
  const addressBytes = encoder.encode(params.accountAddress);
  const recipientBytes = encoder.encode(params.recipient);
  const amountBytes = uint64LE(params.amount);
  const timestampBytes = uint64LE(params.timestamp);

  const out = new Uint8Array(
    addressBytes.length + recipientBytes.length + amountBytes.length + timestampBytes.length,
  );
  let offset = 0;
  out.set(addressBytes, offset);
  offset += addressBytes.length;
  out.set(recipientBytes, offset);
  offset += recipientBytes.length;
  out.set(amountBytes, offset);
  offset += amountBytes.length;
  out.set(timestampBytes, offset);
  return out;
}

/**
 * Concatenate the username-claim-message bytes — fixed prefix
 * `"zkcoins:claim_username"`, address (UTF-8 hex), username (UTF-8),
 * timestamp LE64 — in that order.
 */
export function buildClaimMessage(params: ClaimMessageParams): Uint8Array {
  const encoder = new TextEncoder();
  const prefixBytes = encoder.encode(CLAIM_PREFIX);
  const addressBytes = encoder.encode(params.address);
  const usernameBytes = encoder.encode(params.username);
  const timestampBytes = uint64LE(params.timestamp);

  const out = new Uint8Array(
    prefixBytes.length + addressBytes.length + usernameBytes.length + timestampBytes.length,
  );
  let offset = 0;
  out.set(prefixBytes, offset);
  offset += prefixBytes.length;
  out.set(addressBytes, offset);
  offset += addressBytes.length;
  out.set(usernameBytes, offset);
  offset += usernameBytes.length;
  out.set(timestampBytes, offset);
  return out;
}

/**
 * Concatenate the creator-signed mint-message bytes — raw 33-byte
 * compressed creator pubkey, raw UTF-8 asset name, one decimals byte,
 * amount LE64, timestamp LE64 — in that order.
 *
 * Byte-for-byte mirror of `verify_mint_signature_pub` in
 * `zk-coins/node`:
 *
 * ```text
 * SHA256( creator_pubkey[33] ‖ name_utf8 ‖ decimals[1] ‖ amount_le[8] ‖ timestamp_le[8] )
 * ```
 *
 * Note the asymmetry with {@link buildSendMessage}: the mint layout
 * uses the **raw** pubkey/name bytes (the node hashes the same raw
 * bytes into the owner + asset_id), whereas the send layout
 * UTF-8-encodes the hex *string* of each address. Does **not** hash —
 * the caller hashes + Schnorr-signs the digest with the creator key.
 */
export function buildMintMessage(params: MintMessageParams): Uint8Array {
  const creatorBytes = hexToBytes(params.creatorPubkey);
  if (creatorBytes.length !== 33) {
    throw new Error(
      `buildMintMessage: creatorPubkey must be a 33-byte compressed pubkey (66 hex chars), got ${creatorBytes.length} bytes`,
    );
  }
  if (!Number.isInteger(params.decimals) || params.decimals < 0 || params.decimals > 255) {
    throw new RangeError(
      `buildMintMessage: decimals must be a single byte (integer 0–255), got ${params.decimals}`,
    );
  }
  const nameBytes = new TextEncoder().encode(params.name);
  const decimalsBytes = Uint8Array.of(params.decimals);
  const amountBytes = uint64LE(params.amount);
  const timestampBytes = uint64LE(params.timestamp);

  const out = new Uint8Array(
    creatorBytes.length +
      nameBytes.length +
      decimalsBytes.length +
      amountBytes.length +
      timestampBytes.length,
  );
  let offset = 0;
  out.set(creatorBytes, offset);
  offset += creatorBytes.length;
  out.set(nameBytes, offset);
  offset += nameBytes.length;
  out.set(decimalsBytes, offset);
  offset += decimalsBytes.length;
  out.set(amountBytes, offset);
  offset += amountBytes.length;
  out.set(timestampBytes, offset);
  return out;
}

/**
 * Encode a non-negative integer as 8 bytes little-endian.
 *
 * Accepts both `number` (for ergonomics around timestamps and
 * sub-2^53 amounts) and `bigint` (for full 64-bit range). Throws
 * on values that overflow u64 — the SDK is strict about wire shape.
 */
function uint64LE(value: number | bigint): Uint8Array {
  const big = typeof value === 'bigint' ? value : BigInt(value);
  if (big < 0n || big > 0xffff_ffff_ffff_ffffn) {
    throw new RangeError(`uint64LE: value ${big} is out of u64 range`);
  }
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, big, true);
  return out;
}
