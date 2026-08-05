/**
 * §7.5 Balance-attestation request surface (OwnershipProof + request_hash).
 *
 * Composition is taken from the API/node edges that will verify the proof:
 *   `api/src/ownership.rs` — `ceiling_encoding`, `attest_request_hash`,
 *   `ownership_challenge_message` (request_hash form);
 *   `node/node/src/v1/attest.rs` — same byte layout for challenge/request tags.
 *
 * AttestBalance is a **request-bound** challenge domain (not simple):
 *   `chal = H(domain ‖ nonce ‖ chan_bind ‖ subject ‖ expiry ‖ request_hash)`.
 * Proof verification of the returned attestation is out of scope (thin client).
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { schnorr } from '@noble/curves/secp256k1.js';

import { decodeZkAddress } from './bech32m.js';
import { decodeHexExact, encodeHexLower } from './hex.js';
import { chanBindForHost, parseExpiryDecimal, type OwnershipProofJson } from './ownership.js';
import { bip340NormaliseSecret } from './transitionSignature.js';

/** ChallengeAction::AttestBalance.domain() — exact literal. */
export const ATTEST_BALANCE_CHALLENGE_DOMAIN = 'zkCoins/v1/AttestBalanceChallenge';

/** ATTEST_BALANCE_REQUEST_TAG in node attest.rs / api ownership.rs — exact literal. */
export const ATTEST_BALANCE_REQUEST_TAG = 'zkCoins/v1/AttestBalance';

const U64_MAX = 0xffff_ffff_ffff_ffffn;

/**
 * §7.5 Ceiling-Encoding for request_hash:
 * - both (navCeiling, sizeCeiling) absent → single byte 0x00
 * - both present → 0x01 ‖ navCeiling (32B) ‖ u64-be(sizeCeiling) (8B)
 * - any other combination → throw (no silent absence encoding for one side)
 */
export function ceilingEncoding(
  navCeiling?: Uint8Array,
  sizeCeiling?: bigint | number,
): Uint8Array {
  if (navCeiling === undefined && sizeCeiling === undefined) {
    return new Uint8Array([0x00]);
  }
  if (navCeiling !== undefined && sizeCeiling !== undefined) {
    if (navCeiling.length !== 32) {
      throw new Error(`ceilingEncoding: nav_ceiling must be 32 bytes, got ${navCeiling.length}`);
    }
    let size: bigint;
    if (typeof sizeCeiling === 'number') {
      if (!Number.isSafeInteger(sizeCeiling)) {
        throw new Error(
          'ceilingEncoding: size_ceiling number must be a safe integer (no precision loss)',
        );
      }
      size = BigInt(sizeCeiling);
    } else {
      size = sizeCeiling;
    }
    if (size < 0n || size > U64_MAX) {
      throw new Error('ceilingEncoding: size_ceiling out of u64 range');
    }
    const out = new Uint8Array(1 + 32 + 8);
    out[0] = 0x01;
    out.set(navCeiling, 1);
    let e = size;
    for (let i = 7; i >= 0; i--) {
      out[1 + 32 + i] = Number(e & 0xffn);
      e >>= 8n;
    }
    return out;
  }
  throw new Error(
    'ceilingEncoding: nav_ceiling and size_ceiling must both be present or both omitted (§7.5)',
  );
}

/** SHA256(ATTEST_BALANCE_REQUEST_TAG ‖ subjectRaw(32) ‖ assetId(32) ‖ ceilingEnc). */
export function attestRequestHash(
  subjectRaw: Uint8Array,
  assetId: Uint8Array,
  ceilingEnc: Uint8Array,
): Uint8Array {
  if (subjectRaw.length !== 32) {
    throw new Error(`attestRequestHash: subject must be 32 bytes, got ${subjectRaw.length}`);
  }
  if (assetId.length !== 32) {
    throw new Error(`attestRequestHash: asset_id must be 32 bytes, got ${assetId.length}`);
  }
  const tag = new TextEncoder().encode(ATTEST_BALANCE_REQUEST_TAG);
  const pre = new Uint8Array(tag.length + 32 + 32 + ceilingEnc.length);
  pre.set(tag, 0);
  pre.set(subjectRaw, tag.length);
  pre.set(assetId, tag.length + 32);
  pre.set(ceilingEnc, tag.length + 64);
  return sha256(pre);
}

/**
 * chal = SHA256(domain ‖ nonce(32) ‖ chanBind(32) ‖ subjectRaw(32) ‖ expiry_u64_be(8) ‖ requestHash(32)).
 * Extended form vs pullChallengeMessage (which has no requestHash field).
 */
export function attestChallengeMessage(input: {
  domain: string;
  nonce: Uint8Array;
  chanBind: Uint8Array;
  subjectRaw: Uint8Array;
  expiry: bigint;
  requestHash: Uint8Array;
}): Uint8Array {
  if (input.domain.length === 0) {
    throw new Error('attestChallengeMessage: domain is required');
  }
  if (input.nonce.length !== 32) {
    throw new Error(`attestChallengeMessage: nonce must be 32 bytes, got ${input.nonce.length}`);
  }
  if (input.chanBind.length !== 32) {
    throw new Error(
      `attestChallengeMessage: chan_bind must be 32 bytes, got ${input.chanBind.length}`,
    );
  }
  if (input.subjectRaw.length !== 32) {
    throw new Error(
      `attestChallengeMessage: subject must be 32 bytes, got ${input.subjectRaw.length}`,
    );
  }
  if (input.expiry < 0n || input.expiry > U64_MAX) {
    throw new Error('attestChallengeMessage: expiry out of u64 range');
  }
  if (input.requestHash.length !== 32) {
    throw new Error(
      `attestChallengeMessage: request_hash must be 32 bytes, got ${input.requestHash.length}`,
    );
  }
  const expiryBe = new Uint8Array(8);
  let e = input.expiry;
  for (let i = 7; i >= 0; i--) {
    expiryBe[i] = Number(e & 0xffn);
    e >>= 8n;
  }
  const domainBytes = new TextEncoder().encode(input.domain);
  const pre = new Uint8Array(domainBytes.length + 32 + 32 + 32 + 8 + 32);
  let o = 0;
  pre.set(domainBytes, o);
  o += domainBytes.length;
  pre.set(input.nonce, o);
  o += 32;
  pre.set(input.chanBind, o);
  o += 32;
  pre.set(input.subjectRaw, o);
  o += 32;
  pre.set(expiryBe, o);
  o += 8;
  pre.set(input.requestHash, o);
  return sha256(pre);
}

/**
 * Build and BIP-340-sign an OwnershipProof for an AttestBalance challenge.
 *
 * Signs with `sk₀` over the request-bound chal (with request_hash).
 * Same OwnershipProofJson wire shape as buildOwnershipProof.
 */
export function buildAttestOwnershipProof(input: {
  /** Bech32m `zk…` subject. */
  subject: string;
  /** Raw 32-byte sk₀ (BIP-32 child). */
  sk0: Uint8Array;
  /** 32-byte `nk_commit` (wire encoding). */
  nkCommit: Uint8Array;
  challenge: { nonce: string; expiry: string; domain: string };
  /** Canonical host authority (same string the API recomputes chan_bind from). */
  host: string;
  assetId: Uint8Array;
  navCeiling?: Uint8Array;
  sizeCeiling?: bigint | number;
}): OwnershipProofJson {
  if (input.challenge.domain !== ATTEST_BALANCE_CHALLENGE_DOMAIN) {
    throw new Error(
      `buildAttestOwnershipProof: unexpected challenge domain ${JSON.stringify(input.challenge.domain)}; ` +
        `expected ${JSON.stringify(ATTEST_BALANCE_CHALLENGE_DOMAIN)}`,
    );
  }
  if (input.nkCommit.length !== 32) {
    throw new Error(
      `buildAttestOwnershipProof: nk_commit must be 32 bytes, got ${input.nkCommit.length}`,
    );
  }
  if (input.assetId.length !== 32) {
    throw new Error(
      `buildAttestOwnershipProof: asset_id must be 32 bytes, got ${input.assetId.length}`,
    );
  }

  const subjectRaw = decodeZkAddress(input.subject);
  const nonce = decodeHexExact(input.challenge.nonce, 32, 'challenge.nonce');
  const expiry = parseExpiryDecimal(input.challenge.expiry);
  const chanBind = chanBindForHost(input.host);
  const ceilingEnc = ceilingEncoding(input.navCeiling, input.sizeCeiling);
  const requestHash = attestRequestHash(subjectRaw, input.assetId, ceilingEnc);
  const chal = attestChallengeMessage({
    domain: ATTEST_BALANCE_CHALLENGE_DOMAIN,
    nonce,
    chanBind,
    subjectRaw,
    expiry,
    requestHash,
  });

  const { pkBytes } = bip340NormaliseSecret(input.sk0);
  // BIP-340 over the 32-byte chal digest. noble normalises the secret;
  // zero aux-rand is fine for ownership proofs (not a transition nonce).
  const signature = schnorr.sign(chal, input.sk0, new Uint8Array(32));

  return {
    type: 'ownership',
    subject: input.subject,
    public_key: encodeHexLower(pkBytes),
    nk_commit: encodeHexLower(input.nkCommit),
    signature: encodeHexLower(signature),
  };
}
