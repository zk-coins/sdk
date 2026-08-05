/**
 * §7.5 / §5.2 View-grant request surface (IssueViewGrant + GrantProof pull arm).
 *
 * Composition is taken from the API edge that will verify the proof:
 *   `api/src/ownership.rs` — `ISSUE_GRANT_*` tags, `encode_grant_asset_ids`,
 *   `issue_grant_request_hash`, `GrantProofJson`, `ownership_challenge_message`
 *   (request_hash form via `attestChallengeMessage`);
 *   `api/src/grants.rs` — REST wire bodies for challenge + issue;
 *   `api/src/pull.rs` — Grant arm of `POST /v1/pull` (plain pull chal, no request_hash).
 *
 * Grant strings (`zkgrant…`) are opaque blobs: the SDK never decodes them.
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { schnorr } from '@noble/curves/secp256k1.js';

import { attestChallengeMessage } from './attest.js';
import { decodeZkAddress } from './bech32m.js';
import { decodeHexExact, encodeHexLower } from './hex.js';
import {
  chanBindForHost,
  parseExpiryDecimal,
  pullChallengeMessage,
  PULL_CHALLENGE_DOMAIN,
  type OwnershipProofJson,
  type PullChallenge,
} from './ownership.js';
import { bip340NormaliseSecret } from './transitionSignature.js';

/** `ChallengeAction::IssueViewGrant.domain()` — exact literal. */
export const ISSUE_GRANT_CHALLENGE_DOMAIN = 'zkCoins/v1/IssueGrantChallenge';

/** ISSUE_GRANT_REQUEST_TAG in api/src/ownership.rs — exact literal. */
export const ISSUE_GRANT_REQUEST_TAG = 'zkCoins/v1/IssueGrant';

/** Unbounded `not_after` sentinel: `2⁶³−1` (§5.1 / i64::MAX as u64). */
export const SCOPE_NOT_AFTER_UNBOUNDED = 9223372036854775807n;

const U64_MAX = 0xffff_ffff_ffff_ffffn;

/**
 * Discriminated scope input shared by issueViewGrant and the pull scope echo.
 * Mutually exclusive with `assetIds` when allAssets is true (validated at
 * runtime by encodeGrantAssetIds — a caller passing both is a bug, not a value
 * to silently reconcile).
 */
export type GrantScopeInput =
  | { allAssets: true; notBefore?: bigint; notAfter?: bigint }
  | { allAssets?: false; assetIds: Uint8Array[]; notBefore?: bigint; notAfter?: bigint };

/**
 * Single place for the server-side defaults in `api/src/grants.rs`
 * `normalise_scope`: omitted `not_before` → 0, omitted `not_after` →
 * SCOPE_NOT_AFTER_UNBOUNDED. Used by both request_hash computation and wire JSON
 * so the two never drift.
 */
function resolveScopeBounds(scope: GrantScopeInput): { notBefore: bigint; notAfter: bigint } {
  const notBefore = scope.notBefore !== undefined ? scope.notBefore : 0n;
  const notAfter = scope.notAfter !== undefined ? scope.notAfter : SCOPE_NOT_AFTER_UNBOUNDED;
  if (notBefore < 0n || notBefore > U64_MAX) {
    throw new Error('resolveScopeBounds: not_before out of u64 range');
  }
  if (notAfter < 0n || notAfter > U64_MAX) {
    throw new Error('resolveScopeBounds: not_after out of u64 range');
  }
  return { notBefore, notAfter };
}

/** Lexicographic compare over two equal-length byte arrays (Rust `[u8; N]` Ord). */
function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = a.length;
  for (let i = 0; i < n; i++) {
    const av = a[i]!;
    const bv = b[i]!;
    if (av < bv) return -1;
    if (av > bv) return 1;
  }
  return 0;
}

/**
 * Byte-exact port of `encode_grant_asset_ids` (api/src/ownership.rs):
 * `0x00` for `*`, or `0x01 ‖ u32-be count ‖ ascending 32-byte ids`.
 */
export function encodeGrantAssetIds(allAssets: boolean, assetIds: Uint8Array[]): Uint8Array {
  if (allAssets) {
    if (assetIds.length !== 0) {
      throw new Error('encodeGrantAssetIds: scope.asset_ids must be empty when asset_ids is "*"');
    }
    return new Uint8Array([0x00]);
  }
  if (assetIds.length === 0) {
    throw new Error('encodeGrantAssetIds: scope.asset_ids list must be non-empty when not "*"');
  }
  // unreachable in practice: JS Array length is a uint32; kept for parity with Rust u32::try_from
  /* v8 ignore next 3 */
  if (assetIds.length > 0xffff_ffff) {
    throw new Error('encodeGrantAssetIds: scope.asset_ids count exceeds u32');
  }
  for (let i = 0; i < assetIds.length; i++) {
    const id = assetIds[i]!;
    if (id.length !== 32) {
      throw new Error(
        `encodeGrantAssetIds: scope.asset_ids[${i}] must be 32 bytes, got ${id.length}`,
      );
    }
    if (i > 0 && compareBytes(assetIds[i - 1]!, id) >= 0) {
      throw new Error('encodeGrantAssetIds: scope.asset_ids must be strictly ascending');
    }
  }
  const count = assetIds.length;
  const out = new Uint8Array(1 + 4 + count * 32);
  out[0] = 0x01;
  out[1] = (count >>> 24) & 0xff;
  out[2] = (count >>> 16) & 0xff;
  out[3] = (count >>> 8) & 0xff;
  out[4] = count & 0xff;
  let o = 5;
  for (const id of assetIds) {
    out.set(id, o);
    o += 32;
  }
  return out;
}

function u64Be(n: bigint): Uint8Array {
  const out = new Uint8Array(8);
  let e = n;
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(e & 0xffn);
    e >>= 8n;
  }
  return out;
}

/**
 * Byte-exact port of `issue_grant_request_hash` (api/src/ownership.rs):
 * `SHA256(ISSUE_GRANT_REQUEST_TAG ‖ subject(32) ‖ grantee_pk(32) ‖ asset_ids_enc ‖
 *  not_before_be8 ‖ not_after_be8 ‖ grant_expiry_be8)`.
 */
export function issueGrantRequestHash(
  subjectRaw: Uint8Array,
  granteePk: Uint8Array,
  assetEnc: Uint8Array,
  notBefore: bigint,
  notAfter: bigint,
  grantExpiry: bigint,
): Uint8Array {
  if (subjectRaw.length !== 32) {
    throw new Error(`issueGrantRequestHash: subject must be 32 bytes, got ${subjectRaw.length}`);
  }
  if (granteePk.length !== 32) {
    throw new Error(`issueGrantRequestHash: grantee_pk must be 32 bytes, got ${granteePk.length}`);
  }
  if (notBefore < 0n || notBefore > U64_MAX) {
    throw new Error('issueGrantRequestHash: not_before out of u64 range');
  }
  if (notAfter < 0n || notAfter > U64_MAX) {
    throw new Error('issueGrantRequestHash: not_after out of u64 range');
  }
  if (grantExpiry < 0n || grantExpiry > U64_MAX) {
    throw new Error('issueGrantRequestHash: grant_expiry out of u64 range');
  }
  const tag = new TextEncoder().encode(ISSUE_GRANT_REQUEST_TAG);
  const pre = new Uint8Array(tag.length + 32 + 32 + assetEnc.length + 8 + 8 + 8);
  let o = 0;
  pre.set(tag, o);
  o += tag.length;
  pre.set(subjectRaw, o);
  o += 32;
  pre.set(granteePk, o);
  o += 32;
  pre.set(assetEnc, o);
  o += assetEnc.length;
  pre.set(u64Be(notBefore), o);
  o += 8;
  pre.set(u64Be(notAfter), o);
  o += 8;
  pre.set(u64Be(grantExpiry), o);
  return sha256(pre);
}

/**
 * Action-bound OwnershipProof for `POST /v1/grants`.
 * Structural analogue of `buildAttestOwnershipProof` — signs the request_hash-bound
 * IssueGrant chal with sk₀.
 */
export function buildIssueGrantOwnershipProof(input: {
  /** Bech32m `zk…` subject (the granter's own address). */
  subject: string;
  /** Raw 32-byte sk₀ (BIP-32 child). */
  sk0: Uint8Array;
  /** 32-byte `nk_commit` (wire encoding). */
  nkCommit: Uint8Array;
  challenge: { nonce: string; expiry: string; domain: string };
  /** Canonical host authority (same string the API recomputes chan_bind from). */
  host: string;
  /** 32-byte x-only pubkey of the grantee being authorised. */
  granteePk: Uint8Array;
  scope: GrantScopeInput;
  grantExpiry: bigint;
}): OwnershipProofJson {
  if (input.challenge.domain !== ISSUE_GRANT_CHALLENGE_DOMAIN) {
    throw new Error(
      `buildIssueGrantOwnershipProof: unexpected challenge domain ${JSON.stringify(input.challenge.domain)}; ` +
        `expected ${JSON.stringify(ISSUE_GRANT_CHALLENGE_DOMAIN)}`,
    );
  }
  if (input.nkCommit.length !== 32) {
    throw new Error(
      `buildIssueGrantOwnershipProof: nk_commit must be 32 bytes, got ${input.nkCommit.length}`,
    );
  }
  if (input.granteePk.length !== 32) {
    throw new Error(
      `buildIssueGrantOwnershipProof: grantee_pk must be 32 bytes, got ${input.granteePk.length}`,
    );
  }

  const assetEnc =
    input.scope.allAssets === true
      ? encodeGrantAssetIds(true, [])
      : encodeGrantAssetIds(false, input.scope.assetIds);
  const { notBefore, notAfter } = resolveScopeBounds(input.scope);

  const subjectRaw = decodeZkAddress(input.subject);
  const nonce = decodeHexExact(input.challenge.nonce, 32, 'challenge.nonce');
  const expiry = parseExpiryDecimal(input.challenge.expiry);
  const chanBind = chanBindForHost(input.host);
  const requestHash = issueGrantRequestHash(
    subjectRaw,
    input.granteePk,
    assetEnc,
    notBefore,
    notAfter,
    input.grantExpiry,
  );
  const chal = attestChallengeMessage({
    domain: ISSUE_GRANT_CHALLENGE_DOMAIN,
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

/**
 * Wire JSON body for the `scope` field shared by `POST /v1/grants` and the
 * PullBody.scope echo. Always emits explicit not_before/not_after (resolved
 * bigints as decimal strings). Does not re-validate ascending order — that is
 * encodeGrantAssetIds's job.
 */
export function grantScopeToJsonBody(scope: GrantScopeInput): {
  asset_ids: '*' | string[];
  not_before: string;
  not_after: string;
} {
  const { notBefore, notAfter } = resolveScopeBounds(scope);
  if (scope.allAssets === true) {
    return {
      asset_ids: '*',
      not_before: notBefore.toString(),
      not_after: notAfter.toString(),
    };
  }
  return {
    asset_ids: scope.assetIds.map((id) => encodeHexLower(id)),
    not_before: notBefore.toString(),
    not_after: notAfter.toString(),
  };
}

/** §5.1(b) GrantProof wire shape (api/src/ownership.rs / pull.rs PullProofJson::Grant). */
export interface GrantProofJson {
  type: 'grant';
  grant: string;
  grantee_pk: string;
  signature: string;
}

/**
 * Sign the plain pull chal (`pullChallengeMessage` — no request_hash) with the
 * grantee's own secret `d`. `grantee_pk` on the wire is derived from the
 * signing key so it cannot drift. `subjectRaw` is caller-supplied (SDK does
 * not decode the grant string); it must equal the grant's embedded subject or
 * the server rejects the signature.
 */
export function buildGrantProof(input: {
  /** Opaque Bech32m zkgrant string — not decoded by the SDK. */
  grant: string;
  /** Raw 32-byte secret `d` for the grantee key D. */
  granteeSecret: Uint8Array;
  /**
   * 32-byte address the grant was issued for (caller-supplied — must match
   * the grant's embedded subject for server-side verification).
   */
  subjectRaw: Uint8Array;
  challenge: PullChallenge;
  host: string;
}): GrantProofJson {
  if (input.challenge.domain !== PULL_CHALLENGE_DOMAIN) {
    throw new Error(
      `buildGrantProof: unexpected challenge domain ${JSON.stringify(input.challenge.domain)}; ` +
        `expected ${JSON.stringify(PULL_CHALLENGE_DOMAIN)}`,
    );
  }
  if (typeof input.grant !== 'string' || input.grant.length === 0) {
    throw new Error('buildGrantProof: grant is required');
  }
  if (input.subjectRaw.length !== 32) {
    throw new Error(`buildGrantProof: subject must be 32 bytes, got ${input.subjectRaw.length}`);
  }

  const nonce = decodeHexExact(input.challenge.nonce, 32, 'challenge.nonce');
  const expiry = parseExpiryDecimal(input.challenge.expiry);
  const chanBind = chanBindForHost(input.host);
  const chal = pullChallengeMessage({
    domain: PULL_CHALLENGE_DOMAIN,
    nonce,
    chanBind,
    subjectRaw: input.subjectRaw,
    expiry,
  });

  const { pkBytes } = bip340NormaliseSecret(input.granteeSecret);
  const signature = schnorr.sign(chal, input.granteeSecret, new Uint8Array(32));

  return {
    type: 'grant',
    grant: input.grant,
    grantee_pk: encodeHexLower(pkBytes),
    signature: encodeHexLower(signature),
  };
}
