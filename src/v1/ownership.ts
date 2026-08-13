/**
 * §5.1 OwnershipProof + clearnet `chan_bind` for the pull session.
 *
 * Composition is taken from the API edge that will verify the proof:
 *   `api/src/ownership.rs` — `chan_bind_for_host`, `pull_challenge_message`,
 *   `OwnershipProofJson`, domain `zkCoins/v1/PullChallenge`.
 *
 * Pull is a **simple** challenge domain (`ChallengeDomain::is_simple`):
 *   `chal = H(domain ‖ nonce ‖ chan_bind ‖ subject ‖ expiry)`  — no `request_hash`.
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { schnorr } from '@noble/curves/secp256k1.js';

import { decodeZkAddress } from './bech32m.js';
import { addressFromParts } from './delivery.js';
import { CsprngUnavailableError } from './errors.js';
import { bytesEqual, decodeHexExact, encodeHexLower } from './hex.js';
import { bip340NormaliseSecret } from './transitionSignature.js';

/** `ChallengeDomain::Pull` / `PULL_CHALLENGE_DOMAIN` in api/src/ownership.rs. */
export const PULL_CHALLENGE_DOMAIN = 'zkCoins/v1/PullChallenge';

/** `PULL_HOST_DOMAIN` in api/src/ownership.rs — clearnet chan_bind tag. */
export const PULL_HOST_DOMAIN = 'zkCoins/v1/PullHost';

/** §7.5 / §5.1(a) wire shape for OwnershipProof. */
export interface OwnershipProofJson {
  type: 'ownership';
  subject: string;
  public_key: string;
  nk_commit: string;
  signature: string;
}

export interface PullChallenge {
  nonce: string;
  /** Decimal-string u64 as returned by the API (`expiry.to_string()`). */
  expiry: string;
  domain: string;
}

/**
 * Clearnet `chan_bind = H("zkCoins/v1/PullHost" ‖ host)`.
 *
 * Beleg: `api/src/ownership.rs` `chan_bind_for_host` (L163–168) and
 * spec §5.1: host is the canonical authority the requester connected to —
 * lowercase ASCII, trailing dot removed, `":"port` only when not default 443.
 */
export function chanBindForHost(host: string): Uint8Array {
  if (typeof host !== 'string' || host.length === 0) {
    throw new Error('chanBindForHost: host is required');
  }
  const pre = new TextEncoder().encode(PULL_HOST_DOMAIN + host);
  return sha256(pre);
}

/**
 * Canonical authority for clearnet `chan_bind` from the URL the wallet dialed.
 *
 * Spec §5.1: lowercase, trailing dot removed, port appended only when not 443
 * (HTTPS default). HTTP default 80 is likewise omitted so a plain-http test
 * host matches the authority string without a redundant `:80`.
 */
export function canonicalHostFromApiUrl(apiUrl: string): string {
  let url: URL;
  try {
    url = new URL(apiUrl);
  } catch (cause) {
    throw new Error(`canonicalHostFromApiUrl: invalid URL ${JSON.stringify(apiUrl)}`, { cause });
  }
  let host = url.hostname.toLowerCase();
  if (host.endsWith('.')) {
    host = host.slice(0, -1);
  }
  if (host.length === 0) {
    throw new Error('canonicalHostFromApiUrl: empty hostname');
  }
  const port = url.port;
  if (port.length > 0) {
    const isHttps = url.protocol === 'https:';
    const isHttp = url.protocol === 'http:';
    const defaultPort = isHttps ? '443' : isHttp ? '80' : '';
    /* v8 ignore next -- WHATWG URL removes explicit HTTP(S) default ports before url.port is read, so a non-empty port cannot equal defaultPort */
    if (port !== defaultPort) {
      return `${host}:${port}`;
    }
  }
  return host;
}

/**
 * `chal = H(domain ‖ nonce ‖ chan_bind ‖ subject ‖ expiry)` for pull/bootstrap.
 *
 * Beleg: `api/src/ownership.rs` `pull_challenge_message` (L200–214).
 * `subject` is the **32-byte address payload**, not the Bech32m string.
 * `expiry` is u64 big-endian.
 */
export function pullChallengeMessage(input: {
  domain: string;
  nonce: Uint8Array;
  chanBind: Uint8Array;
  subjectRaw: Uint8Array;
  expiry: bigint;
}): Uint8Array {
  if (input.domain.length === 0) {
    throw new Error('pullChallengeMessage: domain is required');
  }
  if (input.nonce.length !== 32) {
    throw new Error(`pullChallengeMessage: nonce must be 32 bytes, got ${input.nonce.length}`);
  }
  if (input.chanBind.length !== 32) {
    throw new Error(
      `pullChallengeMessage: chan_bind must be 32 bytes, got ${input.chanBind.length}`,
    );
  }
  if (input.subjectRaw.length !== 32) {
    throw new Error(
      `pullChallengeMessage: subject must be 32 bytes, got ${input.subjectRaw.length}`,
    );
  }
  if (input.expiry < 0n || input.expiry > 0xffff_ffff_ffff_ffffn) {
    throw new Error('pullChallengeMessage: expiry out of u64 range');
  }
  const expiryBe = new Uint8Array(8);
  let e = input.expiry;
  for (let i = 7; i >= 0; i--) {
    expiryBe[i] = Number(e & 0xffn);
    e >>= 8n;
  }
  const domainBytes = new TextEncoder().encode(input.domain);
  const pre = new Uint8Array(domainBytes.length + 32 + 32 + 32 + 8);
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
  return sha256(pre);
}

/** Parse the API's decimal-string u64 expiry (canonical: no leading zeros except `0`). */
export function parseExpiryDecimal(s: string): bigint {
  if (typeof s !== 'string' || s.length === 0) {
    throw new Error('parseExpiryDecimal: empty');
  }
  if (s === '0') {
    return 0n;
  }
  if (s[0] === '0') {
    throw new Error('parseExpiryDecimal: leading zeros are not allowed');
  }
  if (!/^[1-9][0-9]*$/.test(s)) {
    throw new Error(`parseExpiryDecimal: not a canonical u64 decimal: ${JSON.stringify(s)}`);
  }
  const n = BigInt(s);
  if (n > 0xffff_ffff_ffff_ffffn) {
    throw new Error('parseExpiryDecimal: out of u64 range');
  }
  return n;
}

/**
 * Build and BIP-340-sign an OwnershipProof for a pull challenge.
 *
 * Signs with `sk₀` over `chal` (simple form, no request_hash).
 * `nk_commit` is the 32-byte commitment already bound into the address —
 * the wallet supplies it; this function does not recompute Poseidon.
 */
export function buildOwnershipProof(input: {
  /** Bech32m `zk…` subject. */
  subject: string;
  /** Raw 32-byte sk₀ (BIP-32 child). */
  sk0: Uint8Array;
  /** 32-byte `nk_commit` (wire encoding). */
  nkCommit: Uint8Array;
  challenge: PullChallenge;
  /** Canonical host authority (same string the API recomputes chan_bind from). */
  host: string;
}): OwnershipProofJson {
  if (input.challenge.domain !== PULL_CHALLENGE_DOMAIN) {
    throw new Error(
      `buildOwnershipProof: unexpected challenge domain ${JSON.stringify(input.challenge.domain)}; ` +
        `expected ${JSON.stringify(PULL_CHALLENGE_DOMAIN)}`,
    );
  }
  const subjectRaw = decodeZkAddress(input.subject);
  const nonce = decodeHexExact(input.challenge.nonce, 32, 'challenge.nonce');
  const expiry = parseExpiryDecimal(input.challenge.expiry);
  const chanBind = chanBindForHost(input.host);
  const chal = pullChallengeMessage({
    domain: PULL_CHALLENGE_DOMAIN,
    nonce,
    chanBind,
    subjectRaw,
    expiry,
  });

  if (input.nkCommit.length !== 32) {
    throw new Error(
      `buildOwnershipProof: nk_commit must be 32 bytes, got ${input.nkCommit.length}`,
    );
  }

  const { pkBytes } = bip340NormaliseSecret(input.sk0);
  const derived = addressFromParts(pkBytes, input.nkCommit);
  if (!bytesEqual(derived, subjectRaw)) {
    throw new Error('buildOwnershipProof: subject does not match SHA-256(Pk0 || nk_commit)');
  }
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
 * 32 unmodified CSPRNG bytes for `npk_rand` (§7.5 / §2.1 clause 2).
 * Fail-closed when no CSPRNG is available — never Math.random / seed-derived.
 */
export function freshNpkRand(): Uint8Array {
  const cryptoObj = globalThis.crypto;
  if (cryptoObj === undefined || typeof cryptoObj.getRandomValues !== 'function') {
    throw new CsprngUnavailableError(
      'freshNpkRand: no CSPRNG (crypto.getRandomValues) available; refuse to invent entropy',
    );
  }
  const out = new Uint8Array(32);
  cryptoObj.getRandomValues(out);
  return out;
}

/**
 * `npk_commit = H("zkCoins/v1/NpkCommit" ‖ next_pubkey ‖ npk_rand)` (§1.4 / §2.1 clause 2).
 */
export function computeNpkCommit(nextPubkey: Uint8Array, npkRand: Uint8Array): Uint8Array {
  if (nextPubkey.length !== 32) {
    throw new Error(`computeNpkCommit: next_pubkey must be 32 bytes, got ${nextPubkey.length}`);
  }
  if (npkRand.length !== 32) {
    throw new Error(`computeNpkCommit: npk_rand must be 32 bytes, got ${npkRand.length}`);
  }
  const tag = new TextEncoder().encode('zkCoins/v1/NpkCommit');
  const pre = new Uint8Array(tag.length + 32 + 32);
  pre.set(tag, 0);
  pre.set(nextPubkey, tag.length);
  pre.set(npkRand, tag.length + 32);
  return sha256(pre);
}
