/**
 * Spec V.4 / §1.7.3 derivation helpers built purely on `hc`.
 * Port of the Poseidon call sites in `node/shared/src/spec_v1/hashes.rs`
 * (and the empty constants in nflog.rs / coinhist.rs leaf-hash).
 */

import { hc, HcInput, type Digest } from './hc.js';
import {
  GENESIS_TAG,
  NETWORK_TAG_MAINNET,
  NETWORK_TAG_REGTEST,
  NETWORK_TAG_TESTNET,
  TAG_ASSET_ID,
  TAG_ASSET_ID_V2,
  TAG_COINHIST_LEAF,
  TAG_COINHIST_NODE,
  TAG_DETECT_TAG,
  TAG_ISSUANCE_TERMS,
  TAG_ISSUANCE_TERMS_V2,
  TAG_NAV_COMMIT,
  TAG_NETWORK,
  TAG_NFLOG_EMPTY,
  TAG_NFLOG_ROOT,
  TAG_NK_COMMIT,
  TAG_NULLIFIER,
} from './tags.js';

/** `nk_commit = Hc("NkCommit", ByteString(nk))`. */
export function nkCommit(nk: Uint8Array): Digest {
  if (nk.length !== 32) {
    throw new RangeError(`nkCommit: nk must be 32 bytes, got ${nk.length}`);
  }
  return hc(TAG_NK_COMMIT, [HcInput.byteString(nk)]);
}

/** `nf = Hc("Nullifier", ByteString(nk), Digest(coin_identifier))`. */
export function nullifier(nk: Uint8Array, coinIdentifier: Digest): Digest {
  if (nk.length !== 32) {
    throw new RangeError(`nullifier: nk must be 32 bytes, got ${nk.length}`);
  }
  return hc(TAG_NULLIFIER, [HcInput.byteString(nk), HcInput.digest(coinIdentifier)]);
}

/** Token-standard-1 `asset_id`. */
export function assetIdV1(
  genesisTag: Uint8Array,
  creatorPubkey: Uint8Array,
  nameHash: Uint8Array,
  decimals: number,
  issuanceVersion: number,
): Digest {
  if (creatorPubkey.length !== 32) {
    throw new RangeError(`assetIdV1: creatorPubkey must be 32 bytes, got ${creatorPubkey.length}`);
  }
  if (nameHash.length !== 32) {
    throw new RangeError(`assetIdV1: nameHash must be 32 bytes, got ${nameHash.length}`);
  }
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 255) {
    throw new RangeError(`assetIdV1: decimals must be a u8, got ${decimals}`);
  }
  if (!Number.isInteger(issuanceVersion) || issuanceVersion < 0 || issuanceVersion > 255) {
    throw new RangeError(`assetIdV1: issuanceVersion must be a u8, got ${issuanceVersion}`);
  }
  return hc(TAG_ASSET_ID, [
    HcInput.byteString(genesisTag),
    HcInput.byteString(creatorPubkey),
    HcInput.byteString(nameHash),
    HcInput.smallNumeric(BigInt(decimals)),
    HcInput.smallNumeric(BigInt(issuanceVersion)),
  ]);
}

/** Token-standard-2 `asset_id`. */
export function assetIdV2(
  genesisTag: Uint8Array,
  creatorPubkey: Uint8Array,
  nameHash: Uint8Array,
  decimals: number,
  issuanceVersion: number,
  capTotal: bigint,
  termsSalt: Uint8Array,
): Digest {
  if (creatorPubkey.length !== 32) {
    throw new RangeError(`assetIdV2: creatorPubkey must be 32 bytes, got ${creatorPubkey.length}`);
  }
  if (nameHash.length !== 32) {
    throw new RangeError(`assetIdV2: nameHash must be 32 bytes, got ${nameHash.length}`);
  }
  if (termsSalt.length !== 32) {
    throw new RangeError(`assetIdV2: termsSalt must be 32 bytes, got ${termsSalt.length}`);
  }
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 255) {
    throw new RangeError(`assetIdV2: decimals must be a u8, got ${decimals}`);
  }
  if (!Number.isInteger(issuanceVersion) || issuanceVersion < 0 || issuanceVersion > 255) {
    throw new RangeError(`assetIdV2: issuanceVersion must be a u8, got ${issuanceVersion}`);
  }
  if (capTotal < 0n || capTotal >= 1n << 128n) {
    throw new RangeError(`assetIdV2: capTotal must be a u128, got ${capTotal.toString()}`);
  }
  const capBe = new Uint8Array(16);
  let cap = capTotal;
  for (let i = 15; i >= 0; i--) {
    capBe[i] = Number(cap & 0xffn);
    cap >>= 8n;
  }
  return hc(TAG_ASSET_ID_V2, [
    HcInput.byteString(genesisTag),
    HcInput.byteString(creatorPubkey),
    HcInput.byteString(nameHash),
    HcInput.smallNumeric(BigInt(decimals)),
    HcInput.smallNumeric(BigInt(issuanceVersion)),
    HcInput.byteString(capBe),
    HcInput.byteString(termsSalt),
  ]);
}

/** `terms_hash` for token-standard-1. */
export function termsHashV1(assetId: Digest, issuanceVersion: number): Digest {
  if (!Number.isInteger(issuanceVersion) || issuanceVersion < 0 || issuanceVersion > 255) {
    throw new RangeError(`termsHashV1: issuanceVersion must be a u8, got ${issuanceVersion}`);
  }
  return hc(TAG_ISSUANCE_TERMS, [
    HcInput.digest(assetId),
    HcInput.smallNumeric(BigInt(issuanceVersion)),
  ]);
}

/** `terms_hash` for token-standard-2. */
export function termsHashV2(
  assetId: Digest,
  issuanceVersion: number,
  capTotal: bigint,
  termsSalt: Uint8Array,
): Digest {
  if (!Number.isInteger(issuanceVersion) || issuanceVersion < 0 || issuanceVersion > 255) {
    throw new RangeError(`termsHashV2: issuanceVersion must be a u8, got ${issuanceVersion}`);
  }
  if (termsSalt.length !== 32) {
    throw new RangeError(`termsHashV2: termsSalt must be 32 bytes, got ${termsSalt.length}`);
  }
  if (capTotal < 0n || capTotal >= 1n << 128n) {
    throw new RangeError(`termsHashV2: capTotal must be a u128, got ${capTotal.toString()}`);
  }
  const capBe = new Uint8Array(16);
  let cap = capTotal;
  for (let i = 15; i >= 0; i--) {
    capBe[i] = Number(cap & 0xffn);
    cap >>= 8n;
  }
  return hc(TAG_ISSUANCE_TERMS_V2, [
    HcInput.digest(assetId),
    HcInput.smallNumeric(BigInt(issuanceVersion)),
    HcInput.byteString(capBe),
    HcInput.byteString(termsSalt),
  ]);
}

/** `network_id = Hc("Network", ByteString(network_tag_ascii))`. */
export function networkId(networkTagAscii: Uint8Array): Digest {
  return hc(TAG_NETWORK, [HcInput.byteString(networkTagAscii)]);
}

export function networkIdMainnet(): Digest {
  return networkId(NETWORK_TAG_MAINNET);
}

export function networkIdTestnet(): Digest {
  return networkId(NETWORK_TAG_TESTNET);
}

export function networkIdRegtest(): Digest {
  return networkId(NETWORK_TAG_REGTEST);
}

/** `nav_commitment = Hc("NavCommit", Digest(nav_root), ByteString(nav_rand))`. */
export function navCommitment(navRoot: Digest, navRand: Uint8Array): Digest {
  if (navRand.length !== 32) {
    throw new RangeError(`navCommitment: navRand must be 32 bytes, got ${navRand.length}`);
  }
  return hc(TAG_NAV_COMMIT, [HcInput.digest(navRoot), HcInput.byteString(navRand)]);
}

/** `detect_tag = Hc("DetectTag", ByteString(ss), ByteString(epk))`. */
export function detectTag(ss: Uint8Array, epk: Uint8Array): Digest {
  if (ss.length !== 32) {
    throw new RangeError(`detectTag: ss must be 32 bytes, got ${ss.length}`);
  }
  if (epk.length !== 32) {
    throw new RangeError(`detectTag: epk must be 32 bytes, got ${epk.length}`);
  }
  return hc(TAG_DETECT_TAG, [HcInput.byteString(ss), HcInput.byteString(epk)]);
}

/** Empty NfLog: `Hc("NfLog/Empty", SmallNumeric(0))`. */
export function nflogEmpty(): Digest {
  return hc(TAG_NFLOG_EMPTY, [HcInput.smallNumeric(0n)]);
}

/** `nav_root = Hc("NfLog/Root", ByteString(size_be8), Digest(mth))`. */
export function nflogRoot(size: bigint, mth: Digest): Digest {
  if (size < 0n || size > 0xffffffffffffffffn) {
    throw new RangeError(`nflogRoot: size must be a u64, got ${size.toString()}`);
  }
  const sizeBe = new Uint8Array(8);
  let s = size;
  for (let i = 7; i >= 0; i--) {
    sizeBe[i] = Number(s & 0xffn);
    s >>= 8n;
  }
  return hc(TAG_NFLOG_ROOT, [HcInput.byteString(sizeBe), HcInput.digest(mth)]);
}

/**
 * CoinHist leaf: `Hc("CoinHist/Leaf", SmallNumeric(s))` for s ∈ {0,1,2}.
 * Corresponds to `coinhist_leaf_hash`.
 */
export function coinhistLeafHash(state: 0 | 1 | 2): Digest {
  if (!Number.isInteger(state) || state < 0 || state > 2) {
    throw new RangeError(`coinhistLeafHash: state must be 0, 1 or 2, got ${String(state)}`);
  }
  return hc(TAG_COINHIST_LEAF, [HcInput.smallNumeric(BigInt(state))]);
}

/**
 * CoinHist node: `Hc("CoinHist/Node", SmallNumeric(level), Digest(l), Digest(r))`.
 * Level 0 = leaf, level 256 = root. Levels > 256 are rejected.
 */
export function coinhistNodeHash(level: number, left: Digest, right: Digest): Digest {
  if (!Number.isInteger(level) || level < 0 || level > 256) {
    throw new RangeError(`coinhistNodeHash: level must be in 0..=256, got ${level}`);
  }
  return hc(TAG_COINHIST_NODE, [
    HcInput.smallNumeric(BigInt(level)),
    HcInput.digest(left),
    HcInput.digest(right),
  ]);
}

/**
 * Empty coin-history root E'_256.
 * E'_0 = coinhist_leaf_hash(Absent=0);
 * E'_i = coinhist_node_hash(i, E'_{i-1}, E'_{i-1}) for i in 1..=256.
 */
export function coinhistEmptyRoot(): Digest {
  let cur = coinhistLeafHash(0);
  for (let i = 1; i <= 256; i++) {
    cur = coinhistNodeHash(i, cur, cur);
  }
  return cur;
}

// Re-export GENESIS_TAG for asset_id call sites.
export { GENESIS_TAG };
