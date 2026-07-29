/**
 * Poseidon-over-Goldilocks + E(·) + Hc — public surface for V.4 digests.
 */

export {
  GOLDILOCKS_P,
  GOLDILOCKS_EPSILON,
  reduce,
  fromCanonicalU64,
  fromU64,
  toCanonicalU64,
  add,
  sub,
  mul,
  pow7,
} from './goldilocks.js';

export {
  SPONGE_WIDTH,
  SPONGE_RATE,
  HALF_N_FULL_ROUNDS,
  N_PARTIAL_ROUNDS,
  N_ROUNDS,
} from './constants.js';

export { type Digest, ZERO_DIGEST, poseidonPermute, hashNoPad, digestsEqual } from './poseidon.js';

export {
  MAX_BYTE_STRING_LEN,
  MAX_SMALL_NUMERIC,
  type EncodingErrorKind,
  EncodingError,
  type HcInput as HcInputType,
  HcInput,
  encodeByteString,
  encodeDigest,
  encodeSmallNumeric,
  digestToBytes,
  digestFromBytes,
  digestToHex,
  digestFromHex,
  hc,
} from './hc.js';

export {
  TAG_ACCOUNT_STATE,
  TAG_COIN,
  TAG_ASSET_ID,
  TAG_ASSET_ID_V2,
  TAG_ISSUANCE_TERMS,
  TAG_ISSUANCE_TERMS_V2,
  TAG_NK_COMMIT,
  TAG_NULLIFIER,
  TAG_NETWORK,
  TAG_NAV_COMMIT,
  TAG_DETECT_TAG,
  TAG_NFLOG_EMPTY,
  TAG_NFLOG_ROOT,
  TAG_NFLOG_LEAF,
  TAG_NFLOG_NODE,
  TAG_COINHIST_LEAF,
  TAG_COINHIST_NODE,
  GENESIS_TAG,
  NETWORK_TAG_MAINNET,
  NETWORK_TAG_TESTNET,
  NETWORK_TAG_REGTEST,
} from './tags.js';

export {
  nkCommit,
  nullifier,
  assetIdV1,
  assetIdV2,
  termsHashV1,
  termsHashV2,
  networkId,
  networkIdMainnet,
  networkIdTestnet,
  networkIdRegtest,
  navCommitment,
  detectTag,
  nflogEmpty,
  nflogRoot,
  coinhistLeafHash,
  coinhistNodeHash,
  coinhistEmptyRoot,
} from './hashes.js';
