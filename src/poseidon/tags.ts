/**
 * Domain-separation tag catalogue (full prefixed strings).
 * Port of `node/shared/src/spec_v1/tags.rs` — only the Hc contexts needed
 * for V.4 primitives and the call sites built on `hc`.
 */

export const TAG_ACCOUNT_STATE = 'zkCoins/v1/AccountState';
export const TAG_COIN = 'zkCoins/v1/Coin';
export const TAG_ASSET_ID = 'zkCoins/v1/AssetId';
export const TAG_ASSET_ID_V2 = 'zkCoins/v1/AssetIdV2';
export const TAG_ISSUANCE_TERMS = 'zkCoins/v1/IssuanceTerms';
export const TAG_ISSUANCE_TERMS_V2 = 'zkCoins/v1/IssuanceTermsV2';
export const TAG_NK_COMMIT = 'zkCoins/v1/NkCommit';
export const TAG_NULLIFIER = 'zkCoins/v1/Nullifier';
export const TAG_NETWORK = 'zkCoins/v1/Network';
export const TAG_NAV_COMMIT = 'zkCoins/v1/NavCommit';
export const TAG_DETECT_TAG = 'zkCoins/v1/DetectTag';

export const TAG_NFLOG_EMPTY = 'zkCoins/v1/NfLog/Empty';
export const TAG_NFLOG_ROOT = 'zkCoins/v1/NfLog/Root';
export const TAG_NFLOG_LEAF = 'zkCoins/v1/NfLog/Leaf';
export const TAG_NFLOG_NODE = 'zkCoins/v1/NfLog/Node';

export const TAG_COINHIST_LEAF = 'zkCoins/v1/CoinHist/Leaf';
export const TAG_COINHIST_NODE = 'zkCoins/v1/CoinHist/Node';

/** Genesis tag input to AssetId / AssetIdV2 (18 ASCII bytes). */
export const GENESIS_TAG = new TextEncoder().encode('zkCoins/v1/genesis');

export const NETWORK_TAG_MAINNET = new TextEncoder().encode('zkCoins/v1/mainnet');
export const NETWORK_TAG_TESTNET = new TextEncoder().encode('zkCoins/v1/testnet');
export const NETWORK_TAG_REGTEST = new TextEncoder().encode('zkCoins/v1/regtest');
