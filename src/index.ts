// Public surface of @zkcoins/sdk.
//
// This file is the single import site every consumer hits, and serves
// as the contract surface that `tsup` builds into
// `dist/index.{js,cjs,d.ts}`.

export { VERSION } from './version.js';

export {
  generateMnemonic,
  validateMnemonic,
  mnemonicFromEntropy,
  generateAccountKeys,
  generateAccountKeysFromMnemonic,
  derivePublicKeys,
  deriveSigningKey,
} from './derivation.js';
export type { AccountKeys } from './derivation.js';

export { signSchnorr, createCommitment } from './signing.js';
export type { Commitment } from './signing.js';

export { buildSendMessage, buildClaimMessage, buildMintMessage } from './messages.js';
export type { SendMessageParams, ClaimMessageParams, MintMessageParams } from './messages.js';

export {
  BalanceResponseSchema,
  AssetBalanceSchema,
  OwnerBalanceResponseSchema,
  UsernameResponseSchema,
  ClaimUsernameResponseSchema,
  ResolveUsernameResponseSchema,
  CapabilitiesSchema,
  BitcoinNetworkSchema,
  InfoResponseSchema,
  TxItemSchema,
  HistoryResponseSchema,
  TxDetailSchema,
  JobStatusValueSchema,
  JobKindSchema,
  JobAcceptedSchema,
  JobResultSchema,
  JobStatusSchema,
  JobErrorResponseSchema,
  ReadyResponseSchema,
  PublisherHealthResponseSchema,
  RootEndpointsSchema,
  RootResponseSchema,
  AddressesResponseSchema,
  InscriptionKindSchema,
  InscriptionSummarySchema,
} from './schemas.js';
export type {
  BalanceResponse,
  AssetBalance,
  OwnerBalanceResponse,
  UsernameResponse,
  ClaimUsernameResponse,
  ResolveUsernameResponse,
  Capabilities,
  BitcoinNetwork,
  InfoResponse,
  TxItem,
  HistoryResponse,
  TxDetail,
  JobStatusValue,
  JobKind,
  JobAccepted,
  JobResult,
  JobStatus,
  JobErrorResponse,
  ReadyResponse,
  PublisherHealthResponse,
  RootEndpoints,
  RootResponse,
  AddressesResponse,
  InscriptionKind,
  InscriptionSummary,
} from './schemas.js';

export { ApiError, JobFailedError } from './errors.js';

export { ZkCoinsClient, newIdempotencyKey } from './client.js';
export type {
  ZkCoinsClientOptions,
  MintRequest,
  SendRequest,
  SignedSendRequest,
  CommitRequest,
  SignedClaimRequest,
  HistoryOpts,
  JobStatusWithRetry,
} from './client.js';

export { ZkCoinsAccount } from './account.js';
export type {
  ZkCoinsAccountOptions,
  MintResult,
  PayResult,
  WaitForJobOpts,
  WaitForIncomingOpts,
} from './account.js';

// Poseidon-over-Goldilocks, E(·), Hc (spec §§1.7 / V.4).
export {
  GOLDILOCKS_P,
  type Digest,
  ZERO_DIGEST,
  poseidonPermute,
  hashNoPad,
  digestsEqual,
  EncodingError,
  HcInput,
  encodeByteString,
  encodeDigest,
  encodeSmallNumeric,
  digestToBytes,
  digestFromBytes,
  digestToHex,
  digestFromHex,
  hc,
  TAG_NK_COMMIT,
  TAG_ASSET_ID,
  TAG_NFLOG_EMPTY,
  TAG_NETWORK,
  GENESIS_TAG,
  NETWORK_TAG_MAINNET,
  NETWORK_TAG_TESTNET,
  NETWORK_TAG_REGTEST,
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
} from './poseidon/index.js';
export type { EncodingErrorKind, HcInputType } from './poseidon/index.js';
