// Public surface of @zkcoins/sdk.
//
// Most implementations land in follow-up commits on the bootstrap PR
// (see CONTRIBUTING.md §Branch flow). This file is the single import
// site every consumer hits, and serves as the contract surface that
// `tsup` builds into `dist/index.{js,cjs,d.ts}`.

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

export { buildSendMessage, buildClaimMessage } from './messages.js';
export type { SendMessageParams, ClaimMessageParams } from './messages.js';

export {
  SendResponseSchema,
  MintResponseSchema,
  CommitResponseSchema,
  BalanceResponseSchema,
  UsernameResponseSchema,
  ClaimUsernameResponseSchema,
  ResolveUsernameResponseSchema,
  CapabilitiesSchema,
  InfoResponseSchema,
  TxItemSchema,
  HistoryResponseSchema,
} from './schemas.js';
export type {
  SendResponse,
  MintResponse,
  CommitResponse,
  BalanceResponse,
  UsernameResponse,
  ClaimUsernameResponse,
  ResolveUsernameResponse,
  Capabilities,
  InfoResponse,
  TxItem,
  HistoryResponse,
} from './schemas.js';

export { ApiError, NotImplementedError } from './errors.js';

export { ZkCoinsClient } from './client.js';
export type {
  ZkCoinsClientOptions,
  SendRequest,
  SignedSendRequest,
  CommitRequest,
  SignedClaimRequest,
  HistoryOpts,
} from './client.js';

export { ZkCoinsAccount } from './account.js';
export type {
  ZkCoinsAccountOptions,
  PayResult,
  HistoryOpts as AccountHistoryOpts,
} from './account.js';
