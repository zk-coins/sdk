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
