/**
 * zkCoins v1 signing surface + transition client.
 *
 * Intentionally separate from the legacy ash‖ocr surface in
 * `src/signing.ts` / `src/client.ts`.
 */

export { mStateBytes, mStateString, type Network } from './mstate.js';

export {
  PROOF_DATA_FIELD_LEN,
  PROOF_DATA_SERIALIZED_LEN,
  assertProofData,
  serializeProofData,
  hashProofData,
  type ProofData,
} from './proofData.js';

export {
  TransitionSignatureError,
  bip340NormaliseSecret,
  liftXOnly,
  requireCanonicalScalar,
  tweakScalarOrReject,
  isAcceptableCommittedR,
  runWithRedrawBudget,
  signTransition,
  signTransitionTrace,
  signTransitionOverProofData,
  signTransitionWithFixtureNonce,
  verify,
  commVerify,
  SECP256K1_ORDER,
  type TransitionSignature,
  type SignTrace,
} from './transitionSignature.js';

export {
  aggregationCoefficients,
  aggregateSig,
  aggregateVerify,
  commRetrieve,
  pointHasEvenY,
  type HalfAggMember,
  type AggregateSigResult,
} from './halfAgg.js';

export {
  CsprngUnavailableError,
  KeyBindingRefusalError,
  ProofDataHashRefusalError,
  NetworkMismatchRefusalError,
  NpkCommitRefusalError,
  V1ApiError,
  redactBearerToken,
} from './errors.js';

export {
  ZKCOINS_PURPOSE,
  SPEND_BRANCH,
  deriveSpendKey,
  deriveSk0,
  seedFromMnemonicV1,
  xOnlyPubkeyFromSecret,
  type SpendKey,
} from './keys.js';

export {
  PULL_CHALLENGE_DOMAIN,
  PULL_HOST_DOMAIN,
  chanBindForHost,
  canonicalHostFromApiUrl,
  pullChallengeMessage,
  parseExpiryDecimal,
  buildOwnershipProof,
  freshNpkRand,
  computeNpkCommit,
  type OwnershipProofJson,
  type PullChallenge,
} from './ownership.js';

export { encodeZkAddress, decodeZkAddress, ZK_ADDRESS_HRP } from './bech32m.js';

export { encodeHexLower, decodeHexExact, bytesEqual } from './hex.js';

export {
  assertTransitionRequest,
  transitionRequestToJson,
  type OutputTemplate,
  type Issuance,
  type IssuanceV1,
  type IssuanceV2,
  type TransitionRequest,
  type TransitionRequestSend,
  type TransitionRequestMint,
  type TransitionRequestReceive,
  type DeliveryCredential,
} from './transitionRequest.js';

export {
  INVOICE_MESSAGE_DOMAIN,
  addressFromParts,
  invoiceMessage,
  profileInvoiceMessage,
  parseDeliveryCredential,
  parseU128Decimal,
  verifyDeliveryCredential,
  placeDeliveryCredential,
  assertOutputDeliveries,
  PaymentIdentityPinStore,
  DeliveryCredentialError,
  PaymentIdentityPinMismatchError,
  type InvoiceJson,
  type PaymentIdentityPin,
  type PinCheckResult,
  type VerifyDeliveryOptions,
  type InvoiceMessageParts,
} from './delivery.js';

export {
  escapeNip01String,
  serializeNip01IdPreimage,
  computeNip01EventId,
  verifyNip01Event,
  signNip01Event,
  type NostrEventJson,
} from './nostrEvent.js';

export {
  refuseOrSignTransition,
  signBodyFromSignature,
  type AwaitingSignature,
  type AccountStateHead,
} from './signGate.js';

export {
  ZkCoinsV1Client,
  type ZkCoinsV1ClientOptions,
  type V1JobStatusValue,
  type V1JobAccepted,
  type V1Job,
  type V1SsePhasePayload,
  type V1SseStreamFrame,
  type V1JobWithRetry,
  type V1JobResult,
  type V1JobErrorBody,
  type V1AccountState,
  type V1PullResult,
  type V1Info,
} from './client.js';
