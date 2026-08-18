/**
 * dbsc-server — server-side toolkit for Device Bound Session Credentials (DBSC).
 *
 * Protocol primitives are exported below. The high-level session flows
 * (registration, refresh, termination) are assembled on top of these and exported
 * as they land. Until 1.0.0-rc.1 this surface is unstable.
 */

/** The npm package name. Used in diagnostics. */
export const PACKAGE_NAME = 'dbsc-server';

export {
  ALGORITHMS,
  HEADERS,
  LEGACY_HEADERS,
  MIN_RSA_MODULUS_BITS,
  PROOF_TYP,
  SKIP_REASONS,
  SPEC_TRACKING,
  STATUS,
  WELL_KNOWN_PATH,
  type Algorithm,
  type SkipReason,
} from './protocol/constants.js';

export {
  buildChallengeHeader,
  buildRegistrationHeader,
  getProofHeader,
  getSessionIdHeader,
  getSkippedHeader,
  parseChallengeHeader,
  parseRegistrationHeader,
  type ChallengeHeaderInit,
  type InboundHeaderOptions,
  type ParsedChallenge,
  type ParsedRegistration,
  type ParsedSkipped,
  type RegistrationHeaderInit,
} from './protocol/headers.js';

export {
  createHmacChallenger,
  createMemoryConsumedStore,
  withSingleUse,
  type ChallengeConsumedStore,
  type ChallengeContext,
  type ChallengePurpose,
  type Challenger,
  type HmacChallengerOptions,
} from './protocol/challenge.js';

export {
  algorithmForKey,
  importVerifyKey,
  jwkThumbprint,
  normalizePublicJwk,
  type PublicEcJwk,
  type PublicJwk,
  type PublicRsaJwk,
  type UnknownJwk,
} from './protocol/jwk.js';

export {
  verifyProof,
  type ProofFailureReason,
  type ProofPayload,
  type VerifyProofOptions,
  type VerifyProofResult,
} from './protocol/proof.js';
