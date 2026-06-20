export { BraidPrototype } from "./BraidPrototype.ts";
export {
  braidHash,
  generateEd25519KeyPair,
  hashToField,
  importPrivateJwk,
  importPublicJwk,
  signObject,
  stableStringify,
  verifyObject,
} from "./crypto/index.ts";
export {
  assertDidFormat,
  createAssociationDid,
  createIdentifierDid,
  hashDid,
} from "./did/method.ts";
export { DID_CONTEXT } from "./did/constants.ts";
export { createDidDocument, updateDidDocument } from "./did/document.ts";
export { IncrementalMerkleTree } from "./merkle/IncrementalMerkleTree.ts";
export { createCampaign, getCampaign } from "./protocol/campaigns.ts";
export type * from "./protocol/types.ts";
export {
  createPresentation,
  deriveCredentialForPresentation,
  type VerifiablePresentation,
} from "./vc/presentation.ts";
export {
  credentialHash,
  issueCredential,
  verifyCredentialSignature,
  type VerifiableCredential,
} from "./vc/credential.ts";
