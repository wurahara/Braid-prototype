import type { KeyObject } from "node:crypto";

import type { DidDocument, DidService } from "../did/document.ts";
import type { IncrementalMerkleTreeSnapshot } from "../merkle/IncrementalMerkleTree.ts";
import type {
  DerivedCredential,
  VerifiablePresentation,
} from "../vc/presentation.ts";
import type { VerifiableCredential } from "../vc/credential.ts";

export type IdentifierState =
  | "active"
  | "rotated"
  | "recovered"
  | "blocklisted";
export type AssociationState = "active" | "superseded" | "blocklisted";
export type CredentialState = "active" | "revoked";
export type CampaignState = "implicit" | "active";

export interface ProtocolEvent {
  type: string;
  createdAt: string;
  payload: Record<string, unknown>;
}

export interface ClaimPredicate {
  equals?: string | number | boolean;
  min?: number;
  max?: number;
  includes?: string | number;
}

export interface CampaignRequirement {
  id?: string;
  credentialType?: string;
  disclosedClaims?: string[];
  claimPredicates?: Record<string, ClaimPredicate>;
}

export interface CampaignRecord {
  id: string;
  verifierDid: string | null;
  minCredentials: number;
  requirements: CampaignRequirement[];
  policyHash: string | null;
  state: CampaignState;
  createdAt: string;
  nullifiers: Set<string>;
}

export interface IdentifierRecord {
  did: string;
  didHash: string;
  owner: string;
  document: DidDocument;
  controllerKeyFingerprint: string;
  controllerSecret: bigint;
  currentPrivateKey: KeyObject;
  currentPrivateJwk: JsonWebKey;
  currentPublicJwk: JsonWebKey;
  currentPublicKey: KeyObject;
  commitment: string;
  leafIndex: number;
  state: IdentifierState;
  version: number;
  currentAssociation: string | null;
  history: Array<Record<string, unknown>>;
}

export interface AssociationRecord {
  did: string;
  didHash: string;
  owner: string;
  memberDids: string[];
  nonce: number;
  version: number;
  state: AssociationState;
  parentAssociation: string[] | null;
  commitment: string;
  leafIndex: number;
  history: Array<Record<string, unknown>>;
}

export interface CredentialAnchor {
  id: string;
  issuerDid: string;
  holderDid: string;
  credential: VerifiableCredential;
  credentialHash: string;
  issuerPublicKey: KeyObject;
  issuerPublicJwk: JsonWebKey;
  commitment: string;
  leafIndex: number;
  version: number;
  nonce: number;
  state: CredentialState;
  history: Array<Record<string, unknown>>;
}

export interface NullifierState {
  associationMembers: Set<string>;
  associationUpdates: Set<string>;
  credentialLifecycle: Set<string>;
  didLifecycle: Set<string>;
  presentationCampaigns: Set<string>;
  recovery: Set<string>;
}

export interface BraidState {
  network: string;
  recoveryThreshold: number;
  identifierTree: import("../merkle/IncrementalMerkleTree.ts").IncrementalMerkleTree;
  associationTree: import("../merkle/IncrementalMerkleTree.ts").IncrementalMerkleTree;
  credentialTrees: Map<
    string,
    import("../merkle/IncrementalMerkleTree.ts").IncrementalMerkleTree
  >;
  identifiers: Map<string, IdentifierRecord>;
  associations: Map<string, AssociationRecord>;
  credentials: Map<string, CredentialAnchor>;
  events: ProtocolEvent[];
  nullifiers: NullifierState;
  campaigns: Map<string, CampaignRecord>;
}

export interface IdentifierSnapshot {
  did: string;
  didHash: string;
  owner: string;
  document: DidDocument;
  state: IdentifierState;
  version: number;
  currentAssociation: string | null;
  controllerKeyFingerprint: string;
  commitment: string;
  history: Array<Record<string, unknown>>;
  leafIndex: number;
}

export interface AssociationSnapshot {
  did: string;
  didHash: string;
  owner: string;
  memberDids: string[];
  nonce: number;
  version: number;
  state: AssociationState;
  parentAssociation: string[] | null;
  commitment: string;
  leafIndex: number;
  history: Array<Record<string, unknown>>;
}

export interface CredentialSnapshot {
  id: string;
  issuerDid: string;
  holderDid: string;
  state: CredentialState;
  version: number;
  nonce: number;
  credentialHash: string;
  commitment: string;
  leafIndex: number;
  credential: VerifiableCredential;
  history: Array<Record<string, unknown>>;
}

export interface PresentationVerification {
  accepted: true;
  associationDid: string;
  campaignId: string;
  credentialIds: string[];
}

export interface SnapshotState {
  network: string;
  recoveryThreshold: number;
  identifierTree: IncrementalMerkleTreeSnapshot;
  associationTree: IncrementalMerkleTreeSnapshot;
  credentialTrees: Array<[string, IncrementalMerkleTreeSnapshot]>;
  identifiers: Array<{
    did: string;
    didHash: string;
    owner: string;
    document: DidDocument;
    controllerKeyFingerprint: string;
    controllerSecret: string;
    currentPrivateJwk: JsonWebKey;
    currentPublicJwk: JsonWebKey;
    commitment: string;
    leafIndex: number;
    state: IdentifierState;
    version: number;
    currentAssociation: string | null;
    history: Array<Record<string, unknown>>;
  }>;
  associations: AssociationRecord[];
  credentials: Array<{
    id: string;
    issuerDid: string;
    holderDid: string;
    credential: VerifiableCredential;
    credentialHash: string;
    issuerPublicJwk: JsonWebKey;
    commitment: string;
    leafIndex: number;
    version: number;
    nonce: number;
    state: CredentialState;
    history: Array<Record<string, unknown>>;
  }>;
  events: ProtocolEvent[];
  nullifiers: Record<keyof NullifierState, string[]>;
  campaigns: Array<{
    id: string;
    verifierDid: string | null;
    minCredentials: number;
    requirements: CampaignRequirement[];
    policyHash: string | null;
    state: CampaignState;
    createdAt: string;
    nullifiers: string[];
  }>;
}

export interface RegisterIdentifierInput {
  alsoKnownAs?: string[];
  owner: string;
  services?: DidService[];
}

export interface UpdateIdentifierInput {
  alsoKnownAs?: string[];
  did: string;
  reason?: "update" | "rotation" | "recovery";
  rotateController?: boolean;
  services?: DidService[];
}

export interface IssueCredentialInput {
  claims: Record<string, unknown>;
  extraTypes?: string[];
  holderDid: string;
  issuerDid: string;
  validUntil?: string;
}

export interface PresentCredentialsInput {
  associationDid: string;
  campaignId: string;
  credentialIds: string[];
  disclosedClaims?: Record<string, string[]>;
  verifierDid: string;
}

export type {
  DidDocument,
  DidService,
  DerivedCredential,
  VerifiableCredential,
  VerifiablePresentation,
};
