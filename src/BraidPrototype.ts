import {
  appendIdentifier,
  associateIdentifiers,
  blockAssociation,
  mergeAssociations,
  refreshAssociation,
} from "./protocol/associations.ts";
import { createCampaign, getCampaign } from "./protocol/campaigns.ts";
import {
  issueCredentialToHolder,
  presentCredentials,
  refreshCredential,
  revokeCredential,
  verifyPresentation,
} from "./protocol/credentials.ts";
import {
  associationSnapshot,
  credentialSnapshot,
  identifierSnapshot,
  requireAssociation,
  requireCredential,
  requireIdentifier,
} from "./protocol/helpers.ts";
import {
  recoverKey,
  registerIdentifier,
  resolveDidDocument,
  rotateKey,
  updateIdentifier,
} from "./protocol/identifiers.ts";
import { createProofDigest } from "./protocol/nullifiers.ts";
import {
  createBraidState,
  hydrateState,
  snapshotState,
} from "./protocol/state.ts";
import type {
  AssociationSnapshot,
  BraidState,
  CredentialSnapshot,
  IdentifierSnapshot,
  IssueCredentialInput,
  PresentCredentialsInput,
  SnapshotState,
  UpdateIdentifierInput,
} from "./protocol/types.ts";

export class BraidPrototype {
  readonly state: BraidState;

  constructor(
    options: {
      network?: string;
      recoveryThreshold?: number;
      treeDepth?: number;
    } = {},
  ) {
    this.state = createBraidState(options);
  }

  static fromSnapshot(snapshot: SnapshotState): BraidPrototype {
    const instance = new BraidPrototype({
      network: snapshot.network,
      recoveryThreshold: snapshot.recoveryThreshold,
      treeDepth: snapshot.identifierTree.depth,
    });

    (instance as { state: BraidState }).state = hydrateState(snapshot);
    return instance;
  }

  snapshot(): SnapshotState {
    return snapshotState(this.state);
  }

  createProofDigest(statement: Record<string, unknown>): string {
    return createProofDigest(statement);
  }

  createCampaign = (options: Parameters<typeof createCampaign>[1]) =>
    createCampaign(this.state, options);

  getCampaign = (campaignId: string) => getCampaign(this.state, campaignId);

  registerIdentifier(
    options: Parameters<typeof registerIdentifier>[1],
  ): IdentifierSnapshot {
    return registerIdentifier(this.state, options);
  }

  resolveDidDocument(did: string) {
    return resolveDidDocument(this.state, did);
  }

  updateIdentifier(options: UpdateIdentifierInput): IdentifierSnapshot {
    return updateIdentifier(this.state, options);
  }

  rotateKey(options: { did: string }): IdentifierSnapshot {
    return rotateKey(this.state, options.did);
  }

  associateIdentifiers(options: { dids: string[] }): AssociationSnapshot {
    return associateIdentifiers(this.state, options.dids);
  }

  appendIdentifier(options: {
    associationDid: string;
    newDid: string;
  }): AssociationSnapshot {
    return appendIdentifier(this.state, options);
  }

  mergeAssociations(options: {
    leftAssociationDid: string;
    rightAssociationDid: string;
  }): AssociationSnapshot {
    return mergeAssociations(this.state, options);
  }

  refreshAssociation(options: { associationDid: string }): AssociationSnapshot {
    return refreshAssociation(this.state, options);
  }

  blockAssociation(options: { associationDid: string; reason?: string }): void {
    blockAssociation(this.state, options);
  }

  issueCredential(options: IssueCredentialInput): CredentialSnapshot {
    return issueCredentialToHolder(this.state, options);
  }

  revokeCredential(options: {
    credentialId: string;
    reason?: string;
  }): CredentialSnapshot {
    return revokeCredential(this.state, options);
  }

  refreshCredential(options: { credentialId: string }): CredentialSnapshot {
    return refreshCredential(this.state, options);
  }

  presentCredentials(options: PresentCredentialsInput) {
    return presentCredentials(this.state, options);
  }

  verifyPresentation(options: {
    presentation: Parameters<typeof verifyPresentation>[1]["presentation"];
    verifierDid: string;
  }) {
    return verifyPresentation(this.state, options);
  }

  recoverKey(options: {
    did: string;
    witnessDids: string[];
  }): IdentifierSnapshot {
    return recoverKey(this.state, options);
  }

  getIdentifier(did: string): IdentifierSnapshot {
    return identifierSnapshot(requireIdentifier(this.state, did));
  }

  getAssociation(did: string): AssociationSnapshot {
    return associationSnapshot(requireAssociation(this.state, did));
  }

  getCredential(credentialId: string): CredentialSnapshot {
    return credentialSnapshot(requireCredential(this.state, credentialId));
  }
}
