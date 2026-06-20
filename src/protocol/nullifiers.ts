import { braidHash, hashToField } from "../crypto/index.ts";
import type {
  AssociationRecord,
  BraidState,
  CredentialAnchor,
  IdentifierRecord,
} from "./types.ts";

export function createProofDigest(statement: Record<string, unknown>): string {
  return braidHash({
    createdAt: new Date().toISOString(),
    statement,
  });
}

export function associationUpdateNullifier(
  association: AssociationRecord,
): string {
  return braidHash({
    associationDid: association.did,
    nonce: association.nonce,
    type: "association-update-nullifier",
    version: association.version,
  });
}

export function associationPresentationNullifier(
  association: AssociationRecord,
): string {
  return braidHash({
    associationDid: association.did,
    nonce: association.nonce,
    type: "association-presentation-nullifier",
    version: association.version,
  });
}

export function campaignNullifier(
  association: AssociationRecord,
  campaignId: string,
): string {
  return braidHash({
    campaignId,
    memberDids: association.memberDids,
    type: "campaign-nullifier",
  });
}

export function credentialNullifier(anchor: CredentialAnchor): string {
  return braidHash({
    credentialId: anchor.id,
    nonce: anchor.nonce,
    type: "credential-nullifier",
    version: anchor.version,
  });
}

export function associationMemberNullifier(
  identifier: IdentifierRecord,
): string {
  return braidHash({
    controllerKeyFingerprint: identifier.controllerKeyFingerprint,
    did: identifier.did,
    type: "association-member-nullifier",
    version: identifier.version,
  });
}

export function identifierLifecycleNullifier(
  identifier: IdentifierRecord,
): string {
  return braidHash({
    controllerKeyFingerprint: identifier.controllerKeyFingerprint,
    did: identifier.did,
    type: "identifier-update-nullifier",
    version: identifier.version,
  });
}

export function recoveryNullifier(
  did: string,
  associationDid: string,
  version: number,
  witnesses: string[],
): string {
  return braidHash({
    associationDid,
    did,
    type: "key-recovery-nullifier",
    version,
    witnesses,
  });
}

export function operationScopeField(scope: string): bigint {
  return hashToField({ scope });
}

export function findActiveAssociationByPresentationNullifier(
  state: BraidState,
  expectedNullifier: string,
): AssociationRecord | null {
  for (const association of state.associations.values()) {
    if (association.state !== "active") {
      continue;
    }

    if (associationPresentationNullifier(association) === expectedNullifier) {
      return association;
    }
  }

  return null;
}
