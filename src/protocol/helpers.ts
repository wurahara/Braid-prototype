import { hashDid } from "../did/method.ts";
import { IncrementalMerkleTree } from "../merkle/IncrementalMerkleTree.ts";
import { ensure } from "../utils/assert.ts";
import { deepClone } from "../utils/clone.ts";
import type {
  AssociationRecord,
  AssociationSnapshot,
  BraidState,
  CampaignRequirement,
  ClaimPredicate,
  CredentialAnchor,
  CredentialSnapshot,
  IdentifierRecord,
  IdentifierSnapshot,
} from "./types.ts";

export function requireIdentifier(
  state: BraidState,
  did: string,
): IdentifierRecord {
  const record = state.identifiers.get(did);
  ensure(record, `Unknown identifier: ${did}`);
  return record;
}

export function requireUsableIdentifier(
  state: BraidState,
  did: string,
): IdentifierRecord {
  const record = requireIdentifier(state, did);
  ensure(record.state !== "blocklisted", `Identifier is blocklisted: ${did}`);
  return record;
}

export function requireAssociation(
  state: BraidState,
  aid: string,
): AssociationRecord {
  const association = state.associations.get(aid);
  ensure(association, `Unknown association: ${aid}`);
  return association;
}

export function requireActiveAssociation(
  state: BraidState,
  aid: string,
): AssociationRecord {
  const association = requireAssociation(state, aid);
  ensure(association.state === "active", `Association is not active: ${aid}`);
  return association;
}

export function requireCredential(
  state: BraidState,
  credentialId: string,
): CredentialAnchor {
  const anchor = state.credentials.get(credentialId);
  ensure(anchor, `Unknown credential: ${credentialId}`);
  return anchor;
}

export function requireActiveCredential(
  state: BraidState,
  credentialId: string,
): CredentialAnchor {
  const anchor = requireCredential(state, credentialId);
  ensure(
    anchor.state === "active",
    `Credential is not active: ${credentialId}`,
  );
  return anchor;
}

export function activeAssociationForIdentifier(
  state: BraidState,
  identifier: IdentifierRecord,
): AssociationRecord | null {
  if (!identifier.currentAssociation) {
    return null;
  }

  const association = state.associations.get(identifier.currentAssociation);
  if (!association || association.state !== "active") {
    return null;
  }

  return association;
}

export function identifierSnapshot(
  record: IdentifierRecord,
): IdentifierSnapshot {
  return {
    did: record.did,
    didHash: record.didHash,
    owner: record.owner,
    document: deepClone(record.document),
    state: record.state,
    version: record.version,
    currentAssociation: record.currentAssociation,
    controllerKeyFingerprint: record.controllerKeyFingerprint,
    commitment: record.commitment,
    history: deepClone(record.history),
    leafIndex: record.leafIndex,
  };
}

export function associationSnapshot(
  association: AssociationRecord,
): AssociationSnapshot {
  return {
    did: association.did,
    didHash: association.didHash,
    owner: association.owner,
    memberDids: [...association.memberDids],
    nonce: association.nonce,
    version: association.version,
    state: association.state,
    parentAssociation: association.parentAssociation,
    commitment: association.commitment,
    leafIndex: association.leafIndex,
    history: deepClone(association.history),
  };
}

export function credentialSnapshot(
  anchor: CredentialAnchor,
): CredentialSnapshot {
  return {
    id: anchor.id,
    issuerDid: anchor.issuerDid,
    holderDid: anchor.holderDid,
    state: anchor.state,
    version: anchor.version,
    nonce: anchor.nonce,
    credentialHash: anchor.credentialHash,
    commitment: anchor.commitment,
    leafIndex: anchor.leafIndex,
    credential: deepClone(anchor.credential),
    history: deepClone(anchor.history),
  };
}

export function issuerCredentialTree(
  state: BraidState,
  issuerDid: string,
): IncrementalMerkleTree {
  const existing = state.credentialTrees.get(issuerDid);
  if (existing) {
    return existing;
  }

  const tree = new IncrementalMerkleTree({
    depth: 16,
    label: `${state.network}-credential-tree-${hashDid(issuerDid)}`,
  });
  state.credentialTrees.set(issuerDid, tree);
  return tree;
}

export function claimPredicateMatches(
  value: unknown,
  predicate: ClaimPredicate = {},
): boolean {
  if (predicate.equals !== undefined && value !== predicate.equals) {
    return false;
  }

  if (
    predicate.min !== undefined &&
    !(typeof value === "number" && value >= predicate.min)
  ) {
    return false;
  }

  if (
    predicate.max !== undefined &&
    !(typeof value === "number" && value <= predicate.max)
  ) {
    return false;
  }

  if (predicate.includes !== undefined) {
    if (Array.isArray(value)) {
      return value.includes(predicate.includes);
    }

    if (typeof value === "string") {
      return value.includes(String(predicate.includes));
    }

    return false;
  }

  return true;
}
