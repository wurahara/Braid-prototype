import { braidHash } from "../crypto/index.ts";
import { createAssociationDid, hashDid } from "../did/method.ts";
import { ensure } from "../utils/assert.ts";
import { uniqueSorted } from "../utils/collections.ts";
import { nowIso } from "../utils/time.ts";
import {
  associationMemberNullifier,
  associationUpdateNullifier,
} from "./nullifiers.ts";
import { logEvent } from "./state.ts";
import {
  activeAssociationForIdentifier,
  associationSnapshot,
  requireActiveAssociation,
  requireIdentifier,
  requireUsableIdentifier,
} from "./helpers.ts";
import type {
  AssociationRecord,
  AssociationSnapshot,
  BraidState,
} from "./types.ts";

export function associateIdentifiers(
  state: BraidState,
  dids: string[],
): AssociationSnapshot {
  const memberDids = uniqueSorted(dids);
  ensure(
    memberDids.length >= 2,
    "Association requires at least two identifiers",
  );

  const members = memberDids.map((did) => requireUsableIdentifier(state, did));
  const owner = members[0].owner;

  for (const member of members) {
    ensure(
      member.owner === owner,
      "All associated identifiers must share the same owner",
    );
    ensure(
      !activeAssociationForIdentifier(state, member),
      `Identifier is already in an active association: ${member.did}`,
    );
  }

  const memberNullifiers = members.map((member) =>
    associationMemberNullifier(member),
  );

  for (const nullifier of memberNullifiers) {
    ensure(
      !state.nullifiers.associationMembers.has(nullifier),
      "An identifier version has already been consumed by an association",
    );
  }

  memberNullifiers.forEach((nullifier) =>
    state.nullifiers.associationMembers.add(nullifier),
  );

  const nonce = 0;
  const did = createAssociationDid({
    network: state.network,
    memberDids,
    nonce,
  });
  const commitment = braidHash({
    did,
    memberDids,
    nonce,
    type: "association-commitment",
    version: 1,
  });
  const inserted = state.associationTree.insert(commitment);

  const association: AssociationRecord = {
    did,
    didHash: hashDid(did),
    owner,
    memberDids,
    nonce,
    version: 1,
    state: "active",
    parentAssociation: null,
    commitment,
    leafIndex: inserted.index,
    history: [
      {
        action: "associate",
        at: nowIso(),
        memberNullifiers,
        merkleRoot: inserted.root,
      },
    ],
  };

  state.associations.set(did, association);

  for (const member of members) {
    member.currentAssociation = did;
  }

  logEvent(state, "AssociationCreated", {
    aid: did,
    memberDids,
    merkleRoot: inserted.root,
    nonce,
  });

  return associationSnapshot(association);
}

function spawnSupersedingAssociation(
  state: BraidState,
  options: {
    action: "append" | "merge" | "refresh";
    memberDids: string[];
    nonce: number;
    parentAssociations: AssociationRecord[];
  },
): AssociationRecord {
  const did = createAssociationDid({
    network: state.network,
    memberDids: options.memberDids,
    nonce: options.nonce,
  });
  const version =
    Math.max(
      ...options.parentAssociations.map((association) => association.version),
      0,
    ) + 1;
  const commitment = braidHash({
    did,
    memberDids: options.memberDids,
    nonce: options.nonce,
    type: "association-commitment",
    version,
  });
  const inserted = state.associationTree.insert(commitment);
  const owner = options.parentAssociations[0].owner;

  const association: AssociationRecord = {
    did,
    didHash: hashDid(did),
    owner,
    memberDids: options.memberDids,
    nonce: options.nonce,
    version,
    state: "active",
    parentAssociation: options.parentAssociations.map((entry) => entry.did),
    commitment,
    leafIndex: inserted.index,
    history: [
      {
        action: options.action,
        at: nowIso(),
        parents: options.parentAssociations.map((entry) => entry.did),
        merkleRoot: inserted.root,
      },
    ],
  };

  state.associations.set(did, association);

  for (const previous of options.parentAssociations) {
    previous.state = "superseded";
    previous.history.push({
      action: `${options.action}:superseded`,
      at: nowIso(),
      replacedBy: did,
    });
  }

  for (const memberDid of options.memberDids) {
    requireIdentifier(state, memberDid).currentAssociation = did;
  }

  logEvent(state, "AssociationUpdated", {
    aid: did,
    action: options.action,
    memberDids: options.memberDids,
    nonce: options.nonce,
    parents: options.parentAssociations.map((entry) => entry.did),
  });

  return association;
}

export function appendIdentifier(
  state: BraidState,
  options: { associationDid: string; newDid: string },
): AssociationSnapshot {
  const association = requireActiveAssociation(state, options.associationDid);
  const nextIdentifier = requireUsableIdentifier(state, options.newDid);

  ensure(
    nextIdentifier.owner === association.owner,
    "Appended identifier must share owner",
  );
  ensure(
    !activeAssociationForIdentifier(state, nextIdentifier),
    "Identifier is already bound",
  );

  const associationNullifier = associationUpdateNullifier(association);
  ensure(
    !state.nullifiers.associationUpdates.has(associationNullifier),
    "Association update nullifier already used",
  );
  state.nullifiers.associationUpdates.add(associationNullifier);

  const identifierNullifier = associationMemberNullifier(nextIdentifier);
  ensure(
    !state.nullifiers.associationMembers.has(identifierNullifier),
    "Identifier version has already been consumed by an association",
  );
  state.nullifiers.associationMembers.add(identifierNullifier);

  const mergedMembers = uniqueSorted([
    ...association.memberDids,
    options.newDid,
  ]);
  const spawned = spawnSupersedingAssociation(state, {
    action: "append",
    memberDids: mergedMembers,
    nonce: association.nonce,
    parentAssociations: [association],
  });

  spawned.history[0].associationNullifier = associationNullifier;
  spawned.history[0].identifierNullifier = identifierNullifier;

  return associationSnapshot(spawned);
}

export function mergeAssociations(
  state: BraidState,
  options: { leftAssociationDid: string; rightAssociationDid: string },
): AssociationSnapshot {
  const left = requireActiveAssociation(state, options.leftAssociationDid);
  const right = requireActiveAssociation(state, options.rightAssociationDid);

  ensure(left.did !== right.did, "Cannot merge the same association twice");
  ensure(
    left.owner === right.owner,
    "Merged associations must share the same owner",
  );

  const leftNullifier = associationUpdateNullifier(left);
  const rightNullifier = associationUpdateNullifier(right);
  ensure(
    !state.nullifiers.associationUpdates.has(leftNullifier),
    "Left association nullifier already consumed",
  );
  ensure(
    !state.nullifiers.associationUpdates.has(rightNullifier),
    "Right association nullifier already consumed",
  );
  state.nullifiers.associationUpdates.add(leftNullifier);
  state.nullifiers.associationUpdates.add(rightNullifier);

  const mergedMembers = uniqueSorted([...left.memberDids, ...right.memberDids]);
  const spawned = spawnSupersedingAssociation(state, {
    action: "merge",
    memberDids: mergedMembers,
    nonce: Math.max(left.nonce, right.nonce),
    parentAssociations: [left, right],
  });

  spawned.history[0].leftNullifier = leftNullifier;
  spawned.history[0].rightNullifier = rightNullifier;

  return associationSnapshot(spawned);
}

export function refreshAssociation(
  state: BraidState,
  options: { associationDid: string },
): AssociationSnapshot {
  const association = requireActiveAssociation(state, options.associationDid);
  const associationNullifier = associationUpdateNullifier(association);

  ensure(
    !state.nullifiers.associationUpdates.has(associationNullifier),
    "Association refresh nullifier already consumed",
  );
  state.nullifiers.associationUpdates.add(associationNullifier);

  const refreshed = spawnSupersedingAssociation(state, {
    action: "refresh",
    memberDids: association.memberDids,
    nonce: association.nonce + 1,
    parentAssociations: [association],
  });

  refreshed.history[0].associationNullifier = associationNullifier;

  return associationSnapshot(refreshed);
}

export function blockAssociation(
  state: BraidState,
  options: { associationDid: string; reason?: string },
): void {
  const association = requireActiveAssociation(state, options.associationDid);
  association.state = "blocklisted";
  association.history.push({
    action: "blocklist",
    at: nowIso(),
    reason: options.reason ?? "manual-blocklist",
  });

  for (const memberDid of association.memberDids) {
    const member = requireIdentifier(state, memberDid);
    member.state = "blocklisted";
    member.history.push({
      action: "blocked-by-association",
      at: nowIso(),
      reason: options.reason ?? "manual-blocklist",
    });
  }

  logEvent(state, "AssociationBlocklisted", {
    aid: options.associationDid,
    reason: options.reason ?? "manual-blocklist",
  });
}
