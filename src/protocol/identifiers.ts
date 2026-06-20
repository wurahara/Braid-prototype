import { braidHash, generateEd25519KeyPair } from "../crypto/index.ts";
import { createDidDocument, updateDidDocument } from "../did/document.ts";
import { createIdentifierDid, hashDid } from "../did/method.ts";
import { ensure } from "../utils/assert.ts";
import { nowIso } from "../utils/time.ts";
import {
  identifierLifecycleNullifier,
  recoveryNullifier,
} from "./nullifiers.ts";
import { logEvent } from "./state.ts";
import {
  activeAssociationForIdentifier,
  identifierSnapshot,
  requireIdentifier,
  requireUsableIdentifier,
} from "./helpers.ts";
import type {
  BraidState,
  IdentifierSnapshot,
  RegisterIdentifierInput,
  UpdateIdentifierInput,
} from "./types.ts";
import { uniqueSorted } from "../utils/collections.ts";

function randomControllerSecret(): bigint {
  return BigInt(braidHash({ type: "controller-secret", createdAt: nowIso() }));
}

export function registerIdentifier(
  state: BraidState,
  options: RegisterIdentifierInput,
): IdentifierSnapshot {
  ensure(options.owner, "Identifier registration requires an owner label");

  const keyPair = generateEd25519KeyPair();
  const did = createIdentifierDid({
    network: state.network,
    fingerprint: keyPair.fingerprint,
  });

  ensure(!state.identifiers.has(did), `DID already exists: ${did}`);

  const document = createDidDocument({
    alsoKnownAs: options.alsoKnownAs,
    did,
    publicJwk: keyPair.publicJwk,
    services: options.services,
  });
  const controllerSecret = randomControllerSecret();
  const commitment = braidHash({
    controllerKeyFingerprint: keyPair.fingerprint,
    controllerSecret: controllerSecret.toString(),
    did,
    documentHash: braidHash(document),
    type: "identifier-commitment",
    version: 1,
  });
  const inserted = state.identifierTree.insert(commitment);

  const record = {
    did,
    didHash: hashDid(did),
    owner: options.owner,
    document,
    controllerKeyFingerprint: keyPair.fingerprint,
    controllerSecret,
    currentPrivateKey: keyPair.privateKey,
    currentPrivateJwk: keyPair.privateJwk,
    currentPublicJwk: keyPair.publicJwk,
    currentPublicKey: keyPair.publicKey,
    commitment,
    leafIndex: inserted.index,
    state: "active" as const,
    version: 1,
    currentAssociation: null,
    history: [
      {
        action: "register",
        at: nowIso(),
        merkleRoot: inserted.root,
      },
    ],
  };

  state.identifiers.set(did, record);
  logEvent(state, "IdentifierRegistered", {
    did,
    leafIndex: inserted.index,
    merkleRoot: inserted.root,
    owner: options.owner,
  });

  return identifierSnapshot(record);
}

export function resolveDidDocument(state: BraidState, did: string) {
  return requireIdentifier(state, did).document;
}

export function updateIdentifier(
  state: BraidState,
  options: UpdateIdentifierInput,
): IdentifierSnapshot {
  const record = requireUsableIdentifier(state, options.did);
  const updateNullifier = identifierLifecycleNullifier(record);

  ensure(
    !state.nullifiers.didLifecycle.has(updateNullifier),
    `Identifier update nullifier already used for ${options.did}`,
  );
  state.nullifiers.didLifecycle.add(updateNullifier);

  let nextKey = {
    fingerprint: record.controllerKeyFingerprint,
    controllerSecret: record.controllerSecret,
    privateKey: record.currentPrivateKey,
    privateJwk: record.currentPrivateJwk,
    publicJwk: record.currentPublicJwk,
    publicKey: record.currentPublicKey,
  };

  let nextDocument = updateDidDocument(record.document, {
    alsoKnownAs: options.alsoKnownAs,
    services: options.services,
  });

  if (options.rotateController) {
    const rotated = generateEd25519KeyPair();
    nextKey = {
      fingerprint: rotated.fingerprint,
      controllerSecret: randomControllerSecret(),
      privateKey: rotated.privateKey,
      privateJwk: rotated.privateJwk,
      publicJwk: rotated.publicJwk,
      publicKey: rotated.publicKey,
    };
    nextDocument = createDidDocument({
      alsoKnownAs: nextDocument.alsoKnownAs,
      did: options.did,
      publicJwk: rotated.publicJwk,
      services: nextDocument.service.slice(1),
    });
  }

  const nextVersion = record.version + 1;
  const commitment = braidHash({
    controllerKeyFingerprint: nextKey.fingerprint,
    controllerSecret: nextKey.controllerSecret.toString(),
    did: options.did,
    documentHash: braidHash(nextDocument),
    type: "identifier-commitment",
    version: nextVersion,
  });
  const inserted = state.identifierTree.insert(commitment);

  record.document = nextDocument;
  record.controllerKeyFingerprint = nextKey.fingerprint;
  record.controllerSecret = nextKey.controllerSecret;
  record.currentPrivateKey = nextKey.privateKey;
  record.currentPrivateJwk = nextKey.privateJwk;
  record.currentPublicJwk = nextKey.publicJwk;
  record.currentPublicKey = nextKey.publicKey;
  record.commitment = commitment;
  record.version = nextVersion;
  record.leafIndex = inserted.index;
  record.state =
    options.reason === "recovery"
      ? "recovered"
      : options.rotateController
        ? "rotated"
        : "active";
  record.history.push({
    action: options.reason ?? "update",
    at: nowIso(),
    merkleRoot: inserted.root,
    nullifier: updateNullifier,
  });

  logEvent(state, "IdentifierUpdated", {
    did: options.did,
    nullifier: updateNullifier,
    reason: options.reason ?? "update",
    version: nextVersion,
  });

  return identifierSnapshot(record);
}

export function rotateKey(state: BraidState, did: string): IdentifierSnapshot {
  return updateIdentifier(state, {
    did,
    reason: "rotation",
    rotateController: true,
  });
}

export function recoverKey(
  state: BraidState,
  options: { did: string; witnessDids: string[] },
): IdentifierSnapshot {
  const record = requireUsableIdentifier(state, options.did);
  const association = activeAssociationForIdentifier(state, record);

  ensure(
    association,
    "Key recovery requires the identifier to be inside an active association",
  );

  const witnesses = uniqueSorted(
    options.witnessDids.filter((entry) => entry !== options.did),
  );
  const threshold = Math.min(
    state.recoveryThreshold,
    Math.max(1, association.memberDids.length - 1),
  );

  ensure(
    witnesses.length >= threshold,
    `Key recovery requires at least ${threshold} witness identifiers`,
  );

  for (const witnessDid of witnesses) {
    ensure(
      association.memberDids.includes(witnessDid),
      `Witness ${witnessDid} is not part of association ${association.did}`,
    );
    ensure(
      requireUsableIdentifier(state, witnessDid).owner === association.owner,
      "All witnesses must be controlled by the same holder",
    );
  }

  const usedNullifier = recoveryNullifier(
    options.did,
    association.did,
    record.version,
    witnesses,
  );

  ensure(
    !state.nullifiers.recovery.has(usedNullifier),
    `Recovery nullifier already used for ${options.did}`,
  );
  state.nullifiers.recovery.add(usedNullifier);

  const recovered = updateIdentifier(state, {
    did: options.did,
    reason: "recovery",
    rotateController: true,
  });

  const liveRecord = requireIdentifier(state, options.did);
  liveRecord.history.push({
    action: "recover:key",
    at: nowIso(),
    recoveryNullifier: usedNullifier,
    witnesses,
  });

  logEvent(state, "KeyRecovered", {
    did: options.did,
    recoveryNullifier: usedNullifier,
    witnesses,
  });

  return recovered;
}
