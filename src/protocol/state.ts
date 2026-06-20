import { importPrivateJwk, importPublicJwk } from "../crypto/index.ts";
import { IncrementalMerkleTree } from "../merkle/IncrementalMerkleTree.ts";
import { deepClone } from "../utils/clone.ts";
import { nowIso } from "../utils/time.ts";
import type {
  BraidState,
  CampaignRecord,
  NullifierState,
  ProtocolEvent,
  SnapshotState,
} from "./types.ts";

function createNullifierState(): NullifierState {
  return {
    associationMembers: new Set(),
    associationUpdates: new Set(),
    credentialLifecycle: new Set(),
    didLifecycle: new Set(),
    presentationCampaigns: new Set(),
    recovery: new Set(),
  };
}

export function createBraidState(
  options: {
    network?: string;
    recoveryThreshold?: number;
    treeDepth?: number;
  } = {},
): BraidState {
  const network = options.network ?? "local";
  const treeDepth = options.treeDepth ?? 32;

  return {
    network,
    recoveryThreshold: options.recoveryThreshold ?? 2,
    identifierTree: new IncrementalMerkleTree({
      depth: treeDepth,
      label: `${network}-identifier-tree`,
    }),
    associationTree: new IncrementalMerkleTree({
      depth: treeDepth,
      label: `${network}-association-tree`,
    }),
    credentialTrees: new Map(),
    identifiers: new Map(),
    associations: new Map(),
    credentials: new Map(),
    events: [],
    nullifiers: createNullifierState(),
    campaigns: new Map(),
  };
}

export function logEvent(
  state: BraidState,
  type: string,
  payload: Record<string, unknown>,
): void {
  const event: ProtocolEvent = {
    type,
    createdAt: nowIso(),
    payload: deepClone(payload),
  };

  state.events.push(event);
}

export function getOrCreateCampaignState(
  state: BraidState,
  campaignId: string,
  verifierDid: string | null = null,
): CampaignRecord {
  const existing = state.campaigns.get(campaignId);
  if (existing) {
    return existing;
  }

  const campaign: CampaignRecord = {
    id: campaignId,
    verifierDid,
    minCredentials: 1,
    requirements: [],
    policyHash: null,
    state: "implicit",
    createdAt: nowIso(),
    nullifiers: new Set(),
  };

  state.campaigns.set(campaignId, campaign);
  return campaign;
}

export function snapshotState(state: BraidState): SnapshotState {
  return {
    network: state.network,
    recoveryThreshold: state.recoveryThreshold,
    identifierTree: state.identifierTree.snapshot(),
    associationTree: state.associationTree.snapshot(),
    credentialTrees: [...state.credentialTrees.entries()].map(
      ([issuerDid, tree]) => [issuerDid, tree.snapshot()],
    ),
    identifiers: [...state.identifiers.values()].map((record) => ({
      did: record.did,
      didHash: record.didHash,
      owner: record.owner,
      document: deepClone(record.document),
      controllerKeyFingerprint: record.controllerKeyFingerprint,
      controllerSecret: record.controllerSecret.toString(),
      currentPrivateJwk: deepClone(record.currentPrivateJwk),
      currentPublicJwk: deepClone(record.currentPublicJwk),
      commitment: record.commitment,
      leafIndex: record.leafIndex,
      state: record.state,
      version: record.version,
      currentAssociation: record.currentAssociation,
      history: deepClone(record.history),
    })),
    associations: [...state.associations.values()].map((association) =>
      deepClone(association),
    ),
    credentials: [...state.credentials.values()].map((anchor) => ({
      id: anchor.id,
      issuerDid: anchor.issuerDid,
      holderDid: anchor.holderDid,
      credential: deepClone(anchor.credential),
      credentialHash: anchor.credentialHash,
      issuerPublicJwk: deepClone(anchor.issuerPublicJwk),
      commitment: anchor.commitment,
      leafIndex: anchor.leafIndex,
      version: anchor.version,
      nonce: anchor.nonce,
      state: anchor.state,
      history: deepClone(anchor.history),
    })),
    events: deepClone(state.events),
    nullifiers: {
      associationMembers: [...state.nullifiers.associationMembers],
      associationUpdates: [...state.nullifiers.associationUpdates],
      credentialLifecycle: [...state.nullifiers.credentialLifecycle],
      didLifecycle: [...state.nullifiers.didLifecycle],
      presentationCampaigns: [...state.nullifiers.presentationCampaigns],
      recovery: [...state.nullifiers.recovery],
    },
    campaigns: [...state.campaigns.values()].map((campaign) => ({
      id: campaign.id,
      verifierDid: campaign.verifierDid,
      minCredentials: campaign.minCredentials,
      requirements: deepClone(campaign.requirements),
      policyHash: campaign.policyHash,
      state: campaign.state,
      createdAt: campaign.createdAt,
      nullifiers: [...campaign.nullifiers],
    })),
  };
}

export function hydrateState(snapshot: SnapshotState): BraidState {
  const state = createBraidState({
    network: snapshot.network,
    recoveryThreshold: snapshot.recoveryThreshold,
    treeDepth: snapshot.identifierTree.depth,
  });

  state.identifierTree = IncrementalMerkleTree.fromSnapshot(
    snapshot.identifierTree,
  );
  state.associationTree = IncrementalMerkleTree.fromSnapshot(
    snapshot.associationTree,
  );
  state.credentialTrees = new Map(
    snapshot.credentialTrees.map(([issuerDid, treeSnapshot]) => [
      issuerDid,
      IncrementalMerkleTree.fromSnapshot(treeSnapshot),
    ]),
  );

  state.identifiers = new Map(
    snapshot.identifiers.map((record) => [
      record.did,
      {
        ...record,
        controllerSecret: BigInt(record.controllerSecret),
        currentPrivateKey: importPrivateJwk(record.currentPrivateJwk),
        currentPublicKey: importPublicJwk(record.currentPublicJwk),
      },
    ]),
  );

  state.associations = new Map(
    snapshot.associations.map((association) => [association.did, association]),
  );

  state.credentials = new Map(
    snapshot.credentials.map((anchor) => [
      anchor.id,
      {
        ...anchor,
        issuerPublicKey: importPublicJwk(anchor.issuerPublicJwk),
      },
    ]),
  );

  state.events = deepClone(snapshot.events);
  state.nullifiers = {
    associationMembers: new Set(snapshot.nullifiers.associationMembers),
    associationUpdates: new Set(snapshot.nullifiers.associationUpdates),
    credentialLifecycle: new Set(snapshot.nullifiers.credentialLifecycle),
    didLifecycle: new Set(snapshot.nullifiers.didLifecycle),
    presentationCampaigns: new Set(snapshot.nullifiers.presentationCampaigns),
    recovery: new Set(snapshot.nullifiers.recovery),
  };
  state.campaigns = new Map(
    snapshot.campaigns.map((campaign) => [
      campaign.id,
      {
        ...campaign,
        nullifiers: new Set(campaign.nullifiers),
      },
    ]),
  );

  return state;
}
