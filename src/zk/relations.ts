import { hashToField } from "../crypto/index.ts";
import type {
  AssociationRecord,
  CredentialAnchor,
  IdentifierRecord,
} from "../protocol/types.ts";
import {
  commitmentHash,
  fieldHash2,
  fieldHashMany,
  modField,
  scopedNullifierHash,
} from "../utils/field.ts";
import type { FieldMerkleProof } from "./FieldMerkleTree.ts";

export const MAX_OPERATION_LEAVES = 4;
export const RELATION_VALUE_COUNT = 24;
export const MERKLE_TREE_DEPTH = 32;

export const OperationCode = {
  RegisterIdentifier: 1n,
  AssociateIdentifiers: 2n,
  AppendAssociation: 3n,
  MergeAssociations: 4n,
  RefreshAssociation: 5n,
  PresentCredential: 6n,
  RecoverKey: 7n,
  UpdateIdentifier: 8n,
} as const;

export const RelationDomain = {
  Identifier: 1_001n,
  Association: 1_003n,
  Credential: 1_009n,
  Presentation: 1_021n,
  Recovery: 1_033n,
  RelationDigest: 503n,
  NullifierAggregate: 601n,
} as const;

export interface OperationLeaf {
  enabled: boolean;
  subject: bigint;
  secret: bigint;
  commitment: bigint;
  pathElements: bigint[];
  pathIndices: number[];
}

export interface OperationProofWitness {
  operation: bigint;
  root: bigint;
  outputSubject: bigint;
  outputSecret: bigint;
  outputCommitment: bigint;
  scope: bigint;
  nullifier: bigint;
  relationDigest: bigint;
  predicateValue: bigint;
  predicateMin: bigint;
  predicateMax: bigint;
  relationValues: bigint[];
  leaves: OperationLeaf[];
}

export function fieldFromHex(hex: string): bigint {
  return modField(BigInt(hex));
}

export function fieldFromValue(value: unknown): bigint {
  return hashToField(value);
}

export function padRelationValues(values: readonly bigint[]): bigint[] {
  if (values.length > RELATION_VALUE_COUNT) {
    throw new Error(`Relation has more than ${RELATION_VALUE_COUNT} values`);
  }

  return [
    ...values.map((value) => modField(value)),
    ...Array<bigint>(RELATION_VALUE_COUNT - values.length).fill(0n),
  ];
}

export function deriveRelationSubject(values: readonly bigint[]): bigint {
  return fieldHashMany(padRelationValues(values));
}

export function identifierSubject(did: string): bigint {
  return deriveRelationSubject([
    RelationDomain.Identifier,
    fieldFromValue({ did, type: "identifier" }),
  ]);
}

export function associationSubject(
  memberDids: readonly string[],
  nonce: number | bigint,
): bigint {
  const members = [...memberDids].sort();
  return deriveRelationSubject([
    RelationDomain.Association,
    BigInt(members.length),
    ...members.map((did) => identifierSubject(did)),
    BigInt(nonce),
  ]);
}

export function credentialSubject(anchor: CredentialAnchor): bigint {
  return deriveRelationSubject([
    RelationDomain.Credential,
    fieldFromHex(anchor.credentialHash),
    identifierSubject(anchor.issuerDid),
    identifierSubject(anchor.holderDid),
    BigInt(anchor.version),
    BigInt(anchor.nonce),
  ]);
}

export function identifierTag(record: IdentifierRecord): bigint {
  return commitmentHash(identifierSubject(record.did), record.controllerSecret);
}

export function associationCommitment(
  memberDids: readonly string[],
  nonce: number | bigint,
): bigint {
  return commitmentHash(associationSubject(memberDids, nonce), BigInt(nonce));
}

export function credentialCommitment(anchor: CredentialAnchor): bigint {
  return commitmentHash(credentialSubject(anchor), BigInt(anchor.nonce));
}

function emptyPathElements(): bigint[] {
  return Array<bigint>(MERKLE_TREE_DEPTH).fill(0n);
}

function emptyPathIndices(): number[] {
  return Array<number>(MERKLE_TREE_DEPTH).fill(0);
}

export function disabledOperationLeaf(): OperationLeaf {
  return {
    enabled: false,
    subject: 0n,
    secret: 0n,
    commitment: commitmentHash(0n, 0n),
    pathElements: emptyPathElements(),
    pathIndices: emptyPathIndices(),
  };
}

export function identifierLeaf(
  record: IdentifierRecord,
  proof: FieldMerkleProof,
): OperationLeaf {
  const subject = identifierSubject(record.did);
  const commitment = commitmentHash(subject, record.controllerSecret);

  if (proof.leaf !== commitment) {
    throw new Error(
      `Merkle proof does not match identifier tag for ${record.did}`,
    );
  }

  return {
    enabled: true,
    subject,
    secret: record.controllerSecret,
    commitment,
    pathElements: proof.pathElements,
    pathIndices: proof.pathIndices,
  };
}

export function associationLeaf(
  association: AssociationRecord,
  proof: FieldMerkleProof,
): OperationLeaf {
  const subject = associationSubject(association.memberDids, association.nonce);
  const secret = BigInt(association.nonce);
  const commitment = commitmentHash(subject, secret);

  if (proof.leaf !== commitment) {
    throw new Error(
      `Merkle proof does not match association ${association.did}`,
    );
  }

  return {
    enabled: true,
    subject,
    secret,
    commitment,
    pathElements: proof.pathElements,
    pathIndices: proof.pathIndices,
  };
}

export function credentialLeaf(
  anchor: CredentialAnchor,
  proof: FieldMerkleProof,
): OperationLeaf {
  const subject = credentialSubject(anchor);
  const secret = BigInt(anchor.nonce);
  const commitment = commitmentHash(subject, secret);

  if (proof.leaf !== commitment) {
    throw new Error(`Merkle proof does not match credential ${anchor.id}`);
  }

  return {
    enabled: true,
    subject,
    secret,
    commitment,
    pathElements: proof.pathElements,
    pathIndices: proof.pathIndices,
  };
}

function padLeaves(leaves: readonly OperationLeaf[]): OperationLeaf[] {
  if (leaves.length > MAX_OPERATION_LEAVES) {
    throw new Error(`Operation has more than ${MAX_OPERATION_LEAVES} leaves`);
  }

  return [
    ...leaves,
    ...Array.from(
      { length: MAX_OPERATION_LEAVES - leaves.length },
      disabledOperationLeaf,
    ),
  ];
}

function aggregateNullifier(options: {
  leaves: readonly OperationLeaf[];
  operation: bigint;
  outputSecret: bigint;
  outputSubject: bigint;
  scope: bigint;
}): bigint {
  const outputNullifier = scopedNullifierHash(
    options.outputSubject,
    options.outputSecret,
    options.scope,
  );
  let accumulator = fieldHash2(
    options.operation,
    options.scope,
    RelationDomain.NullifierAggregate,
  );
  accumulator = fieldHash2(accumulator, outputNullifier);

  for (const leaf of options.leaves) {
    const leafNullifier = leaf.enabled
      ? scopedNullifierHash(leaf.subject, leaf.secret, options.scope)
      : 0n;
    accumulator = fieldHash2(accumulator, leafNullifier);
  }

  return accumulator;
}

function relationDigest(options: {
  leaves: readonly OperationLeaf[];
  operation: bigint;
  outputSecret: bigint;
  outputSubject: bigint;
  predicateMax: bigint;
  predicateMin: bigint;
  predicateValue: bigint;
  relationValues: readonly bigint[];
  scope: bigint;
}): bigint {
  let accumulator = fieldHash2(
    options.operation,
    options.scope,
    RelationDomain.RelationDigest,
  );
  accumulator = fieldHash2(accumulator, options.outputSubject);
  accumulator = fieldHash2(accumulator, options.outputSecret);
  accumulator = fieldHash2(accumulator, options.predicateValue);
  accumulator = fieldHash2(accumulator, options.predicateMin);
  accumulator = fieldHash2(accumulator, options.predicateMax);

  for (const value of options.relationValues) {
    accumulator = fieldHash2(accumulator, value);
  }

  for (const leaf of options.leaves) {
    accumulator = fieldHash2(accumulator, leaf.enabled ? leaf.subject : 0n);
    accumulator = fieldHash2(accumulator, leaf.enabled ? leaf.commitment : 0n);
  }

  return accumulator;
}

export function operationScope(operation: bigint, scopeLabel: unknown): bigint {
  return fieldHashMany([
    operation,
    fieldFromValue({
      scopeLabel,
      type: "braid-operation-scope",
    }),
  ]);
}

export function createOperationWitness(options: {
  operation: bigint;
  root?: bigint;
  outputSubject: bigint;
  outputSecret: bigint;
  scope: bigint;
  relationValues: readonly bigint[];
  leaves?: readonly OperationLeaf[];
  predicateValue?: bigint;
  predicateMin?: bigint;
  predicateMax?: bigint;
}): OperationProofWitness {
  const leaves = padLeaves(options.leaves ?? []);
  const relationValues = padRelationValues(options.relationValues);
  const predicateValue = options.predicateValue ?? 0n;
  const predicateMin = options.predicateMin ?? 0n;
  const predicateMax = options.predicateMax ?? 0n;
  const outputCommitment = commitmentHash(
    options.outputSubject,
    options.outputSecret,
  );
  const scope = modField(options.scope);
  const operation = modField(options.operation);

  return {
    operation,
    root: options.root ?? 0n,
    outputSubject: options.outputSubject,
    outputSecret: options.outputSecret,
    outputCommitment,
    scope,
    nullifier: aggregateNullifier({
      leaves,
      operation,
      outputSecret: options.outputSecret,
      outputSubject: options.outputSubject,
      scope,
    }),
    relationDigest: relationDigest({
      leaves,
      operation,
      outputSecret: options.outputSecret,
      outputSubject: options.outputSubject,
      predicateMax,
      predicateMin,
      predicateValue,
      relationValues,
      scope,
    }),
    predicateValue,
    predicateMin,
    predicateMax,
    relationValues,
    leaves,
  };
}

export function identifierRelationValues(did: string): bigint[] {
  return padRelationValues([
    RelationDomain.Identifier,
    fieldFromValue({ did, type: "identifier" }),
  ]);
}

export function associationRelationValues(
  memberDids: readonly string[],
  nonce: number | bigint,
): bigint[] {
  const members = [...memberDids].sort();
  return padRelationValues([
    RelationDomain.Association,
    BigInt(members.length),
    ...members.map((did) => identifierSubject(did)),
    BigInt(nonce),
  ]);
}
