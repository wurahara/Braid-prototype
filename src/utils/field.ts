import { buildPoseidon } from "circomlibjs";

export const SNARK_FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export const FIELD_HASH_CONSTANTS = {
  domainCommitment: 101n,
  domainNullifier: 211n,
  domainScope: 307n,
  domainMerkle: 401n,
} as const;

const poseidon = await buildPoseidon();

function poseidon2(left: bigint, right: bigint): bigint {
  const value = poseidon([modField(left), modField(right)]);
  return modField(poseidon.F.toObject(value));
}

export function modField(value: bigint): bigint {
  const reduced = value % SNARK_FIELD_PRIME;
  return reduced >= 0n ? reduced : reduced + SNARK_FIELD_PRIME;
}

export function fieldHash2(left: bigint, right: bigint, domain = 0n): bigint {
  return poseidon2(left + domain, right);
}

export function fieldHashMany(values: readonly bigint[], domain = 0n): bigint {
  let accumulator = modField(domain);

  for (const value of values) {
    accumulator = fieldHash2(accumulator, value);
  }

  return accumulator;
}

export function commitmentHash(subject: bigint, witness: bigint): bigint {
  return poseidon2(subject + FIELD_HASH_CONSTANTS.domainCommitment, witness);
}

export function scopedNullifierHash(
  subject: bigint,
  witness: bigint,
  scope: bigint,
): bigint {
  const scopedSubject = poseidon2(
    subject + FIELD_HASH_CONSTANTS.domainScope,
    scope,
  );
  return poseidon2(
    scopedSubject,
    witness + FIELD_HASH_CONSTANTS.domainNullifier,
  );
}
