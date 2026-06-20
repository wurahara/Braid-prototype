import { createHash, randomBytes, randomUUID } from "node:crypto";

export type Hashable = unknown;

const SNARK_FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function sortValue<T>(value: T): T {
  if (Array.isArray(value)) {
    return value.map((item) => sortValue(item)) as T;
  }

  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, item]) => item !== undefined)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, item]) => [key, sortValue(item)]);

    return Object.fromEntries(entries) as T;
  }

  return value;
}

export function stableStringify(value: Hashable): string {
  return JSON.stringify(sortValue(value));
}

export function braidHash(value: Hashable): string {
  return `0x${createHash("sha256").update(stableStringify(value)).digest("hex")}`;
}

export function randomHex(size = 16): string {
  return `0x${randomBytes(size).toString("hex")}`;
}

export function generateCredentialUrn(prefix = "credential"): string {
  return `urn:braid:${prefix}:${randomUUID()}`;
}

export function hashToField(value: Hashable): bigint {
  return BigInt(braidHash(value)) % SNARK_FIELD_PRIME;
}
