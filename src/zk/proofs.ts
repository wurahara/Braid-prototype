import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { Hex } from "viem";

import {
  MAX_OPERATION_LEAVES,
  RELATION_VALUE_COUNT,
  type OperationProofWitness,
} from "./relations.ts";
import { runGnarkBridge } from "./gnark.ts";

export interface PlonkCallData {
  proof: Hex;
  publicSignals: bigint[];
}

export interface OperationProofResult {
  publicSignals: string[];
  proof: Hex;
  callData: PlonkCallData;
  timingMs?: {
    loadInput: number;
    marshal: number;
    prove: number;
    readKeys: number;
    totalInner: number;
    verify: number;
    witness: number;
  };
}

export function enabledLeafCount(witness: OperationProofWitness): number {
  return witness.leaves.filter((leaf) => leaf.enabled).length;
}

function parseProofOutput(raw: string): OperationProofResult {
  const jsonStart = raw.indexOf("{");
  if (jsonStart === -1) {
    throw new Error("gnark bridge did not return JSON output");
  }

  const parsed = JSON.parse(raw.slice(jsonStart)) as {
    proof?: string;
    publicInputs?: string[];
    timingMs?: OperationProofResult["timingMs"];
    verified?: boolean;
  };

  if (!parsed.verified) {
    throw new Error("gnark bridge did not confirm proof verification");
  }
  if (!parsed.proof?.startsWith("0x")) {
    throw new Error("Unexpected gnark proof output");
  }
  if (
    !parsed.publicInputs ||
    parsed.publicInputs.length < 4 ||
    parsed.publicInputs.length > 8
  ) {
    throw new Error("Unexpected gnark public input count");
  }

  const publicInputs = parsed.publicInputs;
  const publicSignals = publicInputs.map((value) => BigInt(value));

  return {
    proof: parsed.proof as Hex,
    publicSignals: publicInputs,
    callData: {
      proof: parsed.proof as Hex,
      publicSignals: publicSignals as PlonkCallData["publicSignals"],
    },
    timingMs: parsed.timingMs,
  };
}

function proofInputJson(witness: OperationProofWitness): string {
  if (witness.relationValues.length !== RELATION_VALUE_COUNT) {
    throw new Error(`Expected ${RELATION_VALUE_COUNT} relation values`);
  }
  if (witness.leaves.length !== MAX_OPERATION_LEAVES) {
    throw new Error(`Expected ${MAX_OPERATION_LEAVES} operation leaves`);
  }

  return JSON.stringify({
    operation: witness.operation.toString(),
    root: witness.root.toString(),
    outputCommitment: witness.outputCommitment.toString(),
    nullifier: witness.nullifier.toString(),
    relationDigest: witness.relationDigest.toString(),
    predicateMin: witness.predicateMin.toString(),
    predicateMax: witness.predicateMax.toString(),
    outputSubject: witness.outputSubject.toString(),
    outputSecret: witness.outputSecret.toString(),
    scope: witness.scope.toString(),
    predicateValue: witness.predicateValue.toString(),
    relationValues: witness.relationValues.map((value) => value.toString()),
    leafCommitments: witness.leaves.map((leaf) =>
      leaf.enabled ? leaf.commitment.toString() : "0",
    ),
    leaves: witness.leaves.map((leaf) => ({
      enabled: leaf.enabled,
      subject: leaf.subject.toString(),
      secret: leaf.secret.toString(),
      pathElements: leaf.pathElements.map((value) => value.toString()),
      pathIndices: leaf.pathIndices,
    })),
  });
}

export async function generateOperationProof(options: {
  buildDir: string;
  witness: OperationProofWitness;
}): Promise<OperationProofResult> {
  const tempDir = await mkdtemp(join(tmpdir(), "braid-gnark-"));
  const inputPath = join(tempDir, "operation-input.json");

  try {
    await writeFile(inputPath, proofInputJson(options.witness));

    const output = await runGnarkBridge([
      "prove",
      "--build-dir",
      options.buildDir,
      "--input",
      inputPath,
    ]);

    return parseProofOutput(output);
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}
