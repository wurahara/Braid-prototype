import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { poseidonContract } from "circomlibjs";
import solc from "solc";
import type { Abi } from "viem";

export interface CompiledContractArtifact {
  abi: Abi;
  bytecode: `0x${string}`;
}

const STATIC_CONTRACT_PATHS = [
  "contracts/IPlonkVerifier.sol",
  "contracts/IPoseidon2.sol",
  "contracts/FieldIncrementalMerkleTree.sol",
  "contracts/BraidRegistry.sol",
] as const;

function rootDir(): string {
  return fileURLToPath(new URL("../../", import.meta.url));
}

export async function compileLocalBraidContracts(
  generatedVerifierPaths: readonly string[],
): Promise<Record<string, CompiledContractArtifact>> {
  const cwd = rootDir();
  const sources: Record<string, { content: string }> = {};

  for (const contractPath of STATIC_CONTRACT_PATHS) {
    sources[contractPath] = {
      content: await readFile(join(cwd, contractPath), "utf8"),
    };
  }

  for (const [
    index,
    generatedVerifierPath,
  ] of generatedVerifierPaths.entries()) {
    const verifierFileName = `contracts/generated/PlonkVerifierLeaf${index}.sol`;
    sources[verifierFileName] = {
      content: await readFile(generatedVerifierPath, "utf8"),
    };
  }

  const input = {
    language: "Solidity",
    sources,
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
      viaIR: true,
      outputSelection: {
        "*": {
          "*": ["abi", "evm.bytecode.object"],
        },
      },
    },
  };

  const output = JSON.parse(solc.compile(JSON.stringify(input)));
  const errors = (output.errors ?? []).filter(
    (entry: { severity: string }) => entry.severity === "error",
  );

  if (errors.length > 0) {
    throw new Error(
      errors
        .map((entry: { formattedMessage: string }) => entry.formattedMessage)
        .join("\n"),
    );
  }

  const artifacts: Record<string, CompiledContractArtifact> = {};

  for (const [sourceName, contracts] of Object.entries(
    output.contracts as Record<
      string,
      Record<string, { abi: Abi; evm: { bytecode: { object: string } } }>
    >,
  )) {
    for (const [contractName, contract] of Object.entries(contracts)) {
      if (!contract.evm.bytecode.object) {
        continue;
      }

      artifacts[`${sourceName}:${contractName}`] = {
        abi: contract.abi,
        bytecode: `0x${contract.evm.bytecode.object}`,
      };
    }
  }

  return artifacts;
}

export function createPoseidon2Artifact(): CompiledContractArtifact {
  return {
    abi: poseidonContract.generateABI(2) as Abi,
    bytecode: poseidonContract.createCode(2) as `0x${string}`,
  };
}
