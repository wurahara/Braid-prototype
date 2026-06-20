import { stat } from "node:fs/promises";
import { join } from "node:path";

import { gnarkBuildDir, runGnarkBridge } from "./gnark.ts";

export const SUPPORTED_LEAF_COUNTS = [0, 1, 2, 3, 4] as const;

export interface OperationArtifactPaths {
  leafCount: number;
  buildDir: string;
  constraintSystemPath: string;
  provingKeyPath: string;
  verifyingKeyPath: string;
  verifierSolidityPath: string;
}

export interface OperationArtifactSet {
  byLeafCount: Record<number, OperationArtifactPaths>;
  verifierSolidityPaths: string[];
}

async function exists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

function leafBuildDir(leafCount: number): string {
  return join(gnarkBuildDir(), `leaf-${leafCount}`);
}

function artifactPathsForLeafCount(leafCount: number): OperationArtifactPaths {
  const buildDir = leafBuildDir(leafCount);
  return {
    leafCount,
    buildDir,
    constraintSystemPath: join(buildDir, "BraidOperation.scs"),
    provingKeyPath: join(buildDir, "BraidOperation.pk"),
    verifyingKeyPath: join(buildDir, "BraidOperation.vk"),
    verifierSolidityPath: join(buildDir, "PlonkVerifier.sol"),
  };
}

async function ensureLeafCountArtifacts(
  leafCount: number,
): Promise<OperationArtifactPaths> {
  const artifactPaths = artifactPathsForLeafCount(leafCount);

  if (
    (await exists(artifactPaths.constraintSystemPath)) &&
    (await exists(artifactPaths.provingKeyPath)) &&
    (await exists(artifactPaths.verifyingKeyPath)) &&
    (await exists(artifactPaths.verifierSolidityPath))
  ) {
    return artifactPaths;
  }

  await runGnarkBridge([
    "setup",
    "--leaf-count",
    String(leafCount),
    "--build-dir",
    artifactPaths.buildDir,
  ]);

  return artifactPaths;
}

export async function ensureOperationArtifacts(): Promise<OperationArtifactSet> {
  const byLeafCount: Record<number, OperationArtifactPaths> = {};

  for (const leafCount of SUPPORTED_LEAF_COUNTS) {
    byLeafCount[leafCount] = await ensureLeafCountArtifacts(leafCount);
  }

  return {
    byLeafCount,
    verifierSolidityPaths: SUPPORTED_LEAF_COUNTS.map(
      (leafCount) => byLeafCount[leafCount].verifierSolidityPath,
    ),
  };
}

export function artifactForLeafCount(
  artifacts: OperationArtifactSet,
  leafCount: number,
): OperationArtifactPaths {
  const artifact = artifacts.byLeafCount[leafCount];
  if (!artifact) {
    throw new Error(`Unsupported gnark artifact leaf count ${leafCount}`);
  }

  return artifact;
}
