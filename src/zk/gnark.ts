import { execFile } from "node:child_process";
import { mkdir, readdir, stat } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
let bridgeBinaryPromise: Promise<string> | null = null;

export function rootDir(): string {
  return fileURLToPath(new URL("../../", import.meta.url));
}

function gnarkBridgeDir(): string {
  return join(rootDir(), "go/gnarkbridge");
}

function goCacheDir(): string {
  return join(rootDir(), ".cache/go-build");
}

function goModCacheDir(): string {
  return join(rootDir(), ".cache/go-mod");
}

function gnarkBridgeBinaryPath(): string {
  const extension = process.platform === "win32" ? ".exe" : "";
  return join(rootDir(), ".cache/bin", `gnarkbridge${extension}`);
}

export function gnarkBuildDir(): string {
  return join(rootDir(), "build/zk/gnark-plonk-bn254-compact-public");
}

async function gnarkBridgeSourcePaths(): Promise<string[]> {
  const baseDir = gnarkBridgeDir();
  const entries = await readdir(baseDir, { withFileTypes: true });

  return entries
    .filter(
      (entry) =>
        entry.isFile() &&
        (entry.name.endsWith(".go") ||
          entry.name === "go.mod" ||
          entry.name === "go.sum"),
    )
    .map((entry) => join(baseDir, entry.name));
}

async function needsBridgeRebuild(binaryPath: string): Promise<boolean> {
  let binaryMtimeMs: number;

  try {
    binaryMtimeMs = (await stat(binaryPath)).mtimeMs;
  } catch {
    return true;
  }

  const sourcePaths = await gnarkBridgeSourcePaths();
  for (const sourcePath of sourcePaths) {
    if ((await stat(sourcePath)).mtimeMs > binaryMtimeMs) {
      return true;
    }
  }

  return false;
}

async function ensureGnarkBridgeBinary(): Promise<string> {
  if (!bridgeBinaryPromise) {
    bridgeBinaryPromise = (async () => {
      const binaryPath = gnarkBridgeBinaryPath();
      await mkdir(goCacheDir(), { recursive: true });
      await mkdir(goModCacheDir(), { recursive: true });
      await mkdir(dirname(binaryPath), { recursive: true });

      if (await needsBridgeRebuild(binaryPath)) {
        try {
          await execFileAsync("go", ["build", "-o", binaryPath, "."], {
            cwd: gnarkBridgeDir(),
            env: {
              ...process.env,
              GOCACHE: goCacheDir(),
              GOMODCACHE: goModCacheDir(),
            },
          });
        } catch (error) {
          const stderr =
            error instanceof Error && "stderr" in error
              ? String(error.stderr)
              : String(error);
          throw new Error(`Failed to build gnark bridge.\n${stderr}`);
        }
      }

      return binaryPath;
    })().catch((error) => {
      bridgeBinaryPromise = null;
      throw error;
    });
  }

  return bridgeBinaryPromise;
}

export async function runGnarkBridge(args: string[]): Promise<string> {
  const binaryPath = await ensureGnarkBridgeBinary();

  await mkdir(goCacheDir(), { recursive: true });
  await mkdir(goModCacheDir(), { recursive: true });

  try {
    const { stdout } = await execFileAsync(binaryPath, args, {
      cwd: gnarkBridgeDir(),
      env: {
        ...process.env,
        GOCACHE: goCacheDir(),
        GOMODCACHE: goModCacheDir(),
      },
    });

    return stdout;
  } catch (error) {
    const stderr =
      error instanceof Error && "stderr" in error
        ? String(error.stderr)
        : String(error);
    throw new Error(`Failed to run gnark bridge.\n${stderr}`);
  }
}
