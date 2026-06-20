# Braid Prototype

This artifact contains the prototype implementation for Braid, a decentralized identity system with Sybil-resistant identifier association, trustless key recovery, and non-transferable anonymous credential presentation.

The artifact is intended to support ACM CCS artifact evaluation. It provides:

- TypeScript protocol logic for DID, association, credential, presentation,
  key rotation, and key recovery workflows.
- Solidity contracts for the unified on-chain registry, incremental Merkle
  tree state, nullifier tracking, and PLONK verifier integration.
- gnark circuits and a local bridge for PLONK proof setup, proof generation,
  Solidity verifier export, and proof verification.
- Local blockchain tests that exercise the full off-chain/on-chain workflow.
- A benchmark script that records operation timing and gas usage.

## Directory Layout

- `src/`: TypeScript protocol implementation, DID/VC handling, cryptographic helpers, local-chain driver, and zero-knowledge bridge.
- `contracts/`: Solidity registry, Merkle tree, Poseidon interface, and PLONK verifier interface.
- `go/gnarkbridge/`: gnark circuit, artifact setup, proof generation, and Solidity verifier export.
- `test/protocol/`: protocol-level unit tests.
- `test/e2e/`: local blockchain end-to-end test.
- `examples/`: protocol-only demonstration script.
- `scripts/benchmark_current.ts`: benchmark runner for timing and gas metrics.

Generated files are written under `build/zk/` and `.cache/`. They are not required in the source archive because they are regenerated automatically.

## Requirements

The artifact has been tested with:

- Node.js 20 or newer
- npm 10 or newer
- Go 1.22 or newer

The first run may download npm packages and Go modules. A typical laptop should be sufficient; the end-to-end and benchmark commands generate several PLONK proofs and may take a few minutes.

## Installation

From the artifact root:

```bash
npm ci
```

This installs the JavaScript dependencies pinned by `package-lock.json`.

## Quick Functional Check

Run the basic checks:

```bash
npm run check
```

Expected result: TypeScript type checking, formatting checks, Go compilation, and protocol tests complete successfully.

## Full Artifact Evaluation Run

Run the full local blockchain workflow:

```bash
npm run test:artifact
```

This command performs the basic checks and then runs the local end-to-end test. The end-to-end test:

1. Builds or reuses gnark PLONK artifacts.
2. Exports Solidity verifier contracts.
3. Compiles the Solidity registry and verifier contracts.
4. Starts an in-process Ganache blockchain.
5. Deploys the Poseidon hash contract, PLONK verifiers, and Braid registry.
6. Registers identifiers and associations on-chain.
7. Issues and anchors a verifiable credential.
8. Generates PLONK proofs off-chain for association updates, credential presentation, and key recovery.
9. Submits the proofs on-chain and checks nullifier-based replay protection.

Expected result: the test named `local registry verifies PLONK relations across the Braid lifecycle` passes.

Ganache may print a message that it is falling back from `uWS` to a Node.js implementation. This does not indicate a test failure.

## Benchmark Reproduction

Run:

```bash
npm run benchmark
```

The benchmark writes JSON results to:

```text
.cache/benchmark-current.json
```

The output includes:

- `setupMs`: artifact checks, Solidity compilation, and deployment time. This is reported but excluded from per-operation comparisons.
- `proveMs`: PLONK proving time measured inside the Go bridge.
- `verifyMs`: local PLONK verification time measured inside the Go bridge.
- `bridgeMs`: TypeScript-to-Go bridge time, including JSON/file I/O and process overhead.
- `gasUsed`: gas used by the corresponding local-chain transaction.

Recent local reference values are:

| Operation                  | Proof time |       Gas |
| -------------------------- | ---------: | --------: |
| Identifier generation      |      0.61s | 1,582,398 |
| Identifier association     |      1.21s | 1,535,461 |
| Association appending      |      1.19s | 1,545,866 |
| Association merging        |      1.19s | 1,543,735 |
| Association refreshing     |      1.17s | 1,534,476 |
| Credential issuance anchor |        n/a | 1,240,956 |
| Credential presentation    |      1.24s |   336,839 |
| Key recovery               |      1.22s | 1,530,588 |

Exact timings vary by machine. Gas values should be stable for the same compiler and dependency versions.

## Demo

Run the protocol-only demonstration:

```bash
npm run demo
```

This prints a JSON object showing identifiers, associations, issued credentials, a credential presentation, verification result, key rotation, and key recovery. This demo does not deploy contracts; use `npm run test:e2e` or `npm run test:artifact` for the full blockchain path.

## Regenerating ZK Artifacts

The PLONK artifacts are generated automatically when needed. To force a clean regeneration, remove the generated directories and rerun the end-to-end test:

```bash
rm -rf build/zk .cache/go-build .cache/go-mod .cache/bin
npm run test:e2e
```
