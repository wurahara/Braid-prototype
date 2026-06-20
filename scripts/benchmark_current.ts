import { writeFile } from "node:fs/promises";
import { performance } from "node:perf_hooks";

import type { Abi, Address } from "viem";

import { BraidPrototype, braidHash } from "../src/index.ts";
import { compileLocalBraidContracts } from "../src/chain/solidity.ts";
import {
  deployLocalBraidChain,
  readContract,
  type LocalBraidChain,
} from "../src/chain/localChain.ts";
import {
  requireAssociation,
  requireCredential,
  requireIdentifier,
} from "../src/protocol/helpers.ts";
import {
  artifactForLeafCount,
  ensureOperationArtifacts,
} from "../src/zk/artifacts.ts";
import { FieldMerkleTree } from "../src/zk/FieldMerkleTree.ts";
import { enabledLeafCount, generateOperationProof } from "../src/zk/proofs.ts";
import {
  OperationCode,
  RelationDomain,
  associationCommitment,
  associationLeaf,
  associationRelationValues,
  associationSubject,
  credentialCommitment,
  credentialLeaf,
  credentialSubject,
  deriveRelationSubject,
  fieldFromValue,
  identifierLeaf,
  identifierRelationValues,
  identifierSubject,
  identifierTag,
  operationScope,
  createOperationWitness,
  type OperationLeaf,
  type OperationProofWitness,
} from "../src/zk/relations.ts";

interface BenchmarkMetric {
  bridgeMs: number | null;
  claims: number | null;
  credentials: number | null;
  gasUsed: string | null;
  members: number | null;
  name: string;
  operationCode: string | null;
  protocolMs: number | null;
  proveMs: number | null;
  txMs: number | null;
  verifyMs: number | null;
}

interface TxMetric {
  gasUsed: bigint;
  txMs: number;
}

function elapsed<T>(fn: () => T): { ms: number; value: T } {
  const startedAt = performance.now();
  const value = fn();
  return {
    ms: performance.now() - startedAt,
    value,
  };
}

async function timedTx(
  chain: LocalBraidChain,
  contract: { abi: Abi; address: Address },
  functionName: string,
  args: readonly unknown[],
): Promise<TxMetric> {
  const startedAt = performance.now();
  const hash = await chain.walletClient.writeContract({
    abi: contract.abi,
    account: chain.account,
    address: contract.address,
    args,
    chain: chain.walletClient.chain,
    functionName,
  });
  const receipt = await chain.publicClient.waitForTransactionReceipt({ hash });

  return {
    gasUsed: receipt.gasUsed,
    txMs: performance.now() - startedAt,
  };
}

function rounded(value: number | null): number | null {
  return value === null ? null : Math.round(value * 100) / 100;
}

function median(values: number[]): number | null {
  if (values.length === 0) {
    return null;
  }

  const sorted = [...values].sort((left, right) => left - right);
  const middle = Math.floor(sorted.length / 2);
  if (sorted.length % 2 === 1) {
    return sorted[middle];
  }

  return (sorted[middle - 1] + sorted[middle]) / 2;
}

function summarize(metrics: BenchmarkMetric[]): BenchmarkMetric[] {
  const groups = new Map<string, BenchmarkMetric[]>();

  for (const metric of metrics) {
    const existing = groups.get(metric.name) ?? [];
    existing.push(metric);
    groups.set(metric.name, existing);
  }

  return [...groups.entries()].map(([name, entries]) => {
    const first = entries[0];
    return {
      bridgeMs: rounded(
        median(entries.flatMap((entry) => entry.bridgeMs ?? [])),
      ),
      claims: first.claims,
      credentials: first.credentials,
      gasUsed:
        median(
          entries.flatMap((entry) => Number(entry.gasUsed ?? "") || []),
        )?.toFixed(0) ?? null,
      members: first.members,
      name,
      operationCode: first.operationCode,
      protocolMs: rounded(
        median(entries.flatMap((entry) => entry.protocolMs ?? [])),
      ),
      proveMs: rounded(median(entries.flatMap((entry) => entry.proveMs ?? []))),
      txMs: rounded(median(entries.flatMap((entry) => entry.txMs ?? []))),
      verifyMs: rounded(
        median(entries.flatMap((entry) => entry.verifyMs ?? [])),
      ),
    };
  });
}

async function main(): Promise<void> {
  const setupStartedAt = performance.now();
  const artifacts = await ensureOperationArtifacts();
  const compiled = await compileLocalBraidContracts(
    artifacts.verifierSolidityPaths,
  );
  const chain = await deployLocalBraidChain(compiled);
  const setupMs = performance.now() - setupStartedAt;

  const braid = new BraidPrototype({ recoveryThreshold: 2 });
  const ledger = new FieldMerkleTree(32);
  const leafIndexes = new Map<string, number>();
  const metrics: BenchmarkMetric[] = [];

  function rememberLeaf(commitment: bigint): void {
    const inserted = ledger.insert(commitment);
    leafIndexes.set(commitment.toString(), inserted.index);
  }

  function proofFor(commitment: bigint) {
    const index = leafIndexes.get(commitment.toString());
    if (index === undefined) {
      throw new Error(`unknown local leaf ${commitment}`);
    }

    return ledger.generateProof(index);
  }

  async function expectOnchainRoot(): Promise<void> {
    const root = await readContract<bigint>(
      chain,
      chain.contracts.registry,
      "latestRoot",
    );
    if (root !== ledger.getRoot()) {
      throw new Error(`root mismatch: chain=${root} local=${ledger.getRoot()}`);
    }
  }

  async function prove(witness: OperationProofWitness) {
    const startedAt = performance.now();
    const artifact = artifactForLeafCount(artifacts, enabledLeafCount(witness));
    const proof = await generateOperationProof({
      buildDir: artifact.buildDir,
      witness,
    });

    return {
      bridgeMs: performance.now() - startedAt,
      proof,
    };
  }

  function record(options: {
    bridgeMs?: number;
    claims?: number | null;
    credentials?: number | null;
    gasUsed?: bigint | null;
    members?: number | null;
    name: string;
    operationCode?: bigint | null;
    protocolMs?: number | null;
    proveMs?: number | null;
    txMs?: number | null;
    verifyMs?: number | null;
  }): void {
    metrics.push({
      bridgeMs: rounded(options.bridgeMs ?? null),
      claims: options.claims ?? null,
      credentials: options.credentials ?? null,
      gasUsed: options.gasUsed?.toString() ?? null,
      members: options.members ?? null,
      name: options.name,
      operationCode: options.operationCode?.toString() ?? null,
      protocolMs: rounded(options.protocolMs ?? null),
      proveMs: rounded(options.proveMs ?? null),
      txMs: rounded(options.txMs ?? null),
      verifyMs: rounded(options.verifyMs ?? null),
    });
  }

  async function registerIdentifier(owner: string) {
    const protocol = elapsed(() => braid.registerIdentifier({ owner }));
    const recordState = requireIdentifier(braid.state, protocol.value.did);
    const relationValues = identifierRelationValues(recordState.did);
    const witness = createOperationWitness({
      operation: OperationCode.RegisterIdentifier,
      outputSubject: deriveRelationSubject(relationValues),
      outputSecret: recordState.controllerSecret,
      scope: operationScope(OperationCode.RegisterIdentifier, {
        did: recordState.did,
        version: recordState.version,
      }),
      relationValues,
    });
    const proof = await prove(witness);
    const tx = await timedTx(
      chain,
      chain.contracts.registry,
      "registerIdentifier",
      [
        recordState.didHash as `0x${string}`,
        braidHash(recordState.document) as `0x${string}`,
        recordState.controllerKeyFingerprint as `0x${string}`,
        proof.proof.callData.proof,
        proof.proof.callData.publicSignals,
      ],
    );

    rememberLeaf(witness.outputCommitment);
    await expectOnchainRoot();
    record({
      bridgeMs: proof.bridgeMs,
      gasUsed: tx.gasUsed,
      name: "identifier generation",
      operationCode: OperationCode.RegisterIdentifier,
      protocolMs: protocol.ms,
      proveMs: proof.proof.timingMs?.prove ?? null,
      txMs: tx.txMs,
      verifyMs: proof.proof.timingMs?.verify ?? null,
    });

    return protocol.value;
  }

  async function registerAssociation(dids: string[]) {
    const protocol = elapsed(() => braid.associateIdentifiers({ dids }));
    const association = requireAssociation(braid.state, protocol.value.did);
    const relationValues = associationRelationValues(
      association.memberDids,
      association.nonce,
    );
    const leaves = association.memberDids.map((did) => {
      const identifier = requireIdentifier(braid.state, did);
      return identifierLeaf(identifier, proofFor(identifierTag(identifier)));
    });
    const witness = createOperationWitness({
      operation: OperationCode.AssociateIdentifiers,
      root: ledger.getRoot(),
      outputSubject: deriveRelationSubject(relationValues),
      outputSecret: BigInt(association.nonce),
      scope: operationScope(OperationCode.AssociateIdentifiers, {
        aid: association.did,
      }),
      relationValues,
      leaves,
    });
    const proof = await prove(witness);
    const tx = await timedTx(
      chain,
      chain.contracts.registry,
      "registerAssociation",
      [
        association.didHash as `0x${string}`,
        proof.proof.callData.proof,
        proof.proof.callData.publicSignals,
      ],
    );

    rememberLeaf(witness.outputCommitment);
    await expectOnchainRoot();
    record({
      bridgeMs: proof.bridgeMs,
      gasUsed: tx.gasUsed,
      members: association.memberDids.length,
      name: "identifier association",
      operationCode: OperationCode.AssociateIdentifiers,
      protocolMs: protocol.ms,
      proveMs: proof.proof.timingMs?.prove ?? null,
      txMs: tx.txMs,
      verifyMs: proof.proof.timingMs?.verify ?? null,
    });

    return protocol.value;
  }

  async function supersedeAssociation(options: {
    extraOldAid?: string;
    functionName:
      | "appendAssociation"
      | "mergeAssociations"
      | "refreshAssociation";
    leaves: OperationLeaf[];
    name: string;
    newAid: string;
    oldAid: string;
    operation: bigint;
    protocolMs: number;
  }): Promise<void> {
    const next = requireAssociation(braid.state, options.newAid);
    const relationValues = associationRelationValues(
      next.memberDids,
      next.nonce,
    );
    const witness = createOperationWitness({
      operation: options.operation,
      root: ledger.getRoot(),
      outputSubject: deriveRelationSubject(relationValues),
      outputSecret: BigInt(next.nonce),
      scope: operationScope(options.operation, {
        extraOldAid: options.extraOldAid ?? null,
        newAid: next.did,
        oldAid: options.oldAid,
      }),
      relationValues,
      leaves: options.leaves,
    });
    const proof = await prove(witness);
    const args =
      options.functionName === "mergeAssociations"
        ? [
            requireAssociation(braid.state, options.oldAid)
              .didHash as `0x${string}`,
            requireAssociation(braid.state, options.extraOldAid ?? "")
              .didHash as `0x${string}`,
            next.didHash as `0x${string}`,
            proof.proof.callData.proof,
            proof.proof.callData.publicSignals,
          ]
        : [
            requireAssociation(braid.state, options.oldAid)
              .didHash as `0x${string}`,
            next.didHash as `0x${string}`,
            proof.proof.callData.proof,
            proof.proof.callData.publicSignals,
          ];
    const tx = await timedTx(
      chain,
      chain.contracts.registry,
      options.functionName,
      args,
    );

    rememberLeaf(witness.outputCommitment);
    await expectOnchainRoot();
    record({
      bridgeMs: proof.bridgeMs,
      gasUsed: tx.gasUsed,
      members: next.memberDids.length,
      name: options.name,
      operationCode: options.operation,
      protocolMs: options.protocolMs,
      proveMs: proof.proof.timingMs?.prove ?? null,
      txMs: tx.txMs,
      verifyMs: proof.proof.timingMs?.verify ?? null,
    });
  }

  try {
    const issuer = await registerIdentifier("issuer");
    const verifier = await registerIdentifier("verifier");
    const alice1 = await registerIdentifier("alice");
    const alice2 = await registerIdentifier("alice");
    const alice3 = await registerIdentifier("alice");
    const alice4 = await registerIdentifier("alice");
    const alice5 = await registerIdentifier("alice");

    const baseAssociation = await registerAssociation([alice1.did, alice2.did]);
    const appendProtocol = elapsed(() =>
      braid.appendIdentifier({
        associationDid: baseAssociation.did,
        newDid: alice3.did,
      }),
    );
    const baseRecord = requireAssociation(braid.state, baseAssociation.did);
    const alice3Record = requireIdentifier(braid.state, alice3.did);
    await supersedeAssociation({
      functionName: "appendAssociation",
      leaves: [
        associationLeaf(
          baseRecord,
          proofFor(
            associationCommitment(baseRecord.memberDids, baseRecord.nonce),
          ),
        ),
        identifierLeaf(alice3Record, proofFor(identifierTag(alice3Record))),
      ],
      name: "association appending",
      newAid: appendProtocol.value.did,
      oldAid: baseAssociation.did,
      operation: OperationCode.AppendAssociation,
      protocolMs: appendProtocol.ms,
    });

    const sideAssociation = await registerAssociation([alice4.did, alice5.did]);
    const mergeProtocol = elapsed(() =>
      braid.mergeAssociations({
        leftAssociationDid: appendProtocol.value.did,
        rightAssociationDid: sideAssociation.did,
      }),
    );
    const appendedRecord = requireAssociation(
      braid.state,
      appendProtocol.value.did,
    );
    const sideRecord = requireAssociation(braid.state, sideAssociation.did);
    await supersedeAssociation({
      extraOldAid: sideAssociation.did,
      functionName: "mergeAssociations",
      leaves: [
        associationLeaf(
          appendedRecord,
          proofFor(
            associationCommitment(
              appendedRecord.memberDids,
              appendedRecord.nonce,
            ),
          ),
        ),
        associationLeaf(
          sideRecord,
          proofFor(
            associationCommitment(sideRecord.memberDids, sideRecord.nonce),
          ),
        ),
      ],
      name: "association merging",
      newAid: mergeProtocol.value.did,
      oldAid: appendProtocol.value.did,
      operation: OperationCode.MergeAssociations,
      protocolMs: mergeProtocol.ms,
    });

    const refreshProtocol = elapsed(() =>
      braid.refreshAssociation({ associationDid: mergeProtocol.value.did }),
    );
    const mergedRecord = requireAssociation(
      braid.state,
      mergeProtocol.value.did,
    );
    await supersedeAssociation({
      functionName: "refreshAssociation",
      leaves: [
        associationLeaf(
          mergedRecord,
          proofFor(
            associationCommitment(mergedRecord.memberDids, mergedRecord.nonce),
          ),
        ),
      ],
      name: "association refreshing",
      newAid: refreshProtocol.value.did,
      oldAid: mergeProtocol.value.did,
      operation: OperationCode.RefreshAssociation,
      protocolMs: refreshProtocol.ms,
    });

    const issueProtocol = elapsed(() =>
      braid.issueCredential({
        claims: {
          project: "braid",
          score: 96,
        },
        extraTypes: ["DeveloperCredential"],
        holderDid: alice1.did,
        issuerDid: issuer.did,
      }),
    );
    const credentialRecord = requireCredential(
      braid.state,
      issueProtocol.value.id,
    );
    const credentialLeafCommitment = credentialCommitment(credentialRecord);
    const credentialTx = await timedTx(
      chain,
      chain.contracts.registry,
      "registerCredential",
      [
        issueProtocol.value.credentialHash as `0x${string}`,
        issuer.didHash as `0x${string}`,
        alice1.didHash as `0x${string}`,
        braidHash(
          issueProtocol.value.credential.credentialStatus,
        ) as `0x${string}`,
        credentialLeafCommitment,
      ],
    );
    rememberLeaf(credentialLeafCommitment);
    await expectOnchainRoot();
    record({
      credentials: 1,
      gasUsed: credentialTx.gasUsed,
      name: "credential issuance anchor",
      protocolMs: issueProtocol.ms,
      txMs: credentialTx.txMs,
    });

    const campaignId = "future-dao-round-1";
    braid.createCampaign({
      campaignId,
      requirements: [
        {
          claimPredicates: {
            score: {
              min: 90,
            },
          },
          credentialType: "DeveloperCredential",
          disclosedClaims: ["score"],
        },
      ],
      verifierDid: verifier.did,
    });
    const presentProtocol = elapsed(() =>
      braid.presentCredentials({
        associationDid: refreshProtocol.value.did,
        campaignId,
        credentialIds: [issueProtocol.value.id],
        disclosedClaims: {
          [issueProtocol.value.id]: ["score"],
        },
        verifierDid: verifier.did,
      }),
    );
    const verifyProtocol = elapsed(() =>
      braid.verifyPresentation({
        presentation: presentProtocol.value,
        verifierDid: verifier.did,
      }),
    );
    const refreshedRecord = requireAssociation(
      braid.state,
      refreshProtocol.value.did,
    );
    const alice1Record = requireIdentifier(braid.state, alice1.did);
    const predicateValue = BigInt(
      issueProtocol.value.credential.credentialSubject.score as number,
    );
    const presentationValues = [
      RelationDomain.Presentation,
      associationSubject(refreshedRecord.memberDids, refreshedRecord.nonce),
      credentialSubject(credentialRecord),
      identifierSubject(alice1.did),
      identifierSubject(issuer.did),
      identifierSubject(verifier.did),
      fieldFromValue({ campaignId }),
      predicateValue,
      90n,
    ];
    const presentationWitness = createOperationWitness({
      leaves: [
        associationLeaf(
          refreshedRecord,
          proofFor(
            associationCommitment(
              refreshedRecord.memberDids,
              refreshedRecord.nonce,
            ),
          ),
        ),
        credentialLeaf(credentialRecord, proofFor(credentialLeafCommitment)),
        identifierLeaf(alice1Record, proofFor(identifierTag(alice1Record))),
      ],
      operation: OperationCode.PresentCredential,
      outputSecret: fieldFromValue({
        presentation: presentProtocol.value.proof.proofDigest,
      }),
      outputSubject: deriveRelationSubject(presentationValues),
      predicateMin: 90n,
      predicateValue,
      relationValues: presentationValues,
      root: ledger.getRoot(),
      scope: operationScope(OperationCode.PresentCredential, {
        campaignId,
        verifierDid: verifier.did,
      }),
    });
    const presentationProof = await prove(presentationWitness);
    const campaignHash = braidHash({
      campaignId,
      verifierDid: verifier.did,
    }) as `0x${string}`;
    const presentationTx = await timedTx(
      chain,
      chain.contracts.registry,
      "presentCredential",
      [
        refreshProtocol.value.didHash as `0x${string}`,
        issueProtocol.value.credentialHash as `0x${string}`,
        campaignHash,
        presentationProof.proof.callData.proof,
        presentationProof.proof.callData.publicSignals,
      ],
    );
    record({
      bridgeMs: presentationProof.bridgeMs,
      claims: 1,
      credentials: 1,
      gasUsed: presentationTx.gasUsed,
      members: refreshedRecord.memberDids.length,
      name: "credential presentation",
      operationCode: OperationCode.PresentCredential,
      protocolMs: presentProtocol.ms + verifyProtocol.ms,
      proveMs: presentationProof.proof.timingMs?.prove ?? null,
      txMs: presentationTx.txMs,
      verifyMs: presentationProof.proof.timingMs?.verify ?? null,
    });

    const recoverProtocol = elapsed(() =>
      braid.recoverKey({
        did: alice1.did,
        witnessDids: [alice2.did, alice3.did],
      }),
    );
    const recoveredRecord = requireIdentifier(
      braid.state,
      recoverProtocol.value.did,
    );
    const alice2Record = requireIdentifier(braid.state, alice2.did);
    const recoveryValues = identifierRelationValues(recoverProtocol.value.did);
    const recoveryWitness = createOperationWitness({
      leaves: [
        associationLeaf(
          refreshedRecord,
          proofFor(
            associationCommitment(
              refreshedRecord.memberDids,
              refreshedRecord.nonce,
            ),
          ),
        ),
        identifierLeaf(alice2Record, proofFor(identifierTag(alice2Record))),
        identifierLeaf(alice3Record, proofFor(identifierTag(alice3Record))),
      ],
      operation: OperationCode.RecoverKey,
      outputSecret: recoveredRecord.controllerSecret,
      outputSubject: deriveRelationSubject(recoveryValues),
      relationValues: recoveryValues,
      root: ledger.getRoot(),
      scope: operationScope(OperationCode.RecoverKey, {
        aid: refreshProtocol.value.did,
        did: recoverProtocol.value.did,
        witnesses: [alice2.did, alice3.did],
      }),
    });
    const recoveryProof = await prove(recoveryWitness);
    const recoveryTx = await timedTx(
      chain,
      chain.contracts.registry,
      "recoverIdentifierKey",
      [
        recoverProtocol.value.didHash as `0x${string}`,
        refreshProtocol.value.didHash as `0x${string}`,
        braidHash(recoverProtocol.value.document) as `0x${string}`,
        recoverProtocol.value.controllerKeyFingerprint as `0x${string}`,
        recoveryProof.proof.callData.proof,
        recoveryProof.proof.callData.publicSignals,
      ],
    );
    rememberLeaf(recoveryWitness.outputCommitment);
    await expectOnchainRoot();
    record({
      bridgeMs: recoveryProof.bridgeMs,
      gasUsed: recoveryTx.gasUsed,
      members: refreshedRecord.memberDids.length,
      name: "key recovery",
      operationCode: OperationCode.RecoverKey,
      protocolMs: recoverProtocol.ms,
      proveMs: recoveryProof.proof.timingMs?.prove ?? null,
      txMs: recoveryTx.txMs,
      verifyMs: recoveryProof.proof.timingMs?.verify ?? null,
    });

    const output = {
      generatedAt: new Date().toISOString(),
      notes: [
        "setupMs includes artifact checks, Solidity compilation, and deployment;",
        "setupMs is reported but excluded from operation timing comparisons.",
        "proveMs and verifyMs are measured inside the Go gnark bridge.",
        "bridgeMs includes TypeScript JSON/file IO plus gnark bridge process overhead.",
      ],
      setupMs: rounded(setupMs),
      raw: metrics,
      summary: summarize(metrics),
    };

    await writeFile(
      ".cache/benchmark-current.json",
      `${JSON.stringify(output, null, 2)}\n`,
    );
    console.log(JSON.stringify(output, null, 2));
  } finally {
    await chain.close();
  }
}

await main();
