import assert from "node:assert/strict";
import test from "node:test";

import { BraidPrototype, braidHash } from "../../src/index.ts";
import {
  deployLocalBraidChain,
  readContract,
  writeContractAndWait,
} from "../../src/chain/localChain.ts";
import { compileLocalBraidContracts } from "../../src/chain/solidity.ts";
import {
  requireAssociation,
  requireCredential,
  requireIdentifier,
} from "../../src/protocol/helpers.ts";
import {
  artifactForLeafCount,
  ensureOperationArtifacts,
} from "../../src/zk/artifacts.ts";
import { FieldMerkleTree } from "../../src/zk/FieldMerkleTree.ts";
import {
  enabledLeafCount,
  generateOperationProof,
} from "../../src/zk/proofs.ts";
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
} from "../../src/zk/relations.ts";

test("local registry verifies PLONK relations across the Braid lifecycle", async () => {
  const braid = new BraidPrototype({ recoveryThreshold: 2 });
  const issuer = braid.registerIdentifier({ owner: "issuer" });
  const verifier = braid.registerIdentifier({ owner: "verifier" });
  const alice1 = braid.registerIdentifier({ owner: "alice" });
  const alice2 = braid.registerIdentifier({ owner: "alice" });
  const alice3 = braid.registerIdentifier({ owner: "alice" });
  const alice4 = braid.registerIdentifier({ owner: "alice" });
  const alice5 = braid.registerIdentifier({ owner: "alice" });

  const artifacts = await ensureOperationArtifacts();
  const compiled = await compileLocalBraidContracts(
    artifacts.verifierSolidityPaths,
  );
  const chain = await deployLocalBraidChain(compiled);
  const ledger = new FieldMerkleTree(32);
  const leafIndexes = new Map<string, number>();

  function rememberLeaf(commitment: bigint): void {
    const inserted = ledger.insert(commitment);
    leafIndexes.set(commitment.toString(), inserted.index);
  }

  function proofFor(commitment: bigint) {
    const index = leafIndexes.get(commitment.toString());
    assert.notEqual(index, undefined, `unknown local leaf ${commitment}`);
    return ledger.generateProof(index as number);
  }

  async function expectOnchainRoot(): Promise<void> {
    const root = await readContract<bigint>(
      chain,
      chain.contracts.registry,
      "latestRoot",
    );
    assert.equal(root, ledger.getRoot());
  }

  async function submitProof(
    witness: ReturnType<typeof createOperationWitness>,
  ) {
    const artifact = artifactForLeafCount(artifacts, enabledLeafCount(witness));
    return generateOperationProof({
      buildDir: artifact.buildDir,
      witness,
    });
  }

  async function registerIdentifierOnChain(did: string): Promise<void> {
    const record = requireIdentifier(braid.state, did);
    const relationValues = identifierRelationValues(record.did);
    const witness = createOperationWitness({
      operation: OperationCode.RegisterIdentifier,
      outputSubject: deriveRelationSubject(relationValues),
      outputSecret: record.controllerSecret,
      scope: operationScope(OperationCode.RegisterIdentifier, {
        did: record.did,
        version: record.version,
      }),
      relationValues,
    });
    const zk = await submitProof(witness);

    await writeContractAndWait(
      chain,
      chain.contracts.registry,
      "registerIdentifier",
      [
        record.didHash as `0x${string}`,
        braidHash(record.document) as `0x${string}`,
        record.controllerKeyFingerprint as `0x${string}`,
        zk.callData.proof,
        zk.callData.publicSignals,
      ],
    );

    assert.equal(witness.outputCommitment, identifierTag(record));
    rememberLeaf(witness.outputCommitment);
    await expectOnchainRoot();
  }

  async function registerAssociationOnChain(aid: string): Promise<void> {
    const association = requireAssociation(braid.state, aid);
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
    const zk = await submitProof(witness);

    await writeContractAndWait(
      chain,
      chain.contracts.registry,
      "registerAssociation",
      [
        association.didHash as `0x${string}`,
        zk.callData.proof,
        zk.callData.publicSignals,
      ],
    );

    assert.equal(
      witness.outputCommitment,
      associationCommitment(association.memberDids, association.nonce),
    );
    rememberLeaf(witness.outputCommitment);
    await expectOnchainRoot();
  }

  async function supersedeAssociationOnChain(options: {
    functionName:
      | "appendAssociation"
      | "mergeAssociations"
      | "refreshAssociation";
    oldAid: string;
    newAid: string;
    extraOldAid?: string;
    leaves: OperationLeaf[];
    operation: bigint;
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
        newAid: next.did,
        oldAid: options.oldAid,
        extraOldAid: options.extraOldAid ?? null,
      }),
      relationValues,
      leaves: options.leaves,
    });
    const zk = await submitProof(witness);
    const args =
      options.functionName === "mergeAssociations"
        ? [
            requireAssociation(braid.state, options.oldAid)
              .didHash as `0x${string}`,
            requireAssociation(braid.state, options.extraOldAid ?? "")
              .didHash as `0x${string}`,
            next.didHash as `0x${string}`,
            zk.callData.proof,
            zk.callData.publicSignals,
          ]
        : [
            requireAssociation(braid.state, options.oldAid)
              .didHash as `0x${string}`,
            next.didHash as `0x${string}`,
            zk.callData.proof,
            zk.callData.publicSignals,
          ];

    await writeContractAndWait(
      chain,
      chain.contracts.registry,
      options.functionName,
      args,
    );

    rememberLeaf(witness.outputCommitment);
    await expectOnchainRoot();
  }

  try {
    for (const did of [
      issuer.did,
      verifier.did,
      alice1.did,
      alice2.did,
      alice3.did,
      alice4.did,
      alice5.did,
    ]) {
      await registerIdentifierOnChain(did);
    }

    const baseAssociation = braid.associateIdentifiers({
      dids: [alice1.did, alice2.did],
    });
    await registerAssociationOnChain(baseAssociation.did);

    const appended = braid.appendIdentifier({
      associationDid: baseAssociation.did,
      newDid: alice3.did,
    });
    const baseRecord = requireAssociation(braid.state, baseAssociation.did);
    const alice3Record = requireIdentifier(braid.state, alice3.did);
    await supersedeAssociationOnChain({
      functionName: "appendAssociation",
      oldAid: baseAssociation.did,
      newAid: appended.did,
      operation: OperationCode.AppendAssociation,
      leaves: [
        associationLeaf(
          baseRecord,
          proofFor(
            associationCommitment(baseRecord.memberDids, baseRecord.nonce),
          ),
        ),
        identifierLeaf(alice3Record, proofFor(identifierTag(alice3Record))),
      ],
    });

    const sideAssociation = braid.associateIdentifiers({
      dids: [alice4.did, alice5.did],
    });
    await registerAssociationOnChain(sideAssociation.did);

    const merged = braid.mergeAssociations({
      leftAssociationDid: appended.did,
      rightAssociationDid: sideAssociation.did,
    });
    const appendedRecord = requireAssociation(braid.state, appended.did);
    const sideRecord = requireAssociation(braid.state, sideAssociation.did);
    await supersedeAssociationOnChain({
      functionName: "mergeAssociations",
      oldAid: appended.did,
      extraOldAid: sideAssociation.did,
      newAid: merged.did,
      operation: OperationCode.MergeAssociations,
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
    });

    const refreshed = braid.refreshAssociation({ associationDid: merged.did });
    const mergedRecord = requireAssociation(braid.state, merged.did);
    await supersedeAssociationOnChain({
      functionName: "refreshAssociation",
      oldAid: merged.did,
      newAid: refreshed.did,
      operation: OperationCode.RefreshAssociation,
      leaves: [
        associationLeaf(
          mergedRecord,
          proofFor(
            associationCommitment(mergedRecord.memberDids, mergedRecord.nonce),
          ),
        ),
      ],
    });

    const credential = braid.issueCredential({
      issuerDid: issuer.did,
      holderDid: alice1.did,
      extraTypes: ["DeveloperCredential"],
      claims: {
        project: "braid",
        score: 96,
      },
    });
    const credentialRecord = requireCredential(braid.state, credential.id);
    const credentialLeafCommitment = credentialCommitment(credentialRecord);

    await writeContractAndWait(
      chain,
      chain.contracts.registry,
      "registerCredential",
      [
        credential.credentialHash as `0x${string}`,
        issuer.didHash as `0x${string}`,
        alice1.didHash as `0x${string}`,
        braidHash(credential.credential.credentialStatus) as `0x${string}`,
        credentialLeafCommitment,
      ],
    );
    rememberLeaf(credentialLeafCommitment);
    await expectOnchainRoot();

    const campaignId = "future-dao-round-1";
    braid.createCampaign({
      campaignId,
      verifierDid: verifier.did,
      requirements: [
        {
          credentialType: "DeveloperCredential",
          disclosedClaims: ["score"],
          claimPredicates: {
            score: {
              min: 90,
            },
          },
        },
      ],
    });
    const presentation = braid.presentCredentials({
      associationDid: refreshed.did,
      campaignId,
      credentialIds: [credential.id],
      disclosedClaims: {
        [credential.id]: ["score"],
      },
      verifierDid: verifier.did,
    });
    assert.equal(presentation.verifiableCredential.length, 1);
    assert.equal(
      braid.verifyPresentation({ presentation, verifierDid: verifier.did })
        .accepted,
      true,
    );

    const refreshedRecord = requireAssociation(braid.state, refreshed.did);
    const alice1Record = requireIdentifier(braid.state, alice1.did);
    const predicateValue = BigInt(
      credential.credential.credentialSubject.score as number,
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
      operation: OperationCode.PresentCredential,
      root: ledger.getRoot(),
      outputSubject: deriveRelationSubject(presentationValues),
      outputSecret: fieldFromValue({
        presentation: presentation.proof.proofDigest,
      }),
      scope: operationScope(OperationCode.PresentCredential, {
        campaignId,
        verifierDid: verifier.did,
      }),
      relationValues: presentationValues,
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
      predicateValue,
      predicateMin: 90n,
    });
    const presentationZk = await submitProof(presentationWitness);
    const campaignHash = braidHash({
      campaignId,
      verifierDid: verifier.did,
    }) as `0x${string}`;

    await writeContractAndWait(
      chain,
      chain.contracts.registry,
      "presentCredential",
      [
        refreshed.didHash as `0x${string}`,
        credential.credentialHash as `0x${string}`,
        campaignHash,
        presentationZk.callData.proof,
        presentationZk.callData.publicSignals,
      ],
    );

    const used = await readContract<boolean>(
      chain,
      chain.contracts.registry,
      "nullifiers",
      [presentationWitness.nullifier],
    );
    assert.equal(used, true);

    await assert.rejects(async () => {
      await writeContractAndWait(
        chain,
        chain.contracts.registry,
        "presentCredential",
        [
          refreshed.didHash as `0x${string}`,
          credential.credentialHash as `0x${string}`,
          campaignHash,
          presentationZk.callData.proof,
          presentationZk.callData.publicSignals,
        ],
      );
    });

    const recovered = braid.recoverKey({
      did: alice1.did,
      witnessDids: [alice2.did, alice3.did],
    });
    const recoveredRecord = requireIdentifier(braid.state, recovered.did);
    const alice2Record = requireIdentifier(braid.state, alice2.did);
    const recoveryValues = identifierRelationValues(recovered.did);
    const recoveryWitness = createOperationWitness({
      operation: OperationCode.RecoverKey,
      root: ledger.getRoot(),
      outputSubject: deriveRelationSubject(recoveryValues),
      outputSecret: recoveredRecord.controllerSecret,
      scope: operationScope(OperationCode.RecoverKey, {
        aid: refreshed.did,
        did: recovered.did,
        witnesses: [alice2.did, alice3.did],
      }),
      relationValues: recoveryValues,
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
    });
    const recoveryZk = await submitProof(recoveryWitness);

    await writeContractAndWait(
      chain,
      chain.contracts.registry,
      "recoverIdentifierKey",
      [
        recovered.didHash as `0x${string}`,
        refreshed.didHash as `0x${string}`,
        braidHash(recovered.document) as `0x${string}`,
        recovered.controllerKeyFingerprint as `0x${string}`,
        recoveryZk.callData.proof,
        recoveryZk.callData.publicSignals,
      ],
    );

    rememberLeaf(recoveryWitness.outputCommitment);
    await expectOnchainRoot();
  } finally {
    await chain.close();
  }
});
