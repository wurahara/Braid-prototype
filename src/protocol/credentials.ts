import { braidHash, signObject, verifyObject } from "../crypto/index.ts";
import { ensure } from "../utils/assert.ts";
import { nowIso } from "../utils/time.ts";
import { credentialMatchesRequirement } from "./campaigns.ts";
import {
  activeAssociationForIdentifier,
  credentialSnapshot,
  issuerCredentialTree,
  requireActiveAssociation,
  requireActiveCredential,
  requireUsableIdentifier,
} from "./helpers.ts";
import {
  campaignNullifier,
  createProofDigest,
  credentialNullifier,
  findActiveAssociationByPresentationNullifier,
} from "./nullifiers.ts";
import { getOrCreateCampaignState, logEvent } from "./state.ts";
import type {
  BraidState,
  IssueCredentialInput,
  PresentCredentialsInput,
  PresentationVerification,
  VerifiablePresentation,
} from "./types.ts";
import {
  credentialHash,
  issueCredential,
  verifyCredentialSignature,
} from "../vc/credential.ts";
import {
  createPresentation,
  deriveCredentialForPresentation,
} from "../vc/presentation.ts";

export function issueCredentialToHolder(
  state: BraidState,
  options: IssueCredentialInput,
) {
  const issuer = requireUsableIdentifier(state, options.issuerDid);
  const holder = requireUsableIdentifier(state, options.holderDid);

  const credential = issueCredential({
    claims: options.claims,
    extraTypes: options.extraTypes,
    holderDid: options.holderDid,
    issuerDid: options.issuerDid,
    issuerPrivateKey: issuer.currentPrivateKey,
    validUntil: options.validUntil,
  });
  const digest = credentialHash(credential);
  const tree = issuerCredentialTree(state, options.issuerDid);
  const commitment = braidHash({
    credentialHash: digest,
    holderDid: options.holderDid,
    issuerDid: options.issuerDid,
    type: "credential-commitment",
    version: 1,
  });
  const inserted = tree.insert(commitment);

  const anchor = {
    id: credential.id,
    issuerDid: options.issuerDid,
    holderDid: options.holderDid,
    credential,
    credentialHash: digest,
    issuerPublicKey: issuer.currentPublicKey,
    issuerPublicJwk: issuer.currentPublicJwk,
    commitment,
    leafIndex: inserted.index,
    version: 1,
    nonce: 0,
    state: "active" as const,
    history: [
      {
        action: "issue",
        at: nowIso(),
        merkleRoot: inserted.root,
      },
    ],
  };

  state.credentials.set(anchor.id, anchor);
  logEvent(state, "CredentialIssued", {
    credentialId: anchor.id,
    holderDid: holder.did,
    issuerDid: issuer.did,
  });

  return credentialSnapshot(anchor);
}

export function revokeCredential(
  state: BraidState,
  options: { credentialId: string; reason?: string },
) {
  const anchor = requireActiveCredential(state, options.credentialId);
  const nullifier = braidHash({
    credentialId: options.credentialId,
    nonce: anchor.nonce,
    type: "credential-revocation-nullifier",
    version: anchor.version,
  });

  ensure(
    !state.nullifiers.credentialLifecycle.has(nullifier),
    "Credential lifecycle nullifier already used",
  );
  state.nullifiers.credentialLifecycle.add(nullifier);

  anchor.state = "revoked";
  anchor.history.push({
    action: "revoke",
    at: nowIso(),
    nullifier,
    reason: options.reason ?? "issuer-revocation",
  });

  logEvent(state, "CredentialRevoked", {
    credentialId: options.credentialId,
    reason: options.reason ?? "issuer-revocation",
  });

  return credentialSnapshot(anchor);
}

export function refreshCredential(
  state: BraidState,
  options: { credentialId: string },
) {
  const anchor = requireActiveCredential(state, options.credentialId);
  const nullifier = credentialNullifier(anchor);

  ensure(
    !state.nullifiers.credentialLifecycle.has(nullifier),
    "Credential refresh nullifier already used",
  );
  state.nullifiers.credentialLifecycle.add(nullifier);

  anchor.version += 1;
  anchor.nonce += 1;
  anchor.commitment = braidHash({
    credentialHash: anchor.credentialHash,
    credentialId: options.credentialId,
    nonce: anchor.nonce,
    type: "credential-commitment",
    version: anchor.version,
  });

  const inserted = issuerCredentialTree(state, anchor.issuerDid).insert(
    anchor.commitment,
  );
  anchor.leafIndex = inserted.index;
  anchor.history.push({
    action: "refresh",
    at: nowIso(),
    merkleRoot: inserted.root,
    nullifier,
  });

  logEvent(state, "CredentialRefreshed", {
    credentialId: options.credentialId,
    nonce: anchor.nonce,
    version: anchor.version,
  });

  return credentialSnapshot(anchor);
}

export function presentCredentials(
  state: BraidState,
  options: PresentCredentialsInput,
): VerifiablePresentation {
  const association = requireActiveAssociation(state, options.associationDid);
  ensure(
    options.credentialIds.length > 0,
    "At least one credential must be presented",
  );

  const campaign = getOrCreateCampaignState(
    state,
    options.campaignId,
    options.verifierDid,
  );
  const registeredCampaign = campaign.state === "active" ? campaign : null;

  if (registeredCampaign) {
    ensure(
      registeredCampaign.verifierDid === options.verifierDid,
      `Campaign ${options.campaignId} is bound to a different verifier`,
    );
    ensure(
      options.credentialIds.length >= registeredCampaign.minCredentials,
      `Campaign ${options.campaignId} requires at least ${registeredCampaign.minCredentials} credentials`,
    );
  }

  const scopedCampaignNullifier = campaignNullifier(
    association,
    options.campaignId,
  );
  ensure(
    !campaign.nullifiers.has(scopedCampaignNullifier),
    `Campaign ${options.campaignId} already contains this association`,
  );

  const globalAssociationNullifier = braidHash({
    associationDid: association.did,
    nonce: association.nonce,
    type: "association-presentation-nullifier",
    version: association.version,
  });
  const derivedCredentials = [];
  const credentialNullifiers = [];
  const disclosedCredentialIds = [];

  for (const credentialId of options.credentialIds) {
    const anchor = requireActiveCredential(state, credentialId);
    ensure(
      association.memberDids.includes(anchor.holderDid),
      "Credential holder is not part of the presenting association",
    );
    ensure(
      verifyCredentialSignature(anchor.credential, anchor.issuerPublicKey),
      `Issuer signature is invalid for credential ${credentialId}`,
    );

    const holder = requireUsableIdentifier(state, anchor.holderDid);
    const holderDidDigest = braidHash({ holderDid: holder.did });
    const holderBindingPayload = {
      campaignId: options.campaignId,
      credentialId,
      holderDidDigest,
      verifierDid: options.verifierDid,
    };
    const holderBindingSignature = signObject(
      holder.currentPrivateKey,
      holderBindingPayload,
    );
    const derived = deriveCredentialForPresentation({
      credential: anchor.credential,
      disclosedClaims: options.disclosedClaims?.[credentialId] ?? [],
      holderBindingPayload,
      holderBindingSignature,
      holderDidDigest,
    });

    derivedCredentials.push(derived);
    credentialNullifiers.push(credentialNullifier(anchor));
    disclosedCredentialIds.push(credentialId);
  }

  const proofDigest = createProofDigest({
    campaignId: options.campaignId,
    credentialIds: disclosedCredentialIds,
    globalAssociationNullifier,
    verifierDid: options.verifierDid,
  });

  return createPresentation({
    campaignId: options.campaignId,
    campaignPolicyHash: registeredCampaign?.policyHash ?? null,
    credentialNullifiers,
    derivedCredentials,
    disclosedCredentialIds,
    globalAssociationNullifier,
    proofDigest,
    verifierDid: options.verifierDid,
    campaignNullifier: scopedCampaignNullifier,
  });
}

export function verifyPresentation(
  state: BraidState,
  options: { presentation: VerifiablePresentation; verifierDid: string },
): PresentationVerification {
  const { presentation, verifierDid } = options;
  ensure(
    presentation.proof?.challenge,
    "Presentation is missing a campaign challenge",
  );
  ensure(
    presentation.proof.domain === verifierDid,
    "Presentation domain does not match the verifier DID",
  );

  const association = findActiveAssociationByPresentationNullifier(
    state,
    presentation.proof.globalAssociationNullifier,
  );
  ensure(
    association,
    "Presentation references an unknown or inactive association",
  );

  const campaignId = presentation.proof.challenge;
  const expectedCampaignNullifier = campaignNullifier(association, campaignId);
  const campaign = getOrCreateCampaignState(state, campaignId, verifierDid);
  const registeredCampaign = campaign.state === "active" ? campaign : null;

  if (registeredCampaign) {
    ensure(
      registeredCampaign.verifierDid === verifierDid,
      `Campaign ${campaignId} is registered for another verifier`,
    );
    ensure(
      presentation.proof.campaignPolicyHash === registeredCampaign.policyHash,
      `Campaign ${campaignId} policy hash does not match`,
    );
    ensure(
      presentation.verifiableCredential.length >=
        registeredCampaign.minCredentials,
      `Campaign ${campaignId} requires at least ${registeredCampaign.minCredentials} credentials`,
    );
  }

  ensure(
    expectedCampaignNullifier === presentation.proof.campaignNullifier,
    "Campaign nullifier does not match the active association",
  );
  ensure(
    !campaign.nullifiers.has(expectedCampaignNullifier),
    "This association has already participated in the campaign",
  );
  ensure(
    presentation.verifiableCredential.length ===
      presentation.proof.disclosedCredentialIds.length,
    "Presentation proof metadata does not match the number of credentials",
  );

  for (
    let index = 0;
    index < presentation.verifiableCredential.length;
    index += 1
  ) {
    const derived = presentation.verifiableCredential[index];
    const credentialId = derived.proof.referenceCredentialId;
    const anchor = requireActiveCredential(state, credentialId);

    ensure(
      credentialHash(anchor.credential) ===
        derived.proof.referenceCredentialHash,
      `Credential hash mismatch for ${credentialId}`,
    );
    ensure(
      verifyCredentialSignature(anchor.credential, anchor.issuerPublicKey),
      `Issuer signature mismatch for ${credentialId}`,
    );
    ensure(
      association.memberDids.includes(anchor.holderDid),
      `Credential holder is outside the presenting association for ${credentialId}`,
    );

    for (const claim of derived.proof.disclosedClaims ?? []) {
      ensure(
        anchor.credential.credentialSubject[claim] ===
          derived.credentialSubject[claim],
        `Disclosed claim ${claim} does not match the issued credential`,
      );
    }

    const holder = requireUsableIdentifier(state, anchor.holderDid);
    ensure(
      braidHash({ holderDid: holder.did }) === derived.proof.holderDidDigest,
      `Holder DID digest mismatch for ${credentialId}`,
    );
    ensure(
      verifyObject(
        holder.currentPublicKey,
        derived.proof.holderBindingPayload,
        derived.proof.holderBindingSignature,
      ),
      `Holder binding signature mismatch for ${credentialId}`,
    );

    const expectedCredentialNullifier = credentialNullifier(anchor);
    ensure(
      presentation.proof.credentialNullifiers[index] ===
        expectedCredentialNullifier,
      `Credential nullifier mismatch for ${credentialId}`,
    );
  }

  if (registeredCampaign && registeredCampaign.requirements.length > 0) {
    const usedCredentialIndices = new Set<number>();

    for (const requirement of registeredCampaign.requirements) {
      let satisfied = false;

      for (
        let index = 0;
        index < presentation.verifiableCredential.length;
        index += 1
      ) {
        if (usedCredentialIndices.has(index)) {
          continue;
        }

        const derived = presentation.verifiableCredential[index];
        if (
          credentialMatchesRequirement(state, {
            credentialId: derived.proof.referenceCredentialId,
            derived,
            requirement,
          })
        ) {
          usedCredentialIndices.add(index);
          satisfied = true;
          break;
        }
      }

      ensure(
        satisfied,
        `Presentation does not satisfy campaign requirement ${requirement.id ?? "unnamed"}`,
      );
    }
  }

  campaign.nullifiers.add(expectedCampaignNullifier);
  state.campaigns.set(campaignId, campaign);
  state.nullifiers.presentationCampaigns.add(expectedCampaignNullifier);

  logEvent(state, "PresentationVerified", {
    aid: association.did,
    campaignId,
    credentialIds: presentation.proof.disclosedCredentialIds,
    verifierDid,
  });

  return {
    accepted: true,
    associationDid: association.did,
    campaignId,
    credentialIds: [...presentation.proof.disclosedCredentialIds],
  };
}
