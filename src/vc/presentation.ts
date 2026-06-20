import { credentialHash, type VerifiableCredential } from "./credential.ts";
import { deepClone } from "../utils/clone.ts";
import { nowIso } from "../utils/time.ts";

const VC_CONTEXT = ["https://www.w3.org/ns/credentials/v2"] as const;

export interface DerivedCredential {
  "@context": readonly string[];
  type: string[];
  issuer: string;
  validFrom: string;
  validUntil?: string;
  credentialSubject: Record<string, unknown>;
  credentialStatus: {
    id: string;
    type: string;
  };
  proof: {
    type: string;
    cryptosuite: string;
    created: string;
    proofPurpose: string;
    verificationMethod: string;
    referenceCredentialHash: string;
    referenceCredentialId: string;
    disclosedClaims: string[];
    holderBindingPayload: Record<string, unknown>;
    holderBindingSignature: string;
    holderDidDigest: string;
    issuerProofValue: string;
  };
}

export interface VerifiablePresentation {
  "@context": readonly string[];
  type: string[];
  verifiableCredential: DerivedCredential[];
  proof: {
    type: string;
    created: string;
    proofPurpose: string;
    challenge: string;
    domain: string;
    campaignPolicyHash: string | null;
    campaignNullifier: string;
    globalAssociationNullifier: string;
    credentialNullifiers: string[];
    disclosedCredentialIds: string[];
    proofDigest: string;
  };
}

export function deriveCredentialForPresentation(options: {
  credential: VerifiableCredential;
  disclosedClaims?: string[];
  holderBindingPayload: Record<string, unknown>;
  holderBindingSignature: string;
  holderDidDigest: string;
}): DerivedCredential {
  const subject: Record<string, unknown> = {};

  for (const claim of options.disclosedClaims ?? []) {
    if (claim in options.credential.credentialSubject && claim !== "id") {
      subject[claim] = options.credential.credentialSubject[claim];
    }
  }

  return {
    "@context": options.credential["@context"],
    type: [...options.credential.type, "BraidDerivedCredential"],
    issuer: options.credential.issuer,
    validFrom: options.credential.validFrom,
    validUntil: options.credential.validUntil,
    credentialSubject: subject,
    credentialStatus: deepClone(options.credential.credentialStatus),
    proof: {
      type: "DataIntegrityProof",
      cryptosuite: "braid-derived-eddsa-2026",
      created: nowIso(),
      proofPurpose: "assertionMethod",
      verificationMethod: options.credential.proof.verificationMethod,
      referenceCredentialHash: credentialHash(options.credential),
      referenceCredentialId: options.credential.id,
      disclosedClaims: Object.keys(subject),
      holderBindingPayload: deepClone(options.holderBindingPayload),
      holderBindingSignature: options.holderBindingSignature,
      holderDidDigest: options.holderDidDigest,
      issuerProofValue: options.credential.proof.proofValue,
    },
  };
}

export function createPresentation(options: {
  campaignId: string;
  credentialNullifiers: string[];
  derivedCredentials: DerivedCredential[];
  disclosedCredentialIds: string[];
  campaignPolicyHash: string | null;
  proofDigest: string;
  globalAssociationNullifier: string;
  verifierDid: string;
  campaignNullifier: string;
}): VerifiablePresentation {
  return {
    "@context": VC_CONTEXT,
    type: ["VerifiablePresentation", "BraidVerifiablePresentation"],
    verifiableCredential: deepClone(options.derivedCredentials),
    proof: {
      type: "BraidNullifierPresentationProof2026",
      created: nowIso(),
      proofPurpose: "authentication",
      challenge: options.campaignId,
      domain: options.verifierDid,
      campaignPolicyHash: options.campaignPolicyHash,
      campaignNullifier: options.campaignNullifier,
      globalAssociationNullifier: options.globalAssociationNullifier,
      credentialNullifiers: deepClone(options.credentialNullifiers),
      disclosedCredentialIds: deepClone(options.disclosedCredentialIds),
      proofDigest: options.proofDigest,
    },
  };
}
