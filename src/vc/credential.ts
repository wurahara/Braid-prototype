import {
  braidHash,
  generateCredentialUrn,
  signObject,
  verifyObject,
} from "../crypto/index.ts";
import { deepClone } from "../utils/clone.ts";
import { nowIso } from "../utils/time.ts";

const VC_CONTEXT = [
  "https://www.w3.org/ns/credentials/v2",
  "https://w3id.org/security/data-integrity/v2",
] as const;

const VC_CRYPTOSUITE = "eddsa-jcs-2022";

export interface VerifiableCredential {
  "@context": readonly string[];
  id: string;
  type: string[];
  issuer: string;
  validFrom: string;
  issuanceDate: string;
  validUntil?: string;
  credentialSubject: Record<string, unknown> & { id: string };
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
    proofValue: string;
  };
}

function unsignedCredential(
  credential: VerifiableCredential,
): Omit<VerifiableCredential, "proof"> {
  const clone = deepClone(credential);
  delete (clone as Partial<VerifiableCredential>).proof;
  return clone;
}

export function credentialHash(credential: VerifiableCredential): string {
  return braidHash({
    proof: credential.proof
      ? {
          cryptosuite: credential.proof.cryptosuite,
          proofValue: credential.proof.proofValue,
          proofPurpose: credential.proof.proofPurpose,
          type: credential.proof.type,
          verificationMethod: credential.proof.verificationMethod,
        }
      : null,
    unsigned: unsignedCredential(credential),
  });
}

export function issueCredential(options: {
  claims: Record<string, unknown>;
  credentialId?: string;
  extraTypes?: string[];
  holderDid: string;
  issuerDid: string;
  issuerPrivateKey: CryptoKey | import("node:crypto").KeyObject;
  statusId?: string;
  validFrom?: string;
  validUntil?: string;
}): VerifiableCredential {
  const validFrom = options.validFrom ?? nowIso();
  const unsigned: Omit<VerifiableCredential, "proof"> = {
    "@context": VC_CONTEXT,
    id: options.credentialId ?? generateCredentialUrn(),
    type: ["VerifiableCredential", ...(options.extraTypes ?? [])],
    issuer: options.issuerDid,
    validFrom,
    issuanceDate: validFrom,
    credentialSubject: {
      id: options.holderDid,
      ...deepClone(options.claims),
    },
    credentialStatus: {
      id:
        options.statusId ??
        `urn:braid:status:${braidHash({ credentialId: options.credentialId ?? null }).slice(2, 34)}`,
      type: "BraidCredentialStatus2026",
    },
  };

  if (options.validUntil) {
    unsigned.validUntil = options.validUntil;
  }

  const proof = {
    type: "DataIntegrityProof",
    cryptosuite: VC_CRYPTOSUITE,
    created: nowIso(),
    proofPurpose: "assertionMethod",
    verificationMethod: `${options.issuerDid}#controller-1`,
    proofValue: signObject(
      options.issuerPrivateKey as import("node:crypto").KeyObject,
      unsigned,
    ),
  };

  return {
    ...unsigned,
    proof,
  };
}

export function verifyCredentialSignature(
  credential: VerifiableCredential,
  issuerPublicKey: import("node:crypto").KeyObject,
): boolean {
  if (!credential.proof?.proofValue) {
    return false;
  }

  return verifyObject(
    issuerPublicKey,
    unsignedCredential(credential),
    credential.proof.proofValue,
  );
}
