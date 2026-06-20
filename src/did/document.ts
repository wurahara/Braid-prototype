import { deepClone } from "../utils/clone.ts";
import { DID_CONTEXT } from "./constants.ts";
import { assertDidFormat } from "./method.ts";

export interface DidService {
  id?: string;
  type?: string;
  serviceEndpoint?: string;
}

export interface DidDocument {
  "@context": readonly string[];
  id: string;
  alsoKnownAs: string[];
  verificationMethod: Array<{
    id: string;
    type: string;
    controller: string;
    publicKeyJwk: JsonWebKey;
  }>;
  authentication: string[];
  assertionMethod: string[];
  capabilityInvocation: string[];
  capabilityDelegation: string[];
  keyAgreement: string[];
  service: Array<{
    id: string;
    type: string;
    serviceEndpoint: string;
  }>;
}

function normalizeServices(
  did: string,
  services: DidService[] = [],
): DidDocument["service"] {
  return services.map((service, index) => ({
    id: service.id ?? `${did}#service-${index + 1}`,
    type: service.type ?? "BraidService",
    serviceEndpoint:
      service.serviceEndpoint ??
      `braid://registry/${encodeURIComponent(did)}/${index + 1}`,
  }));
}

export function createDidDocument(options: {
  alsoKnownAs?: string[];
  did: string;
  publicJwk: JsonWebKey;
  services?: DidService[];
}): DidDocument {
  const did = assertDidFormat(options.did);

  return {
    "@context": DID_CONTEXT,
    id: did,
    alsoKnownAs: [...new Set(options.alsoKnownAs ?? [])],
    verificationMethod: [
      {
        id: `${did}#controller-1`,
        type: "JsonWebKey2020",
        controller: did,
        publicKeyJwk: deepClone(options.publicJwk),
      },
    ],
    authentication: [`${did}#controller-1`],
    assertionMethod: [`${did}#controller-1`],
    capabilityInvocation: [`${did}#controller-1`],
    capabilityDelegation: [`${did}#controller-1`],
    keyAgreement: [],
    service: [
      {
        id: `${did}#vdr`,
        type: "BraidRegistryService",
        serviceEndpoint: `braid://registry/${encodeURIComponent(did)}`,
      },
      ...normalizeServices(did, options.services),
    ],
  };
}

export function updateDidDocument(
  document: DidDocument,
  patch: {
    alsoKnownAs?: string[];
    services?: DidService[];
  },
): DidDocument {
  const next = deepClone(document);

  if (patch.alsoKnownAs) {
    next.alsoKnownAs = [...new Set(patch.alsoKnownAs)];
  }

  if (patch.services) {
    next.service = [
      {
        id: `${document.id}#vdr`,
        type: "BraidRegistryService",
        serviceEndpoint: `braid://registry/${encodeURIComponent(document.id)}`,
      },
      ...normalizeServices(document.id, patch.services),
    ];
  }

  return next;
}
