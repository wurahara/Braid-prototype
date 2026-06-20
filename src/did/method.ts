import { braidHash } from "../crypto/index.ts";
import { ensure } from "../utils/assert.ts";

const DID_PATTERN = /^did:braid:[a-z0-9-]+:(id|aid):[A-Za-z0-9._:-]+$/;

export function assertDidFormat(did: string): string {
  ensure(DID_PATTERN.test(did), `Invalid Braid DID: ${did}`);
  return did;
}

export function createIdentifierDid(options: {
  network?: string;
  fingerprint: string;
}): string {
  const network = options.network ?? "local";
  const suffix = braidHash({
    network,
    fingerprint: options.fingerprint,
    namespace: "identifier",
  }).slice(2, 34);

  return assertDidFormat(`did:braid:${network}:id:${suffix}`);
}

export function createAssociationDid(options: {
  network?: string;
  memberDids: string[];
  nonce: number;
}): string {
  const network = options.network ?? "local";
  const suffix = braidHash({
    memberDids: [...options.memberDids].sort(),
    network,
    nonce: options.nonce,
    namespace: "association",
  }).slice(2, 34);

  return assertDidFormat(`did:braid:${network}:aid:${suffix}`);
}

export function hashDid(did: string): string {
  return braidHash({ did: assertDidFormat(did) });
}
