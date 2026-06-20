import { Buffer } from "node:buffer";
import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as nodeSign,
  type KeyObject,
  verify as nodeVerify,
} from "node:crypto";

import { braidHash, stableStringify, type Hashable } from "./hash.ts";

export interface Ed25519KeyPair {
  publicKey: KeyObject;
  privateKey: KeyObject;
  publicJwk: JsonWebKey;
  privateJwk: JsonWebKey;
  fingerprint: string;
}

export function generateEd25519KeyPair(): Ed25519KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicJwk = publicKey.export({ format: "jwk" }) as JsonWebKey;
  const privateJwk = privateKey.export({ format: "jwk" }) as JsonWebKey;
  const fingerprint = braidHash({
    crv: publicJwk.crv ?? null,
    kty: publicJwk.kty ?? null,
    x: publicJwk.x ?? null,
  });

  return {
    publicKey,
    privateKey,
    publicJwk,
    privateJwk,
    fingerprint,
  };
}

export function importPublicJwk(publicJwk: JsonWebKey): KeyObject {
  return createPublicKey({
    key: publicJwk as never,
    format: "jwk",
  });
}

export function importPrivateJwk(privateJwk: JsonWebKey): KeyObject {
  return createPrivateKey({
    key: privateJwk as never,
    format: "jwk",
  });
}

export function signObject(privateKey: KeyObject, payload: Hashable): string {
  const signature = nodeSign(
    null,
    Buffer.from(stableStringify(payload)),
    privateKey,
  );
  return signature.toString("base64url");
}

export function verifyObject(
  publicKey: KeyObject,
  payload: Hashable,
  signature: string,
): boolean {
  return nodeVerify(
    null,
    Buffer.from(stableStringify(payload)),
    publicKey,
    Buffer.from(signature, "base64url"),
  );
}
