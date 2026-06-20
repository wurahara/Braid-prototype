import assert from "node:assert/strict";
import test from "node:test";

import { BraidPrototype } from "../../src/index.ts";

test("identifier registration produces W3C DID documents and supports updates", () => {
  const braid = new BraidPrototype();
  const alice = braid.registerIdentifier({
    owner: "alice",
    services: [
      {
        type: "LinkedDomains",
        serviceEndpoint:
          "https://alice.example/.well-known/did-configuration.json",
      },
    ],
  });

  assert.match(alice.did, /^did:braid:local:id:/);
  assert.equal(alice.document["@context"][0], "https://www.w3.org/ns/did/v1");
  assert.equal(alice.document.authentication[0], `${alice.did}#controller-1`);

  const updated = braid.updateIdentifier({
    did: alice.did,
    services: [
      {
        type: "LinkedDomains",
        serviceEndpoint: "https://alice.example/updated.json",
      },
      {
        type: "MessagingService",
        serviceEndpoint: "https://alice.example/messages",
      },
    ],
  });

  assert.equal(updated.version, 2);
  assert.equal(updated.state, "active");
  assert.equal(updated.document.service.length, 3);
  assert.equal(updated.document.service[2].type, "MessagingService");
});

test("key rotation preserves the DID while replacing the controller binding", () => {
  const braid = new BraidPrototype();
  const alice = braid.registerIdentifier({ owner: "alice" });
  const rotated = braid.rotateKey({ did: alice.did });

  assert.equal(rotated.did, alice.did);
  assert.equal(rotated.state, "rotated");
  assert.equal(rotated.version, 2);
  assert.notEqual(
    rotated.controllerKeyFingerprint,
    alice.controllerKeyFingerprint,
  );
});
