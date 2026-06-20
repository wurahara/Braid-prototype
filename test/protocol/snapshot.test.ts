import assert from "node:assert/strict";
import test from "node:test";

import { BraidPrototype } from "../../src/index.ts";

test("snapshots round-trip the protocol state", () => {
  const braid = new BraidPrototype();
  const issuer = braid.registerIdentifier({ owner: "issuer" });
  const alice1 = braid.registerIdentifier({ owner: "alice" });
  const alice2 = braid.registerIdentifier({ owner: "alice" });

  const association = braid.associateIdentifiers({
    dids: [alice1.did, alice2.did],
  });
  const credential = braid.issueCredential({
    issuerDid: issuer.did,
    holderDid: alice1.did,
    claims: {
      project: "braid",
    },
  });

  const snapshot = braid.snapshot();
  const restored = BraidPrototype.fromSnapshot(snapshot);

  assert.deepEqual(
    restored.getAssociation(association.did),
    braid.getAssociation(association.did),
  );
  assert.deepEqual(
    restored.getCredential(credential.id),
    braid.getCredential(credential.id),
  );
  assert.deepEqual(
    restored.getIdentifier(alice1.did),
    braid.getIdentifier(alice1.did),
  );
});
