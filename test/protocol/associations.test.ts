import assert from "node:assert/strict";
import test from "node:test";

import { BraidPrototype } from "../../src/index.ts";

test("association operations cover associate, append, merge, and refresh", () => {
  const braid = new BraidPrototype();

  const alice1 = braid.registerIdentifier({ owner: "alice" });
  const alice2 = braid.registerIdentifier({ owner: "alice" });
  const alice3 = braid.registerIdentifier({ owner: "alice" });
  const alice4 = braid.registerIdentifier({ owner: "alice" });
  const alice5 = braid.registerIdentifier({ owner: "alice" });

  const baseAssociation = braid.associateIdentifiers({
    dids: [alice1.did, alice2.did],
  });
  assert.match(baseAssociation.did, /^did:braid:local:aid:/);
  assert.deepEqual(baseAssociation.memberDids, [alice1.did, alice2.did].sort());

  const appended = braid.appendIdentifier({
    associationDid: baseAssociation.did,
    newDid: alice3.did,
  });
  assert.equal(appended.state, "active");
  assert.deepEqual(
    appended.memberDids,
    [alice1.did, alice2.did, alice3.did].sort(),
  );
  assert.equal(braid.getAssociation(baseAssociation.did).state, "superseded");

  const sideAssociation = braid.associateIdentifiers({
    dids: [alice4.did, alice5.did],
  });

  const merged = braid.mergeAssociations({
    leftAssociationDid: appended.did,
    rightAssociationDid: sideAssociation.did,
  });
  assert.equal(merged.memberDids.length, 5);
  assert.equal(braid.getAssociation(sideAssociation.did).state, "superseded");

  const refreshed = braid.refreshAssociation({
    associationDid: merged.did,
  });
  assert.equal(refreshed.nonce, merged.nonce + 1);
  assert.equal(braid.getAssociation(merged.did).state, "superseded");

  const alice3Live = braid.getIdentifier(alice3.did);
  assert.equal(alice3Live.currentAssociation, refreshed.did);
});

test("association blocklisting cascades to all linked identifiers", () => {
  const braid = new BraidPrototype();
  const alice1 = braid.registerIdentifier({ owner: "alice" });
  const alice2 = braid.registerIdentifier({ owner: "alice" });
  const association = braid.associateIdentifiers({
    dids: [alice1.did, alice2.did],
  });

  braid.blockAssociation({
    associationDid: association.did,
    reason: "malicious-behavior",
  });

  assert.equal(braid.getAssociation(association.did).state, "blocklisted");
  assert.equal(braid.getIdentifier(alice1.did).state, "blocklisted");
  assert.equal(braid.getIdentifier(alice2.did).state, "blocklisted");
});
