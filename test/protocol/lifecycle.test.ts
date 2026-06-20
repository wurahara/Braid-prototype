import assert from "node:assert/strict";
import test from "node:test";

import { BraidPrototype } from "../../src/index.ts";

test("credential refresh and revocation update lifecycle state", () => {
  const braid = new BraidPrototype();
  const issuer = braid.registerIdentifier({ owner: "issuer" });
  const holder = braid.registerIdentifier({ owner: "holder" });

  const credential = braid.issueCredential({
    issuerDid: issuer.did,
    holderDid: holder.did,
    claims: { level: 3 },
  });
  const refreshed = braid.refreshCredential({
    credentialId: credential.id,
  });

  assert.equal(refreshed.version, 2);
  assert.equal(refreshed.nonce, 1);
  assert.notEqual(refreshed.commitment, credential.commitment);

  const revoked = braid.revokeCredential({
    credentialId: credential.id,
    reason: "issuer-revocation",
  });
  assert.equal(revoked.state, "revoked");
});

test("key recovery rotates the controller after witness checks", () => {
  const braid = new BraidPrototype({ recoveryThreshold: 2 });
  const alice1 = braid.registerIdentifier({ owner: "alice" });
  const alice2 = braid.registerIdentifier({ owner: "alice" });
  const alice3 = braid.registerIdentifier({ owner: "alice" });

  const association = braid.associateIdentifiers({
    dids: [alice1.did, alice2.did, alice3.did],
  });

  assert.equal(association.memberDids.length, 3);

  const recovered = braid.recoverKey({
    did: alice1.did,
    witnessDids: [alice2.did, alice3.did],
  });

  assert.equal(recovered.did, alice1.did);
  assert.equal(recovered.state, "recovered");
  assert.equal(recovered.version, 2);
});
