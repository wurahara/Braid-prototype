import assert from "node:assert/strict";
import test from "node:test";

import { BraidPrototype } from "../../src/index.ts";

test("credentials follow VC shape and campaign anti-replay", () => {
  const braid = new BraidPrototype();

  const issuer = braid.registerIdentifier({ owner: "issuer" });
  const verifier = braid.registerIdentifier({ owner: "verifier" });
  const alice1 = braid.registerIdentifier({ owner: "alice" });
  const alice2 = braid.registerIdentifier({ owner: "alice" });
  const bob = braid.registerIdentifier({ owner: "bob" });
  const bob1 = braid.registerIdentifier({ owner: "bob" });

  const aliceAid = braid.associateIdentifiers({
    dids: [alice1.did, alice2.did],
  });
  const bobAid = braid.associateIdentifiers({
    dids: [bob.did, bob1.did],
  });

  const developer = braid.issueCredential({
    issuerDid: issuer.did,
    holderDid: alice1.did,
    extraTypes: ["DeveloperCredential"],
    claims: {
      project: "braid",
      score: 95,
    },
  });
  const community = braid.issueCredential({
    issuerDid: issuer.did,
    holderDid: alice2.did,
    extraTypes: ["CommunityCredential"],
    claims: {
      forumLevel: "gold",
      years: 3,
    },
  });

  assert.equal(developer.credential.type[0], "VerifiableCredential");
  assert.equal(developer.credential.credentialSubject.id, alice1.did);

  const presentation = braid.presentCredentials({
    associationDid: aliceAid.did,
    campaignId: "future-dao-round-1",
    credentialIds: [developer.id, community.id],
    disclosedClaims: {
      [developer.id]: ["project"],
      [community.id]: ["forumLevel"],
    },
    verifierDid: verifier.did,
  });

  assert.equal(presentation.type[0], "VerifiablePresentation");
  assert.equal(presentation.verifiableCredential.length, 2);
  assert.equal(
    presentation.verifiableCredential[0].proof.disclosedClaims[0],
    "project",
  );

  const accepted = braid.verifyPresentation({
    presentation,
    verifierDid: verifier.did,
  });
  assert.equal(accepted.accepted, true);
  assert.equal(accepted.campaignId, "future-dao-round-1");

  assert.throws(() => {
    braid.verifyPresentation({
      presentation,
      verifierDid: verifier.did,
    });
  }, /already participated/);

  assert.throws(() => {
    braid.presentCredentials({
      associationDid: bobAid.did,
      campaignId: "future-dao-round-2",
      credentialIds: [developer.id],
      verifierDid: verifier.did,
    });
  }, /Credential holder is not part of the presenting association/);
});
