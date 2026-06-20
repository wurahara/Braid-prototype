import assert from "node:assert/strict";
import test from "node:test";

import { BraidPrototype } from "../../src/index.ts";

test("campaign policies enforce disclosed claims and designated verifier binding", () => {
  const braid = new BraidPrototype();

  const issuer = braid.registerIdentifier({ owner: "issuer" });
  const verifier = braid.registerIdentifier({ owner: "verifier" });
  const strangerVerifier = braid.registerIdentifier({
    owner: "stranger-verifier",
  });
  const alice1 = braid.registerIdentifier({ owner: "alice" });
  const alice2 = braid.registerIdentifier({ owner: "alice" });

  const aid = braid.associateIdentifiers({
    dids: [alice1.did, alice2.did],
  });

  const developer = braid.issueCredential({
    issuerDid: issuer.did,
    holderDid: alice1.did,
    extraTypes: ["DeveloperCredential"],
    claims: {
      score: 97,
      project: "braid",
    },
  });
  const community = braid.issueCredential({
    issuerDid: issuer.did,
    holderDid: alice2.did,
    extraTypes: ["CommunityCredential"],
    claims: {
      forumLevel: "gold",
      years: 4,
    },
  });

  const campaign = braid.createCampaign({
    campaignId: "future-dao-membership",
    verifierDid: verifier.did,
    minCredentials: 2,
    requirements: [
      {
        id: "developer-threshold",
        credentialType: "DeveloperCredential",
        disclosedClaims: ["score"],
        claimPredicates: {
          score: { min: 90 },
        },
      },
      {
        id: "community-presence",
        credentialType: "CommunityCredential",
        disclosedClaims: ["forumLevel"],
        claimPredicates: {
          forumLevel: { equals: "gold" },
        },
      },
    ],
  });

  assert.equal(campaign.minCredentials, 2);
  assert.equal(campaign.requirements.length, 2);

  const invalidPresentation = braid.presentCredentials({
    associationDid: aid.did,
    campaignId: "future-dao-membership",
    credentialIds: [developer.id, community.id],
    disclosedClaims: {
      [developer.id]: ["project"],
      [community.id]: ["forumLevel"],
    },
    verifierDid: verifier.did,
  });

  assert.throws(() => {
    braid.verifyPresentation({
      presentation: invalidPresentation,
      verifierDid: verifier.did,
    });
  }, /does not satisfy campaign requirement/);

  const presentation = braid.presentCredentials({
    associationDid: aid.did,
    campaignId: "future-dao-membership",
    credentialIds: [developer.id, community.id],
    disclosedClaims: {
      [developer.id]: ["score"],
      [community.id]: ["forumLevel"],
    },
    verifierDid: verifier.did,
  });

  assert.equal(presentation.proof.campaignPolicyHash, campaign.policyHash);

  const verification = braid.verifyPresentation({
    presentation,
    verifierDid: verifier.did,
  });
  assert.equal(verification.accepted, true);

  assert.throws(() => {
    braid.verifyPresentation({
      presentation,
      verifierDid: strangerVerifier.did,
    });
  }, /Presentation domain does not match the verifier DID/);
});
