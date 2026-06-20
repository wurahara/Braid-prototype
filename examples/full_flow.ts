import { BraidPrototype } from "../src/index.ts";

const braid = new BraidPrototype({
  network: "local",
  recoveryThreshold: 2,
});

const issuer = braid.registerIdentifier({ owner: "issuer" });
const verifier = braid.registerIdentifier({ owner: "verifier" });
const alice1 = braid.registerIdentifier({
  owner: "alice",
  services: [
    {
      type: "LinkedDomains",
      serviceEndpoint:
        "https://alice.example/.well-known/did-configuration.json",
    },
  ],
});
const alice2 = braid.registerIdentifier({ owner: "alice" });
const alice3 = braid.registerIdentifier({ owner: "alice" });

const initialAssociation = braid.associateIdentifiers({
  dids: [alice1.did, alice2.did],
});

const expandedAssociation = braid.appendIdentifier({
  associationDid: initialAssociation.did,
  newDid: alice3.did,
});

const developerCredential = braid.issueCredential({
  issuerDid: issuer.did,
  holderDid: alice1.did,
  extraTypes: ["DeveloperCredential"],
  claims: {
    project: "braid",
    score: 97,
  },
});

const communityCredential = braid.issueCredential({
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

const presentation = braid.presentCredentials({
  associationDid: expandedAssociation.did,
  campaignId: campaign.id,
  credentialIds: [developerCredential.id, communityCredential.id],
  disclosedClaims: {
    [developerCredential.id]: ["score"],
    [communityCredential.id]: ["forumLevel"],
  },
  verifierDid: verifier.did,
});

const verification = braid.verifyPresentation({
  presentation,
  verifierDid: verifier.did,
});

const rotated = braid.rotateKey({
  did: alice1.did,
});

const recovered = braid.recoverKey({
  did: alice1.did,
  witnessDids: [alice2.did, alice3.did],
});

console.log(
  JSON.stringify(
    {
      identifiers: {
        issuer,
        verifier,
        alice1,
        alice2,
        alice3,
      },
      associations: {
        initialAssociation,
        expandedAssociation,
      },
      credentials: {
        developerCredential,
        communityCredential,
      },
      campaign,
      presentation,
      verification,
      rotated,
      recovered,
    },
    null,
    2,
  ),
);
