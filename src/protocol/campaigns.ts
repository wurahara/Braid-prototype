import { braidHash } from "../crypto/index.ts";
import { ensure } from "../utils/assert.ts";
import { deepClone } from "../utils/clone.ts";
import { logEvent, getOrCreateCampaignState } from "./state.ts";
import { claimPredicateMatches, requireActiveCredential } from "./helpers.ts";
import type {
  BraidState,
  CampaignRecord,
  CampaignRequirement,
  DerivedCredential,
} from "./types.ts";

export function createCampaign(
  state: BraidState,
  options: {
    campaignId: string;
    minCredentials?: number;
    requirements?: CampaignRequirement[];
    verifierDid: string;
  },
): Omit<CampaignRecord, "nullifiers"> & { nullifiers: string[] } {
  ensure(options.campaignId, "Campaign creation requires a campaign id");
  ensure(options.verifierDid, "Campaign creation requires a verifier DID");
  ensure(
    (options.minCredentials ?? 1) > 0,
    "Campaign must require at least one credential",
  );
  const campaign = getOrCreateCampaignState(
    state,
    options.campaignId,
    options.verifierDid,
  );
  ensure(
    campaign.state !== "active",
    `Campaign already exists: ${options.campaignId}`,
  );

  campaign.verifierDid = options.verifierDid;
  campaign.minCredentials = options.minCredentials ?? 1;
  campaign.requirements = deepClone(options.requirements ?? []);
  campaign.policyHash = braidHash({
    campaignId: options.campaignId,
    minCredentials: campaign.minCredentials,
    requirements: campaign.requirements,
    verifierDid: options.verifierDid,
  });
  campaign.state = "active";

  logEvent(state, "CampaignCreated", {
    campaignId: options.campaignId,
    minCredentials: campaign.minCredentials,
    verifierDid: options.verifierDid,
    requirementCount: campaign.requirements.length,
  });

  return {
    ...deepClone(campaign),
    nullifiers: [...campaign.nullifiers],
  };
}

export function getCampaign(
  state: BraidState,
  campaignId: string,
): Omit<CampaignRecord, "nullifiers"> & { nullifiers: string[] } {
  const campaign = state.campaigns.get(campaignId);
  ensure(campaign, `Unknown campaign: ${campaignId}`);
  return {
    ...deepClone(campaign),
    nullifiers: [...campaign.nullifiers],
  };
}

export function credentialMatchesRequirement(
  state: BraidState,
  options: {
    credentialId: string;
    derived: DerivedCredential;
    requirement: CampaignRequirement;
  },
): boolean {
  const anchor = requireActiveCredential(state, options.credentialId);

  if (options.requirement.credentialType) {
    ensure(
      Array.isArray(anchor.credential.type),
      `Credential ${anchor.id} is missing its type array`,
    );
    if (!anchor.credential.type.includes(options.requirement.credentialType)) {
      return false;
    }
  }

  const disclosedClaims = new Set(options.derived.proof.disclosedClaims ?? []);

  for (const claim of options.requirement.disclosedClaims ?? []) {
    if (!disclosedClaims.has(claim)) {
      return false;
    }
  }

  for (const [claim, predicate] of Object.entries(
    options.requirement.claimPredicates ?? {},
  )) {
    if (!disclosedClaims.has(claim)) {
      return false;
    }

    if (
      !claimPredicateMatches(
        options.derived.credentialSubject[claim],
        predicate,
      )
    ) {
      return false;
    }
  }

  return true;
}
