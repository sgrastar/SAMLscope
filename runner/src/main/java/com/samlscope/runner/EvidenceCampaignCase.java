package com.samlscope.runner;

import java.util.List;

/**
 * Describes how a case obtains evidence for interaction-budget and orchestration purposes.
 * Implementations do not decide outcomes here; they only identify a reusable evidence action.
 */
public interface EvidenceCampaignCase extends ExternallyObservedCase {
    /** Additional shared operations, without counting the owning case again in the denominator. */
    default List<EvidenceCampaignCase> supplementalEvidenceCampaigns() { return List.of(); }

    String evidenceCampaignId();

    String evidenceCampaignTitle();

    RunCampaignQuery.ActionKind evidenceActionKind();

    /**
     * Stable operation keys needed by this case. Cases in one campaign may reuse the same key;
     * the interaction budget counts the union rather than one answer per case.
     */
    default List<String> evidenceActionKeys() { return List.of(evidenceCampaignId()); }

    /** True only when one real operator action supplies evidence to every case in this campaign. */
    default boolean sharesDeliberateAction() { return true; }
}
