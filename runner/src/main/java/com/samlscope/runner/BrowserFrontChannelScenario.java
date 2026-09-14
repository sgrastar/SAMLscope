package com.samlscope.runner;

import java.util.ArrayList;
import java.util.List;
import com.samlscope.core.caseexec.CaseState;

/** Marker and presentation contract for a persisted scenario delivered through a real browser. */
public interface BrowserFrontChannelScenario extends EvidenceCampaignCase {
    enum Binding { HTTP_POST, SIGNED_REDIRECT }

    default Binding outboundBinding(CaseState state) { return Binding.HTTP_POST; }

    default boolean requiresFreshSession(CaseState state) { return false; }

    /** True when any fixture in this scenario crosses an empty-session boundary. */
    default boolean plansFreshSessionBoundary() { return false; }

    @Override default String evidenceCampaignId() { return "active-probe-chain"; }

    @Override default String evidenceCampaignTitle() { return "Browser-assisted SAML protocol scenarios"; }

    @Override default RunCampaignQuery.ActionKind evidenceActionKind() {
        return RunCampaignQuery.ActionKind.LOGIN;
    }

    /** Planned human checkpoints inside the automatically chained scenario. */
    default int plannedDeliberateActions() { return 0; }

    /**
     * Session actions are shared across the active-probe chain. A scenario that needs two
     * checkpoints (for example an established session followed by forced reauthentication)
     * reuses the first key and adds only the second one; it does not charge every case for a new
     * login. RunCampaignService adds one recovery key when any fixture crosses a fresh-session
     * boundary.
     */
    @Override
    default List<String> evidenceActionKeys() {
        var keys = new ArrayList<String>();
        var count = Math.max(1, plannedDeliberateActions());
        for (var index = 0; index < count; index++) {
            keys.add("active-probe-login-" + (index + 1));
        }
        return List.copyOf(keys);
    }

    String instructionsEn(CaseState state);
}
