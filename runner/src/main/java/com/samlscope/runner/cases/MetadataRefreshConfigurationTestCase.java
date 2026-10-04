package com.samlscope.runner.cases;

import java.nio.file.Path;
import java.util.List;
import java.util.Objects;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseState;
import com.samlscope.core.caseexec.CaseStep;
import com.samlscope.core.caseexec.TestCase;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.TranscriptContentReader;

/**
 * Decides MD02.a only from a native recurring-fetch campaign whose changed key is used in a
 * correlated SAML exchange after the Run's approved refresh wait has elapsed.
 */
public final class MetadataRefreshConfigurationTestCase implements TestCase, ConfigurationPrompt,
        AttestationPrompt, ProtocolEvidenceCase, com.samlscope.runner.EvidenceCampaignCase {
    public static final String ID = "IIP-MD02-a-idp-01";
    private final TestCase fallback;
    private final MetadataRefreshEvidenceFile evidence;

    public MetadataRefreshConfigurationTestCase(
            TestCase fallback, TranscriptContentReader content, Path directory) {
        this.fallback = Objects.requireNonNull(fallback);
        this.evidence = new MetadataRefreshEvidenceFile(content, directory);
        if (!ID.equals(fallback.id()) || !(fallback instanceof ConfigurationPrompt)
                || !(fallback instanceof AttestationPrompt)) {
            throw new IllegalArgumentException("Metadata refresh requires the approved CONFIG fallback");
        }
    }

    @Override public String id() { return fallback.id(); }
    @Override public TargetRole role() { return fallback.role(); }
    @Override public String instructionEn() { return ((ConfigurationPrompt) fallback).instructionEn(); }
    @Override public String promptEn() { return ((AttestationPrompt) fallback).promptEn(); }
    @Override public List<AttestationOption> options() { return ((AttestationPrompt) fallback).options(); }
    @Override public String evidenceCampaignId() { return "native-metadata-refresh"; }
    @Override public String evidenceCampaignTitle() { return "Native recurring metadata refresh and use"; }
    @Override public com.samlscope.runner.RunCampaignQuery.ActionKind evidenceActionKind() {
        return com.samlscope.runner.RunCampaignQuery.ActionKind.METADATA_REFRESH;
    }
    @Override public CaseStep start(CaseContext context) { return fallback.start(context); }
    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        if (event instanceof CaseEvent.ConfigConfirmed && evidence.exists(context.runId())) {
            return new CaseStep.Finish(observe(context));
        }
        return fallback.resume(context, state, event);
    }
    @Override public EvidenceStatus evidenceStatus(CaseContext context) {
        var result = observe(context);
        var ready = result.outcome() == Outcome.SATISFIED;
        var required = List.of(
                "native-fetch-version-a", "correlated-saml-control-a",
                "wait-at-least-metadata-refresh-wait-seconds", "native-fetch-version-b",
                "changed-key-correlated-saml-success", "configuration-restored");
        return new EvidenceStatus(ready, required, ready ? required : List.of(), result.details());
    }

    private CaseOutcome observe(CaseContext context) {
        return evidence.evaluate(context);
    }
}
