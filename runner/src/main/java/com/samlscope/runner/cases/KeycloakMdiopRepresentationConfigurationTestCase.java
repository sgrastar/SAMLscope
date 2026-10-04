package com.samlscope.runner.cases;

import java.nio.file.Path;
import java.util.*;
import java.util.function.Function;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.runner.RecordedEvidenceReevaluation;

/** Native MDIOP representation admission; later runtime key use is deliberately separate. */
public final class KeycloakMdiopRepresentationConfigurationTestCase implements TestCase,
        ConfigurationPrompt, ProtocolEvidenceCase, com.samlscope.runner.EvidenceCampaignCase,
        RecordedEvidenceReevaluation {
    private final TestCase fallback;
    private final Function<String, byte[]> metadata;
    private final KeycloakMdiopRepresentationEvidenceFile evidence;
    private final SimpleSamlPhpMdiopAdmissionEvidence simpleSamlPhpEvidence;

    public KeycloakMdiopRepresentationConfigurationTestCase(TestCase fallback,
            TranscriptContentReader content, Function<String, byte[]> metadata, Path directory) {
        this.fallback = Objects.requireNonNull(fallback);
        this.metadata = Objects.requireNonNull(metadata);
        this.evidence = new KeycloakMdiopRepresentationEvidenceFile(directory, Objects.requireNonNull(content));
        this.simpleSamlPhpEvidence = new SimpleSamlPhpMdiopAdmissionEvidence(directory, content);
        if (!KeycloakMdiopRepresentationEvidenceFile.ID.equals(fallback.id()))
            throw new IllegalArgumentException("Unsupported MDIOP admission case");
    }

    @Override public String id() { return fallback.id(); }
    @Override public TargetRole role() { return fallback.role(); }
    @Override public String instructionEn() { return ((ConfigurationPrompt) fallback).instructionEn(); }
    @Override public String evidenceCampaignId() { return "metadata-fixture-refresh"; }
    @Override public String evidenceCampaignTitle() { return "Refresh or re-import Suite metadata fixtures"; }
    @Override public com.samlscope.runner.RunCampaignQuery.ActionKind evidenceActionKind() {
        return com.samlscope.runner.RunCampaignQuery.ActionKind.METADATA_REFRESH;
    }
    @Override public List<String> evidenceActionKeys() {
        return ((com.samlscope.runner.EvidenceCampaignCase) fallback).evidenceActionKeys();
    }
    @Override public boolean requiresPreparationConfirmation() { return true; }
    @Override public CaseStep start(CaseContext context) { return fallback.start(context); }
    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        if (event instanceof CaseEvent.ConfigConfirmed && hasNativeEvidence(context.runId()))
            return new CaseStep.Finish(observe(context, true));
        return fallback.resume(context, state, event);
    }
    private boolean hasNativeEvidence(String runId) {
        return evidence.exists(runId) || simpleSamlPhpEvidence.exists(runId);
    }
    private CaseOutcome observe(CaseContext context, boolean confirmed) {
        CaseOutcome result;
        try {
            boolean keycloak = evidence.exists(context.runId());
            boolean simpleSamlPhp = simpleSamlPhpEvidence.exists(context.runId());
            // A malformed or ambiguous native receipt owns this branch. It must not fall
            // through to another adapter or the weaker generic fixture observations.
            if (keycloak == simpleSamlPhp) throw new IllegalArgumentException("Native adapter unavailable or ambiguous");
            byte[] target = metadata.apply(context.runId());
            result = simpleSamlPhp ? simpleSamlPhpEvidence.evaluate(context, target)
                    : evidence.evaluate(context, target);
        }
        catch (Exception unavailable) {
            result = CaseOutcome.notVerified("native_mdiop_admission_incomplete",
                    "metadata.mdiop.native-representation-admission-incomplete");
        }
        var details = new LinkedHashMap<String, Object>(result.details());
        details.put("configuration_confirmed", confirmed);
        return new CaseOutcome(result.outcome(), result.notVerifiedReason(), result.reasonCode(),
                result.reasonMessageKey(), result.evidence(), details);
    }
    @Override public EvidenceStatus evidenceStatus(CaseContext context) {
        if (!hasNativeEvidence(context.runId())) return ((ProtocolEvidenceCase) fallback).evidenceStatus(context);
        var result = observe(context, false);
        boolean ready = result.outcome() == Outcome.SATISFIED;
        return new EvidenceStatus(ready, evidenceActionKeys(), ready ? evidenceActionKeys() : List.of(), result.details());
    }
    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous) {
        return previous != null && previous.outcome() == Outcome.NOT_VERIFIED
                && Boolean.TRUE.equals(previous.details().get("configuration_confirmed"))
                && Set.of("metadata.fixture-probe.incomplete", "metadata.mdiop.native-representation-admission-incomplete")
                        .contains(previous.reasonCode());
    }
    @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context, CaseOutcome previous) {
        if (!supportsRecordedEvidenceReevaluation(previous)) return Optional.empty();
        if (hasNativeEvidence(context.runId()))
            return RecordedEvidenceReevaluation.conclusiveUpdate(previous, observe(context, true));
        return ((RecordedEvidenceReevaluation) fallback).reevaluateRecordedEvidence(context, previous);
    }
}
