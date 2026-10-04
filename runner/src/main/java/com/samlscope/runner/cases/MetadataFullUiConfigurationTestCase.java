package com.samlscope.runner.cases;

import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.runner.*;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;

/** Full UI values require native consumer read-back. Import or a successful SSO alone is insufficient.
 * This CONFIG case has no browser action. General operators may apply the prepared fixture and
 * submit the adapter's actual native export and restoration originals; a confirmation is not proof. */
public final class MetadataFullUiConfigurationTestCase implements TestCase, ConfigurationPrompt,
        ProtocolEvidenceCase, EvidenceCampaignCase, FallbackEvidenceCase, RecordedEvidenceReevaluation {
    public static final String CASE = "IIP-MD05-f-idp-01";
    private static final String PHASE = "await-native-full-ui-values";
    private final TestCase delegate;
    private final ShibbolethMetadataFullUiEvidence evidence;
    private final Function<String, byte[]> target;

    public MetadataFullUiConfigurationTestCase(TestCase delegate, ShibbolethMetadataFullUiEvidence evidence,
            Function<String, byte[]> target) {
        this.delegate = Objects.requireNonNull(delegate); this.evidence = Objects.requireNonNull(evidence);
        this.target = Objects.requireNonNull(target);
        if (!CASE.equals(delegate.id()) || delegate.role() != TargetRole.IDP)
            throw new IllegalArgumentException("Full UI configuration is only for MD05.f IdP");
    }
    @Override public String id() { return delegate.id(); }
    @Override public TargetRole role() { return delegate.role(); }
    @Override public String evidenceCampaignId() { return "native-metadata-full-ui"; }
    @Override public String evidenceCampaignTitle() { return "Read complete native UI metadata values"; }
    @Override public RunCampaignQuery.ActionKind evidenceActionKind() { return RunCampaignQuery.ActionKind.CONFIGURATION; }
    @Override public RunCampaignQuery.ActionKind evidenceActionKind(CaseExecution execution) {
        return execution.status() == CaseExecutionStatus.FINISHED && execution.outcome() != null
                && execution.outcome().outcome() != Outcome.NOT_VERIFIED
                ? RunCampaignQuery.ActionKind.NONE : RunCampaignQuery.ActionKind.CONFIGURATION;
    }
    @Override public List<String> evidenceActionKeys() { return List.of("native-full-ui-readback"); }
    @Override public String instructionEn() {
        return "Apply the Suite full-ui-info metadata through the target's native metadata consumer. "
                + "Export the loaded UIInfo and DiscoHints values with the supported native read-back adapter, "
                + "and restore the captured original configuration. Confirm only after those originals are recorded. "
                + "A metadata import or another login does not prove these values.";
    }
    @Override public CaseStep start(CaseContext context) {
        var observed = observe(context);
        return observed.outcome() != Outcome.NOT_VERIFIED ? new CaseStep.Finish(observed)
                : new CaseStep.AwaitConfig(new CaseState(PHASE, Map.of()), List.of(),
                        "native-full-ui-readback", Duration.ofDays(7));
    }
    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        if (event instanceof CaseEvent.TimedOut) return new CaseStep.Finish(missing("metadata.full-ui.timeout"));
        if (event instanceof CaseEvent.Aborted) return new CaseStep.Finish(missing("metadata.full-ui.skipped"));
        if (event instanceof CaseEvent.ConfigUnavailable unavailable) return new CaseStep.Finish(new CaseOutcome(
                Outcome.NOT_VERIFIED, "native_full_ui_configuration_unavailable", "metadata.full-ui.unavailable",
                "metadata.full-ui.unavailable", List.of(), Map.of("configuration_issue",
                        unavailable.issue().name().toLowerCase(java.util.Locale.ROOT), "configuration_note", unavailable.note())));
        if (event instanceof CaseEvent.ConfigConfirmed) return new CaseStep.Finish(observe(context));
        throw new IllegalArgumentException("Expected complete native full UI configuration evidence");
    }
    private CaseOutcome observe(CaseContext context) {
        try { return evidence.evaluate(context, target.apply(context.runId())).orElseGet(
                () -> missing("metadata.full-ui.native-values-unproven")); }
        catch (Exception unavailable) { return missing("metadata.full-ui.native-values-unproven"); }
    }
    private static CaseOutcome missing(String reason) { return CaseOutcome.notVerified("native_full_ui_values_unproven", reason); }
    @Override public EvidenceStatus evidenceStatus(CaseContext context) {
        var observed = observe(context); boolean ready = observed.outcome() != Outcome.NOT_VERIFIED;
        var requirements = List.of("native-ui-values", "native-hints-values", "multilingual-values", "foreign-extension-harmlessness", "restoration");
        return new EvidenceStatus(ready, requirements, ready ? requirements : List.of(), observed.details());
    }
    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous) {
        return previous != null && previous.outcome() == Outcome.NOT_VERIFIED;
    }
    @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context, CaseOutcome previous) {
        if (!context.transcriptComplete() || !supportsRecordedEvidenceReevaluation(previous)) return Optional.empty();
        return RecordedEvidenceReevaluation.conclusiveUpdate(previous, observe(context));
    }
    @Override public boolean resolvedFromExternalEvidence(CaseExecution execution) {
        return execution.outcome() != null && Boolean.TRUE.equals(execution.outcome().details().get("native_full_ui_values_verified"));
    }
    @Override public RunCampaignQuery.EvidenceClass evidenceClass(CaseExecution execution) {
        return RunCampaignQuery.EvidenceClass.OPERATOR_ASSISTED;
    }
}
