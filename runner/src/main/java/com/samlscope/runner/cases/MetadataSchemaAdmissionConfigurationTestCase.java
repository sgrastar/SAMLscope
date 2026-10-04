package com.samlscope.runner.cases;

import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.runner.*;
import java.nio.file.Path;
import java.util.*;
import java.util.function.Function;

/** A native valid-input rejection is a counterexample, not proof of all schema variants. */
public final class MetadataSchemaAdmissionConfigurationTestCase implements TestCase, ConfigurationPrompt,
        QueuedProtocolEvidenceCase, RecordedEvidenceReevaluation, EvidenceCampaignCase {
    public static final String ID = "IIP-MD05-b-idp-01";
    private static final List<String> REQUIRED = List.of("schema-valid-original", "native-parser-rejection",
            "otherwise-identical-accepted-control", "signed-normal-control", "configuration-restoration");
    private final TestCase fallback;
    private final Function<String, byte[]> metadata;
    private final KeycloakNativeSchemaAdmissionEvidence evidence;

    MetadataSchemaAdmissionConfigurationTestCase(TestCase fallback, TranscriptContentReader content,
            Function<String, byte[]> metadata, Path directory) {
        this.fallback = Objects.requireNonNull(fallback);
        this.metadata = Objects.requireNonNull(metadata);
        this.evidence = new KeycloakNativeSchemaAdmissionEvidence(directory, Objects.requireNonNull(content));
        if (!ID.equals(fallback.id()) || fallback.role() != TargetRole.IDP
                || !(fallback instanceof MetadataFixtureObservationTestCase))
            throw new IllegalArgumentException("Approved metadata schema CONFIG case required");
    }
    @Override public String id() { return fallback.id(); }
    @Override public TargetRole role() { return fallback.role(); }
    @Override public String instructionEn() { return ((ConfigurationPrompt) fallback).instructionEn(); }
    @Override public String evidenceCampaignId() { return "metadata-native-schema-admission"; }
    @Override public String evidenceCampaignTitle() { return "Native metadata schema admission"; }
    @Override public RunCampaignQuery.ActionKind evidenceActionKind() { return RunCampaignQuery.ActionKind.METADATA_REFRESH; }
    @Override public List<String> evidenceActionKeys() {
        var keys = new ArrayList<>(((EvidenceCampaignCase) fallback).evidenceActionKeys());
        if (!keys.contains("schema-sso-endpoint-without-foreign")) keys.add("schema-sso-endpoint-without-foreign");
        if (!keys.contains("schema-invalid-endpoint-location")) keys.add("schema-invalid-endpoint-location");
        return List.copyOf(keys);
    }
    private static CaseOutcome unproven() {
        return CaseOutcome.notVerified("native_schema_admission_incomplete", "metadata.schema.native-admission-incomplete");
    }
    private Optional<CaseOutcome> observe(CaseContext context) {
        if (!evidence.exists(context.runId())) return Optional.empty();
        if (!context.transcriptComplete()) return Optional.of(unproven());
        try { return Optional.of(evidence.evaluate(context, metadata.apply(context.runId()))); }
        catch (RuntimeException unavailable) { return Optional.of(unproven()); }
    }
    @Override public CaseStep start(CaseContext context) {
        return observe(context).<CaseStep>map(CaseStep.Finish::new).orElseGet(() -> fallback.start(context));
    }
    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        return observe(context).<CaseStep>map(CaseStep.Finish::new).orElseGet(() -> fallback.resume(context, state, event));
    }
    @Override public CaseOutcome queuedEvidenceOutcome(CaseContext context) {
        // Only recorded originals can complete a queued case; no configuration action is started.
        return observe(context).orElseGet(MetadataSchemaAdmissionConfigurationTestCase::unproven);
    }
    @Override public EvidenceStatus evidenceStatus(CaseContext context) {
        var observed = observe(context);
        if (observed.isEmpty()) return ((ProtocolEvidenceCase) fallback).evidenceStatus(context);
        boolean ready = observed.isPresent() && observed.get().outcome() == Outcome.VIOLATED;
        return new EvidenceStatus(ready, REQUIRED, ready ? REQUIRED : List.of(),
                observed.map(CaseOutcome::details).orElse(Map.of()));
    }
    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous) {
        return previous != null && previous.outcome() == Outcome.NOT_VERIFIED;
    }
    @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context, CaseOutcome previous) {
        if (!context.transcriptComplete() || !supportsRecordedEvidenceReevaluation(previous)) return Optional.empty();
        var observed = observe(context);
        return observed.isPresent() ? RecordedEvidenceReevaluation.conclusiveUpdate(previous, observed.get())
                : ((RecordedEvidenceReevaluation) fallback).reevaluateRecordedEvidence(context, previous);
    }
}
