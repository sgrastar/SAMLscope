package com.samlscope.runner.cases;

import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.runner.*;
import java.nio.file.Path;
import java.util.*;
import java.util.function.Function;

/** Both native duplicate conflict and distinct peer use are required by the approved case. */
public final class EntityIdUniquenessConfigurationTestCase implements TestCase, ConfigurationPrompt,
        ProtocolEvidenceCase, RecordedEvidenceReevaluation, EvidenceCampaignCase, FallbackEvidenceCase {
    private final MetadataFixtureObservationTestCase fallback;
    private final ShibbolethEntityIdUniquenessEvidence evidence;

    EntityIdUniquenessConfigurationTestCase(MetadataFixtureObservationTestCase fallback,
            TranscriptContentReader content, Function<String, byte[]> metadata,
            SamlDecryptionKeyProvider keys, Path directory) {
        if (!ShibbolethEntityIdUniquenessEvidence.CASE.equals(fallback.id()))
            throw new IllegalArgumentException("Approved entityID uniqueness case required");
        this.fallback = Objects.requireNonNull(fallback);
        this.evidence = new ShibbolethEntityIdUniquenessEvidence(directory, content, metadata, keys);
    }
    @Override public String id() { return fallback.id(); }
    @Override public TargetRole role() { return fallback.role(); }
    @Override public String instructionEn() { return fallback.instructionEn(); }
    @Override public String evidenceCampaignId() { return fallback.evidenceCampaignId(); }
    @Override public String evidenceCampaignTitle() { return fallback.evidenceCampaignTitle(); }
    @Override public RunCampaignQuery.ActionKind evidenceActionKind() { return fallback.evidenceActionKind(); }
    @Override public List<String> evidenceActionKeys() { return fallback.evidenceActionKeys(); }

    private Optional<CaseOutcome> observe(CaseContext context) {
        if (!evidence.exists(context.runId())) return Optional.empty();
        if (!context.transcriptComplete()) return Optional.of(unproven());
        try { return Optional.of(evidence.read(context).orElseGet(EntityIdUniquenessConfigurationTestCase::unproven)); }
        catch (RuntimeException unavailable) { return Optional.of(unproven()); }
    }
    private static CaseOutcome unproven() {
        return CaseOutcome.notVerified("native_entityid_originals_unproven", "metadata.entityid.native-unproven");
    }
    @Override public CaseStep start(CaseContext context) {
        return observe(context).<CaseStep>map(CaseStep.Finish::new).orElseGet(() -> fallback.start(context));
    }
    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        return observe(context).<CaseStep>map(CaseStep.Finish::new).orElseGet(() -> fallback.resume(context, state, event));
    }
    @Override public EvidenceStatus evidenceStatus(CaseContext context) {
        var observed = observe(context);
        if (observed.isEmpty()) return fallback.evidenceStatus(context);
        var required = List.of("native-duplicate-conflict", "two-distinct-peer-flows", "signed-normal-control", "byte-exact-restoration");
        boolean ready = observed.get().outcome() == Outcome.SATISFIED;
        return new EvidenceStatus(ready, required, ready ? required : List.of(), observed.get().details());
    }
    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous) {
        return previous != null && previous.outcome() == Outcome.NOT_VERIFIED;
    }
    @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context, CaseOutcome previous) {
        if (!context.transcriptComplete() || !supportsRecordedEvidenceReevaluation(previous)) return Optional.empty();
        var observed = observe(context);
        if (observed.isPresent()) return RecordedEvidenceReevaluation.conclusiveUpdate(previous, observed.get());
        return fallback.reevaluateRecordedEvidence(context, previous);
    }
    @Override public boolean resolvedFromExternalEvidence(CaseExecution execution) {
        var outcome = execution.outcome();
        return id().equals(execution.caseId()) && outcome != null && outcome.outcome() == Outcome.SATISFIED
                && "metadata.entityid.native-conflict-and-distinct-peers".equals(outcome.reasonCode())
                && "shibboleth-native-entityid-uniqueness".equals(outcome.details().get("adapter"))
                && outcome.evidence().stream().anyMatch(ref -> "transcript".equals(ref.kind()))
                && outcome.evidence().stream().anyMatch(ref -> "native-entityid-evidence".equals(ref.kind())
                        && ref.reference().startsWith(execution.runId() + "/"));
    }
}
