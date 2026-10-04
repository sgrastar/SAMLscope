package com.samlscope.runner.cases;

import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.runner.EvidenceCampaignCase;
import com.samlscope.runner.FallbackEvidenceCase;
import com.samlscope.runner.RecordedEvidenceReevaluation;
import com.samlscope.runner.RunCampaignQuery;

/** One native publisher inventory can resolve both approved publication cases. */
public final class MetadataPublisherKeyInventoryConfigurationTestCase implements TestCase,
        ConfigurationPrompt, AttestationPrompt, ProtocolEvidenceCase, EvidenceCampaignCase,
        FallbackEvidenceCase, RecordedEvidenceReevaluation {
    private static final Set<String> CASES = Set.of("IIP-MD05-c1-idp-01", "IIP-MD05-c3-idp-01");
    private static final Set<String> REASONS = Set.of(
            "metadata.publisher.role-description-complete",
            "metadata.publisher.current-key-inventory-complete",
            "metadata.publisher.role-description-incomplete",
            "metadata.publisher.current-key-omitted");
    private static final Set<Outcome> CONCLUSIVE = Set.of(
            Outcome.SATISFIED, Outcome.SATISFIED_WITH_NOTE, Outcome.VIOLATED);
    private static final List<String> ACTIONS = List.of(
            "native-role-inventory", "native-published-metadata", "native-publication-controls");
    private final TestCase fallback;
    private final Function<CaseContext, CaseOutcome> observation;

    public MetadataPublisherKeyInventoryConfigurationTestCase(TestCase fallback,
            TranscriptContentReader content, Function<String, byte[]> metadata, Path directory) {
        this(fallback, reader(fallback, content, metadata, directory));
    }

    private static Function<CaseContext, CaseOutcome> reader(TestCase fallback,
            TranscriptContentReader content, Function<String, byte[]> metadata, Path directory) {
        var evidence = new MetadataPublisherKeyInventoryEvidence(directory, content, metadata);
        return context -> evidence.evaluate(fallback.id(), context);
    }

    MetadataPublisherKeyInventoryConfigurationTestCase(TestCase fallback,
            Function<CaseContext, CaseOutcome> observation) {
        this.fallback = Objects.requireNonNull(fallback);
        this.observation = Objects.requireNonNull(observation);
        if (!supports(fallback.id()) || fallback.role() != TargetRole.IDP
                || !(fallback instanceof ConfigurationPrompt) || !(fallback instanceof AttestationPrompt)) {
            throw new IllegalArgumentException("Expected approved publisher CONFIG fallback");
        }
    }

    public static boolean supports(String caseId) { return CASES.contains(caseId); }
    @Override public String id() { return fallback.id(); }
    @Override public TargetRole role() { return fallback.role(); }
    @Override public String instructionEn() { return ((ConfigurationPrompt) fallback).instructionEn(); }
    @Override public String promptEn() { return ((AttestationPrompt) fallback).promptEn(); }
    @Override public List<AttestationOption> options() { return ((AttestationPrompt) fallback).options(); }
    @Override public String evidenceCampaignId() { return "native-metadata-publisher-key-inventory"; }
    @Override public String evidenceCampaignTitle() { return "Published role information and current keys"; }
    @Override public RunCampaignQuery.ActionKind evidenceActionKind() {
        return RunCampaignQuery.ActionKind.CONFIGURATION;
    }
    @Override public List<String> evidenceActionKeys() { return ACTIONS; }

    @Override public CaseStep start(CaseContext context) {
        return observed(context).<CaseStep>map(CaseStep.Finish::new)
                .orElseGet(() -> fallback.start(context));
    }

    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        // Retain the approved configuration-failure semantics, including normative capability.
        if (event instanceof CaseEvent.ConfigUnavailable) return fallback.resume(context, state, event);
        return observed(context).<CaseStep>map(CaseStep.Finish::new)
                .orElseGet(() -> fallback.resume(context, state, event));
    }

    private Optional<CaseOutcome> observed(CaseContext context) {
        try {
            var result = observation.apply(context);
            if (result == null || !CONCLUSIVE.contains(result.outcome()) || !reasonMatchesCase(result.reasonCode())
                    || Boolean.TRUE.equals(result.details().get("counterfactual_calibration_only"))
                    || !hasOriginalReferences(context.runId(), result)) return Optional.empty();
            var details = new LinkedHashMap<String, Object>(result.details());
            details.put("native_publisher_inventory_verified", true);
            details.put("native_publisher_inventory_case_id", id());
            return Optional.of(new CaseOutcome(result.outcome(), result.notVerifiedReason(),
                    result.reasonCode(), result.reasonMessageKey(), result.evidence(), details));
        } catch (RuntimeException unavailable) {
            return Optional.empty();
        }
    }

    private boolean reasonMatchesCase(String reason) {
        return REASONS.contains(reason) && (id().equals("IIP-MD05-c1-idp-01")
                ? reason.startsWith("metadata.publisher.role-description-")
                : reason.startsWith("metadata.publisher.current-key-"));
    }

    private static boolean hasOriginalReferences(String runId, CaseOutcome result) {
        return result.evidence().stream().anyMatch(ref -> "transcript".equals(ref.kind())
                    && ref.reference() != null && !ref.reference().isBlank())
                && result.evidence().stream().anyMatch(ref -> "native-metadata-publisher-key-evidence".equals(ref.kind())
                    && ref.reference() != null && ref.reference().matches(java.util.regex.Pattern.quote(runId)
                        + "/manifest\\.json#[0-9a-f]{64}"));
    }

    @Override public EvidenceStatus evidenceStatus(CaseContext context) {
        var result = observed(context);
        return new EvidenceStatus(result.isPresent(), ACTIONS, result.isPresent() ? ACTIONS : List.of(),
                result.map(CaseOutcome::details).orElse(java.util.Map.of("native_inventory_unproven", true)));
    }

    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous) {
        return previous != null && previous.outcome() == Outcome.NOT_VERIFIED;
    }

    @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context, CaseOutcome previous) {
        if (!supportsRecordedEvidenceReevaluation(previous)) return Optional.empty();
        return observed(context).flatMap(next -> RecordedEvidenceReevaluation.conclusiveUpdate(previous, next));
    }

    @Override public boolean resolvedFromExternalEvidence(CaseExecution execution) {
        return execution != null && id().equals(execution.caseId()) && execution.outcome() != null
                && CONCLUSIVE.contains(execution.outcome().outcome()) && reasonMatchesCase(execution.outcome().reasonCode())
                && hasOriginalReferences(execution.runId(), execution.outcome())
                && Boolean.TRUE.equals(execution.outcome().details().get("native_publisher_inventory_verified"))
                && id().equals(execution.outcome().details().get("native_publisher_inventory_case_id"));
    }

    @Override public RunCampaignQuery.EvidenceClass evidenceClass(CaseExecution execution) {
        if (resolvedFromExternalEvidence(execution)) return RunCampaignQuery.EvidenceClass.OPERATOR_ASSISTED;
        if (execution != null && ("await-attestation".equals(execution.state().phase())
                || execution.outcome() != null && (CONCLUSIVE.contains(execution.outcome().outcome())
                    || Boolean.TRUE.equals(execution.outcome().details().get("attested"))))) {
            return fallback instanceof FallbackEvidenceCase original ? original.evidenceClass(execution)
                    : RunCampaignQuery.EvidenceClass.SELF_ATTESTED;
        }
        return RunCampaignQuery.EvidenceClass.OPERATOR_ASSISTED;
    }
}
