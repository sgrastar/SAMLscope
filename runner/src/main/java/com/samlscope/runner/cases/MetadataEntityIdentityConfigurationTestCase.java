package com.samlscope.runner.cases;

import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.runner.*;
import java.nio.file.Path;
import java.util.*;
import java.util.function.Function;

/** One restored native registration campaign supplies both approved entity identity cases. */
public final class MetadataEntityIdentityConfigurationTestCase implements TestCase, ConfigurationPrompt,
        ProtocolEvidenceCase, EvidenceCampaignCase, RecordedEvidenceReevaluation, FallbackEvidenceCase {
    public static final Set<String> IDS = Set.of("IIP-MD05-a1-idp-01", "IIP-MD05-a2-idp-01");
    private static final String ADAPTER = "keycloak-native-simultaneous-entity-registration-v1";
    private static final List<String> REQUIRED = List.of("two-simultaneously-registered-entities",
            "original-native-metadata-import", "correlated-signed-normal-controls",
            "duplicate-conflict-and-unchanged-native-identity", "configuration-restored");
    private final TestCase fallback;
    private final KeycloakMetadataEntityIdentityEvidence evidence;
    private final ShibbolethEntityIdUniquenessEvidence shibboleth;

    public MetadataEntityIdentityConfigurationTestCase(TestCase fallback, Path directory,
            TranscriptContentReader content, Function<String, byte[]> metadata, SamlDecryptionKeyProvider keys) {
        this.fallback = Objects.requireNonNull(fallback);
        if (!IDS.contains(fallback.id()) || !(fallback instanceof ConfigurationPrompt)
                || !(fallback instanceof ProtocolEvidenceCase) || !(fallback instanceof EvidenceCampaignCase)
                || !(fallback instanceof RecordedEvidenceReevaluation)) {
            throw new IllegalArgumentException("Approved metadata entity identity fallback required");
        }
        evidence = new KeycloakMetadataEntityIdentityEvidence(directory, content, metadata, keys);
        shibboleth = new ShibbolethEntityIdUniquenessEvidence(
                directory.resolveSibling("entityid-uniqueness-evidence"), content, metadata, keys);
    }

    @Override public String id() { return fallback.id(); }
    @Override public TargetRole role() { return fallback.role(); }
    @Override public String instructionEn() { return ((ConfigurationPrompt) fallback).instructionEn(); }
    @Override public String evidenceCampaignId() { return ((EvidenceCampaignCase) fallback).evidenceCampaignId(); }
    @Override public String evidenceCampaignTitle() { return ((EvidenceCampaignCase) fallback).evidenceCampaignTitle(); }
    @Override public RunCampaignQuery.ActionKind evidenceActionKind() {
        return ((EvidenceCampaignCase) fallback).evidenceActionKind();
    }
    @Override public List<String> evidenceActionKeys() { return ((EvidenceCampaignCase) fallback).evidenceActionKeys(); }

    private CaseOutcome unproven(CaseContext context) {
        return new CaseOutcome(Outcome.NOT_VERIFIED, "native_entity_identity_originals_unproven",
                "metadata.entity-identity.native-unproven", "metadata.entity-identity.native-unproven",
                List.of(), Map.of("evidence_adapter", ADAPTER, "native_run_id", context.runId(),
                        "case_id", id(), "native_receipt_owned", true));
    }

    private Optional<CaseOutcome> observe(CaseContext context) {
        if (!evidence.exists(context.runId())) return Optional.empty();
        if (!context.transcriptComplete() || ShibbolethEntityIdUniquenessEvidence.CASE.equals(id())
                && shibboleth.exists(context.runId())) return Optional.of(unproven(context));
        try { return Optional.of(evidence.evaluate(context, id()).orElseGet(() -> unproven(context))); }
        catch (RuntimeException unavailable) { return Optional.of(unproven(context)); }
    }

    @Override public CaseStep start(CaseContext context) {
        return observe(context).<CaseStep>map(CaseStep.Finish::new).orElseGet(() -> fallback.start(context));
    }
    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        if (evidence.exists(context.runId()) && ShibbolethEntityIdUniquenessEvidence.CASE.equals(id())
                && shibboleth.exists(context.runId())) return new CaseStep.Finish(unproven(context));
        if (event instanceof CaseEvent.ConfigUnavailable) return fallback.resume(context, state, event);
        return observe(context).<CaseStep>map(CaseStep.Finish::new)
                .orElseGet(() -> fallback.resume(context, state, event));
    }
    @Override public EvidenceStatus evidenceStatus(CaseContext context) {
        var observed = observe(context);
        if (observed.isEmpty()) return ((ProtocolEvidenceCase) fallback).evidenceStatus(context);
        var result = observed.orElseThrow();
        boolean ready = result.outcome() == Outcome.SATISFIED
                || result.outcome() == Outcome.SATISFIED_WITH_NOTE || result.outcome() == Outcome.VIOLATED;
        return new EvidenceStatus(ready, REQUIRED, ready ? REQUIRED : List.of(), result.details());
    }
    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous) {
        return previous != null && previous.outcome() == Outcome.NOT_VERIFIED;
    }
    @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context, CaseOutcome previous) {
        if (!context.transcriptComplete() || !supportsRecordedEvidenceReevaluation(previous)) return Optional.empty();
        var observed = observe(context);
        return observed.isPresent() ? RecordedEvidenceReevaluation.conclusiveUpdate(previous, observed.orElseThrow())
                : ((RecordedEvidenceReevaluation) fallback).reevaluateRecordedEvidence(context, previous);
    }

    private boolean recordedNativeOutcome(CaseExecution execution) {
        var result = execution.outcome();
        boolean bound = id().equals(execution.caseId()) && result != null
                && ADAPTER.equals(result.details().get("evidence_adapter"))
                && execution.runId().equals(result.details().get("native_run_id"))
                && id().equals(result.details().get("case_id"));
        if (!bound) return false;
        if (result.outcome() == Outcome.NOT_VERIFIED) {
            return "metadata.entity-identity.native-unproven".equals(result.reasonCode())
                    && Boolean.TRUE.equals(result.details().get("native_receipt_owned"));
        }
        return result.evidence().stream().anyMatch(ref -> "transcript".equals(ref.kind()))
                && result.evidence().stream().anyMatch(ref -> "native-metadata-entity-identity-evidence".equals(ref.kind())
                        && ref.reference().matches(java.util.regex.Pattern.quote(execution.runId())
                                + "/manifest\\.json#[0-9a-f]{64}"));
    }
    @Override public boolean resolvedFromExternalEvidence(CaseExecution execution) {
        if (recordedNativeOutcome(execution)) {
            return switch (execution.outcome().outcome()) {
                case SATISFIED, SATISFIED_WITH_NOTE, VIOLATED -> true;
                default -> false;
            };
        }
        return fallback instanceof FallbackEvidenceCase original && original.resolvedFromExternalEvidence(execution);
    }
    @Override public RunCampaignQuery.EvidenceClass evidenceClass(CaseExecution execution) {
        // Read the recorded result, never newly placed files, when reporting earlier evidence.
        if (recordedNativeOutcome(execution)) return RunCampaignQuery.EvidenceClass.OPERATOR_ASSISTED;
        return fallback instanceof FallbackEvidenceCase original ? original.evidenceClass(execution)
                : RunCampaignQuery.EvidenceClass.OPERATOR_ASSISTED;
    }
}
