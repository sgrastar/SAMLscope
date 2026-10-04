package com.samlscope.runner.cases;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseState;
import com.samlscope.core.caseexec.CaseStep;
import com.samlscope.core.caseexec.TestCase;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.TargetRole;

/**
 * Gates a metadata fixture observer behind a Run-scoped proof that the target actually verifies the
 * metadata document signature with an out-of-band trust anchor. A consumer that never verifies the
 * signature accepts every signed fixture through its ordinary parser, so fixture acceptance alone
 * must never become PASS or FAIL for these cases. When the proof is missing or incomplete the case
 * is NOT_VERIFIED; the approval-time adoption verifier still owns the product-specific configuration
 * and read-back evidence.
 */
public final class MetadataSignatureVerificationConfigurationTestCase implements TestCase, ConfigurationPrompt,
        ProtocolEvidenceCase, com.samlscope.runner.EvidenceCampaignCase,
        com.samlscope.runner.RecordedEvidenceReevaluation {
    /** Approved cases whose verdict is only meaningful once the metadata signature is verified. */
    private static final Set<String> CASES = Set.of(
            "IIP-MD03-b-idp-01", "IIP-MD03-c-idp-01");
    private final TestCase fallback;
    private final MetadataFixtureObservationTestCase observer;
    private final TranscriptContentReader content;
    private final Function<String, byte[]> metadata;
    private final MetadataSignatureVerificationEvidenceFile evidence;

    public MetadataSignatureVerificationConfigurationTestCase(
            TestCase fallback, TranscriptContentReader content, Function<String, byte[]> metadata, Path directory) {
        this.fallback = Objects.requireNonNull(fallback);
        if (!(fallback instanceof MetadataFixtureObservationTestCase fixtureObserver)) {
            throw new IllegalArgumentException("Metadata signature verification requires a fixture observer");
        }
        this.observer = fixtureObserver;
        this.content = Objects.requireNonNull(content);
        this.metadata = Objects.requireNonNull(metadata);
        this.evidence = new MetadataSignatureVerificationEvidenceFile(directory);
        if (!supports(fallback.id())) throw new IllegalArgumentException("Unsupported signature-verification case");
    }

    public static boolean supports(String id) { return CASES.contains(id); }

    @Override public String id() { return fallback.id(); }
    @Override public TargetRole role() { return fallback.role(); }
    @Override public String instructionEn() { return ((ConfigurationPrompt) fallback).instructionEn(); }
    @Override public boolean requiresPreparationConfirmation() {
        return ((ProtocolEvidenceCase) fallback).requiresPreparationConfirmation();
    }

    @Override public CaseStep start(CaseContext context) { return fallback.start(context); }

    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        var step = fallback.resume(context, state, event);
        if (step instanceof CaseStep.Finish finish) return new CaseStep.Finish(gate(context, finish.outcome()));
        return step;
    }

    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous) {
        return ((com.samlscope.runner.RecordedEvidenceReevaluation) fallback)
                .supportsRecordedEvidenceReevaluation(previous);
    }

    @Override public java.util.Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context, CaseOutcome previous) {
        return ((com.samlscope.runner.RecordedEvidenceReevaluation) fallback)
                .reevaluateRecordedEvidence(context, previous).map(outcome -> gate(context, outcome));
    }

    @Override public EvidenceStatus evidenceStatus(CaseContext context) {
        var base = observer.evidenceStatus(context);
        if (proven(context)) return base;
        var required = new ArrayList<>(base.requiredObservations());
        required.add(SIGNATURE_REQUIREMENT);
        return new EvidenceStatus(false, required, base.completedObservations(), base.details());
    }

    @Override public String evidenceCampaignId() {
        return ((com.samlscope.runner.EvidenceCampaignCase) fallback).evidenceCampaignId();
    }
    @Override public String evidenceCampaignTitle() {
        return ((com.samlscope.runner.EvidenceCampaignCase) fallback).evidenceCampaignTitle();
    }
    @Override public com.samlscope.runner.RunCampaignQuery.ActionKind evidenceActionKind() {
        return ((com.samlscope.runner.EvidenceCampaignCase) fallback).evidenceActionKind();
    }
    @Override public List<String> evidenceActionKeys() {
        return ((com.samlscope.runner.EvidenceCampaignCase) fallback).evidenceActionKeys();
    }
    @Override public List<com.samlscope.runner.EvidenceCampaignCase> supplementalEvidenceCampaigns() {
        return ((com.samlscope.runner.EvidenceCampaignCase) fallback).supplementalEvidenceCampaigns();
    }

    private static final String SIGNATURE_REQUIREMENT = "signature-verification:out-of-band-anchor";

    private boolean proven(CaseContext context) {
        try {
            evidence.verify(context, metadata.apply(context.runId()), content, evidenceCampaignId());
            return true;
        } catch (Exception unproven) {
            return false;
        }
    }

    /** Only the fixture-probe decisions depend on whether the target verifies document signatures. */
    private static boolean signatureRelevant(CaseOutcome outcome) {
        return "metadata.fixture-probe.incomplete".equals(outcome.reasonCode())
                || "metadata.fixture-probe.satisfied".equals(outcome.reasonCode())
                || "metadata.fixture-probe.violated".equals(outcome.reasonCode());
    }

    private CaseOutcome gate(CaseContext context, CaseOutcome outcome) {
        if (outcome.outcome() != Outcome.SATISFIED && outcome.outcome() != Outcome.SATISFIED_WITH_NOTE
                && outcome.outcome() != Outcome.VIOLATED) {
            return outcome;
        }
        // Configuration-failure semantics (an absent normative capability, an unavailable probe)
        // are approved independently of document-signature verification and must pass unchanged.
        if (!signatureRelevant(outcome)) return outcome;
        try {
            var proof = evidence.verify(context, metadata.apply(context.runId()), content, evidenceCampaignId());
            var details = new LinkedHashMap<String, Object>(outcome.details());
            details.put("signature_verification_adapter", proof.adapter());
            details.put("signature_verification_anchor", proof.anchorCertificateSha256());
            details.put("signature_verification_embedded_key_info", proof.embeddedKeyInfoSha256());
            return new CaseOutcome(outcome.outcome(), outcome.notVerifiedReason(), outcome.reasonCode(),
                    outcome.reasonMessageKey(), outcome.evidence(), details);
        } catch (Exception unproven) {
            return CaseOutcome.notVerified(
                    "metadata_signature_verification_unproven",
                    "metadata.signature-verification.unproven");
        }
    }
}
