package com.samlscope.runner.cases;

import java.nio.file.Path;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.BiFunction;
import java.util.function.Function;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.runner.EvidenceCampaignCase;
import com.samlscope.runner.RecordedEvidenceReevaluation;
import com.samlscope.runner.RunCampaignQuery.ActionKind;
import com.samlscope.saml.crypto.PlanCredentials;

/**
 * Reuses a restored native metadata campaign for the approved validity obligation.
 * A declaration or a timeout cannot replace before-expiry use and native rejection after expiry.
 * This wrapper creates no browser actions; configuration preparation retains its approved meaning.
 */
public final class MetadataValidityConfigurationTestCase implements TestCase, ConfigurationPrompt,
        AttestationPrompt, ProtocolEvidenceCase, EvidenceCampaignCase, RecordedEvidenceReevaluation {
    public static final String ID = "IIP-MD05-ar-idp-01";
    private static final List<String> REQUIRED = List.of(
            "root-validity:use-before-expiry-and-native-rejection-after-expiry",
            "parent-validity:use-before-expiry-and-native-rejection-after-expiry",
            "child-validity:use-before-expiry-and-native-rejection-after-expiry",
            "native-clock-and-effective-validity", "positive-and-negative-controls",
            "configuration-restored");
    private final TestCase fallback;
    private final MetadataValidityEvidence shibbolethEvidence;
    private final SimpleSamlPhpMetadataValidityEvidence simpleSamlPhpEvidence;

    public MetadataValidityConfigurationTestCase(TestCase fallback, Path directory,
            TranscriptContentReader content, Function<String, byte[]> metadata,
            BiFunction<String, String, Optional<PlanCredentials>> keys) {
        this.fallback = Objects.requireNonNull(fallback);
        if (!ID.equals(fallback.id()) || !(fallback instanceof ConfigurationPrompt)
                || !(fallback instanceof AttestationPrompt)) {
            throw new IllegalArgumentException("Metadata validity requires its approved CONFIG fallback");
        }
        this.shibbolethEvidence = new MetadataValidityEvidence(directory, content, metadata, keys);
        this.simpleSamlPhpEvidence = new SimpleSamlPhpMetadataValidityEvidence(
                directory.resolveSibling("simplesamlphp-metadata-validity-evidence"), content, metadata, keys);
    }

    @Override public String id() { return fallback.id(); }
    @Override public TargetRole role() { return fallback.role(); }
    @Override public String instructionEn() { return ((ConfigurationPrompt) fallback).instructionEn(); }
    @Override public boolean requiresPreparationConfirmation() {
        return true;
    }
    @Override public String promptEn() { return ((AttestationPrompt) fallback).promptEn(); }
    @Override public List<AttestationOption> options() { return ((AttestationPrompt) fallback).options(); }
    @Override public String evidenceCampaignId() { return "native-metadata-validity"; }
    @Override public String evidenceCampaignTitle() { return "Native metadata expiry and use"; }
    @Override public ActionKind evidenceActionKind() { return ActionKind.METADATA_REFRESH; }

    @Override public CaseStep start(CaseContext context) {
        return ownsNativeEvidence(context.runId())
                ? new CaseStep.Finish(observe(context)) : fallback.start(context);
    }

    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        // An unavailable normative capability and an unavailable test precondition keep the
        // semantics of the approved definition, independently of an incomplete local receipt.
        if (event instanceof CaseEvent.ConfigUnavailable) return fallback.resume(context, state, event);
        if (ownsNativeEvidence(context.runId())) return new CaseStep.Finish(observe(context));
        return fallback.resume(context, state, event);
    }

    private static CaseOutcome unproven() {
        return CaseOutcome.notVerified("native_metadata_validity_originals_unproven",
                "metadata.validity.native-unproven");
    }

    private boolean ownsNativeEvidence(String runId) {
        return shibbolethEvidence.exists(runId) || simpleSamlPhpEvidence.exists(runId);
    }

    private CaseOutcome observe(CaseContext context) {
        if (!context.transcriptComplete()) return unproven();
        try {
            boolean shibboleth = shibbolethEvidence.exists(context.runId());
            boolean simpleSamlPhp = simpleSamlPhpEvidence.exists(context.runId());
            if (shibboleth == simpleSamlPhp) return unproven();
            return (shibboleth ? shibbolethEvidence.evaluate(context) : simpleSamlPhpEvidence.evaluate(context))
                    .orElseGet(MetadataValidityConfigurationTestCase::unproven);
        } catch (RuntimeException unavailable) {
            return unproven();
        }
    }

    @Override public EvidenceStatus evidenceStatus(CaseContext context) {
        var result = observe(context);
        boolean ready = result.outcome() == Outcome.SATISFIED
                || result.outcome() == Outcome.SATISFIED_WITH_NOTE || result.outcome() == Outcome.VIOLATED;
        return new EvidenceStatus(ready, REQUIRED, ready ? REQUIRED : List.of(), result.details());
    }

    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous) {
        return previous != null && previous.outcome() == Outcome.NOT_VERIFIED;
    }

    @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context, CaseOutcome previous) {
        if (!supportsRecordedEvidenceReevaluation(previous) || !context.transcriptComplete()) {
            return Optional.empty();
        }
        return RecordedEvidenceReevaluation.conclusiveUpdate(previous, observe(context));
    }
}
