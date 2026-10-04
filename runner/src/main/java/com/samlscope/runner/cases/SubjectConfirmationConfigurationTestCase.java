package com.samlscope.runner.cases;

import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.runner.*;
import com.samlscope.saml.crypto.PlanCredentials;
import java.nio.file.Path;
import java.util.*;
import java.util.function.Function;
import java.util.function.BiFunction;

/** Original-backed ordinary bearer observations retain the approved CONFIG fallback. */
public final class SubjectConfirmationConfigurationTestCase implements TestCase, ConfigurationPrompt,
        AttestationPrompt, ProtocolEvidenceCase, RecordedEvidenceReevaluation, EvidenceCampaignCase, FallbackEvidenceCase {
    private final TestCase fallback;
    private final TranscriptContentReader content;
    private final Function<String, byte[]> metadata;
    private final Path directory;
    private final Function<String, String> profiles;
    private final SimpleSamlPhpSubjectConfirmationEvidence evidence;
    private final KeycloakSubjectConfirmationEvidence keycloakEvidence;
    private final ShibbolethSubjectConfirmationEvidence shibbolethEvidence;

    SubjectConfirmationConfigurationTestCase(TestCase fallback, TranscriptContentReader content,
            Function<String, byte[]> metadata, Path directory, Function<String, String> profiles) {
        this(fallback, content, metadata, directory, profiles, (run, variant) -> Optional.empty());
    }

    SubjectConfirmationConfigurationTestCase(TestCase fallback, TranscriptContentReader content,
            Function<String, byte[]> metadata, Path directory, Function<String, String> profiles,
            BiFunction<String, String, Optional<PlanCredentials>> metadataKeys) {
        if (!supports(fallback.id()) || !(fallback instanceof ConfigurationPrompt) || !(fallback instanceof AttestationPrompt))
            throw new IllegalArgumentException("Approved subject-confirmation CONFIG fallback required");
        this.fallback = Objects.requireNonNull(fallback);
        this.content = Objects.requireNonNull(content);
        this.metadata = Objects.requireNonNull(metadata);
        this.directory = Objects.requireNonNull(directory);
        this.profiles = Objects.requireNonNull(profiles);
        this.evidence = new SimpleSamlPhpSubjectConfirmationEvidence(directory, content, profiles);
        this.keycloakEvidence = new KeycloakSubjectConfirmationEvidence(directory, content, profiles);
        this.shibbolethEvidence = new ShibbolethSubjectConfirmationEvidence(directory, content, profiles,
                Objects.requireNonNull(metadataKeys));
    }

    /** The existing later preparation hook supplies the metadata-variant credentials. */
    SubjectConfirmationConfigurationTestCase withMetadataKeys(
            BiFunction<String, String, Optional<PlanCredentials>> keys) {
        return new SubjectConfirmationConfigurationTestCase(fallback, content, metadata, directory, profiles, keys);
    }

    static boolean supports(String id) {
        return Set.of(SimpleSamlPhpSubjectConfirmationEvidence.FR, SimpleSamlPhpSubjectConfirmationEvidence.GD).contains(id);
    }
    @Override public String id() { return fallback.id(); }
    @Override public TargetRole role() { return fallback.role(); }
    @Override public String instructionEn() { return ((ConfigurationPrompt)fallback).instructionEn(); }
    @Override public String promptEn() { return ((AttestationPrompt)fallback).promptEn(); }
    @Override public List<AttestationOption> options() { return ((AttestationPrompt)fallback).options(); }
    @Override public String evidenceCampaignId() { return "native-subject-confirmation"; }
    @Override public String evidenceCampaignTitle() { return "Native ordinary bearer subject confirmation"; }
    @Override public RunCampaignQuery.ActionKind evidenceActionKind() { return RunCampaignQuery.ActionKind.NONE; }

    private Optional<CaseOutcome> observe(CaseContext context) {
        boolean ssp = evidence.exists(context.runId());
        boolean keycloak = keycloakEvidence.exists(context.runId());
        boolean shibboleth = shibbolethEvidence.exists(context.runId());
        int owners = (ssp ? 1 : 0) + (keycloak ? 1 : 0) + (shibboleth ? 1 : 0);
        if (owners == 0) return Optional.empty();
        if (owners != 1) return Optional.of(unproven());
        if (!context.transcriptComplete()) return Optional.of(unproven());
        try {
            var target = metadata.apply(context.runId());
            var observed = ssp ? evidence.evaluate(context, id(), target)
                    : keycloak ? keycloakEvidence.evaluate(context, id(), target)
                    : shibbolethEvidence.evaluate(context, id(), target);
            return Optional.of(observed.orElseGet(
                    SubjectConfirmationConfigurationTestCase::unproven));
        } catch (RuntimeException unavailable) {
            return Optional.of(unproven());
        }
    }
    private static CaseOutcome unproven() {
        return CaseOutcome.notVerified("native_subject_confirmation_originals_unproven", "browser.subject-confirmation.native-unproven");
    }
    @Override public CaseStep start(CaseContext context) {
        return observe(context).<CaseStep>map(CaseStep.Finish::new).orElseGet(() -> fallback.start(context));
    }
    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        return observe(context).<CaseStep>map(CaseStep.Finish::new).orElseGet(() -> fallback.resume(context, state, event));
    }
    @Override public EvidenceStatus evidenceStatus(CaseContext context) {
        var observed = observe(context);
        if (observed.isEmpty() && fallback instanceof ProtocolEvidenceCase observer) return observer.evidenceStatus(context);
        var required = List.of("native-stock-bearer-factory", "signed-ordinary-response", "signed-attester-controls", "byte-exact-restoration");
        boolean ready = observed.map(value -> value.outcome() == Outcome.SATISFIED_WITH_NOTE).orElse(false);
        return new EvidenceStatus(ready, required, ready ? required : List.of(), observed.map(CaseOutcome::details).orElse(Map.of()));
    }
    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous) {
        return previous != null && previous.outcome() == Outcome.NOT_VERIFIED;
    }
    @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context, CaseOutcome previous) {
        if (!context.transcriptComplete() || !supportsRecordedEvidenceReevaluation(previous)) return Optional.empty();
        return observe(context).flatMap(next -> RecordedEvidenceReevaluation.conclusiveUpdate(previous, next));
    }
    @Override public boolean resolvedFromExternalEvidence(CaseExecution execution) {
        var outcome = execution.outcome();
        return id().equals(execution.caseId()) && outcome != null && outcome.outcome() == Outcome.SATISFIED_WITH_NOTE
                && "browser.subject-confirmation.native-no-opportunity".equals(outcome.reasonCode())
                && outcome.evidence().stream().anyMatch(ref -> "transcript".equals(ref.kind()))
                && nativeReferenceMatches(execution, outcome);
    }

    private static boolean nativeReferenceMatches(CaseExecution execution, CaseOutcome outcome) {
        var adapter = outcome.details().get("evidence_adapter");
        String kind;
        String prefix;
        if (SimpleSamlPhpSubjectConfirmationEvidence.SCHEMA.equals(adapter)) {
            kind = "native-subject-confirmation";
            prefix = execution.runId() + "/";
        } else if (KeycloakSubjectConfirmationEvidence.SCHEMA.equals(adapter)) {
            kind = "native-keycloak-subject-confirmation";
            prefix = execution.runId() + ".keycloak-subject-confirmation.json#";
        } else if (ShibbolethSubjectConfirmationEvidence.SCHEMA.equals(adapter)) {
            kind = "native-shibboleth-subject-confirmation";
            prefix = execution.runId() + ".shibboleth-subject-confirmation.json#";
        } else {
            return false;
        }
        return outcome.evidence().stream().anyMatch(ref -> kind.equals(ref.kind())
                && ref.reference().startsWith(prefix));
    }
}
