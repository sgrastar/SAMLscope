package com.samlscope.runner.cases;

import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseExecution;
import com.samlscope.core.caseexec.CaseState;
import com.samlscope.core.caseexec.CaseStep;
import com.samlscope.core.caseexec.TestCase;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.runner.RecordedEvidenceReevaluation;
import com.samlscope.runner.FallbackEvidenceCase;

/** Replaces self-attestation with a Run-bound Shibboleth A/B/A protocol observation when available. */
public final class AlgorithmPreventionConfigurationTestCase implements TestCase, ConfigurationPrompt,
        AttestationPrompt, ProtocolEvidenceCase, FallbackEvidenceCase, RecordedEvidenceReevaluation {
    private static final Set<String> CASES = Set.of(
            AlgorithmPreventionEvidenceFile.CASE_A, AlgorithmPreventionEvidenceFile.CASE_B);
    private static final String SATISFIED = "configuration.algorithm-prevention.observed";
    private static final String VIOLATED = "configuration.algorithm-prevention.ineffective";
    private static final String INCOMPLETE = "configuration.algorithm-prevention.evidence-incomplete";
    private final TestCase fallback;
    private final AlgorithmPreventionEvidenceFile evidence;

    public AlgorithmPreventionConfigurationTestCase(TestCase fallback, TranscriptContentReader content,
            Function<String, byte[]> metadata, SamlDecryptionKeyProvider keys,
            Function<String, String> profiles, Path directory) {
        this(fallback, new AlgorithmPreventionEvidenceFile(directory, content, metadata, keys, profiles));
    }

    AlgorithmPreventionConfigurationTestCase(TestCase fallback, AlgorithmPreventionEvidenceFile evidence) {
        this.fallback = Objects.requireNonNull(fallback);
        this.evidence = Objects.requireNonNull(evidence);
        if (!supports(fallback.id()) || fallback.role() != TargetRole.IDP
                || !(fallback instanceof ConfigurationPrompt) || !(fallback instanceof AttestationPrompt)) {
            throw new IllegalArgumentException("Expected approved ALG08 IdP CONFIG fallback");
        }
    }

    public static boolean supports(String id) { return CASES.contains(id); }
    @Override public String id() { return fallback.id(); }
    @Override public TargetRole role() { return TargetRole.IDP; }
    @Override public String instructionEn() { return ((ConfigurationPrompt) fallback).instructionEn(); }
    @Override public String promptEn() { return ((AttestationPrompt) fallback).promptEn(); }
    @Override public List<AttestationOption> options() { return ((AttestationPrompt) fallback).options(); }
    @Override public CaseStep start(CaseContext context) {
        return observed(context).<CaseStep>map(CaseStep.Finish::new).orElseGet(() -> fallback.start(context));
    }
    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        var observed = observed(context);
        if (observed.isPresent()) return new CaseStep.Finish(observed.orElseThrow());
        if (event instanceof CaseEvent.ConfigConfirmed && evidence.exists(context.runId()))
            return new CaseStep.Finish(incomplete());
        return fallback.resume(context, state, event);
    }

    CaseOutcome observe(CaseContext context) {
        return observed(context).orElseGet(this::incomplete);
    }

    private Optional<CaseOutcome> observed(CaseContext context) {
        var proof = evidence.read(context);
        if (proof.isEmpty()) return Optional.empty();
        var value = proof.orElseThrow();
        var details = new LinkedHashMap<String, Object>();
        details.put("native_receipt_sha256", value.receiptSha256());
        details.put("observed_key_transport_algorithms", value.algorithms());
        details.put("configuration_sequence", List.of(
                "allow-rsa-1_5", "prevent-rsa-1_5", "allow-rsa-1_5"));
        details.put("configuration_restored", true);
        var outcome = value.result() == AlgorithmPreventionEvidenceFile.Result.SATISFIED
                ? Outcome.SATISFIED : Outcome.VIOLATED;
        var reason = outcome == Outcome.SATISFIED ? SATISFIED : VIOLATED;
        return Optional.of(new CaseOutcome(outcome, null, reason, reason, value.evidence(), Map.copyOf(details)));
    }

    private CaseOutcome incomplete() {
        return new CaseOutcome(Outcome.NOT_VERIFIED, "algorithm_prevention_evidence_incomplete",
                INCOMPLETE, INCOMPLETE, List.of(), Map.of("automatic_observation", true));
    }

    @Override public boolean resolvedFromExternalEvidence(CaseExecution execution) {
        return execution != null && execution.outcome() != null
                && Set.of(SATISFIED, VIOLATED).contains(execution.outcome().reasonCode())
                && !execution.outcome().evidence().isEmpty()
                && execution.outcome().evidence().stream().allMatch(ref -> "transcript".equals(ref.kind()));
    }

    @Override public EvidenceStatus evidenceStatus(CaseContext context) {
        var result = observed(context);
        var required = List.of("allowed-before:rsa-1_5", "blocked:rsa-oaep-mgf1p",
                "allowed-after:rsa-1_5", "configuration:exact-restore");
        return new EvidenceStatus(result.isPresent(), required, result.isPresent() ? required : List.of(),
                result.map(CaseOutcome::details).orElse(Map.of("automatic_observation", true)));
    }

    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous) {
        return previous != null && previous.outcome() == Outcome.NOT_VERIFIED
                && Set.of("attestation.interaction-disallowed", "configuration.evidence-unavailable",
                        "case.pending-interaction", INCOMPLETE).contains(previous.reasonCode());
    }

    @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context, CaseOutcome previous) {
        if (!supportsRecordedEvidenceReevaluation(previous)) return Optional.empty();
        return observed(context).flatMap(next -> RecordedEvidenceReevaluation.conclusiveUpdate(previous, next));
    }
}
