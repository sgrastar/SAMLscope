package com.samlscope.runner.cases;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseState;
import com.samlscope.core.caseexec.CaseStep;
import com.samlscope.core.caseexec.TestCase;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.runner.RecordedEvidenceReevaluation;

/** Completes approved SLO browser cases from target-emitted protocol evidence after a user logout action. */
public final class LogoutBrowserEvidenceTestCase implements TestCase, BrowserPrompt, ProtocolEvidenceCase,
        com.samlscope.runner.EvidenceCampaignCase, RecordedEvidenceReevaluation {
    private static final Map<String, LogoutTranscriptProfileCase.Rule> RULES = Map.ofEntries(
            Map.entry("IIP-IDP17-f-idp-01", LogoutTranscriptProfileCase.Rule.RESPONSE_ISSUER_COUNT),
            Map.entry("IIP-IDP17-g-idp-01", LogoutTranscriptProfileCase.Rule.RESPONSE_ISSUER_VALUE),
            Map.entry("IIP-IDP17-h-idp-01", LogoutTranscriptProfileCase.Rule.RESPONSE_ISSUER_FORMAT),
            Map.entry("IIP-IDP17-i-idp-01", LogoutTranscriptProfileCase.Rule.RESPONSE_SIGNATURE),
            Map.entry("IIP-IDP17-j-idp-01", LogoutTranscriptProfileCase.Rule.REQUEST_ISSUER_COUNT),
            Map.entry("IIP-IDP17-k-idp-01", LogoutTranscriptProfileCase.Rule.REQUEST_ISSUER_VALUE),
            Map.entry("IIP-IDP17-l-idp-01", LogoutTranscriptProfileCase.Rule.REQUEST_ISSUER_FORMAT),
            Map.entry("IIP-IDP17-m-idp-01", LogoutTranscriptProfileCase.Rule.REQUEST_SIGNATURE),
            Map.entry("IIP-IDP17-n-idp-01", LogoutTranscriptProfileCase.Rule.REQUEST_IDENTIFIER_MATCH),
            Map.entry("IIP-IDP17-t-idp-01", LogoutTranscriptProfileCase.Rule.REQUEST_NOT_ON_OR_AFTER),
            Map.entry("IIP-IDP17-u-idp-01", LogoutTranscriptProfileCase.Rule.REQUEST_NOT_ON_OR_AFTER_BOUND),
            Map.entry("IIP-IDP18-a-idp-01", LogoutTranscriptProfileCase.Rule.REDIRECT_LOGOUT_REQUEST_ACCEPTED),
            Map.entry("IIP-IDP18-c-idp-01", LogoutTranscriptProfileCase.Rule.TARGET_REDIRECT_LOGOUT_REQUEST),
            Map.entry("IIP-IDP18-d-idp-01", LogoutTranscriptProfileCase.Rule.TARGET_REDIRECT_RESPONSE_CONSUMED),
            Map.entry("IIP-IDP17-c-idp-01", LogoutTranscriptProfileCase.Rule.INFORMATIONAL_PROPAGATION),
            Map.entry("IIP-IDP17-r-idp-01", LogoutTranscriptProfileCase.Rule.TARGET_PROPAGATION_CONTINUE),
            Map.entry("IIP-IDP17-s-idp-01", LogoutTranscriptProfileCase.Rule.TARGET_PARTIAL_LOGOUT));

    private final BrowserEvidenceTestCase fallback;
    private final TranscriptContentReader content;
    private final Function<String, Optional<String>> targetEntityIds;
    private final Function<String, List<X509Certificate>> signingCertificates;
    private final SamlDecryptionKeyProvider decryptionKeys;
    private final ShibbolethNativeSloPropagationEvidence nativePropagation;
    private final ShibbolethNativeSloContinuationEvidence nativeContinuation;

    public LogoutBrowserEvidenceTestCase(
            BrowserEvidenceTestCase fallback,
            TranscriptContentReader content,
            Function<String, Optional<String>> targetEntityIds,
            Function<String, List<X509Certificate>> signingCertificates) {
        this(fallback, content, targetEntityIds, signingCertificates, ignored -> Optional.empty());
    }

    public LogoutBrowserEvidenceTestCase(
            BrowserEvidenceTestCase fallback,
            TranscriptContentReader content,
            Function<String, Optional<String>> targetEntityIds,
            Function<String, List<X509Certificate>> signingCertificates,
            SamlDecryptionKeyProvider decryptionKeys) {
        this(fallback, content, targetEntityIds, signingCertificates, decryptionKeys, null, null);
    }

    private LogoutBrowserEvidenceTestCase(
            BrowserEvidenceTestCase fallback,
            TranscriptContentReader content,
            Function<String, Optional<String>> targetEntityIds,
            Function<String, List<X509Certificate>> signingCertificates,
            SamlDecryptionKeyProvider decryptionKeys,
            ShibbolethNativeSloPropagationEvidence nativePropagation,
            ShibbolethNativeSloContinuationEvidence nativeContinuation) {
        this.fallback = Objects.requireNonNull(fallback, "fallback");
        this.content = Objects.requireNonNull(content, "content");
        this.targetEntityIds = Objects.requireNonNull(targetEntityIds, "targetEntityIds");
        this.signingCertificates = Objects.requireNonNull(signingCertificates, "signingCertificates");
        this.decryptionKeys = Objects.requireNonNull(decryptionKeys, "decryptionKeys");
        this.nativePropagation = nativePropagation;
        this.nativeContinuation = nativeContinuation;
        if (!supports(fallback.id())) throw new IllegalArgumentException("No SLO oracle for " + fallback.id());
    }

    /** Adds the original-backed native processing observer without changing the browser contract. */
    LogoutBrowserEvidenceTestCase withNativePropagation(
            java.nio.file.Path directory, Function<String, byte[]> metadata) {
        return withNativePropagation(directory, metadata, false);
    }

    /** Permits isolated control originals to enter the same continuation predicate. */
    LogoutBrowserEvidenceTestCase withNativePropagation(
            java.nio.file.Path directory, Function<String, byte[]> metadata, boolean diagnosticPermission) {
        if (ShibbolethNativeSloPropagationEvidence.CASE.equals(id()))
            return new LogoutBrowserEvidenceTestCase(fallback, content, targetEntityIds, signingCertificates,
                    decryptionKeys, new ShibbolethNativeSloPropagationEvidence(directory, content, metadata, decryptionKeys),
                    nativeContinuation);
        if (ShibbolethNativeSloContinuationEvidence.CASE.equals(id()))
            return new LogoutBrowserEvidenceTestCase(fallback, content, targetEntityIds, signingCertificates,
                    decryptionKeys, nativePropagation,
                    new ShibbolethNativeSloContinuationEvidence(directory, content, metadata, decryptionKeys,
                            diagnosticPermission));
        return this;
    }

    boolean nativeOwned(CaseContext context) {
        return (nativePropagation != null && ShibbolethNativeSloPropagationEvidence.CASE.equals(id())
                && nativePropagation.exists(context.runId()))
                || (nativeContinuation != null && ShibbolethNativeSloContinuationEvidence.CASE.equals(id())
                && nativeContinuation.exists(context.runId()));
    }

    static boolean supports(String caseId) { return RULES.containsKey(caseId); }
    @Override public String id() { return fallback.id(); }
    @Override public TargetRole role() { return fallback.role(); }
    @Override public String evidenceCampaignId() { return "target-initiated-logout"; }
    @Override public String evidenceCampaignTitle() { return "Target-initiated browser logout"; }
    @Override public com.samlscope.runner.RunCampaignQuery.ActionKind evidenceActionKind() {
        return com.samlscope.runner.RunCampaignQuery.ActionKind.LOGIN;
    }
    @Override public String browserInstructionsEn() { return fallback.browserInstructionsEn(); }

    @Override public CaseStep start(CaseContext context) {
        var result = observed(context);
        return result.<CaseStep>map(CaseStep.Finish::new).orElseGet(() -> fallback.start(context));
    }

    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        if (nativeOwned(context)) return new CaseStep.Finish(observed(context).orElseThrow());
        if (event instanceof CaseEvent.Aborted aborted
                && "target-initiated-not-issued".equals(aborted.reason())) {
            // The campaign ended without target-emitted evidence; record the rule's observation.
            if (!context.transcriptComplete()) return new CaseStep.Finish(LogoutTranscriptProfileCase.incompleteHistory());
            var outcome = new LogoutTranscriptProfileCase(
                    RULES.get(id()), signingCertificates.apply(context.runId()),
                    targetEntityIds.apply(context.runId()).orElse(null),
                    decryptionKeys.keyFor(context.runId()).orElse(null))
                    .evaluate(context.runId(), context.transcript(), content);
            return new CaseStep.Finish(outcome);
        }
        if (event instanceof CaseEvent.TranscriptReady) {
            return observed(context).<CaseStep>map(CaseStep.Finish::new)
                    .orElseThrow(() -> new IllegalStateException("SLO Transcript evidence is not ready"));
        }
        return fallback.resume(context, state, event);
    }

    @Override public EvidenceStatus evidenceStatus(CaseContext context) {
        var result = observed(context);
        var required = List.of("target-emitted-slo:" + id());
        if (nativeOwned(context)) {
            boolean ready = result.map(value -> java.util.Set.of(
                    com.samlscope.core.evaluation.Outcome.SATISFIED,
                    com.samlscope.core.evaluation.Outcome.SATISFIED_WITH_NOTE,
                    com.samlscope.core.evaluation.Outcome.VIOLATED).contains(value.outcome())).orElse(false);
            return new EvidenceStatus(ready, required, ready ? required : List.of(),
                    result.map(com.samlscope.core.evaluation.CaseOutcome::details).orElseGet(Map::of));
        }
        var incomplete = result.map(value -> "slo.evidence.incomplete".equals(value.reasonCode())).orElse(false);
        return new EvidenceStatus(result.isPresent(), required, result.isPresent() && !incomplete ? required : List.of(),
                result.<Map<String, Object>>map(value -> Map.of(
                        "outcome", value.outcome().name(), "evidence_count", value.evidence().size(),
                        "evidence_issues", value.details().getOrDefault("evidence_issues", List.of())))
                        .orElseGet(Map::of));
    }

    @Override
    public boolean supportsRecordedEvidenceReevaluation(
            com.samlscope.core.evaluation.CaseOutcome previous) {
        return previous != null && previous.outcome() == com.samlscope.core.evaluation.Outcome.NOT_VERIFIED;
    }

    @Override
    public Optional<com.samlscope.core.evaluation.CaseOutcome> reevaluateRecordedEvidence(
            CaseContext context, com.samlscope.core.evaluation.CaseOutcome previous) {
        return observed(context).flatMap(next -> RecordedEvidenceReevaluation.conclusiveUpdate(previous, next));
    }

    private Optional<com.samlscope.core.evaluation.CaseOutcome> observed(CaseContext context) {
        if (!context.transcriptComplete()) return Optional.of(LogoutTranscriptProfileCase.incompleteHistory());
        if (nativeOwned(context)) {
            if (ShibbolethNativeSloContinuationEvidence.CASE.equals(id()))
                return Optional.of(nativeContinuation.read(context, id()).orElseGet(() ->
                        com.samlscope.core.evaluation.CaseOutcome.notVerified(
                                "native_soap_continuation_unproven", "slo.propagation.native-soap-evidence-incomplete")));
            return Optional.of(nativePropagation.read(context, id()).orElseGet(() ->
                    com.samlscope.core.evaluation.CaseOutcome.notVerified(
                            "native_slo_originals_unproven", "slo.native-propagation.evidence-incomplete")));
        }
        var outcome = new LogoutTranscriptProfileCase(
                RULES.get(id()), signingCertificates.apply(context.runId()),
                targetEntityIds.apply(context.runId()).orElse(null),
                decryptionKeys.keyFor(context.runId()).orElse(null))
                .evaluate(context.runId(), context.transcript(), content);
        return outcome.evidence().isEmpty() && !"slo.evidence.incomplete".equals(outcome.reasonCode())
                ? Optional.empty() : Optional.of(outcome);
    }
}
