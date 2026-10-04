package com.samlscope.runner.cases;

import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseState;
import com.samlscope.core.caseexec.CaseStep;
import com.samlscope.core.caseexec.TestCase;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.runner.RecordedEvidenceReevaluation;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;

/** Adds the approved verified-nonuse path while preserving the existing active oracle. */
final class NativeUiFeatureAbsenceTestCase implements TestCase, QueuedProtocolEvidenceCase,
        RecordedEvidenceReevaluation {
    private final TestCase delegate;
    private final Function<String, byte[]> metadata;
    private final NativeUiFeatureAbsenceEvidence evidence;
    private final ShibbolethUiConsumerEvidence nativeShibboleth;
    private final SimpleSamlPhpConsentUriEvidence nativeSimpleSamlPhp;

    NativeUiFeatureAbsenceTestCase(TestCase delegate, Function<String, byte[]> metadata,
            NativeUiFeatureAbsenceEvidence evidence) {
        this(delegate, metadata, evidence, null);
    }

    NativeUiFeatureAbsenceTestCase(TestCase delegate, Function<String, byte[]> metadata,
            NativeUiFeatureAbsenceEvidence evidence, ShibbolethUiConsumerEvidence nativeShibboleth) {
        this(delegate, metadata, evidence, nativeShibboleth, null);
    }

    NativeUiFeatureAbsenceTestCase(TestCase delegate, Function<String, byte[]> metadata,
            NativeUiFeatureAbsenceEvidence evidence, ShibbolethUiConsumerEvidence nativeShibboleth,
            SimpleSamlPhpConsentUriEvidence nativeSimpleSamlPhp) {
        this.delegate = Objects.requireNonNull(delegate);
        this.metadata = Objects.requireNonNull(metadata);
        this.evidence = Objects.requireNonNull(evidence);
        this.nativeShibboleth = nativeShibboleth;
        this.nativeSimpleSamlPhp = nativeSimpleSamlPhp;
        if (!NativeUiFeatureAbsenceEvidence.SUPPORTED.contains(delegate.id())) {
            throw new IllegalArgumentException("Unsupported native UI absence case");
        }
    }

    @Override public String id() { return delegate.id(); }
    @Override public TargetRole role() { return delegate.role(); }

    @Override public CaseStep start(CaseContext context) {
        var nativeOutcome = nativeOutcome(context);
        return nativeOutcome.<CaseStep>map(CaseStep.Finish::new).orElseGet(() -> delegate.start(context));
    }

    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        var nativeOutcome = nativeOutcome(context);
        return nativeOutcome.<CaseStep>map(CaseStep.Finish::new)
                .orElseGet(() -> delegate.resume(context, state, event));
    }

    @Override public CaseOutcome queuedEvidenceOutcome(CaseContext context) {
        return nativeOutcome(context).orElseGet(() -> delegate instanceof QueuedProtocolEvidenceCase queued
                ? queued.queuedEvidenceOutcome(context)
                : CaseOutcome.notVerified("native_ui_feature_evidence_unproven",
                        "browser.ui-native-feature.evidence-incomplete"));
    }

    @Override public EvidenceStatus evidenceStatus(CaseContext context) {
        var nativeOutcome = nativeOutcome(context);
        if (nativeOutcome.isPresent()) {
            boolean ready = nativeOutcome.get().outcome() != Outcome.NOT_VERIFIED;
            return new EvidenceStatus(ready, List.of("native-ui-feature-absence"),
                    ready ? List.of("native-ui-feature-absence") : List.of(), nativeOutcome.get().details());
        }
        if (delegate instanceof ProtocolEvidenceCase protocol) return protocol.evidenceStatus(context);
        return new EvidenceStatus(false, List.of("native-ui-feature-absence"), List.of(),
                java.util.Map.of("reason", "native_ui_feature_evidence_unproven"));
    }

    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous) {
        return previous != null && previous.outcome() == Outcome.NOT_VERIFIED;
    }

    @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(
            CaseContext context, CaseOutcome previous) {
        if (!context.transcriptComplete() || !supportsRecordedEvidenceReevaluation(previous)) {
            return Optional.empty();
        }
        var nativeOutcome = nativeOutcome(context);
        if (nativeOutcome.isPresent()) {
            return RecordedEvidenceReevaluation.conclusiveUpdate(previous, nativeOutcome.get());
        }
        if (delegate instanceof RecordedEvidenceReevaluation recorded
                && recorded.supportsRecordedEvidenceReevaluation(previous)) {
            return recorded.reevaluateRecordedEvidence(context, previous);
        }
        // Older wrapper results may carry its reason rather than the delegate's.
        // This opt-in path consumes recorded originals without starting a scenario.
        return delegate instanceof QueuedProtocolEvidenceCase queued
                ? RecordedEvidenceReevaluation.conclusiveUpdate(previous, queued.queuedEvidenceOutcome(context))
                : Optional.empty();
    }

    private Optional<CaseOutcome> nativeOutcome(CaseContext context) {
        boolean shibbolethOwned = nativeShibboleth != null && nativeShibboleth.exists(context.runId());
        boolean simpleSamlPhpOwned = NativeUiFeatureAbsenceEvidence.DISCOVERY.equals(id())
                && nativeSimpleSamlPhp != null && nativeSimpleSamlPhp.exists(context.runId());
        try {
            if ((shibbolethOwned ? 1 : 0) + (simpleSamlPhpOwned ? 1 : 0)
                    + (evidence.exists(context.runId()) ? 1 : 0) > 1)
                return Optional.of(unprovenShibboleth());
            if (simpleSamlPhpOwned)
                return Optional.of(nativeSimpleSamlPhp.evaluateDiscovery(context, metadata.apply(context.runId()))
                        .orElseGet(NativeUiFeatureAbsenceTestCase::unprovenShibboleth));
            if (shibbolethOwned) {
                return Optional.of(nativeShibboleth.read(context, metadata.apply(context.runId()), id())
                        .orElseGet(NativeUiFeatureAbsenceTestCase::unprovenShibboleth));
            }
            return evidence.read(context, metadata.apply(context.runId()), id());
        } catch (Exception unavailable) {
            if (shibbolethOwned || simpleSamlPhpOwned)
                return Optional.of(unprovenShibboleth());
            return Optional.empty();
        }
    }

    private static CaseOutcome unprovenShibboleth() {
        return CaseOutcome.notVerified("native_shibboleth_ui_originals_unproven",
                "browser.ui-native-feature.evidence-incomplete");
    }
}
