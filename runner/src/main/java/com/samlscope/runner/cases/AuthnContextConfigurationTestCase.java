package com.samlscope.runner.cases;

import java.nio.file.Path;
import java.util.*;
import java.util.function.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.saml.crypto.PlanCredentials;

/** Native preparation enables protocol comparison; manual evidence review remains available. */
public final class AuthnContextConfigurationTestCase implements TestCase, ConfigurationPrompt,
        ProtocolEvidenceCase, com.samlscope.runner.EvidenceCampaignCase, com.samlscope.runner.RecordedEvidenceReevaluation {
    private final TestCase fallback;
    private final TranscriptContentReader content;
    private final Function<String, byte[]> metadata;
    private final BiFunction<String, String, Optional<PlanCredentials>> keys;
    private final AuthnContextPreparationFile preparations;

    public AuthnContextConfigurationTestCase(TestCase fallback, TranscriptContentReader content,
            Function<String, byte[]> metadata, BiFunction<String, String, Optional<PlanCredentials>> keys, Path directory) {
        this.fallback = Objects.requireNonNull(fallback); this.content = Objects.requireNonNull(content);
        this.metadata = Objects.requireNonNull(metadata); this.keys = Objects.requireNonNull(keys);
        preparations = new AuthnContextPreparationFile(directory);
        if (!supports(fallback.id())) throw new IllegalArgumentException("Unsupported authentication context case");
    }
    public static boolean supports(String id) {
        return List.of("IIP-SSO01-ga-idp-01", "IIP-SSO01-gb-idp-01", "IIP-SSO01-gc-idp-01", "IIP-SSO01-gj-idp-01").contains(id);
    }
    @Override public String id() { return fallback.id(); }
    @Override public TargetRole role() { return fallback.role(); }
    @Override public boolean requiresPreparationConfirmation() { return true; }
    @Override public String instructionEn() {
        return "Prepare the target's native context ordering and satisfiable candidates, execute signed comparison "
                + "requests for ClassRef and DeclRef with fixed login inputs, and restore native configuration. "
                + "Confirmation alone does not establish conformance.";
    }
    @Override public String evidenceCampaignId() { return "authn-context-comparison"; }
    @Override public String evidenceCampaignTitle() { return "Native authentication context comparisons"; }
    @Override public com.samlscope.runner.RunCampaignQuery.ActionKind evidenceActionKind() {
        return com.samlscope.runner.RunCampaignQuery.ActionKind.CONFIGURATION;
    }
    @Override public List<String> evidenceActionKeys() {
        return List.of();
    }
    @Override public CaseStep start(CaseContext context) { return fallback.start(context); }
    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        if (event instanceof CaseEvent.ConfigConfirmed) {
            var outcome = observe(context);
            if (outcome.outcome() == Outcome.SATISFIED || outcome.outcome() == Outcome.VIOLATED) {
                var details = new LinkedHashMap<String, Object>(outcome.details());
                details.put("configuration_confirmed", true);
                details.put("preparation_source", "local-native-adapter");
                return new CaseStep.Finish(new CaseOutcome(outcome.outcome(), outcome.notVerifiedReason(),
                        outcome.reasonCode(), outcome.reasonMessageKey(), outcome.evidence(), details));
            }
        }
        return fallback.resume(context, state, event);
    }
    CaseOutcome observe(CaseContext context) {
        try {
            var target = metadata.apply(context.runId());
            var preparation = preparations.read(id(), context, target, content);
            if (preparation.isEmpty()) {
                return AuthnContextComparison.evaluate(id(), null, List.of(), List.of("verified_preparation_unavailable"));
            }
            var exchanges = preparation.orElseThrow().allExchanges().stream().map(e ->
                    new AuthnContextProtocolEvidence.Exchange(e.condition(), e.metadataReference(),
                            e.requestReference(), e.responseReference())).toList();
            var protocol = AuthnContextProtocolEvidence.collect(context, content, target, keys, exchanges);
            return AuthnContextExperimentBinding.evaluate(protocol, preparation.orElseThrow());
        } catch (Exception unproven) {
            return AuthnContextComparison.evaluate(id(), null, List.of(), List.of("native_preparation_or_evidence_unproven"));
        }
    }
    @Override public EvidenceStatus evidenceStatus(CaseContext context) {
        var outcome = observe(context);
        var details = new LinkedHashMap<String, Object>(outcome.details());
        details.put("configuration_confirmation_required", true);
        return new EvidenceStatus(outcome.outcome() == Outcome.SATISFIED || outcome.outcome() == Outcome.VIOLATED, evidenceActionKeys(), List.of(), details);
    }
    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous) {
        return previous != null && previous.outcome() == Outcome.NOT_VERIFIED
                && Set.of("attestation.interaction-disallowed", "configuration.authn-context.evidence-incomplete")
                    .contains(String.valueOf(previous.reasonCode()));
    }
    @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context, CaseOutcome previous) {
        if (!supportsRecordedEvidenceReevaluation(previous)) return Optional.empty();
        var next = observe(context);
        var details = new LinkedHashMap<String, Object>(next.details());
        details.put("preparation_source", "local-native-adapter");
        details.put("recorded_evidence_rechecked", true);
        return com.samlscope.runner.RecordedEvidenceReevaluation.conclusiveUpdate(previous,
                new CaseOutcome(next.outcome(), next.notVerifiedReason(), next.reasonCode(), next.reasonMessageKey(), next.evidence(), details));
    }

}
