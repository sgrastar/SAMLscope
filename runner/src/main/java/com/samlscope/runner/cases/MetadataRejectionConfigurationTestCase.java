package com.samlscope.runner.cases;

import java.nio.file.Path;
import java.util.*;
import java.util.function.Function;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.TranscriptContentReader;

/**
 * Native metadata rejection augments the approved metadata fixture campaign. A product that refuses a
 * reject fixture through its own metadata path is accepted only when the Run-scoped receipt proves the
 * refusal against the fetched original. Without such a receipt the approved fixture oracle decides.
 */
public final class MetadataRejectionConfigurationTestCase implements TestCase, ConfigurationPrompt,
        ProtocolEvidenceCase, com.samlscope.runner.EvidenceCampaignCase,
        com.samlscope.runner.RecordedEvidenceReevaluation {
    private static final Set<String> CASES = Set.of(
            "IIP-MD03-a-idp-01", "IIP-MD04-a-idp-01", "IIP-MD04-b-idp-01", "IIP-MD04-c-idp-01",
            // MUST_NOT: a document the target refuses to load cannot have its endpoints or keys used.
            "IIP-MD05-as-idp-01");
    private final TestCase fallback;
    private final MetadataFixtureObservationTestCase observer;
    private final TranscriptContentReader content;
    private final Function<String, byte[]> metadata;
    private final MetadataRejectionEvidenceFile evidence;

    public MetadataRejectionConfigurationTestCase(TestCase fallback, TranscriptContentReader content,
            Function<String, byte[]> metadata, Path directory) {
        this.fallback = Objects.requireNonNull(fallback);
        if (!(fallback instanceof MetadataFixtureObservationTestCase fixtureObserver))
            throw new IllegalArgumentException("Native metadata rejection requires a fixture observer");
        this.observer = fixtureObserver;
        this.content = Objects.requireNonNull(content);
        this.metadata = Objects.requireNonNull(metadata);
        this.evidence = new MetadataRejectionEvidenceFile(directory);
        if (!supports(fallback.id())) throw new IllegalArgumentException("Unsupported metadata rejection case");
    }

    public static boolean supports(String id) { return CASES.contains(id); }

    @Override public String id() { return fallback.id(); }
    @Override public TargetRole role() { return fallback.role(); }
    @Override public String instructionEn() { return ((ConfigurationPrompt) fallback).instructionEn(); }
    @Override public boolean requiresPreparationConfirmation() { return true; }
    @Override public CaseStep start(CaseContext context) { return fallback.start(context); }
    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        var step = fallback.resume(context, state, event);
        if (!(event instanceof CaseEvent.ConfigConfirmed) || !(step instanceof CaseStep.Finish finish)) return step;
        return concludeFromReceipt(context, finish.outcome())
                .<CaseStep>map(CaseStep.Finish::new).orElse(step);
    }

    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous) {
        return previous != null && previous.outcome() == Outcome.NOT_VERIFIED
                && "metadata.fixture-probe.incomplete".equals(previous.reasonCode());
    }

    @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context, CaseOutcome previous) {
        if (!supportsRecordedEvidenceReevaluation(previous) || !context.transcriptComplete())
            return Optional.empty();
        return concludeFromReceipt(context, previous);
    }

    /** Concludes SATISFIED only when every accept fixture was used and every reject fixture was natively refused. */
    private Optional<CaseOutcome> concludeFromReceipt(CaseContext context, CaseOutcome outcome) {
        if (outcome.outcome() != Outcome.NOT_VERIFIED || !evidence.exists(context.runId())) return Optional.empty();
        try {
            var proven = evidence.rejectedVariants(context, metadata.apply(context.runId()), content);
            var details = outcome.details();
            var missingFetches = stringList(details.get("missing_fetches"));
            var missingAcceptance = stringList(details.get("missing_acceptance"));
            var unresolved = stringList(details.get("unresolved_rejection"));
            if (!missingFetches.isEmpty() || !missingAcceptance.isEmpty() || unresolved.isEmpty()) return Optional.empty();
            if (proven.size() != unresolved.size() || !proven.keySet().containsAll(unresolved)) return Optional.empty();
            var verified = new LinkedHashMap<String, Object>(details);
            verified.put("native_rejections", new LinkedHashMap<>(proven));
            verified.put("evidence_source", "local-native-adapter");
            verified.put("rejected_variants", new ArrayList<>(proven.keySet()));
            return Optional.of(new CaseOutcome(Outcome.SATISFIED, null,
                    "metadata.fixture-probe.satisfied", "metadata.fixture-probe.satisfied",
                    outcome.evidence(), verified));
        } catch (Exception unproven) {
            return Optional.empty();
        }
    }

    @Override public EvidenceStatus evidenceStatus(CaseContext context) {
        var base = observer.evidenceStatus(context);
        if (!evidence.exists(context.runId())) return base;
        try {
            var proven = evidence.rejectedVariants(context, metadata.apply(context.runId()), content);
            var completed = new ArrayList<>(base.completedObservations());
            for (var required : base.requiredObservations()) {
                if (!required.startsWith("conclusive-rejection:")) continue;
                var variant = required.substring("conclusive-rejection:".length());
                if (proven.containsKey(variant) && !completed.contains(required)) completed.add(required);
            }
            var details = new LinkedHashMap<String, Object>(base.details());
            details.put("native_rejections", new LinkedHashMap<>(proven));
            return new EvidenceStatus(base.requiredObservations().stream().allMatch(completed::contains),
                    base.requiredObservations(), completed, details);
        } catch (Exception unproven) {
            return base;
        }
    }

    @Override public String evidenceCampaignId() { return ((com.samlscope.runner.EvidenceCampaignCase) fallback).evidenceCampaignId(); }
    @Override public String evidenceCampaignTitle() { return ((com.samlscope.runner.EvidenceCampaignCase) fallback).evidenceCampaignTitle(); }
    @Override public com.samlscope.runner.RunCampaignQuery.ActionKind evidenceActionKind() {
        return ((com.samlscope.runner.EvidenceCampaignCase) fallback).evidenceActionKind();
    }
    @Override public List<String> evidenceActionKeys() { return ((com.samlscope.runner.EvidenceCampaignCase) fallback).evidenceActionKeys(); }
    @Override public List<com.samlscope.runner.EvidenceCampaignCase> supplementalEvidenceCampaigns() {
        return ((com.samlscope.runner.EvidenceCampaignCase) fallback).supplementalEvidenceCampaigns();
    }

    private static List<String> stringList(Object value) {
        return value instanceof List<?> values && values.stream().allMatch(String.class::isInstance)
                ? values.stream().map(String.class::cast).toList() : List.of();
    }
}
