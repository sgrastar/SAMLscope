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
            "IIP-MD05-as-idp-01",
            // Native refusal of a schema-valid positive fixture is a product violation when the
            // baseline and every other schema-family fixture were consumed in the same Run.
            "IIP-MD05-b-idp-01",
            // Duplicate entityIDs with conflicting endpoints: the target refused to use the conflicting
            // entry, which is how it rejects such a conflict.
            "IIP-MD05-a2-idp-01");
    private final TestCase fallback;
    private final MetadataFixtureObservationTestCase observer;
    private final TranscriptContentReader content;
    private final Function<String, byte[]> metadata;
    private final MetadataRejectionEvidenceFile evidence;
    private final MetadataSignatureVerificationEvidenceFile signatureVerification;

    public MetadataRejectionConfigurationTestCase(TestCase fallback, TranscriptContentReader content,
            Function<String, byte[]> metadata, Path directory) {
        this.fallback = Objects.requireNonNull(fallback);
        if (!(fallback instanceof MetadataFixtureObservationTestCase fixtureObserver))
            throw new IllegalArgumentException("Native metadata rejection requires a fixture observer");
        this.observer = fixtureObserver;
        this.content = Objects.requireNonNull(content);
        this.metadata = Objects.requireNonNull(metadata);
        this.evidence = new MetadataRejectionEvidenceFile(directory);
        this.signatureVerification = new MetadataSignatureVerificationEvidenceFile(directory);
        if (!supports(fallback.id())) throw new IllegalArgumentException("Unsupported metadata rejection case");
    }

    /** Only the signature-rejection case depends on the target verifying the document signature. */
    private static final Set<String> SIGNATURE_CASES = Set.of("IIP-MD03-a-idp-01");

    private boolean signatureVerificationRequired() { return SIGNATURE_CASES.contains(id()); }

    /** A rejected document is only meaningful when the target actually verifies document signatures. */
    private boolean signatureVerificationProven(CaseContext context) {
        if (!signatureVerificationRequired()) return true;
        try {
            signatureVerification.verify(context, metadata.apply(context.runId()), content, evidenceCampaignId());
            return true;
        } catch (Exception unproven) {
            return false;
        }
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
        // Only the fixture-probe decisions depend on whether the target verifies document
        // signatures. Approved configuration-failure outcomes (an absent normative capability, an
        // unavailable probe) must pass unchanged.
        if (!signatureRelevant(finish.outcome())) return step;
        if (!signatureVerificationProven(context)) return new CaseStep.Finish(unproven(finish.outcome()));
        return concludeFromReceipt(context, finish.outcome())
                .<CaseStep>map(CaseStep.Finish::new).orElse(step);
    }

    /** Only the fixture-probe decisions depend on whether the target verifies document signatures. */
    private static boolean signatureRelevant(CaseOutcome outcome) {
        return "metadata.fixture-probe.incomplete".equals(outcome.reasonCode())
                || "metadata.fixture-probe.satisfied".equals(outcome.reasonCode())
                || "metadata.fixture-probe.violated".equals(outcome.reasonCode());
    }

    private static CaseOutcome unproven(CaseOutcome outcome) {
        return new CaseOutcome(Outcome.NOT_VERIFIED, "metadata_signature_verification_unproven",
                "metadata.signature-verification.unproven", "metadata.signature-verification.unproven",
                outcome.evidence(), outcome.details());
    }

    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous) {
        return previous != null && previous.outcome() == Outcome.NOT_VERIFIED
                && "metadata.fixture-probe.incomplete".equals(previous.reasonCode());
    }

    @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context, CaseOutcome previous) {
        if (!supportsRecordedEvidenceReevaluation(previous) || !context.transcriptComplete())
            return Optional.empty();
        // The signature-rejection case must not conclude through the re-evaluation path either: a
        // refusal is only meaningful once the target is proven to verify document signatures.
        if (!signatureVerificationProven(context)) return Optional.empty();
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
            if ("IIP-MD05-b-idp-01".equals(id()) && unresolved.isEmpty()
                    && missingAcceptance.contains("schema-global-element-families")
                    && proven.equals(Map.of("schema-global-element-families", "simplesamlphp-native-mdq-positive"))
                    && stringList(details.get("used_variants")).contains("control")) {
                var verified = new LinkedHashMap<String, Object>(details);
                verified.put("native_positive_refusal", new LinkedHashMap<>(proven));
                verified.put("evidence_source", "local-native-adapter");
                return Optional.of(new CaseOutcome(Outcome.VIOLATED, null,
                        "metadata.fixture-probe.violated", "metadata.fixture-probe.violated",
                        outcome.evidence(), verified));
            }
            if (!missingFetches.isEmpty() || !missingAcceptance.isEmpty() || unresolved.isEmpty()) return Optional.empty();
            if (!proven.keySet().containsAll(unresolved)) return Optional.empty();
            // A shared campaign can prove refusals for several cases. Every receipt record was
            // validated above; this conclusion uses only this case's complete required subset.
            var applicable = new LinkedHashMap<String, String>();
            for (var variant : unresolved) applicable.put(variant, proven.get(variant));
            var verified = new LinkedHashMap<String, Object>(details);
            verified.put("native_rejections", applicable);
            verified.put("evidence_source", "local-native-adapter");
            verified.put("rejected_variants", new ArrayList<>(applicable.keySet()));
            return Optional.of(new CaseOutcome(Outcome.SATISFIED, null,
                    "metadata.fixture-probe.satisfied", "metadata.fixture-probe.satisfied",
                    outcome.evidence(), verified));
        } catch (Exception unproven) {
            return Optional.empty();
        }
    }

    @Override public EvidenceStatus evidenceStatus(CaseContext context) {
        return requireSignatureVerification(context, rejectionStatus(context));
    }

    private EvidenceStatus requireSignatureVerification(CaseContext context, EvidenceStatus status) {
        if (signatureVerificationProven(context)) return status;
        var required = new ArrayList<>(status.requiredObservations());
        required.add("signature-verification:out-of-band-anchor");
        return new EvidenceStatus(false, required, status.completedObservations(), status.details());
    }

    private EvidenceStatus rejectionStatus(CaseContext context) {
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
            boolean positiveRefusal = "IIP-MD05-b-idp-01".equals(id())
                    && proven.equals(Map.of("schema-global-element-families", "simplesamlphp-native-mdq-positive"))
                    && stringList(base.details().get("missing_acceptance")).contains("schema-global-element-families")
                    && stringList(base.details().get("used_variants")).contains("control")
                    && base.requiredObservations().stream().anyMatch("fetched:schema-global-element-families"::equals)
                    && completed.contains("fetched:schema-global-element-families");
            if (positiveRefusal) completed.add("positive-refusal:schema-global-element-families");
            return new EvidenceStatus(positiveRefusal || base.requiredObservations().stream().allMatch(completed::contains),
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
