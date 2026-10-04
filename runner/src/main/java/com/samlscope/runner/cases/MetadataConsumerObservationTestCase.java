package com.samlscope.runner.cases;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseState;
import com.samlscope.core.caseexec.CaseStep;
import com.samlscope.core.caseexec.TestCase;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.Direction;
import com.samlscope.core.transcript.TranscriptContentReader;

/**
 * Observes a target consuming controlled metadata variants. Configuration is a setup step; the
 * verdict is derived from Suite-recorded fetches and variant-correlated inbound SAML only. For the
 * excluded-content rule a Run-scoped native rejection receipt can prove that the target refused a
 * document whose signed content is excluded, which is the other way to ensure non-use.
 */
public final class MetadataConsumerObservationTestCase
        implements TestCase, ConfigurationPrompt, ProtocolEvidenceCase, com.samlscope.runner.EvidenceCampaignCase,
        com.samlscope.runner.RecordedEvidenceReevaluation {
    public enum Rule { PERMITTED_IDENTITY_TRANSFORM, EXCLUDED_CONTENT, OMITTED_KEY_INFO }

    private static final String CONFIGURATION_PHASE = "await-metadata-consumer-probe";
    private static final String CONTROL = "control";
    private final String id;
    private final TargetRole role;
    private final Rule rule;
    private final List<String> variants;
    private final String instructionEn;
    private final TranscriptContentReader content;
    private final java.util.function.Function<String, byte[]> metadata;
    private final MetadataRejectionEvidenceFile rejectionEvidence;
    private final MetadataSignatureVerificationEvidenceFile signatureVerification;

    public MetadataConsumerObservationTestCase(String id, TargetRole role, Rule rule) {
        this(id, role, rule, null, null, null);
    }

    public MetadataConsumerObservationTestCase(String id, TargetRole role, Rule rule,
            TranscriptContentReader content, java.util.function.Function<String, byte[]> metadata,
            java.nio.file.Path rejectionDirectory) {
        this.id = required(id, "id");
        this.role = java.util.Objects.requireNonNull(role, "role");
        this.rule = java.util.Objects.requireNonNull(rule, "rule");
        this.variants = switch (rule) {
            case PERMITTED_IDENTITY_TRANSFORM -> List.of("xpath-identity");
            case EXCLUDED_CONTENT -> List.of(
                    "xpath-exclude-role-descriptors",
                    "xpath-exclude-endpoints",
                    "xpath-exclude-key-descriptors");
            case OMITTED_KEY_INFO -> List.of("no-key-info");
        };
        this.instructionEn = instruction(rule, variants);
        this.content = content;
        this.metadata = metadata;
        this.rejectionEvidence = rejectionDirectory == null ? null : new MetadataRejectionEvidenceFile(rejectionDirectory);
        this.signatureVerification = rejectionDirectory == null
                ? null : new MetadataSignatureVerificationEvidenceFile(rejectionDirectory);
    }

    /**
     * The transform and KeyInfo rules only decide once the target verifies the document signature.
     * Fail closed when the evidence directory is not wired so a real Run can never treat a missing
     * receipt as proof.
     */
    private boolean signatureVerificationProven(CaseContext context) {
        if (signatureVerification == null || metadata == null || content == null) return false;
        try {
            signatureVerification.verify(context, metadata.apply(context.runId()), content, evidenceCampaignId());
            return true;
        } catch (Exception unproven) {
            return false;
        }
    }

    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous) {
        return previous != null && previous.outcome() == Outcome.NOT_VERIFIED
                && ("metadata.consumer-probe.incomplete".equals(previous.reasonCode())
                    || "metadata.signature-verification.unproven".equals(previous.reasonCode()));
    }

    @Override public java.util.Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context, CaseOutcome previous) {
        if (!supportsRecordedEvidenceReevaluation(previous) || !context.transcriptComplete()) return java.util.Optional.empty();
        var fromReceipt = concludeFromReceipt(context, previous);
        if (fromReceipt.isPresent()) return fromReceipt;
        var next = evaluate(context, false);
        if ("metadata.signature-verification.unproven".equals(previous.reasonCode())) {
            // The original probe evidence is already in the previous outcome. Record the actual
            // signature-proof originals read by the gate so a late proof can be a new, auditable
            // basis for conclusiveUpdate without replaying the protocol operation.
            if (next.outcome() != Outcome.SATISFIED && next.outcome() != Outcome.SATISFIED_WITH_NOTE
                    && next.outcome() != Outcome.VIOLATED) return java.util.Optional.empty();
            var proofEvidence = new ArrayList<EvidenceRef>();
            try {
                signatureVerification.verify(context, metadata.apply(context.runId()), entry -> {
                    var original = content.readDecodedSaml(entry);
                    proofEvidence.add(new EvidenceRef("transcript", "transcript:" + entry.id()));
                    return original;
                }, evidenceCampaignId());
            } catch (Exception unproven) {
                return java.util.Optional.empty();
            }
            var refs = new ArrayList<>(next.evidence());
            refs.addAll(proofEvidence);
            next = new CaseOutcome(next.outcome(), next.notVerifiedReason(), next.reasonCode(),
                    next.reasonMessageKey(), distinct(refs), next.details());
        }
        return com.samlscope.runner.RecordedEvidenceReevaluation.conclusiveUpdate(previous, next);
    }

    /** A native refusal of every probed document proves the recorded choice without a probe flow. */
    private java.util.Optional<CaseOutcome> concludeFromReceipt(CaseContext context, CaseOutcome previous) {
        if ((rule != Rule.EXCLUDED_CONTENT && rule != Rule.PERMITTED_IDENTITY_TRANSFORM)
                || rejectionEvidence == null || content == null || metadata == null) {
            return java.util.Optional.empty();
        }
        // A native refusal is only meaningful once the target is proven to verify document
        // signatures, so the receipt path obeys the same precondition as the probe path.
        if (!signatureVerificationProven(context)) return java.util.Optional.empty();
        if (previous.outcome() != Outcome.NOT_VERIFIED
                || !"metadata.consumer-probe.incomplete".equals(previous.reasonCode())
                || !rejectionEvidence.exists(context.runId())) {
            return java.util.Optional.empty();
        }
        try {
            var proven = rejectionEvidence.rejectedVariants(context, metadata.apply(context.runId()), content);
            var details = previous.details();
            if (!stringList(details.get("missing_fetches")).isEmpty() || !proven.keySet().containsAll(variants)) {
                return java.util.Optional.empty();
            }
            var verified = new java.util.LinkedHashMap<String, Object>(details);
            verified.put("native_rejections", new java.util.LinkedHashMap<>(proven));
            verified.put("evidence_source", "local-native-adapter");
            var refs = new ArrayList<EvidenceRef>(previous.evidence());
            for (var entry : context.transcript().list(context.runId())) {
                if ("MetadataPrepared".equals(entry.samlSummary().get("type"))
                        && proven.containsKey(String.valueOf(entry.samlSummary().get("variant")))) {
                    var ref = new EvidenceRef("transcript", "transcript:" + entry.id());
                    if (!refs.contains(ref)) refs.add(ref);
                }
            }
            var outcome = rule == Rule.EXCLUDED_CONTENT ? Outcome.SATISFIED : Outcome.SATISFIED_WITH_NOTE;
            var code = rule == Rule.EXCLUDED_CONTENT
                    ? "metadata.excluded-content.rejected" : "metadata.unauthorized-transform.rejected";
            return java.util.Optional.of(new CaseOutcome(outcome, null, code, code, List.copyOf(refs), verified));
        } catch (Exception unproven) {
            return java.util.Optional.empty();
        }
    }

    private static List<String> stringList(Object value) {
        return value instanceof List<?> values && values.stream().allMatch(String.class::isInstance)
                ? values.stream().map(String.class::cast).toList() : List.of();
    }

    @Override public String id() { return id; }
    @Override public TargetRole role() { return role; }
    @Override public String evidenceCampaignId() { return "metadata-fixture-refresh"; }
    @Override public String evidenceCampaignTitle() { return "Refresh or re-import Suite metadata fixtures"; }
    @Override public com.samlscope.runner.RunCampaignQuery.ActionKind evidenceActionKind() {
        return com.samlscope.runner.RunCampaignQuery.ActionKind.METADATA_REFRESH;
    }
    @Override public String instructionEn() { return instructionEn; }

    @Override
    public CaseStep start(CaseContext context) {
        return new CaseStep.AwaitConfig(
                new CaseState(CONFIGURATION_PHASE, Map.of()), List.of(),
                "metadata-consumer-probe", Duration.ofHours(24));
    }

    @Override
    public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        if (!CONFIGURATION_PHASE.equals(state.phase())) {
            throw new IllegalArgumentException("Metadata consumer case is not waiting for its probe");
        }
        if (event instanceof CaseEvent.ConfigConfirmed) {
            var outcome = evaluate(context, true);
            return concludeFromReceipt(context, outcome)
                    .<CaseStep>map(CaseStep.Finish::new).orElseGet(() -> new CaseStep.Finish(outcome));
        }
        if (event instanceof CaseEvent.ConfigUnavailable unavailable) {
            return new CaseStep.Finish(unavailable(unavailable));
        }
        if (event instanceof CaseEvent.TimedOut) {
            return new CaseStep.Finish(CaseOutcome.notVerified(
                    "metadata_consumer_probe_timeout", "metadata.consumer-probe.timeout"));
        }
        if (event instanceof CaseEvent.Aborted) {
            return new CaseStep.Finish(CaseOutcome.notVerified(
                    "metadata_consumer_probe_skipped", "metadata.consumer-probe.skipped"));
        }
        throw new IllegalArgumentException("Expected metadata consumer configuration completion");
    }

    private CaseOutcome evaluate(CaseContext context, boolean attemptsConfirmed) {
        var observation = observe(context);
        var fetched = observation.fetched();
        var used = observation.used();
        var evidence = observation.evidence();
        var details = observation.details();
        var ready = observation.ready();
        if (!ready) {
            return new CaseOutcome(
                    Outcome.NOT_VERIFIED, "metadata_consumer_probe_incomplete",
                    "metadata.consumer-probe.incomplete", "metadata.consumer-probe.incomplete",
                    distinct(evidence), details);
        }
        // A consumer that never verifies the document signature accepts every transform/KeyInfo
        // variant through its parser, so acceptance alone cannot decide these rules.
        if (!signatureVerificationProven(context)) {
            return new CaseOutcome(
                    Outcome.NOT_VERIFIED, "metadata_signature_verification_unproven",
                    "metadata.signature-verification.unproven", "metadata.signature-verification.unproven",
                    distinct(evidence), details);
        }
        return switch (rule) {
            case PERMITTED_IDENTITY_TRANSFORM -> new CaseOutcome(
                    Outcome.SATISFIED_WITH_NOTE, null,
                    used.containsAll(variants)
                            ? "metadata.unauthorized-transform.safely-accepted"
                            : "metadata.unauthorized-transform.rejected",
                    "metadata.unauthorized-transform.choice-recorded", distinct(evidence), details);
            case EXCLUDED_CONTENT -> new CaseOutcome(
                    variants.stream().anyMatch(used::contains) ? Outcome.VIOLATED : Outcome.SATISFIED,
                    null,
                    variants.stream().anyMatch(used::contains)
                            ? "metadata.excluded-content.accepted"
                            : "metadata.excluded-content.rejected",
                    variants.stream().anyMatch(used::contains)
                            ? "metadata.excluded-content.accepted"
                            : "metadata.excluded-content.rejected",
                    distinct(evidence), details);
            case OMITTED_KEY_INFO -> new CaseOutcome(
                    used.containsAll(variants) ? Outcome.SATISFIED : Outcome.VIOLATED,
                    null,
                    used.containsAll(variants)
                            ? "metadata.key-info-omission.accepted"
                            : "metadata.key-info-omission.rejected",
                    used.containsAll(variants)
                            ? "metadata.key-info-omission.accepted"
                            : "metadata.key-info-omission.rejected",
                    distinct(evidence), details);
        };
    }

    @Override
    public EvidenceStatus evidenceStatus(CaseContext context) {
        var observation = observe(context);
        var fromReceipt = rejectionStatus(context, observation);
        if (fromReceipt != null) return requireSignatureVerification(context, fromReceipt);
        var required = new ArrayList<String>();
        required.add("fetched:" + CONTROL);
        required.add("used:" + CONTROL);
        variants.forEach(variant -> required.add("fetched:" + variant));
        required.add(rule == Rule.EXCLUDED_CONTENT ? "used:any-excluded-content" : "used:" + variants.getFirst());
        var completed = new ArrayList<String>();
        if (observation.fetched().contains(CONTROL)) completed.add("fetched:" + CONTROL);
        if (observation.used().contains(CONTROL)) completed.add("used:" + CONTROL);
        variants.stream().filter(observation.fetched()::contains)
                .forEach(variant -> completed.add("fetched:" + variant));
        if (rule == Rule.EXCLUDED_CONTENT) {
            if (variants.stream().anyMatch(observation.used()::contains)) {
                completed.add("used:any-excluded-content");
            }
        } else if (observation.used().contains(variants.getFirst())) {
            completed.add("used:" + variants.getFirst());
        }
        return requireSignatureVerification(context, new EvidenceStatus(
                observation.ready(), required,
                completed, observation.details()));
    }

    private EvidenceStatus requireSignatureVerification(CaseContext context, EvidenceStatus status) {
        if (signatureVerificationProven(context)) return status;
        var required = new ArrayList<>(status.requiredObservations());
        required.add("signature-verification:out-of-band-anchor");
        return new EvidenceStatus(false, required, status.completedObservations(), status.details());
    }

    /** When a rejection receipt covers every excluding document, non-use of excluded content is proven. */
    private EvidenceStatus rejectionStatus(CaseContext context, Observation observation) {
        if ((rule != Rule.EXCLUDED_CONTENT && rule != Rule.PERMITTED_IDENTITY_TRANSFORM)
                || rejectionEvidence == null || content == null || metadata == null
                || !context.transcriptComplete() || !rejectionEvidence.exists(context.runId())) {
            return null;
        }
        Map<String, String> proven;
        try {
            proven = rejectionEvidence.rejectedVariants(context, metadata.apply(context.runId()), content);
        } catch (Exception unproven) {
            return null;
        }
        var required = new ArrayList<String>();
        required.add("fetched:" + CONTROL);
        required.add("used:" + CONTROL);
        variants.forEach(variant -> required.add("fetched:" + variant));
        variants.forEach(variant -> required.add("conclusive-rejection:" + variant));
        var completed = new ArrayList<String>();
        if (observation.fetched().contains(CONTROL)) completed.add("fetched:" + CONTROL);
        if (observation.used().contains(CONTROL)) completed.add("used:" + CONTROL);
        variants.stream().filter(observation.fetched()::contains).forEach(variant -> completed.add("fetched:" + variant));
        variants.stream().filter(proven::containsKey).forEach(variant -> completed.add("conclusive-rejection:" + variant));
        var details = new java.util.LinkedHashMap<String, Object>(observation.details());
        details.put("native_rejections", new java.util.LinkedHashMap<>(proven));
        return new EvidenceStatus(required.stream().allMatch(completed::contains),
                required, completed, details);
    }

    private Observation observe(CaseContext context) {
        var entries = context.transcript().list(context.runId());
        var fetched = new LinkedHashSet<String>();
        var used = new LinkedHashSet<String>();
        var evidence = new ArrayList<EvidenceRef>();
        for (var entry : entries) {
            if (MetadataProbeCorrelation.signatureControl(entry)) continue;
            if (entry.direction() != Direction.INBOUND) continue;
            if ("MetadataFetch".equals(entry.samlSummary().get("type"))) {
                var variant = String.valueOf(entry.samlSummary().get("variant"));
                if (CONTROL.equals(variant) || variants.contains(variant)) {
                    fetched.add(variant);
                    evidence.add(new EvidenceRef("transcript", "transcript:" + entry.id()));
                }
                if (entry.samlSummary().get("variants") instanceof List<?> aggregate) {
                    for (var item : aggregate) {
                        if (item instanceof String value && (CONTROL.equals(value) || variants.contains(value))) fetched.add(value);
                    }
                    if (aggregate.stream().anyMatch(item -> item instanceof String value
                            && variants.contains(value))) {
                        evidence.add(new EvidenceRef("transcript", "transcript:" + entry.id()));
                    }
                }
            }
            var requestUse = "AuthnRequest".equals(entry.samlSummary().get("type"));
            var responseUse = "Response".equals(entry.samlSummary().get("type"))
                    && Boolean.TRUE.equals(entry.samlSummary().get("metadataProbeAccepted"))
                    && "urn:oasis:names:tc:SAML:2.0:status:Success".equals(
                            entry.samlSummary().get("statusCode"));
            if (entry.decodedSamlBytes() > 0 && entry.url() != null && (requestUse || responseUse)) {
                for (var variant : union(CONTROL, variants)) {
                    if (fetched.contains(variant)
                            && MetadataProbeCorrelation.matches(entry.url(), context.runId(), variant)) {
                        used.add(variant);
                        evidence.add(new EvidenceRef("transcript", "transcript:" + entry.id()));
                    }
                }
            }
        }
        var details = Map.<String, Object>of(
                "required_variants", variants,
                "fetched_variants", List.copyOf(fetched),
                "used_variants", List.copyOf(used),
                "missing_fetches", union(CONTROL, variants).stream()
                        .filter(value -> !fetched.contains(value)).toList(),
                "missing_protocol_observations", union(CONTROL, variants).stream()
                        .filter(value -> !used.contains(value)).toList(),
                "transcript_complete", context.transcriptComplete());
        var conclusiveVariantObservation = rule == Rule.EXCLUDED_CONTENT
                ? variants.stream().anyMatch(used::contains)
                : used.containsAll(variants);
        // A metadata fetch is not proof that the target attempted or rejected a SAML flow. Only a
        // correlated message is conclusive: it proves acceptance, which is a violation for the
        // excluded-content rule and the permitted/satisfied path for the other two rules.
        return new Observation(
                fetched.contains(CONTROL) && used.contains(CONTROL)
                        && fetched.containsAll(variants) && conclusiveVariantObservation && context.transcriptComplete(),
                fetched.contains(CONTROL) && used.contains(CONTROL)
                        && fetched.containsAll(variants),
                fetched, used, distinct(evidence), details);
    }

    private CaseOutcome unavailable(CaseEvent.ConfigUnavailable event) {
        return new CaseOutcome(
                Outcome.NOT_VERIFIED, "metadata_consumer_probe_unavailable",
                "metadata.consumer-probe.unavailable", "metadata.consumer-probe.unavailable",
                List.of(), Map.of(
                        "configuration_issue", event.issue().name().toLowerCase(java.util.Locale.ROOT),
                        "configuration_note", event.note()));
    }

    private static String instruction(Rule rule, List<String> variants) {
        return "Configure the target once with the stable Suite metadata URL "
                + "`/p/<plan-id>/metadata/live?run=<run-id>`. Select `control` in the metadata lab, trigger the "
                + "target's standard metadata refresh or re-import, and complete one SSO flow. Then select each "
                + "fixture " + variants + ", refresh or re-import through the same product-neutral metadata "
                + "interface, and attempt the same flow. After all attempts, evaluate the recorded protocol "
                + "evidence once for the Run. SAMLscope derives the outcome; do not enter an expected verdict. "
                + "Probe rule: " + rule.name().toLowerCase(java.util.Locale.ROOT) + ".";
    }

    private static List<String> union(String first, List<String> rest) {
        var result = new ArrayList<String>();
        result.add(first);
        result.addAll(rest);
        return result;
    }

    private static List<EvidenceRef> distinct(List<EvidenceRef> evidence) {
        return evidence.stream().distinct().toList();
    }

    private static String required(String value, String name) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(name + " is required");
        return value;
    }

    private record Observation(
            boolean ready,
            boolean attemptPrerequisitesComplete,
            Set<String> fetched,
            Set<String> used,
            List<EvidenceRef> evidence,
            Map<String, Object> details) {}
}
