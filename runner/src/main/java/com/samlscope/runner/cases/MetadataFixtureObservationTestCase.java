package com.samlscope.runner.cases;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseState;
import com.samlscope.core.caseexec.CaseStep;
import com.samlscope.core.caseexec.ConfigurationFailureSemantics;
import com.samlscope.core.caseexec.TestCase;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.Direction;

/** Evaluates accept/reject metadata fixtures using fetches plus Run-correlated SAML traffic. */
public final class MetadataFixtureObservationTestCase
        implements TestCase, ConfigurationPrompt, ProtocolEvidenceCase, com.samlscope.runner.EvidenceCampaignCase,
        com.samlscope.runner.RecordedEvidenceReevaluation {
    private static final String PHASE = "await-metadata-fixture-probe";
    private static final String CONTROL = "control";
    private final String id;
    private final TargetRole role;
    private final List<Fixture> fixtures;
    private final ConfigurationFailureSemantics configurationSemantics;

    public MetadataFixtureObservationTestCase(
            String id,
            TargetRole role,
            List<Fixture> fixtures,
            ConfigurationFailureSemantics configurationSemantics) {
        this.id = text(id, "id");
        this.role = Objects.requireNonNull(role, "role");
        this.fixtures = List.copyOf(fixtures);
        this.configurationSemantics = Objects.requireNonNull(
                configurationSemantics, "configurationSemantics");
        if (fixtures.isEmpty()) throw new IllegalArgumentException("fixtures must not be empty");
        var ids = new LinkedHashSet<String>();
        for (var fixture : fixtures) {
            if (CONTROL.equals(fixture.variant())) {
                throw new IllegalArgumentException("control is reserved for the baseline observation");
            }
            if (!ids.add(fixture.variant())) throw new IllegalArgumentException("Duplicate fixture variant");
        }
    }

    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous) {
        return previous != null && previous.outcome() == Outcome.NOT_VERIFIED
                && "metadata.fixture-probe.incomplete".equals(previous.reasonCode());
    }

    @Override public java.util.Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context, CaseOutcome previous) {
        if (!supportsRecordedEvidenceReevaluation(previous) || !context.transcriptComplete()) return java.util.Optional.empty();
        return com.samlscope.runner.RecordedEvidenceReevaluation.conclusiveUpdate(previous, evaluate(context, false));
    }

    @Override public String id() { return id; }
    @Override public TargetRole role() { return role; }
    @Override public String evidenceCampaignId() { return "metadata-fixture-refresh"; }
    @Override public String evidenceCampaignTitle() { return "Refresh or re-import Suite metadata fixtures"; }
    @Override public com.samlscope.runner.RunCampaignQuery.ActionKind evidenceActionKind() {
        return com.samlscope.runner.RunCampaignQuery.ActionKind.METADATA_REFRESH;
    }
    @Override public List<String> evidenceActionKeys() {
        var keys = new ArrayList<String>();
        keys.add(CONTROL);
        fixtures.forEach(fixture -> keys.add(fixture.variant()));
        return List.copyOf(keys);
    }

    @Override
    public String instructionEn() {
        var value = new StringBuilder()
                .append("Configure the target once with `/p/<plan-id>/metadata/live?run=<run-id>`. ")
                .append("Select `control`, trigger the target's standard refresh or re-import, and complete a ")
                .append("working SAML flow. Then repeat the refresh/re-import and flow attempt for these fixtures:");
        fixtures.forEach(fixture -> value.append("\n- `").append(fixture.variant()).append("`: expected ")
                .append(fixture.behavior().name().toLowerCase(java.util.Locale.ROOT))
                .append(" — ").append(fixture.purpose()));
        return value.append("\nUse the Run-level protocol-evidence action only after every attempt. The Suite ")
                .append("derives the outcome; the operator does not enter a verdict.").toString();
    }

    @Override
    public CaseStep start(CaseContext context) {
        return new CaseStep.AwaitConfig(
                new CaseState(PHASE, Map.of()), List.of(),
                "metadata-fixture-probe", Duration.ofDays(7));
    }

    @Override
    public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        if (!PHASE.equals(state.phase())) throw new IllegalArgumentException("Unexpected metadata fixture phase");
        if (event instanceof CaseEvent.ConfigConfirmed) return new CaseStep.Finish(evaluate(context, true));
        if (event instanceof CaseEvent.ConfigUnavailable unavailable) {
            if (unavailable.issue() == CaseEvent.ConfigurationIssue.CAPABILITY_ABSENT
                    && configurationSemantics == ConfigurationFailureSemantics.NORMATIVE_CAPABILITY) {
                return new CaseStep.Finish(new CaseOutcome(
                        Outcome.VIOLATED, null, "capability_absent", "configuration.capability-absent",
                        List.of(), Map.of(
                                "configuration_issue", "capability_absent",
                                "configuration_note", unavailable.note())));
            }
            return new CaseStep.Finish(new CaseOutcome(
                    Outcome.NOT_VERIFIED, "metadata_fixture_probe_unavailable",
                    "metadata.fixture-probe.unavailable", "metadata.fixture-probe.unavailable",
                    List.of(), Map.of(
                            "configuration_issue", unavailable.issue().name().toLowerCase(java.util.Locale.ROOT),
                            "configuration_note", unavailable.note())));
        }
        if (event instanceof CaseEvent.TimedOut) {
            return new CaseStep.Finish(CaseOutcome.notVerified(
                    "metadata_fixture_probe_timeout", "metadata.fixture-probe.timeout"));
        }
        if (event instanceof CaseEvent.Aborted) {
            return new CaseStep.Finish(CaseOutcome.notVerified(
                    "metadata_fixture_probe_skipped", "metadata.fixture-probe.skipped"));
        }
        throw new IllegalArgumentException("Expected metadata fixture configuration completion");
    }

    @Override
    public EvidenceStatus evidenceStatus(CaseContext context) {
        var observation = observe(context);
        var required = new ArrayList<String>();
        required.add("fetched:" + CONTROL);
        required.add("used:" + CONTROL);
        fixtures.forEach(fixture -> {
            required.add("fetched:" + fixture.variant());
            if (fixture.behavior() == Behavior.ACCEPT) {
                required.add("used:" + fixture.variant());
            } else {
                required.add("conclusive-rejection:" + fixture.variant());
            }
        });
        if (requiresKeyValueDiscrimination()) required.add("signature-discrimination:keyvalue-only");
        if (requiresNamespaceQualification()) required.add("namespace-qualification:extension-points");
        var completed = required.stream().filter(value -> {
            var separator = value.indexOf(':');
            var kind = value.substring(0, separator);
            var variant = value.substring(separator + 1);
            if ("namespace-qualification".equals(kind)) return false;
            if ("signature-discrimination".equals(kind)) return observation.signatureDiscriminated().contains(variant);
            return "fetched".equals(kind)
                    ? observation.fetched().contains(variant)
                    : observation.used().contains(variant);
        }).toList();
        return new EvidenceStatus(observation.ready(), required, completed, observation.details());
    }

    /** Read-only snapshot for a parent case that must retain the supporting transcript refs. */
    CaseOutcome recordedObservation(CaseContext context) {
        return evaluate(context, false);
    }

    private CaseOutcome evaluate(CaseContext context, boolean attemptsConfirmed) {
        var observation = observe(context);
        // An operator confirming that an attempt was made cannot replace the missing protocol
        // observation. In particular, an unrelated error response or a correlation mismatch must
        // not turn a compatible positive fixture into a target violation.
        if (!observation.ready()) {
            return new CaseOutcome(
                    Outcome.NOT_VERIFIED, "metadata_fixture_probe_incomplete",
                    "metadata.fixture-probe.incomplete", "metadata.fixture-probe.incomplete",
                    observation.evidence(), observation.details());
        }
        var mismatches = new ArrayList<String>();
        for (var fixture : fixtures) {
            var used = observation.used().contains(fixture.variant());
            if (observation.wrongEndpoints().contains(fixture.variant())) {
                mismatches.add(fixture.variant() + ":wrong_default_acs");
            } else if (fixture.behavior() == Behavior.REJECT && used) {
                mismatches.add(fixture.variant() + ":expected_rejection");
            }
        }
        var details = new LinkedHashMap<String, Object>(observation.details());
        details.put("attempts_confirmed", attemptsConfirmed);
        details.put("mismatches", List.copyOf(mismatches));
        return new CaseOutcome(
                mismatches.isEmpty() ? Outcome.SATISFIED : Outcome.VIOLATED,
                null,
                mismatches.isEmpty() ? "metadata.fixture-probe.satisfied" : "metadata.fixture-probe.violated",
                mismatches.isEmpty() ? "metadata.fixture-probe.satisfied" : "metadata.fixture-probe.violated",
                observation.evidence(), details);
    }

    private Observation observe(CaseContext context) {
        var relevant = new LinkedHashSet<String>();
        relevant.add(CONTROL);
        fixtures.forEach(fixture -> relevant.add(fixture.variant()));
        var fetched = new LinkedHashSet<String>();
        var used = new LinkedHashSet<String>();
        var wrongEndpoints = new LinkedHashSet<String>();
        var evidence = new ArrayList<EvidenceRef>();
        var entries = context.transcript().list(context.runId());
        var signature = MetadataSignatureObservation.observe(context.runId(), entries);
        signature.evidence().stream().sorted().forEach(id -> evidence.add(new EvidenceRef("transcript", "transcript:" + id)));
        for (var entry : entries) {
            if (entry.direction() != Direction.INBOUND) continue;
            if ("MetadataFetch".equals(entry.samlSummary().get("type"))) {
                var variant = String.valueOf(entry.samlSummary().get("variant"));
                if (relevant.contains(variant)) {
                    fetched.add(variant);
                    evidence.add(new EvidenceRef("transcript", "transcript:" + entry.id()));
                }
                if (entry.samlSummary().get("variants") instanceof List<?> variants) {
                    for (var item : variants) {
                        if (item instanceof String value && relevant.contains(value)) fetched.add(value);
                    }
                    if (variants.stream().anyMatch(item -> item instanceof String value
                            && relevant.contains(value))) {
                        evidence.add(new EvidenceRef("transcript", "transcript:" + entry.id()));
                    }
                }
            }
            if (entry.decodedSamlBytes() <= 0 || entry.url() == null) continue;
            if ("invalid".equals(entry.samlSummary().get("metadataSignatureControl"))
                    || signature.invalidRequestIds().contains(String.valueOf(entry.samlSummary().get("inResponseTo")))) continue;
            if (!Boolean.TRUE.equals(entry.samlSummary().get("metadataProbeAccepted"))
                    || !"urn:oasis:names:tc:SAML:2.0:status:Success".equals(
                            entry.samlSummary().get("statusCode"))) continue;
            for (var variant : relevant) {
                if (fetched.contains(variant)
                        && MetadataProbeCorrelation.matches(entry.url(), context.runId(), variant)) {
                    var fixture = fixtures.stream().filter(value -> value.variant().equals(variant)).findFirst();
                    var expectedIndex = fixture.map(Fixture::expectedAcsIndex).orElse(null);
                    if (expectedIndex != null && !java.net.URI.create(entry.url()).getPath()
                            .endsWith("/sp/acs/" + expectedIndex)) {
                        wrongEndpoints.add(variant);
                    } else {
                        used.add(variant);
                    }
                    evidence.add(new EvidenceRef("transcript", "transcript:" + entry.id()));
                }
            }
        }
        var details = new LinkedHashMap<String, Object>(Map.<String, Object>of(
                "fixtures", fixtures.stream().map(Fixture::variant).toList(),
                "fetched_variants", List.copyOf(fetched),
                "used_variants", List.copyOf(used),
                "missing_fetches", relevant.stream().filter(value -> !fetched.contains(value)).toList(),
                "missing_acceptance", relevant.stream().filter(value -> CONTROL.equals(value)
                        || fixtures.stream().anyMatch(fixture -> fixture.variant().equals(value)
                                && fixture.behavior() == Behavior.ACCEPT))
                        .filter(value -> !used.contains(value)).toList(),
                "unresolved_rejection", fixtures.stream().filter(value -> value.behavior() == Behavior.REJECT)
                        .map(Fixture::variant).filter(value -> !used.contains(value)).toList(),
                "wrong_endpoint_variants", List.copyOf(wrongEndpoints),
                "transcript_complete", context.transcriptComplete()));
        if (requiresNamespaceQualification()) {
            details.put("missing_namespace_qualification_evidence", List.of("extension-points"));
            details.put("consumer_acceptance_proves_namespace_qualification", false);
        }
        if (requiresKeyValueDiscrimination()) {
            details.put("missing_key_consumption_evidence", signature.verified().contains("keyvalue-only")
                    ? List.of() : List.of("signature-discrimination:keyvalue-only"));
        }
        details.put("signature_discriminated_variants", signature.verified().stream().sorted().toList());
        details.put("invalid_signature_accepted_variants", signature.acceptedInvalid().stream().sorted().toList());
        var allFetched = fixtures.stream().allMatch(value -> fetched.contains(value.variant()));
        var acceptedObserved = fixtures.stream()
                .filter(value -> value.behavior() == Behavior.ACCEPT)
                .allMatch(value -> used.contains(value.variant()));
        var rejected = fixtures.stream().filter(value -> value.behavior() == Behavior.REJECT).toList();
        // Silence after a fetch cannot prove that the target rejected the fixture: the operator
        // might not have attempted the flow yet. A reject-only branch becomes conclusive only on
        // the positive counter-observation that the target used forbidden metadata (VIOLATED).
        var forbiddenUseObserved = rejected.stream().anyMatch(value -> used.contains(value.variant()));
        var conclusive = forbiddenUseObserved || !wrongEndpoints.isEmpty() || (rejected.isEmpty() && acceptedObserved);
        return new Observation(
                fetched.contains(CONTROL) && used.contains(CONTROL)
                        && allFetched && conclusive && context.transcriptComplete()
                        && !requiresNamespaceQualification()
                        && (!requiresKeyValueDiscrimination() || signature.verified().contains("keyvalue-only")),
                fetched, used, wrongEndpoints, signature.verified(), distinct(evidence), details);
    }

    private boolean requiresNamespaceQualification() {
        // The signed MD05.a3 constraint explicitly separates namespace qualification
        // from unknown-extension acceptance (MD05.g). Accepting a Suite-produced invalid
        // extension is not evidence that the target publishes invalid extension content.
        // Keep these fixtures available for observation, but require a dedicated evidence
        // path before assigning either a satisfied or violated outcome for this obligation.
        return id.startsWith("IIP-MD05-a3-");
    }

    private boolean requiresKeyValueDiscrimination() {
        // The approved MD05.c interpretation defers runtime key interpretation to the MD06.a group,
        // so MD05.c evaluates acceptance of the MDIOP representation (a correlated use) only and
        // must not demand the signature-discrimination control.
        if (id.startsWith("IIP-MD05-c-")) return false;
        // A native importer may silently disable signature validation when it cannot
        // import KeyValue. Successful SSO then proves neither key import nor use.
        // Require a Suite-issued invalid control and normal request in the same
        // campaign member; a missing response or externally submitted assertion is not enough.
        return fixtures.stream().anyMatch(fixture -> "keyvalue-only".equals(fixture.variant()));
    }

    private static List<EvidenceRef> distinct(List<EvidenceRef> evidence) {
        return evidence.stream().distinct().toList();
    }

    private static String text(String value, String name) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(name + " is required");
        return value;
    }

    public enum Behavior { ACCEPT, REJECT }

    public record Fixture(String variant, Behavior behavior, String purpose, Integer expectedAcsIndex) {
        public Fixture(String variant, Behavior behavior, String purpose) {
            this(variant, behavior, purpose, null);
        }
        public Fixture {
            variant = text(variant, "variant");
            behavior = Objects.requireNonNull(behavior, "behavior");
            purpose = text(purpose, "purpose");
            if (expectedAcsIndex != null && (expectedAcsIndex < 0 || behavior != Behavior.ACCEPT)) {
                throw new IllegalArgumentException("ACS expectation requires an accepting endpoint fixture");
            }
        }
    }

    private record Observation(
            boolean ready,
            Set<String> fetched,
            Set<String> used,
            Set<String> wrongEndpoints,
            Set<String> signatureDiscriminated,
            List<EvidenceRef> evidence,
            Map<String, Object> details) {}
}
