package com.samlscope.runner.cases;

import java.time.Instant;
import java.util.*;
import com.samlscope.core.evaluation.*;

/** Comparison of internal, adapter-verified UI consumption evidence, never browser-submitted claims. */
final class UiUrlComparison {
    static final String CASE_ID = "IIP-MD05-fh-idp-01";
    enum Element { LOGO, INFORMATION, PRIVACY }
    enum Scheme { HTTP, HTTPS, DATA, JAVASCRIPT, FILE }
    enum Use { USED, VERIFIED_NONUSE, UNOBSERVED }
    record Condition(Element element, Scheme scheme) {
        Condition { Objects.requireNonNull(element); Objects.requireNonNull(scheme); }
    }
    /**
     * stableInputs binds the fixed target, SP, native policy/template and browser settings,
     * excluding only the deliberate UI URL condition. The adapter must verify actual use;
     * DOM assignment, missing nodes, browser scheme blocking and a failed load do not prove
     * nonuse. VERIFIED_NONUSE additionally requires a request-bound native policy decision.
     * Evidence: metadata fetch, prepared fixture, request, browser observation, and (only
     * for VERIFIED_NONUSE) the native policy evidence. No arbitrary receipt DTO exposes this type.
     */
    record Sample(String runId, String entityId, Condition condition, String stableInputs,
                  String fixtureHash, Instant requestedAt, Instant observedAt, Use use,
                  List<EvidenceRef> evidence) {
        Sample {
            Objects.requireNonNull(condition); Objects.requireNonNull(requestedAt);
            Objects.requireNonNull(observedAt); Objects.requireNonNull(use);
            evidence = List.copyOf(evidence);
        }
    }

    static CaseOutcome evaluate(List<Sample> samples, List<String> collectionIssues) {
        var issues = new LinkedHashSet<>(collectionIssues);
        var byCondition = new HashMap<Condition, Sample>();
        var identity = new HashSet<List<String>>();
        var stable = new HashSet<String>();
        var fixtures = new HashSet<String>();
        var refs = new LinkedHashSet<EvidenceRef>();
        var forbidden = new ArrayList<String>();
        int nonuse = 0;
        int allowedNonuse = 0;
        for (var sample : samples) {
            if (byCondition.put(sample.condition(), sample) != null) issues.add("duplicate_condition");
            if (sample.runId() == null || sample.runId().isBlank() || sample.entityId() == null || sample.entityId().isBlank()) {
                issues.add("identity_unavailable");
            } else identity.add(List.of(sample.runId(), sample.entityId()));
            if (!hash(sample.stableInputs()) || !hash(sample.fixtureHash())) issues.add("input_fingerprint_unavailable");
            stable.add(sample.stableInputs());
            if (!fixtures.add(sample.fixtureHash())) issues.add("reused_fixture");
            if (!sample.requestedAt().isBefore(sample.observedAt())) issues.add("observation_chronology_unproven");
            var kinds = new ArrayList<>(List.of("transcript", "transcript", "transcript", "browser-observation"));
            if (sample.use() == Use.VERIFIED_NONUSE) kinds.add("native-ui-policy");
            if (!kinds.equals(sample.evidence().stream().map(EvidenceRef::kind).toList())) issues.add("incomplete_provenance");
            for (var ref : sample.evidence()) {
                if (ref.reference() == null || ref.reference().isBlank()) issues.add("empty_evidence_reference");
                if (!refs.add(ref)) issues.add("reused_evidence");
            }
            if (sample.use() == Use.UNOBSERVED) issues.add("consumption_unobserved:" + token(sample.condition()));
            if (sample.use() == Use.VERIFIED_NONUSE) {
                nonuse++;
                if (Set.of(Scheme.HTTP, Scheme.HTTPS, Scheme.DATA).contains(sample.condition().scheme())) allowedNonuse++;
            }
            if (sample.use() == Use.USED && Set.of(Scheme.JAVASCRIPT, Scheme.FILE).contains(sample.condition().scheme())) {
                forbidden.add(token(sample.condition()));
            }
        }
        var missing = new ArrayList<String>();
        for (var element : Element.values()) for (var scheme : Scheme.values()) {
            var condition = new Condition(element, scheme);
            if (!byCondition.containsKey(condition)) missing.add(token(condition));
        }
        if (!missing.isEmpty()) issues.add("missing_condition");
        if (identity.size() != 1) issues.add("mixed_experiment");
        if (stable.size() != 1) issues.add("uncontrolled_input_changed");
        // All approved variants must be bound before a conclusive aggregate outcome.
        var outcome = !issues.isEmpty() ? Outcome.NOT_VERIFIED : !forbidden.isEmpty() ? Outcome.VIOLATED
                : allowedNonuse > 0 ? Outcome.SATISFIED_WITH_NOTE : Outcome.SATISFIED;
        var code = "browser.ui-url." + (!issues.isEmpty() ? "evidence-incomplete"
                : !forbidden.isEmpty() ? "disallowed-scheme-used" : allowedNonuse > 0 ? "verified-nonuse" : "allowed-schemes-used");
        return new CaseOutcome(outcome, outcome == Outcome.NOT_VERIFIED ? "ui_url_consumption_unproven" : null,
                code, code, List.copyOf(refs), Map.of("evidence_issues", List.copyOf(issues),
                "missing_conditions", missing, "disallowed_scheme_uses", forbidden,
                "verified_nonuse_conditions", nonuse));
    }
    private static boolean hash(String value) { return value != null && value.matches("[0-9a-f]{64}"); }
    private static String token(Condition condition) {
        return condition.element().name().toLowerCase(Locale.ROOT) + "-" + condition.scheme().name().toLowerCase(Locale.ROOT);
    }
}
