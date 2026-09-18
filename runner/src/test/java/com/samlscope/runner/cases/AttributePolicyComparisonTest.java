package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;
import com.samlscope.core.evaluation.*;
import com.samlscope.runner.cases.AttributePolicyComparison.Condition;
import com.samlscope.runner.cases.AttributePolicyComparison.Sample;

class AttributePolicyComparisonTest {
    private static final Instant START = Instant.parse("2026-09-18T00:00:00Z");
    private static final String HASH = "a".repeat(64), OTHER = "b".repeat(64);

    private List<Sample> complete(String id) {
        var samples = new ArrayList<Sample>();
        for (var condition : AttributePolicyComparison.required(id)) {
            int index = samples.size();
            var markers = switch (condition) {
                case BASELINE, ENTITY_ABSENT, REQUESTED_ABSENT -> Set.of("anchor");
                case ENTITY_PRESENT -> Set.of("anchor", "entity");
                case REQUESTED_REQUIRED, INDEX_ZERO, INDEX_ZERO_REPEAT -> Set.of("anchor", "required", "optional");
                case REQUESTED_OPTIONAL -> Set.of("anchor", "optional");
                case INDEX_ONE -> Set.of("anchor", "surname");
            };
            samples.add(new Sample("experiment", condition, HASH, HASH, "https://sp.example", HASH, HASH,
                    START.plusSeconds(index * 2L), START.plusSeconds(index * 2L + 1), markers,
                    List.of(new EvidenceRef("transcript", "request-" + index), new EvidenceRef("transcript", "response-" + index))));
        }
        return samples;
    }

    @Test void completeIndependentControlsAreRequiredForEveryCase() {
        for (var id : List.of(AttributePolicyComparison.ENTITY, AttributePolicyComparison.REQUESTED, AttributePolicyComparison.INDEX)) {
            var samples = complete(id);
            var result = AttributePolicyComparison.evaluate(id, samples, List.of());
            assertEquals(Outcome.SATISFIED, result.outcome());
            assertFalse(result.details().toString().contains(HASH), "Do not persist a principal fingerprint");
            for (int index = 0; index < samples.size(); index++) {
                var missing = new ArrayList<>(samples); missing.remove(index);
                assertEquals(Outcome.NOT_VERIFIED, AttributePolicyComparison.evaluate(id, missing, List.of()).outcome());
                var alwaysReleased = new ArrayList<>(samples);
                alwaysReleased.set(index, change(samples.get(index), "markers"));
                assertEquals(Outcome.NOT_VERIFIED, AttributePolicyComparison.evaluate(id, alwaysReleased, List.of()).outcome());
            }
        }
    }

    @Test void doesNotCombineUnrelatedOrUncontrolledObservations() {
        var id = AttributePolicyComparison.INDEX;
        for (String mutation : List.of("experiment", "policy", "principal", "entity", "metadata", "input", "order", "evidence", "empty-fingerprint")) {
            var samples = complete(id);
            samples.set(2, change(samples.get(2), mutation));
            assertEquals(Outcome.NOT_VERIFIED, AttributePolicyComparison.evaluate(id, samples, List.of()).outcome(), mutation);
        }
        var duplicate = complete(id); duplicate.add(duplicate.getLast());
        assertEquals(Outcome.NOT_VERIFIED, AttributePolicyComparison.evaluate(id, duplicate, List.of()).outcome());
        assertEquals(Outcome.NOT_VERIFIED, AttributePolicyComparison.evaluate(id, complete(id), List.of("signature_unverified")).outcome());
    }

    @Test void unknownCaseCannotSilentlyUseAnotherDefinition() {
        assertThrows(IllegalArgumentException.class, () -> AttributePolicyComparison.evaluate("unknown", List.of(), List.of()));
    }

    private Sample change(Sample s, String field) {
        return new Sample(field.equals("experiment") ? "another-experiment" : s.experiment(), s.condition(),
                field.equals("policy") ? OTHER : field.equals("empty-fingerprint") ? "" : s.policyFingerprint(),
                field.equals("principal") ? OTHER : s.principalFingerprint(),
                field.equals("entity") ? "https://other.example" : s.entityId(),
                field.equals("metadata") ? OTHER : s.metadataFingerprint(),
                field.equals("input") ? OTHER : s.stableInputFingerprint(),
                field.equals("order") ? START : s.issued(), s.received(),
                field.equals("markers") ? Set.of("anchor", "entity", "required", "optional", "surname") : s.markers(),
                field.equals("evidence") ? List.of(new EvidenceRef("transcript", "request-0"), new EvidenceRef("transcript", "response-0")) : s.evidence());
    }
}
