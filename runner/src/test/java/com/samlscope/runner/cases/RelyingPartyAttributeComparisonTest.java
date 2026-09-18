package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;
import com.samlscope.core.evaluation.*;
import com.samlscope.runner.cases.RelyingPartyAttributeComparison.*;

class RelyingPartyAttributeComparisonTest {
    private static final String HASH = "a".repeat(64);
    private Sample sample(Condition condition, Set<String> markers) {
        int offset = condition.ordinal() * 2;
        var start = Instant.parse("2026-09-18T00:00:00Z").plusSeconds(offset);
        boolean second = condition == Condition.SECOND;
        return new Sample("experiment", condition, second ? "rp-b" : "rp-a", HASH, HASH, HASH,
                second ? "b".repeat(64) : HASH, HASH, start, start.plusSeconds(1), markers,
                List.of(new EvidenceRef("transcript", "request-" + offset), new EvidenceRef("transcript", "response-" + offset)));
    }
    private List<Sample> valid() {
        return List.of(sample(Condition.FIRST, Set.of("anchor", "first")),
                sample(Condition.SECOND, Set.of("anchor", "second")),
                sample(Condition.FIRST_REPEAT, Set.of("anchor", "first")));
    }
    @Test void fixedPolicyReleasesDifferentAttributesAndReturnsToFirst() {
        assertEquals(Outcome.SATISFIED, RelyingPartyAttributeComparison.evaluate(valid(), List.of()).outcome());
        for (int omitted = 0; omitted < 3; omitted++) {
            var incomplete = new ArrayList<>(valid()); incomplete.remove(omitted);
            assertEquals(Outcome.NOT_VERIFIED, RelyingPartyAttributeComparison.evaluate(incomplete, List.of()).outcome());
        }
        for (var markers : List.of(Set.<String>of(), Set.of("anchor"), Set.of("anchor", "first", "second"))) {
            var input = Arrays.stream(Condition.values()).map(c -> sample(c, markers)).toList();
            assertEquals(Outcome.NOT_VERIFIED, RelyingPartyAttributeComparison.evaluate(input, List.of()).outcome());
        }
    }
    @Test void preparationAndExchangeMutantsCannotPass() {
        var original = valid().get(1);
        for (var mutation : List.of("experiment", "entity", "policy", "login", "input", "metadata", "attribute", "time", "evidence")) {
            var changed = new Sample(mutation.equals("experiment") ? "other" : original.experiment(), original.condition(),
                    mutation.equals("entity") ? "rp-a" : original.entityId(),
                    mutation.equals("policy") ? "c".repeat(64) : original.policyFingerprint(),
                    mutation.equals("login") ? "c".repeat(64) : original.loginInputFingerprint(),
                    mutation.equals("input") ? "c".repeat(64) : original.stableInputs(),
                    mutation.equals("metadata") ? HASH : original.metadataFingerprint(),
                    mutation.equals("attribute") ? "c".repeat(64) : original.attributeInputFingerprint(),
                    mutation.equals("time") ? valid().getFirst().requestedAt() : original.requestedAt(),
                    original.receivedAt(), original.markers(),
                    mutation.equals("evidence") ? valid().getFirst().evidence() : original.evidence());
            assertEquals(Outcome.NOT_VERIFIED, RelyingPartyAttributeComparison.evaluate(
                    List.of(valid().getFirst(), changed, valid().getLast()), List.of()).outcome(), mutation);
        }
        assertEquals(Outcome.NOT_VERIFIED, RelyingPartyAttributeComparison.evaluate(valid(), List.of("signature_unverified")).outcome());
    }
}
