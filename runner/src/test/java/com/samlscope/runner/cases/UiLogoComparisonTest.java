package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;
import com.samlscope.core.evaluation.*;
import com.samlscope.runner.cases.UiLogoComparison.*;

class UiLogoComparisonTest {
    private static final Instant START = Instant.parse("2026-09-18T00:00:00Z");
    private static final String A = "a".repeat(64), B = "b".repeat(64), C = "c".repeat(64);

    private Sample sample(Condition condition, Selection selection) {
        int offset = condition == Condition.PREFERRED_AVAILABLE ? 0 : 2;
        return new Sample("run", "entity", condition, A, offset == 0 ? A : B, B, C,
                START.plusSeconds(offset), START.plusSeconds(offset + 1), selection,
                List.of(new EvidenceRef("transcript", "fetch-" + offset), new EvidenceRef("transcript", "metadata-" + offset),
                        new EvidenceRef("transcript", "request-" + offset), new EvidenceRef("browser-observation", "view-" + offset)));
    }

    @Test void bothDifferentialConditionsAreRequired() {
        for (var first : Selection.values()) for (var second : Selection.values()) {
            var outcome = UiLogoComparison.evaluate(List.of(sample(Condition.PREFERRED_AVAILABLE, first),
                    sample(Condition.PREFERRED_UNAVAILABLE, second)), List.of());
            assertEquals(first == Selection.LOCALIZED && second == Selection.DEFAULT
                    ? Outcome.SATISFIED : Outcome.NOT_VERIFIED, outcome.outcome());
        }
        var control = sample(Condition.PREFERRED_AVAILABLE, Selection.LOCALIZED);
        assertEquals(Outcome.NOT_VERIFIED, UiLogoComparison.evaluate(List.of(control), List.of()).outcome());
        assertEquals(Outcome.NOT_VERIFIED, UiLogoComparison.evaluate(List.of(control, control), List.of()).outcome());
    }

    @Test void rejectedProvenanceCannotBeRescuedByCorrectCandidateTokens() {
        var first = sample(Condition.PREFERRED_AVAILABLE, Selection.LOCALIZED);
        var second = sample(Condition.PREFERRED_UNAVAILABLE, Selection.DEFAULT);
        for (String issue : List.of("metadata_unbound", "native_language_unproven", "image_not_loaded")) {
            assertEquals(Outcome.NOT_VERIFIED, UiLogoComparison.evaluate(List.of(first, second), List.of(issue)).outcome());
        }
        for (String mutation : List.of("run", "entity", "input", "metadata", "image", "same-images", "time", "references")) {
            var altered = new Sample(mutation.equals("run") ? "other" : second.runId(),
                    mutation.equals("entity") ? "other" : second.entityId(), second.condition(),
                    mutation.equals("input") ? C : second.stableInputs(),
                    mutation.equals("metadata") ? first.metadataHash() : second.metadataHash(),
                    mutation.equals("image") ? A : second.defaultImageHash(),
                    mutation.equals("same-images") ? second.defaultImageHash() : second.localizedImageHash(),
                    mutation.equals("time") ? START : second.requestedAt(), second.observedAt(), second.selection(),
                    mutation.equals("references") ? first.evidence() : second.evidence());
            assertEquals(Outcome.NOT_VERIFIED, UiLogoComparison.evaluate(List.of(first, altered), List.of()).outcome(), mutation);
        }
    }
}
