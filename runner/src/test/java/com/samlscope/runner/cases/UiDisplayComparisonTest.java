package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.assertEquals;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;
import com.samlscope.core.evaluation.*;

class UiDisplayComparisonTest {
    private static final String HASH = "a".repeat(64);
    private static final Instant TIME = Instant.parse("2026-09-18T00:00:00Z");
    private List<UiDisplayComparison.Sample> baseline() {
        var rows = new ArrayList<UiDisplayComparison.Sample>();
        for (var condition : UiDisplayComparison.Condition.values()) {
            int i = condition.ordinal();
            rows.add(new UiDisplayComparison.Sample("run_control", "https://sp.example/entity", condition, HASH,
                    String.valueOf(i).repeat(64), i == 2 ? null : "Login to service", TIME.plusSeconds(i * 3),
                    TIME.plusSeconds(i * 3 + 1), UiDisplayComparison.Selection.values()[i],
                    List.of(new EvidenceRef("transcript", "fetch-" + i), new EvidenceRef("transcript", "metadata-" + i),
                            new EvidenceRef("transcript", "request-" + i), new EvidenceRef("browser-observation", "browser-" + i))));
        }
        return rows;
    }
    private UiDisplayComparison.Sample selection(UiDisplayComparison.Sample s, UiDisplayComparison.Selection selected) {
        return new UiDisplayComparison.Sample(s.runId(), s.entityId(), s.condition(), s.stableInputs(), s.metadataHash(),
                s.serviceName(), s.requestedAt(), s.observedAt(), selected, s.evidence());
    }
    @Test void bothApprovedFallbackChoicesCanBeObserved() {
        var rows = baseline();
        assertEquals(Outcome.SATISFIED, UiDisplayComparison.evaluate(rows, List.of()).outcome());
        rows.set(2, selection(rows.get(2), UiDisplayComparison.Selection.HOSTNAME));
        assertEquals(Outcome.SATISFIED, UiDisplayComparison.evaluate(rows, List.of()).outcome());
    }
    @Test void wrongKnownPriorityDiffersFromMissingOrUnrecognizedUi() {
        var rows = baseline();
        rows.set(0, selection(rows.get(0), UiDisplayComparison.Selection.SERVICE));
        assertEquals(Outcome.VIOLATED, UiDisplayComparison.evaluate(rows, List.of()).outcome());
        rows = baseline();
        rows.set(2, selection(rows.get(2), UiDisplayComparison.Selection.UNOBSERVED));
        assertEquals(Outcome.NOT_VERIFIED, UiDisplayComparison.evaluate(rows, List.of()).outcome());
        rows.set(2, selection(rows.get(2), UiDisplayComparison.Selection.DISPLAY));
        assertEquals(Outcome.NOT_VERIFIED, UiDisplayComparison.evaluate(rows, List.of()).outcome());
    }
    @Test void everyConditionAndIndependentEvidenceAreRequired() {
        var original = baseline();
        for (int i = 0; i < original.size(); i++) {
            var rows = baseline(); rows.remove(i);
            assertEquals(Outcome.NOT_VERIFIED, UiDisplayComparison.evaluate(rows, List.of()).outcome());
            rows = baseline(); rows.add(rows.get(i));
            assertEquals(Outcome.NOT_VERIFIED, UiDisplayComparison.evaluate(rows, List.of()).outcome());
        }
        var rows = baseline(); var s = rows.get(2);
        rows.set(2, new UiDisplayComparison.Sample(s.runId(), s.entityId(), s.condition(), s.stableInputs(), s.metadataHash(),
                s.serviceName(), s.requestedAt(), s.observedAt(), s.selection(), rows.getFirst().evidence()));
        assertEquals(Outcome.NOT_VERIFIED, UiDisplayComparison.evaluate(rows, List.of()).outcome());
    }
    @Test void inputDriftCrossRunAndOverlappingExperimentsCannotPass() {
        for (int mutant = 0; mutant < 6; mutant++) {
            var rows = baseline(); var s = rows.get(1);
            rows.set(1, new UiDisplayComparison.Sample(mutant == 0 ? "other-run" : s.runId(),
                    mutant == 1 ? "https://other.example" : s.entityId(), s.condition(),
                    mutant == 2 ? "b".repeat(64) : s.stableInputs(),
                    mutant == 3 ? rows.getFirst().metadataHash() : s.metadataHash(),
                    mutant == 4 ? "different-service" : s.serviceName(),
                    mutant == 5 ? rows.getFirst().observedAt() : s.requestedAt(), s.observedAt(), s.selection(), s.evidence()));
            assertEquals(Outcome.NOT_VERIFIED, UiDisplayComparison.evaluate(rows, List.of()).outcome(), "mutant " + mutant);
        }
        assertEquals(Outcome.NOT_VERIFIED, UiDisplayComparison.evaluate(baseline(), List.of("native_import_unproven")).outcome());
    }
}
