package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;
import com.samlscope.core.evaluation.*;

class UiUrlComparisonTest {
    private List<UiUrlComparison.Sample> baseline() {
        var samples = new ArrayList<UiUrlComparison.Sample>();
        for (var element : UiUrlComparison.Element.values()) for (var scheme : UiUrlComparison.Scheme.values()) {
            var use = Set.of(UiUrlComparison.Scheme.JAVASCRIPT, UiUrlComparison.Scheme.FILE).contains(scheme)
                    ? UiUrlComparison.Use.VERIFIED_NONUSE : UiUrlComparison.Use.USED;
            var n = samples.size() + 1;
            var refs = new ArrayList<EvidenceRef>();
            for (var kind : List.of("fetch", "metadata", "request")) refs.add(new EvidenceRef("transcript", kind + n));
            refs.add(new EvidenceRef("browser-observation", "browser" + n));
            if (use == UiUrlComparison.Use.VERIFIED_NONUSE) refs.add(new EvidenceRef("native-ui-policy", "policy" + n));
            samples.add(new UiUrlComparison.Sample("run_example", "https://sp.example",
                    new UiUrlComparison.Condition(element, scheme), "a".repeat(64), String.format("%064x", n),
                    Instant.EPOCH.plusSeconds(n * 2), Instant.EPOCH.plusSeconds(n * 2 + 1), use, refs));
        }
        return samples;
    }
    private UiUrlComparison.Sample changeUse(UiUrlComparison.Sample s, UiUrlComparison.Use use) {
        var refs = new ArrayList<>(s.evidence().subList(0, 4));
        if (use == UiUrlComparison.Use.VERIFIED_NONUSE) refs.add(new EvidenceRef("native-ui-policy", "policy-" + s.condition()));
        return new UiUrlComparison.Sample(s.runId(), s.entityId(), s.condition(), s.stableInputs(),
                s.fixtureHash(), s.requestedAt(), s.observedAt(), use, refs);
    }
    @Test void permitsDataAndRejectsEachForbiddenSchemeMutant() {
        assertEquals(Outcome.SATISFIED, UiUrlComparison.evaluate(baseline(), List.of()).outcome());
        for (int i = 0; i < baseline().size(); i++) {
            var rows = new ArrayList<>(baseline());
            if (rows.get(i).use() != UiUrlComparison.Use.VERIFIED_NONUSE) continue;
            rows.set(i, changeUse(rows.get(i), UiUrlComparison.Use.USED));
            assertEquals(Outcome.VIOLATED, UiUrlComparison.evaluate(rows, List.of()).outcome());
        }
    }
    @Test void actualNonuseIsANoteButAbsenceOrBrowserBlockingIsUnverified() {
        var nonuse = baseline().stream().map(s -> changeUse(s, UiUrlComparison.Use.VERIFIED_NONUSE)).toList();
        assertEquals(Outcome.SATISFIED_WITH_NOTE, UiUrlComparison.evaluate(nonuse, List.of()).outcome());
        for (int i = 0; i < baseline().size(); i++) {
            var rows = new ArrayList<>(baseline()); rows.set(i, changeUse(rows.get(i), UiUrlComparison.Use.UNOBSERVED));
            assertEquals(Outcome.NOT_VERIFIED, UiUrlComparison.evaluate(rows, List.of()).outcome());
        }
        var rows = new ArrayList<>(nonuse); var s = rows.getFirst();
        rows.set(0, new UiUrlComparison.Sample(s.runId(), s.entityId(), s.condition(), s.stableInputs(),
                s.fixtureHash(), s.requestedAt(), s.observedAt(), s.use(), s.evidence().subList(0, 4)));
        assertEquals(Outcome.NOT_VERIFIED, UiUrlComparison.evaluate(rows, List.of()).outcome());
    }
    @Test void everyConditionAndIndependentProvenanceAreRequired() {
        for (int i = 0; i < baseline().size(); i++) {
            var rows = new ArrayList<>(baseline()); rows.remove(i);
            assertEquals(Outcome.NOT_VERIFIED, UiUrlComparison.evaluate(rows, List.of()).outcome());
        }
        var rows = new ArrayList<>(baseline()); rows.add(rows.getFirst());
        assertEquals(Outcome.NOT_VERIFIED, UiUrlComparison.evaluate(rows, List.of()).outcome());
        assertEquals(Outcome.NOT_VERIFIED, UiUrlComparison.evaluate(baseline(), List.of("unbound-native-import")).outcome());
    }
    @Test void targetPolicyAndChronologyCannotChangeBetweenConditions() {
        for (var mutation : List.of("run", "entity", "policy", "time", "evidence", "fixture")) {
            var rows = new ArrayList<>(baseline()); var s = rows.getFirst(); var other = rows.get(1);
            rows.set(0, new UiUrlComparison.Sample(mutation.equals("run") ? "other" : s.runId(),
                    mutation.equals("entity") ? "other" : s.entityId(), s.condition(),
                    mutation.equals("policy") ? "b".repeat(64) : s.stableInputs(),
                    mutation.equals("fixture") ? other.fixtureHash() : s.fixtureHash(), s.requestedAt(),
                    mutation.equals("time") ? s.requestedAt().minusSeconds(1) : s.observedAt(), s.use(),
                    mutation.equals("evidence") ? other.evidence() : s.evidence()));
            assertEquals(Outcome.NOT_VERIFIED, UiUrlComparison.evaluate(rows, List.of()).outcome(), mutation);
        }
    }
}
