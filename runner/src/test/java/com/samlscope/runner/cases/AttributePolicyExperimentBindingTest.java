package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;
import com.samlscope.core.evaluation.*;
import com.samlscope.runner.cases.AttributePolicyComparison.Condition;
import com.samlscope.runner.cases.AttributePolicyExperimentBinding.*;
import com.samlscope.runner.cases.AttributePolicyProtocolEvidence.*;

class AttributePolicyExperimentBindingTest {
    private static final String ID = AttributePolicyComparison.ENTITY;
    private static final String HASH = "a".repeat(64);
    private Collected protocol() {
        var observations = new ArrayList<Observation>();
        var variants = List.of("control", "attribute-policy-entity-present", "attribute-policy-entity-absent");
        for (int i = 0; i < variants.size(); i++) {
            observations.add(new Observation(variants.get(i), "", HASH, "https://sp.example",
                    Instant.EPOCH.plusSeconds(i * 2), Instant.EPOCH.plusSeconds(i * 2 + 1),
                    new AttributePolicyAttributeReader.Observation(i == 1 ? Set.of("anchor", "entity") : Set.of("anchor"), HASH),
                    List.of(ref("fetch-" + i), ref("prepared-" + i), ref("request-" + i), ref("response-" + i))));
        }
        return new Collected("run_test", observations, List.of());
    }
    private EvidenceRef ref(String id) { return new EvidenceRef("transcript", id); }
    private Preparation preparation() {
        var exchanges = new ArrayList<ExchangePreparation>();
        var conditions = List.of(Condition.BASELINE, Condition.ENTITY_PRESENT, Condition.ENTITY_ABSENT);
        for (int i = 0; i < conditions.size(); i++) {
            exchanges.add(new ExchangePreparation(conditions.get(i), "request-" + i, "response-" + i, HASH, HASH, HASH));
        }
        return new Preparation("run_test", "experiment", exchanges);
    }
    @Test void exactBindingPreservesAllProtocolProvenance() {
        var result = AttributePolicyExperimentBinding.evaluate(ID, protocol(), Optional.of(preparation()));
        assertEquals(Outcome.SATISFIED, result.outcome());
        assertEquals(12, result.evidence().size());
        assertFalse(result.details().toString().contains(HASH));
    }
    @Test void missingScopeOrWrongReferencesCannotBeReplacedByNearbyObservations() {
        assertEquals(Outcome.NOT_VERIFIED, AttributePolicyExperimentBinding.evaluate(ID, protocol(), Optional.empty()).outcome());
        var p = preparation();
        assertEquals(Outcome.NOT_VERIFIED, AttributePolicyExperimentBinding.evaluate(ID, protocol(),
                Optional.of(new Preparation("other_run", p.experimentId(), p.exchanges()))).outcome());
        for (String mutation : List.of("response", "request", "condition", "duplicate")) {
            var exchanges = new ArrayList<>(p.exchanges());
            var e = exchanges.get(1);
            exchanges.set(1, new ExchangePreparation(mutation.equals("condition") ? Condition.ENTITY_ABSENT : e.condition(),
                    mutation.equals("request") ? "missing" : mutation.equals("duplicate") ? "request-0" : e.requestReference(),
                    mutation.equals("response") ? "response-2" : mutation.equals("duplicate") ? "response-0" : e.responseReference(),
                    e.policyFingerprint(), e.principalFingerprint(), e.stableInputFingerprint()));
            assertEquals(Outcome.NOT_VERIFIED, AttributePolicyExperimentBinding.evaluate(ID, protocol(),
                    Optional.of(new Preparation(p.runId(), p.experimentId(), exchanges))).outcome(), mutation);
        }
    }
    @Test void signedAttributeInputMismatchAndDuplicateProtocolRequestsRemainUnverified() {
        var original = protocol();
        var observations = new ArrayList<>(original.observations());
        var changed = observations.get(1);
        observations.set(1, new Observation(changed.variant(), changed.selector(), changed.metadataFingerprint(), changed.entityId(),
                changed.issued(), changed.received(), new AttributePolicyAttributeReader.Observation(changed.attributes().markers(), "b".repeat(64)), changed.evidence()));
        assertEquals(Outcome.NOT_VERIFIED, AttributePolicyExperimentBinding.evaluate(ID,
                new Collected(original.runId(), observations, List.of()), Optional.of(preparation())).outcome());
        observations = new ArrayList<>(original.observations()); observations.add(observations.getFirst());
        assertEquals(Outcome.NOT_VERIFIED, AttributePolicyExperimentBinding.evaluate(ID,
                new Collected(original.runId(), observations, List.of()), Optional.of(preparation())).outcome());
    }
}
