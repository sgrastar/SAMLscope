package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;
import com.samlscope.core.evaluation.*;

class NameIdOmissionExperimentBindingTest {
    private List<EvidenceRef> refs(String suffix) { return List.of(new EvidenceRef("transcript","fetch"),
        new EvidenceRef("transcript","metadata"),new EvidenceRef("transcript","request-"+suffix),new EvidenceRef("transcript","response-"+suffix)); }
    private NameIdOmissionProtocolEvidence.Collected protocol() {
        return new NameIdOmissionProtocolEvidence.Collected("run_test",List.of(
            new NameIdOmissionProtocolEvidence.Observation(NameIdOmissionComparison.Condition.BASELINE,"entity","a".repeat(64),"d".repeat(64),
                Instant.ofEpochSecond(1),Instant.ofEpochSecond(2),NameIdOmissionResponseEvidence.Presence.NAME_ID,refs("base")),
            new NameIdOmissionProtocolEvidence.Observation(NameIdOmissionComparison.Condition.NAME_ID_DISABLED,"entity","a".repeat(64),"d".repeat(64),
                Instant.ofEpochSecond(3),Instant.ofEpochSecond(4),NameIdOmissionResponseEvidence.Presence.OMITTED,refs("omit"))),List.of());
    }
    private NameIdOmissionExperimentBinding.ExchangePreparation exchange(NameIdOmissionComparison.Condition condition,String suffix,String response) {
        return new NameIdOmissionExperimentBinding.ExchangePreparation(condition,"metadata","request-"+suffix,response,"b".repeat(64),"c".repeat(64));
    }
    @Test void exactPreparedReferencesAreRequiredEvenForVerifiedOmission() {
        var baseline=exchange(NameIdOmissionComparison.Condition.BASELINE,"base","response-base");
        var omitted=exchange(NameIdOmissionComparison.Condition.NAME_ID_DISABLED,"omit","response-omit");
        var preparation=new NameIdOmissionExperimentBinding.Preparation("run_test","experiment",List.of(baseline,omitted));
        var valid=NameIdOmissionExperimentBinding.evaluate(protocol(),Optional.of(preparation));
        assertEquals(Outcome.SATISFIED,valid.outcome());assertEquals(6,valid.evidence().size());
        assertEquals(Outcome.NOT_VERIFIED,NameIdOmissionExperimentBinding.evaluate(protocol(),Optional.empty()).outcome());
        for(var bad:List.of(
                new NameIdOmissionExperimentBinding.Preparation("another","experiment",List.of(baseline,omitted)),
                new NameIdOmissionExperimentBinding.Preparation("run_test","experiment",List.of(baseline,baseline)),
                new NameIdOmissionExperimentBinding.Preparation("run_test","experiment",List.of(baseline,
                    exchange(NameIdOmissionComparison.Condition.NAME_ID_DISABLED,"omit","wrong-response"))),
                new NameIdOmissionExperimentBinding.Preparation("run_test","experiment",List.of(baseline,
                    exchange(NameIdOmissionComparison.Condition.BASELINE,"omit","response-omit"))))) {
            assertEquals(Outcome.NOT_VERIFIED,NameIdOmissionExperimentBinding.evaluate(protocol(),Optional.of(bad)).outcome());
        }
    }
}
