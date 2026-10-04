package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;
import com.samlscope.core.evaluation.*;

class NameIdOmissionComparisonTest {
    private NameIdOmissionComparison.Sample sample(NameIdOmissionComparison.Condition condition,
            NameIdOmissionResponseEvidence.Presence presence, String input, int offset) {
        return new NameIdOmissionComparison.Sample("experiment",condition,"https://sp.example","a".repeat(64),input,
            Instant.ofEpochSecond(offset),Instant.ofEpochSecond(offset+1),presence,
            List.of(new EvidenceRef("transcript","request-"+offset),new EvidenceRef("transcript","response-"+offset)));
    }
    @Test void capabilityRequiresCorrelatedBaselineAndOmissionWithoutInputChanges() {
        var baseline=sample(NameIdOmissionComparison.Condition.BASELINE,NameIdOmissionResponseEvidence.Presence.NAME_ID,"b".repeat(64),0);
        var disabled=sample(NameIdOmissionComparison.Condition.NAME_ID_DISABLED,NameIdOmissionResponseEvidence.Presence.OMITTED,"b".repeat(64),2);
        assertEquals(Outcome.SATISFIED,NameIdOmissionComparison.evaluate(List.of(baseline,disabled),List.of()).outcome());
        var bad=new ArrayList<List<NameIdOmissionComparison.Sample>>();
        bad.add(List.of(disabled));bad.add(List.of(baseline,disabled,disabled));
        bad.add(List.of(baseline,sample(NameIdOmissionComparison.Condition.NAME_ID_DISABLED,NameIdOmissionResponseEvidence.Presence.NAME_ID,"b".repeat(64),2)));
        bad.add(List.of(baseline,sample(NameIdOmissionComparison.Condition.NAME_ID_DISABLED,NameIdOmissionResponseEvidence.Presence.BASE_ID,"b".repeat(64),2)));
        bad.add(List.of(baseline,sample(NameIdOmissionComparison.Condition.NAME_ID_DISABLED,NameIdOmissionResponseEvidence.Presence.OMITTED,"c".repeat(64),2)));
        bad.add(List.of(baseline,sample(NameIdOmissionComparison.Condition.NAME_ID_DISABLED,NameIdOmissionResponseEvidence.Presence.OMITTED,"b".repeat(64),0)));
        for(var pair:bad) assertEquals(Outcome.NOT_VERIFIED,NameIdOmissionComparison.evaluate(pair,List.of()).outcome());
        assertEquals(Outcome.NOT_VERIFIED,NameIdOmissionComparison.evaluate(List.of(baseline,disabled),List.of("unverified_original")).outcome());
    }
}
