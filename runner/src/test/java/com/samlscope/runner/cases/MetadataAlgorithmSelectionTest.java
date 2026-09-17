package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import com.samlscope.core.evaluation.Outcome;

class MetadataAlgorithmSelectionTest {
    private List<MetadataAlgorithmSelection.Sample> correct(String id) {
        return MetadataAlgorithmSelection.required(id).stream().map(v->{
            var input=MetadataAlgorithmSelection.INPUTS.get(v);
            var d=input.role().digests().isEmpty()?input.entity().digests():input.role().digests();
            var s=input.role().signatures().isEmpty()?input.entity().signatures():input.role().signatures();
            return new MetadataAlgorithmSelection.Sample("poll_one",v,input,List.of(new MetadataAlgorithmSelection.Methods(
                List.of(d.isEmpty()?MetadataAlgorithmSelection.D256:d.getFirst()),List.of(s.isEmpty()?MetadataAlgorithmSelection.S256:s.getFirst()))),List.of());
        }).toList();
    }
    @Test void verifiesBothOrdersAndDoesNotAssumeLocalPolicy() {
        var samples=correct(MetadataAlgorithmSelection.ORDER);
        assertEquals(Outcome.SATISFIED,MetadataAlgorithmSelection.evaluate(MetadataAlgorithmSelection.ORDER,samples,List.of()).outcome());
        var fixed=samples.stream().map(s->new MetadataAlgorithmSelection.Sample(s.campaign(),s.variant(),s.advertised(),
            List.of(new MetadataAlgorithmSelection.Methods(List.of(MetadataAlgorithmSelection.D256),List.of(MetadataAlgorithmSelection.S256))),s.evidence())).toList();
        var unknown=MetadataAlgorithmSelection.evaluate(MetadataAlgorithmSelection.ORDER,fixed,List.of());
        assertEquals(Outcome.NOT_VERIFIED,unknown.outcome());assertEquals("metadata.algorithms.local-policy-unverified",unknown.reasonCode());
    }
    @Test void sequentialSelectionMustSkipUnsupportedAndProveBothSupportedOrders() {
        var id=MetadataAlgorithmSelection.SEQUENTIAL;
        var unconditionalFirst=correct(id);
        assertEquals(Outcome.NOT_VERIFIED,MetadataAlgorithmSelection.evaluate(id,unconditionalFirst,List.of()).outcome());
        var samples=unconditionalFirst.stream().map(s->!s.variant().equals("algorithm-unsupported-first")?s:
            new MetadataAlgorithmSelection.Sample(s.campaign(),s.variant(),s.advertised(),List.of(
                new MetadataAlgorithmSelection.Methods(List.of(MetadataAlgorithmSelection.D256),List.of(MetadataAlgorithmSelection.S256))),s.evidence())).toList();
        assertEquals(Outcome.SATISFIED,MetadataAlgorithmSelection.evaluate(id,samples,List.of()).outcome());
        assertEquals(Outcome.NOT_VERIFIED,MetadataAlgorithmSelection.evaluate(id,
            samples.stream().filter(s->!s.variant().equals("algorithm-unsupported-first")).toList(),List.of()).outcome());
        var fixed=samples.stream().map(s->new MetadataAlgorithmSelection.Sample(s.campaign(),s.variant(),s.advertised(),List.of(
            new MetadataAlgorithmSelection.Methods(List.of(MetadataAlgorithmSelection.D256),List.of(MetadataAlgorithmSelection.S256))),s.evidence())).toList();
        assertEquals(Outcome.NOT_VERIFIED,MetadataAlgorithmSelection.evaluate(id,fixed,List.of()).outcome());
    }
    @Test void roleOverridesArePerAlgorithmTypeAndCannotMergeEntityLists() {
        var samples=correct(MetadataAlgorithmSelection.ROLE);
        assertEquals(Outcome.SATISFIED,MetadataAlgorithmSelection.evaluate(MetadataAlgorithmSelection.ROLE,samples,List.of()).outcome());
        for(String variant:List.of("algorithm-role-signing-384","algorithm-role-digest-384","algorithm-role-both-384")) {
            var mutant=samples.stream().map(s->!s.variant().equals(variant)?s:new MetadataAlgorithmSelection.Sample(s.campaign(),s.variant(),s.advertised(),
                List.of(new MetadataAlgorithmSelection.Methods(List.of(MetadataAlgorithmSelection.D256),List.of(MetadataAlgorithmSelection.S256))),s.evidence())).toList();
            assertEquals(Outcome.VIOLATED,MetadataAlgorithmSelection.evaluate(MetadataAlgorithmSelection.ROLE,mutant,List.of()).outcome(),variant);
        }
        var discardOtherType=samples.stream().map(s->!s.variant().equals("algorithm-role-digest-384")?s:new MetadataAlgorithmSelection.Sample(s.campaign(),s.variant(),s.advertised(),
            List.of(new MetadataAlgorithmSelection.Methods(List.of(MetadataAlgorithmSelection.D384),List.of(MetadataAlgorithmSelection.S384))),s.evidence())).toList();
        assertEquals(Outcome.VIOLATED,MetadataAlgorithmSelection.evaluate(MetadataAlgorithmSelection.ROLE,discardOtherType,List.of()).outcome());
    }
    @Test void incompleteHistoryWrongFixtureAndMixedCampaignsCannotConclude() {
        var samples=correct(MetadataAlgorithmSelection.ROLE);
        assertEquals(Outcome.NOT_VERIFIED,MetadataAlgorithmSelection.evaluate(MetadataAlgorithmSelection.ROLE,samples.subList(1,samples.size()),List.of()).outcome());
        assertEquals(Outcome.NOT_VERIFIED,MetadataAlgorithmSelection.evaluate(MetadataAlgorithmSelection.ROLE,samples,List.of("signature_unverified")).outcome());
        var mixed=new ArrayList<MetadataAlgorithmSelection.Sample>();
        for(int i=0;i<samples.size();i++) { var s=samples.get(i);mixed.add(new MetadataAlgorithmSelection.Sample("poll_"+(i%2),s.variant(),s.advertised(),s.selected(),s.evidence())); }
        assertEquals(Outcome.NOT_VERIFIED,MetadataAlgorithmSelection.evaluate(MetadataAlgorithmSelection.ROLE,mixed,List.of()).outcome());
        var incorrect=samples.stream().map(s->new MetadataAlgorithmSelection.Sample(s.campaign(),s.variant(),MetadataAlgorithmSelection.INPUTS.get("control"),s.selected(),s.evidence())).toList();
        assertEquals(Outcome.NOT_VERIFIED,MetadataAlgorithmSelection.evaluate(MetadataAlgorithmSelection.ROLE,incorrect,List.of()).outcome());
        var empty=samples.stream().map(s->new MetadataAlgorithmSelection.Sample(s.campaign(),s.variant(),s.advertised(),List.of(new MetadataAlgorithmSelection.Methods(List.of(),List.of())),s.evidence())).toList();
        assertEquals(Outcome.NOT_VERIFIED,MetadataAlgorithmSelection.evaluate(MetadataAlgorithmSelection.ROLE,empty,List.of()).outcome());
    }
}
