package com.samlscope.runner;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.casedef.CaseDefinitionCatalog;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.profile.*;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;

class ReleaseBoundCaseRunProjectionTest {
    static final String RUN="run_0123456789ABCDEFGHJKMNPQRS";
    @Test void retiredOldApprovedIdProjectsWithItsOriginalOwnerWhileLatestCatalogRejectsIt() {
        var base=FunctionalReleaseRegistryTest.fixture("old",'a',Rfc2119Level.MUST,FunctionalReleaseContext.Kind.HISTORICAL);
        var oldCase=base.cases().require("case-a");
        var retired=new CaseDefinitionCatalog.CaseDefinition("retired-old-case",oldCase.obligation(),oldCase.role(),oldCase.mode(),oldCase.milestone(),oldCase.coversVariants(),oldCase.variantScopes(),oldCase.variantPlan(),oldCase.variantGroups(),oldCase.controls(),oldCase.counterexampleEn(),oldCase.interpretationConstraints(),oldCase.requires(),oldCase.destroysSession(),oldCase.configurationFailureSemantics(),oldCase.caseDigest());
        var cases=new CaseDefinitionCatalog(List.of(retired));
        var definition=new FunctionalCaseDefinition("old",base.definition().profile(),base.definition().sourceDigests(),List.of(new FunctionalCaseDefinition.CaseReference(retired.id(),retired.caseDigest())),Set.of(),cases,base.coverage());
        var sources=new HashMap<String,byte[]>();FunctionalReleaseContext.SOURCE_PATHS.forEach(path->sources.put(path,base.sourceBytes(path)));
        var old=new FunctionalReleaseContext(base.identity(),definition,cases,base.coverage(),base.predicates(),sources,base.kind(),base.sourceCommit().orElseThrow());
        var execution=new CaseExecution(RUN,retired.id(),1,CaseExecutionStatus.FINISHED,new CaseState("finished",Map.of()),null,CaseOutcome.of(Outcome.VIOLATED,"owned-old-outcome",List.of()),Instant.EPOCH);
        var projected=ReleaseBoundCaseRunProjection.project(RUN,old,List.of(execution));
        assertEquals("REQ.a",projected.getFirst().obligationKey());
        assertEquals(Verdict.FAIL,old.evaluate(List.of(),projected,List.of()).result().obligations().getFirst().verdict());
        assertThrows(IllegalArgumentException.class,()->ReleaseBoundCaseRunProjection.project(RUN,base,List.of(execution)));
    }
    @Test void changedSameIdRemainsReadableButCannotExecuteThroughLatestImplementation() {
        var old=FunctionalReleaseRegistryTest.fixture("old",'a',Rfc2119Level.MUST,FunctionalReleaseContext.Kind.HISTORICAL);
        var current=FunctionalReleaseRegistryTest.fixture("new",'b',Rfc2119Level.SHOULD,FunctionalReleaseContext.Kind.CURRENT);
        var policy=new HistoricalRunReadPolicy(new FunctionalReleaseRegistry(List.of(current),List.of(old)));
        assertEquals(old,policy.requireEvaluation(old.identity()));
        assertThrows(HistoricalRunReadPolicy.DefinitionUnavailable.class,()->policy.requireExecution(old.identity()));
        assertEquals(current,policy.requireExecution(current.identity()));
        assertArrayEquals(new byte[]{1},policy.readForRuntime(old.identity(),()->Optional.of(new byte[]{1}),()->{throw new AssertionError("No current dispatch");},()->{throw new AssertionError("Cache exists");}));
    }
}
