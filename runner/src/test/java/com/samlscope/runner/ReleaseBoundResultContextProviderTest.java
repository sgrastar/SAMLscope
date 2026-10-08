package com.samlscope.runner;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.profile.*;
import com.samlscope.core.run.*;
import com.samlscope.runner.result.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;

class ReleaseBoundResultContextProviderTest {
    @Test void oldResultUsesOwnCatalogManifestAndHistoricalUrlsWhileKeepingRuntimeSuiteIdentity() {
        var old=FunctionalReleaseRegistryTest.fixture("old-v1",'a',Rfc2119Level.MUST,FunctionalReleaseContext.Kind.HISTORICAL);
        var registry=new FunctionalReleaseRegistry(List.of(),List.of(old));
        var plan=plan(old.identity());var run=run(plan.id());
        var evaluated=old.evaluate(List.of(),List.of(),List.of());
        var provider=new ReleaseBoundResultContextProvider((r,p,c,e)->{throw new AssertionError("Historical result cannot call current campaign metadata");},(r,p,c,e)->context(),registry);
        var result=provider.context(run,plan,evaluated.cases(),evaluated.result());
        assertEquals(old.components(),result.evaluationComponents());
        assertEquals(context().suite(),result.suite());
        assertEquals(Map.of("case-a","PROTOCOL_OBSERVED"),result.caseEvidenceClasses());
        assertTrue(result.caseDefinitionUrls().get("case-a").contains("/064df1c2c49d8f4e2b718c056970f06562c40f4e/tests/cases.yaml#case-a"));
        assertEquals(1,evaluated.result().coverage().mustUnresolved());
        assertEquals(RunResult.Completeness.INCOMPLETE,evaluated.result().completeness());
    }
    @Test void unknownAndForeignRunNeverPublishNewCatalogProvenance() {
        var old=FunctionalReleaseRegistryTest.fixture("old-v1",'a',Rfc2119Level.MUST,FunctionalReleaseContext.Kind.HISTORICAL);
        var registry=new FunctionalReleaseRegistry(List.of(),List.of(old));
        var provider=new ReleaseBoundResultContextProvider((r,p,c,e)->{throw new AssertionError("No provenance without exact scope");},(r,p,c,e)->{throw new AssertionError("No template without exact scope");},registry);
        var result=old.evaluate(List.of(),List.of(),List.of());
        assertThrows(IllegalArgumentException.class,()->provider.context(run("plan_foreign"),plan(old.identity()),List.of(),result.result()));
        var unknown=new FunctionalDefinitionIdentity(old.identity().profile(),"unknown","sha256:"+"f".repeat(64));
        assertThrows(HistoricalRunReadPolicy.DefinitionUnavailable.class,()->provider.context(run("plan_0123456789ABCDEFGHJKMNPQRS"),plan(unknown),List.of(),result.result()));
    }
    static TestPlan plan(FunctionalDefinitionIdentity identity) {
        var now=Instant.parse("2026-10-08T00:00:00Z");
        return new TestPlan("plan_0123456789ABCDEFGHJKMNPQRS","Owned history fixture",identity.profile(),identity,
                new TestPlan.Target(TargetKind.IDP,"https://fixture.example/entity",new TestPlan.MetadataSource(MetadataSourceKind.URL,"https://fixture.example/metadata")),
                MetadataDeliveryKind.MANUAL,Map.of(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),now,now);
    }
    static TestRun run(String plan) {var now=Instant.parse("2026-10-08T00:00:00Z");return new TestRun("run_0123456789ABCDEFGHJKMNPQRS",plan,RunStatus.COMPLETED,Reachability.CONFIRMED,Map.of(),now,now);}
    static ResultDocumentContext context() {
        String digest="sha256:"+"f".repeat(64);
        return new ResultDocumentContext(new ResultDocumentContext.Suite("Suite","current-v2",digest,"local"),
                new ResultDocumentContext.EvaluationComponents(digest,digest,digest,"1","1"),
                new ResultDocumentContext.ProfileSpec("IIP","1.1",LocalDate.parse("2019-12-18"),"Owned fixture"),
                new ResultDocumentContext.TargetDeclaration("fixture","test",digest),
                Map.of("REQ","https://fixture.example/requirements#REQ"),Map.of("case-a","https://fixture.example/cases#case-a"),Map.of("foreign-global-case","SELF_ATTESTED"),List.of());
    }
}
