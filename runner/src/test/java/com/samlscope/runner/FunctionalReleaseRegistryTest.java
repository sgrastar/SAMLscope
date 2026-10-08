package com.samlscope.runner;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.casedef.CaseDefinitionCatalog;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.profile.*;
import com.samlscope.runner.result.EvaluationArtifactDigests;
import java.util.*;
import org.junit.jupiter.api.Test;

class FunctionalReleaseRegistryTest {
    @Test void oldAndNewExactIdentitiesRetainTheirOwnCaseDigestAndCoverage() {
        var old = fixture("old-v1",'a',Rfc2119Level.MUST,FunctionalReleaseContext.Kind.HISTORICAL);
        var current = fixture("new-v2",'b',Rfc2119Level.SHOULD,FunctionalReleaseContext.Kind.CURRENT);
        var registry = new FunctionalReleaseRegistry(List.of(current),List.of(old));
        assertEquals(current.identity(),registry.identity(FunctionalProfile.METADATA_IDP));
        assertEquals("sha256:"+"a".repeat(64),registry.require(old.identity()).definition().cases().getFirst().caseDigest());
        var violated = List.of(CaseRun.completed("case-a","REQ.a",CaseOutcome.of(Outcome.VIOLATED,"fixture-negative",List.of())));
        assertEquals(Verdict.FAIL,registry.require(old.identity()).evaluate(List.of(),violated,List.of()).result().obligations().getFirst().verdict());
        assertEquals(Verdict.WARNING,registry.require(current.identity()).evaluate(List.of(),violated,List.of()).result().obligations().getFirst().verdict());
    }
    @Test void unavailableRevisionNeverAliasesTheSameProfileOrVersion() {
        var old = fixture("old-v1",'a',Rfc2119Level.MUST,FunctionalReleaseContext.Kind.HISTORICAL);
        var registry = new FunctionalReleaseRegistry(List.of(),List.of(old));
        var absent = new FunctionalDefinitionIdentity(old.identity().profile(),old.identity().version(),"sha256:"+"f".repeat(64));
        assertTrue(registry.find(absent).isEmpty());
        assertThrows(HistoricalRunReadPolicy.DefinitionUnavailable.class,()->registry.require(absent));
        assertThrows(IllegalArgumentException.class,()->registry.identity(old.identity().profile()));
    }
    @Test void duplicatesAndChangedCatalogsCannotOverwriteAnExactIdentity() {
        var old = fixture("old-v1",'a',Rfc2119Level.MUST,FunctionalReleaseContext.Kind.HISTORICAL);
        assertThrows(IllegalArgumentException.class,()->new FunctionalReleaseRegistry(List.of(),List.of(old,old)));
        var active = fixture("old-v1",'a',Rfc2119Level.MUST,FunctionalReleaseContext.Kind.CURRENT);
        assertEquals(active.identity(),new FunctionalReleaseRegistry(List.of(active),List.of(old)).identity(active.identity().profile()));
        var conflict = fixture("old-v1",'a',Rfc2119Level.SHOULD,FunctionalReleaseContext.Kind.HISTORICAL);
        assertThrows(IllegalArgumentException.class,()->new FunctionalReleaseRegistry(List.of(active),List.of(conflict)));
    }
    @Test void sourceBytesAreImmutableAndResultComponentsUseHistoricalOriginals() {
        var old = fixture("old-v1",'a',Rfc2119Level.MUST,FunctionalReleaseContext.Kind.HISTORICAL);
        var first = old.sourceBytes("tests/cases.yaml"); first[0]^=1;
        assertNotEquals(EvaluationArtifactDigests.digestBytes(first),old.sourceDigests().get("tests/cases.yaml"));
        assertEquals(old.sourceDigests().get("tests/coverage.yaml"),old.components().coverageYaml());
        assertThrows(IllegalArgumentException.class,()->old.sourceBytes("private/key"));
    }
    @Test void sharedInventoryCopiesIngressOnceAndEveryReaderCannotMutateItsOwner() {
        var original = fixture("old-v1",'a',Rfc2119Level.MUST,FunctionalReleaseContext.Kind.HISTORICAL);
        var inputs = new LinkedHashMap<String,byte[]>();
        FunctionalReleaseContext.SOURCE_PATHS.forEach(path -> inputs.put(path,original.sourceBytes(path)));
        var inventory = new FunctionalReleaseContext.SourceInventory(inputs);
        var first = new FunctionalReleaseContext(original.identity(),original.definition(),original.cases(),original.coverage(),
                original.predicates(),inventory,FunctionalReleaseContext.Kind.HISTORICAL,original.sourceCommit().orElseThrow());
        var second = new FunctionalReleaseContext(original.identity(),original.definition(),original.cases(),original.coverage(),
                original.predicates(),inventory,FunctionalReleaseContext.Kind.CURRENT,null);
        assertSame(first.sourceInventory(),second.sourceInventory());assertSame(first.components(),second.components());
        var expected = first.sourceDigests();inputs.get("tests/cases.yaml")[0]^=1;inputs.remove("tests/specs.yaml");
        byte[] read = second.sourceBytes("tests/cases.yaml");read[0]^=1;
        assertEquals(expected,first.sourceDigests());assertEquals(expected,second.sourceDigests());
        assertArrayEquals(original.sourceBytes("tests/cases.yaml"),first.sourceBytes("tests/cases.yaml"));
        assertFalse(inventory.matches(inputs));assertThrows(UnsupportedOperationException.class,()->inventory.digests().put("private/token","forged"));
        assertThrows(IllegalArgumentException.class,()->new FunctionalReleaseContext.SourceInventory(inputs));
    }

    static FunctionalReleaseContext fixture(String version,char digest,Rfc2119Level level,FunctionalReleaseContext.Kind kind) {
        var sources = new LinkedHashMap<String,byte[]>();
        FunctionalReleaseContext.SOURCE_PATHS.forEach(path -> sources.put(path,(path+":"+version+":"+level).getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        var cases = new CaseDefinitionCatalog(List.of(new CaseDefinitionCatalog.CaseDefinition(
                "case-a","REQ.a",TargetRole.IDP,CaseDefinitionCatalog.ExecutionMode.AUTOMATED,
                CaseDefinitionCatalog.Milestone.M1,List.of(),Map.of(),List.of(),List.of(),List.of(),
                "Owned fixture control.",List.of(),new CaseDefinitionCatalog.Requirements(List.of(),"none"),false,null,"sha256:"+String.valueOf(digest).repeat(64))));
        var coverage = new CoverageCatalog(List.of(new CoverageCatalog.Obligation("REQ.a","REQ",level,List.of(TargetRole.IDP),null,CoverageCatalog.Testability.AUTOMATED,CoverageCatalog.ProfileScope.CORE)));
        var sourceDigests = new LinkedHashMap<String,String>();
        for (var path : List.of("tests/coverage.yaml","tests/cases.yaml","tests/predicates.yaml")) sourceDigests.put(path,EvaluationArtifactDigests.digestBytes(sources.get(path)));
        var definition = new FunctionalCaseDefinition(version,FunctionalProfile.METADATA_IDP,sourceDigests,
                List.of(new FunctionalCaseDefinition.CaseReference("case-a",cases.require("case-a").caseDigest())),Set.of(),cases,coverage);
        var identity = new FunctionalDefinitionIdentity(definition.profile(),version,"sha256:"+String.valueOf(digest).repeat(64));
        return new FunctionalReleaseContext(identity,definition,cases,coverage,new PredicateCatalog(List.of()),sources,kind,
                kind==FunctionalReleaseContext.Kind.HISTORICAL ? "064df1c2c49d8f4e2b718c056970f06562c40f4e":null);
    }
}
