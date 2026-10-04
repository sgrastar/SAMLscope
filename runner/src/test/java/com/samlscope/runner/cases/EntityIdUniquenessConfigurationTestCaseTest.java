package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class EntityIdUniquenessConfigurationTestCaseTest {
    private static final String RUN="run_00000000000000000000000000";
    @TempDir Path data;
    private MetadataFixtureObservationTestCase fallback(String id) {
        return new MetadataFixtureObservationTestCase(id,TargetRole.IDP,List.of(
            new MetadataFixtureObservationTestCase.Fixture("distinct-entity-ids",MetadataFixtureObservationTestCase.Behavior.ACCEPT,"distinct secondary peer"),
            new MetadataFixtureObservationTestCase.Fixture("duplicate-entity-ids",MetadataFixtureObservationTestCase.Behavior.REJECT,"duplicate conflict control")),
            ConfigurationFailureSemantics.TEST_PRECONDITION);
    }
    private EntityIdUniquenessConfigurationTestCase implementation() {
        return new EntityIdUniquenessConfigurationTestCase(fallback(ShibbolethEntityIdUniquenessEvidence.CASE),
            e->{throw new AssertionError("No fabricated protocol original");},r->new byte[0],r->Optional.empty(),data);
    }
    private CaseContext context(boolean complete) {
        var recorder=new TranscriptRecorder(){
            public List<TranscriptEntry> list(String run){return List.of();}
            public TranscriptEntry record(TranscriptInput input){throw new AssertionError("Must remain read only");}
            public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary){throw new AssertionError("Must remain read only");}
        };
        return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,complete);
    }
    @Test void missingProofPreservesConfigurationAndCampaignPresentation() {
        var test=implementation();assertInstanceOf(CaseStep.AwaitConfig.class,test.start(context(true)));
        assertEquals("metadata-fixture-refresh",test.evidenceCampaignId());
        assertEquals(List.of("control","distinct-entity-ids","duplicate-entity-ids"),test.evidenceActionKeys());
        assertFalse(test.evidenceStatus(context(true)).ready());
    }
    @Test void malformedOwnedProofCannotFallBackOnAnyLifecycle()throws Exception {
        Files.createDirectory(data.resolve(RUN));Files.writeString(data.resolve(RUN).resolve("manifest.json"),"{}");
        var test=implementation();var state=new CaseState("await-metadata-fixture-probe",Map.of());
        assertUnproven(test.start(context(true)));
        for(var event:List.<CaseEvent>of(new CaseEvent.ConfigConfirmed(),new CaseEvent.TranscriptReady(),
                new CaseEvent.Aborted("cancelled"),new CaseEvent.TimedOut(Duration.ofMinutes(1))))
            assertUnproven(test.resume(context(true),state,event));
        assertFalse(test.evidenceStatus(context(true)).ready());
        assertTrue(test.reevaluateRecordedEvidence(context(true),CaseOutcome.notVerified("partial","metadata.fixture-probe.incomplete")).isEmpty());
    }
    @Test void ownedFileAndSymlinkAlsoShadowTheLegacyObserver()throws Exception {
        var selected=data.resolve(RUN);Files.writeString(selected,"not a directory");assertUnproven(implementation().start(context(true)));Files.delete(selected);
        var other=Files.createDirectory(data.resolve("other"));Files.writeString(other.resolve("manifest.json"),"{}");
        Files.createSymbolicLink(selected,other);assertUnproven(implementation().start(context(true)));
    }
    @Test void incompleteHistoryCannotBecomeReadyOrUpdateARecordedResult()throws Exception {
        Files.createDirectory(data.resolve(RUN));
        var test=implementation();assertUnproven(test.start(context(false)));assertFalse(test.evidenceStatus(context(false)).ready());
        assertTrue(test.reevaluateRecordedEvidence(context(false),CaseOutcome.notVerified("partial","metadata.fixture-probe.incomplete")).isEmpty());
    }
    @Test void unrelatedCaseCannotAcquireTheNativeGate() {
        assertThrows(IllegalArgumentException.class,()->new EntityIdUniquenessConfigurationTestCase(fallback("IIP-MD05-a2-idp-01"),
            e->new byte[0],r->new byte[0],r->Optional.empty(),data));
    }
    @Test void conclusiveResultsAreNeverReevaluated() {
        var test=implementation();
        for(var outcome:List.of(Outcome.SATISFIED,Outcome.VIOLATED,Outcome.SATISFIED_WITH_NOTE)) {
            var previous=new CaseOutcome(outcome,null,"prior.conclusion","prior.conclusion",List.of(),Map.of());
            assertFalse(test.supportsRecordedEvidenceReevaluation(previous));assertTrue(test.reevaluateRecordedEvidence(context(true),previous).isEmpty());
        }
    }
    @Test void provenanceCannotMoveBetweenCasesOrRuns() {
        var test=implementation();var proof=new CaseOutcome(Outcome.SATISFIED,null,"metadata.entityid.native-conflict-and-distinct-peers",
            "metadata.entityid.native-conflict-and-distinct-peers",List.of(new EvidenceRef("transcript","tx_00000000000000000000000000"),
            new EvidenceRef("native-entityid-evidence",RUN+"/manifest.json#"+"a".repeat(64))),Map.of("adapter","shibboleth-native-entityid-uniqueness"));
        assertTrue(test.resolvedFromExternalEvidence(execution(RUN,test.id(),proof)));
        assertFalse(test.resolvedFromExternalEvidence(execution(RUN,"IIP-MD05-a2-idp-01",proof)));
        assertFalse(test.resolvedFromExternalEvidence(execution("run_11111111111111111111111111",test.id(),proof)));
    }
    private static CaseExecution execution(String run,String id,CaseOutcome proof) {
        return new CaseExecution(run,id,1,CaseExecutionStatus.FINISHED,new CaseState("finished",Map.of()),null,proof,Instant.now());
    }
    private static void assertUnproven(CaseStep step) {
        var finish=assertInstanceOf(CaseStep.Finish.class,step);assertEquals(Outcome.NOT_VERIFIED,finish.outcome().outcome());
        assertEquals("metadata.entityid.native-unproven",finish.outcome().reasonCode());
    }
}
