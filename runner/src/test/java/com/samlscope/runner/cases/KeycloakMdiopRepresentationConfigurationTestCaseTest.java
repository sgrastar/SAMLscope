package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;

class KeycloakMdiopRepresentationConfigurationTestCaseTest {
    @TempDir Path directory;
    private static final String RUN="run_00000000000000000000000001";
    private final TranscriptRecorder recorder=new TranscriptRecorder() {
        public List<TranscriptEntry> list(String run){return List.of();}
        public TranscriptEntry record(TranscriptInput input){throw new UnsupportedOperationException();}
        public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary){throw new UnsupportedOperationException();}
    };
    private DefaultCaseContext context() {
        return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,true);
    }
    private KeycloakMdiopRepresentationConfigurationTestCase testCase() {
        var fallback=new MetadataFixtureObservationTestCase(KeycloakMdiopRepresentationEvidenceFile.ID,
                TargetRole.IDP,KeycloakMdiopRepresentationEvidenceFile.REQUIRED.stream()
                    .filter(v->!v.equals("control"))
                    .map(v->new MetadataFixtureObservationTestCase.Fixture(v,
                        MetadataFixtureObservationTestCase.Behavior.ACCEPT,"Representation admission")).toList(),
                ConfigurationFailureSemantics.NORMATIVE_CAPABILITY);
        return new KeycloakMdiopRepresentationConfigurationTestCase(fallback,e->new byte[0],r->new byte[0],directory);
    }
    @Test void completeNativeMatrixIsRequiredWithoutReceipt() {
        var testCase=testCase();var context=context();
        assertTrue(testCase.requiresPreparationConfirmation());
        assertFalse(testCase.evidenceStatus(context).ready());
        var start=(CaseStep.AwaitConfig)testCase.start(context);
        var finish=(CaseStep.Finish)testCase.resume(context,start.next(),new CaseEvent.ConfigConfirmed());
        assertEquals(Outcome.NOT_VERIFIED,finish.outcome().outcome());
        assertEquals("metadata.fixture-probe.incomplete",finish.outcome().reasonCode());
        assertEquals(KeycloakMdiopRepresentationEvidenceFile.REQUIRED,testCase.evidenceActionKeys());
    }
    @Test void receiptClaimsDoNotReplaceNativeOriginals()throws Exception {
        Files.writeString(directory.resolve(RUN+".mdiop-representation.json"),
                "{\"runId\":\""+RUN+"\",\"restored\":true,\"all_variants_admitted\":true}");
        var testCase=testCase();var context=context();
        var start=(CaseStep.AwaitConfig)testCase.start(context);
        var finish=(CaseStep.Finish)testCase.resume(context,start.next(),new CaseEvent.ConfigConfirmed());
        assertEquals(Outcome.NOT_VERIFIED,finish.outcome().outcome());
        assertEquals("metadata.mdiop.native-representation-admission-incomplete",finish.outcome().reasonCode());
        assertEquals(true,finish.outcome().details().get("configuration_confirmed"));
        assertFalse(testCase.evidenceStatus(context).ready());
    }
    @Test void nativeAdapterDoesNotReplaceApprovedConfigurationFailureSemantics()throws Exception {
        Files.writeString(directory.resolve(RUN+".mdiop-representation.json"),"{}");
        var testCase=testCase();var context=context();var start=(CaseStep.AwaitConfig)testCase.start(context);
        var finish=(CaseStep.Finish)testCase.resume(context,start.next(),new CaseEvent.ConfigUnavailable(
                CaseEvent.ConfigurationIssue.CAPABILITY_ABSENT,"Native capability absent"));
        assertEquals(Outcome.VIOLATED,finish.outcome().outcome());
        assertEquals("capability_absent",finish.outcome().reasonCode());
    }
    @Test void simpleSamlPhpReceiptCannotFallThroughToGenericFixtureClaims()throws Exception {
        Files.writeString(directory.resolve(RUN+".ssp-mdiop-representation.json"),
                "{\"runId\":\""+RUN+"\",\"restored\":true,\"all_variants_admitted\":true}");
        var testCase=testCase();var context=context();
        var start=(CaseStep.AwaitConfig)testCase.start(context);
        var finish=(CaseStep.Finish)testCase.resume(context,start.next(),new CaseEvent.ConfigConfirmed());
        assertEquals(Outcome.NOT_VERIFIED,finish.outcome().outcome());
        assertEquals("metadata.mdiop.native-representation-admission-incomplete",finish.outcome().reasonCode());
        assertEquals(true,finish.outcome().details().get("configuration_confirmed"));
        assertFalse(testCase.evidenceStatus(context).ready());
        assertEquals(Optional.empty(),testCase.reevaluateRecordedEvidence(context,finish.outcome()));
    }
    @Test void twoNativeAdapterReceiptsAreAmbiguous()throws Exception {
        Files.writeString(directory.resolve(RUN+".mdiop-representation.json"),"{}");
        Files.writeString(directory.resolve(RUN+".ssp-mdiop-representation.json"),"{}");
        var testCase=testCase();var context=context();
        var start=(CaseStep.AwaitConfig)testCase.start(context);
        var finish=(CaseStep.Finish)testCase.resume(context,start.next(),new CaseEvent.ConfigConfirmed());
        assertEquals(Outcome.NOT_VERIFIED,finish.outcome().outcome());
        assertEquals("metadata.mdiop.native-representation-admission-incomplete",finish.outcome().reasonCode());
        assertFalse(testCase.evidenceStatus(context).ready());
    }
    @Test void reevaluationCannotInventPreparationConfirmation() {
        var previous=CaseOutcome.notVerified("metadata_fixture_probe_incomplete","metadata.fixture-probe.incomplete");
        assertFalse(testCase().supportsRecordedEvidenceReevaluation(previous));
        assertEquals(Optional.empty(),testCase().reevaluateRecordedEvidence(context(),previous));
    }
}
