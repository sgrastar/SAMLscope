package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SimpleSamlPhpConsentUriWiringTest {
    private static final String RUN="run_00000000000000000000000000";
    @TempDir Path data;
    private final TranscriptContentReader content=e->{throw new AssertionError("No invented original may support a verdict");};
    private DefaultCaseContext context(boolean complete){return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,
        new TranscriptRecorder(){public List<TranscriptEntry> list(String r){return List.of();}public TranscriptEntry record(TranscriptInput input){throw new AssertionError("No sends");}public TranscriptEntry updateSamlAnalysis(String id,String c,Map<String,Object> s){throw new AssertionError("No mutations");}},complete);}
    private UiUrlBrowserEvidenceTestCase url(){return new UiUrlBrowserEvidenceTestCase(content,r->new byte[0],data.resolve("ui-url-evidence"));}
    private final class Original implements TestCase,QueuedProtocolEvidenceCase {
        final String id;int calls;Original(String id){this.id=id;}
        public String id(){return id;}public TargetRole role(){return TargetRole.IDP;}
        private CaseOutcome outcome(){calls++;return CaseOutcome.notVerified("original_path","original.browser-evidence");}
        public CaseStep start(CaseContext c){return new CaseStep.Finish(outcome());}
        public CaseStep resume(CaseContext c,CaseState s,CaseEvent e){return new CaseStep.Finish(outcome());}
        public CaseOutcome queuedEvidenceOutcome(CaseContext c){return outcome();}
        public EvidenceStatus evidenceStatus(CaseContext c){return new EvidenceStatus(false,List.of("original"),List.of(),Map.of("original",true));}
    }
    private NativeUiFeatureAbsenceTestCase discovery(Original original){return new NativeUiFeatureAbsenceTestCase(original,r->new byte[0],new NativeUiFeatureAbsenceEvidence(data.resolve("ui-native-feature-absence"),content),new ShibbolethUiConsumerEvidence(data.resolve("ui-url-evidence"),content),new SimpleSamlPhpConsentUriEvidence(data.resolve("ui-consent-uri-evidence"),content));}
    private Path owned()throws Exception{return Files.createDirectories(data.resolve("ui-consent-uri-evidence")).resolve(RUN);}
    @Test void noOwnedProofPreservesDiscoveryDelegateAndUrlLegacyIncompletePath(){
        var original=new Original(NativeUiFeatureAbsenceEvidence.DISCOVERY);var test=discovery(original);assertEquals("original.browser-evidence",((CaseStep.Finish)test.start(context(true))).outcome().reasonCode());
        assertEquals("original.browser-evidence",((CaseStep.Finish)test.resume(context(true),CaseState.initial(),new CaseEvent.TranscriptReady())).outcome().reasonCode());
        assertEquals(Map.of("original",true),test.evidenceStatus(context(true)).details());assertEquals(2,original.calls);assertEquals(Outcome.NOT_VERIFIED,url().queuedEvidenceOutcome(context(true)).outcome());
    }
    @Test void invalidOwnedProofBlocksQueuedStartResumeStatusAndRecordedFallback()throws Exception{
        Path folder=Files.createDirectory(owned());Files.writeString(folder.resolve("manifest.json"),"{\"restored\":true,\"no_discovery_ui\":true}");
        var original=new Original(NativeUiFeatureAbsenceEvidence.DISCOVERY);var test=discovery(original);var previous=CaseOutcome.notVerified("missing","browser.oracle-unavailable");
        for(boolean complete:List.of(true,false)){
            var context=context(complete);assertEquals(Outcome.NOT_VERIFIED,((CaseStep.Finish)test.start(context)).outcome().outcome());assertEquals(Outcome.NOT_VERIFIED,((CaseStep.Finish)test.resume(context,CaseState.initial(),new CaseEvent.TranscriptReady())).outcome().outcome());
            assertEquals(Outcome.NOT_VERIFIED,test.queuedEvidenceOutcome(context).outcome());assertFalse(test.evidenceStatus(context).ready());assertTrue(test.reevaluateRecordedEvidence(context,previous).isEmpty());
            var url=url();assertEquals(Outcome.NOT_VERIFIED,url.queuedEvidenceOutcome(context).outcome());assertFalse(url.evidenceStatus(context).ready());assertTrue(url.reevaluateRecordedEvidence(context,previous).isEmpty());
        }
        assertEquals(0,original.calls);
    }
    @Test void ownedFileAndSymlinkDoNotFallBackToAnotherProductOrDeclaration()throws Exception{
        Path path=Files.writeString(owned(),"invalid");var original=new Original(NativeUiFeatureAbsenceEvidence.DISCOVERY);
        assertFalse(discovery(original).evidenceStatus(context(true)).ready());assertFalse(url().evidenceStatus(context(true)).ready());Files.delete(path);Files.createSymbolicLink(path,Files.createDirectory(data.resolve("foreign")));
        assertEquals(Outcome.NOT_VERIFIED,discovery(original).queuedEvidenceOutcome(context(true)).outcome());assertEquals(Outcome.NOT_VERIFIED,url().queuedEvidenceOutcome(context(true)).outcome());assertEquals(0,original.calls);
    }
    @Test void simultaneousUrlProductOwnershipIsAlwaysUnverified()throws Exception{
        for(var pair:List.of(List.of("ssp","shib"),List.of("ssp","kc"),List.of("shib","kc"))){
            Path ssp=owned(),shib=Files.createDirectories(data.resolve("ui-url-evidence")).resolve(RUN),kc=Files.createDirectories(data.resolve("ui-native-feature-absence")).resolve(RUN+".keycloak-ui-consumer.json");
            for(String product:pair)Files.writeString(product.equals("ssp")?ssp:product.equals("shib")?shib:kc,"invalid owned originals");
            assertEquals(Outcome.NOT_VERIFIED,url().queuedEvidenceOutcome(context(true)).outcome());assertFalse(url().evidenceStatus(context(true)).ready());Files.deleteIfExists(ssp);Files.deleteIfExists(shib);Files.deleteIfExists(kc);
        }
    }
    @Test void discoveryDualOwnershipAndCaseScopeCannotAssertDisplayAbsence()throws Exception{
        Files.writeString(owned(),"invalid");var original=new Original(NativeUiFeatureAbsenceEvidence.DISCOVERY);Path generic=Files.createDirectories(data.resolve("ui-native-feature-absence")).resolve(RUN+".json");Files.writeString(generic,"invalid owned originals");
        assertEquals(Outcome.NOT_VERIFIED,discovery(original).queuedEvidenceOutcome(context(true)).outcome());assertEquals(0,original.calls);Files.delete(generic);
        Path shib=Files.createDirectories(data.resolve("ui-url-evidence")).resolve(RUN);Files.writeString(shib,"invalid owned originals");assertEquals(Outcome.NOT_VERIFIED,discovery(original).queuedEvidenceOutcome(context(true)).outcome());assertEquals(0,original.calls);Files.delete(shib);
        var display=new Original(NativeUiFeatureAbsenceEvidence.DISPLAY);assertEquals("original.browser-evidence",((CaseStep.Finish)discovery(display).start(context(true))).outcome().reasonCode());assertEquals(1,display.calls);
    }
}
