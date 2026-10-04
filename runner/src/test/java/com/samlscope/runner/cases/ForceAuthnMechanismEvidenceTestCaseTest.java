package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.*;
import java.net.URI;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ForceAuthnMechanismEvidenceTestCaseTest {
    private static final String RUN="run_00000000000000000000000000";
    @TempDir Path directory;
    private IdpForceAuthnScenarioTestCase fallback(){return new IdpForceAuthnScenarioTestCase(IdpForceAuthnScenarioTestCase.MECHANISM_ACCESS_CASE,
        r->new IdpErrorProbeConfiguration(URI.create("https://idp.example/sso"),"https://suite.example/sp",URI.create("https://suite.example/acs"),Duration.ofMinutes(1),true,true,true));}
    private ForceAuthnMechanismEvidenceTestCase test(){return new ForceAuthnMechanismEvidenceTestCase(fallback(),new ShibbolethForceAuthnMechanismEvidence(directory,e->{throw new AssertionError("No originals");},r->new byte[0],r->Optional.empty()));}
    private CaseContext context(boolean complete){return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,new TranscriptRecorder(){
        public List<TranscriptEntry> list(String run){return List.of();}public TranscriptEntry record(TranscriptInput input){throw new AssertionError("Read only");}
        public TranscriptEntry updateSamlAnalysis(String id,String c,Map<String,Object>s){throw new AssertionError("Originals unchanged");}},complete);}
    private static void nv(CaseStep step){assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,step).outcome().outcome());}
    @Test void missingNativeEvidenceDoesNotAskForLoginsOrPrepareAnOutboxAction(){
        var forbidden=new IdpForceAuthnScenarioTestCase(IdpForceAuthnScenarioTestCase.MECHANISM_ACCESS_CASE,
            r->{throw new AssertionError("External logins cannot prove internal mechanism reachability");});
        var test=new ForceAuthnMechanismEvidenceTestCase(forbidden,new ShibbolethForceAuthnMechanismEvidence(
            directory,e->{throw new AssertionError("No originals");},r->new byte[0],r->Optional.empty()));
        for(boolean complete:List.of(false,true)) {
            var result=assertInstanceOf(CaseStep.Finish.class,test.start(context(complete))).outcome();
            assertEquals(Outcome.NOT_VERIFIED,result.outcome());
            assertEquals("administrator_evidence",result.details().get("required_action"));
            assertFalse(test.evidenceStatus(context(complete)).ready());
        }
        assertEquals(RunCampaignQuery.ActionKind.NONE,test.evidenceActionKind());
        assertTrue(test.evidenceActionKeys().isEmpty());
        assertFalse(BrowserFrontChannelScenario.class.isInstance(test));
        assertFalse(BrowserPrompt.class.isInstance(test));
    }
    @Test void malformedOwnedCannotFallThroughAnyLifecycle()throws Exception{
        Files.writeString(directory.resolve(RUN+".shibboleth-force-authn-mechanism.json"),"{}");var test=test();
        for(boolean complete:List.of(false,true)){nv(test.start(context(complete)));for(var event:List.<CaseEvent>of(new CaseEvent.TranscriptReady(),new CaseEvent.ConfigConfirmed(),new CaseEvent.Aborted("cancel")))nv(test.resume(context(complete),null,event));
            assertEquals(Outcome.NOT_VERIFIED,test.queuedEvidenceOutcome(context(complete)).outcome());
            assertEquals("administrator_evidence",test.queuedEvidenceOutcome(context(complete)).details().get("required_action"));
            assertFalse(test.evidenceStatus(context(complete)).ready());}
        assertTrue(test.reevaluateRecordedEvidence(context(true),CaseOutcome.notVerified("pending","case.pending-interaction")).isEmpty());}
    @Test void sidecarFileAndSymlinkOwnInvalidBranch()throws Exception{
        var file=directory.resolve(RUN+".shibboleth-force-authn-mechanism");Files.writeString(file,"broken");nv(test().start(context(true)));Files.delete(file);
        Files.createSymbolicLink(file,Files.createDirectory(directory.resolve("other")));nv(test().start(context(true)));}
    @Test void queuedDoesNotConstructARequest(){var f=new IdpForceAuthnScenarioTestCase(IdpForceAuthnScenarioTestCase.MECHANISM_ACCESS_CASE,r->{throw new AssertionError("Queued proof must not send");});
        var t=new ForceAuthnMechanismEvidenceTestCase(f,new ShibbolethForceAuthnMechanismEvidence(directory,e->new byte[0],r->new byte[0],r->Optional.empty()));assertEquals(Outcome.NOT_VERIFIED,t.queuedEvidenceOutcome(context(true)).outcome());}
    @Test void priorConclusiveAndIncompleteCannotBeReplaced(){for(var o:List.of(Outcome.SATISFIED,Outcome.SATISFIED_WITH_NOTE,Outcome.VIOLATED))assertTrue(test().reevaluateRecordedEvidence(context(true),CaseOutcome.of(o,"prior",List.of())).isEmpty());
        assertTrue(test().reevaluateRecordedEvidence(context(false),CaseOutcome.notVerified("pending","case.pending-interaction")).isEmpty());}
    @Test void legacyBrowserStateCannotContinueOrTurnExternalReauthenticationIntoProof(){
        var forbidden=new IdpForceAuthnScenarioTestCase(IdpForceAuthnScenarioTestCase.MECHANISM_ACCESS_CASE,
            r->{throw new AssertionError("A legacy browser probe must not continue");});
        var test=new ForceAuthnMechanismEvidenceTestCase(forbidden,new ShibbolethForceAuthnMechanismEvidence(
            directory,e->{throw new AssertionError("External evidence is not native proof");},r->new byte[0],r->Optional.empty()));
        var state=new CaseState("await-force-authn-true-with-session",Map.of("stage_index",3,"stage","true-with-session"));
        var inbound=new CaseEvent.InboundMessage("<Response/>".getBytes(java.nio.charset.StandardCharsets.UTF_8),new EvidenceRef("transcript","tx_external"));
        for(var event:List.<CaseEvent>of(inbound,new CaseEvent.RetryInbound(),new CaseEvent.TranscriptReady(),
                new CaseEvent.ConfigConfirmed(),new CaseEvent.Attested("satisfied",""),new CaseEvent.Aborted("cancel"))) {
            nv(test.resume(context(true),state,event));
        }
    }
    @Test void aDifferentWholeNativeClasspathIsNotVerified(){
        var invalid=ShibbolethForceAuthnMechanismEvidence.guardNativeClasspath("{}".getBytes(java.nio.charset.StandardCharsets.UTF_8)).orElseThrow();
        assertEquals(Outcome.NOT_VERIFIED,invalid.outcome());assertEquals("native-whole-classpath-unproven",invalid.details().get("stage"));
    }
    @Test void aCannotUseTheBLeaf(){assertThrows(IllegalArgumentException.class,()->new ForceAuthnMechanismEvidenceTestCase(new IdpForceAuthnScenarioTestCase(r->null),new ShibbolethForceAuthnMechanismEvidence(directory,e->new byte[0],r->new byte[0],r->Optional.empty())));}
}
