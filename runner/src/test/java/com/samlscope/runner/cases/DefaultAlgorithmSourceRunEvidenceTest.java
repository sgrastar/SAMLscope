package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.runner.*;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class DefaultAlgorithmSourceRunEvidenceTest {
    @TempDir Path folder;
    DefaultAlgorithmSourceRunEvidence reader()throws Exception {
        folder=folder.toRealPath();var content=(com.samlscope.core.transcript.TranscriptContentReader)(entry->{throw new AssertionError("Unqualified binding read an original");});
        var metadata=(java.util.function.Function<String,byte[]>)(run->{throw new AssertionError("Unqualified binding accessed target metadata");});
        var source=new DefaultAlgorithmPreventionEvidence(folder.resolve("source"),content,metadata,
                run->{throw new AssertionError("Unqualified binding accessed a private key");},run->"browser_sso_idp");
        return new DefaultAlgorithmSourceRunEvidence(folder.resolve("bindings"),folder.resolve("source"),
                new DefaultAlgorithmSourceRunStore(folder,"sha256:"+"a".repeat(64)),content,metadata,source);
    }
    @Test void missingAndMalformedOwnedBindingsNeverReadMetadataOrKeys()throws Exception {
        var r=reader();var c=ClockSkewEvidenceTestCaseTest.context(true);assertFalse(r.exists(c.runId()));assertTrue(r.evaluate(c).isEmpty());
        Files.createDirectories(folder.resolve("bindings"));Files.writeString(folder.resolve("bindings").resolve(c.runId()),"not a folder");
        assertTrue(r.exists(c.runId()));assertTrue(r.evaluate(c).isEmpty());
    }
    @Test void incompleteForeignCalibrationAndEcpTrafficClaimsNeverPromote()throws Exception {
        var r=reader();var c=ClockSkewEvidenceTestCaseTest.context(true);var owned=Files.createDirectories(folder.resolve("bindings").resolve(c.runId()));
        String base="{\"schema\":\""+DefaultAlgorithmSourceRunEvidence.SCHEMA+"\",\"runId\":\""+c.runId()+"\",\"caseId\":\""+DefaultAlgorithmComparison.CASE
                +"\",\"scope\":\""+DefaultAlgorithmSourceRunEvidence.SCOPE+"\",\"profile\":\"ecp_idp\",\"sourceProfile\":\"browser_sso_idp\",\"counterfactualCalibrationOnly\":false,\"ecpProtocolTrafficVerified\":false,\"caseDigest\":\"sha256:"+"a".repeat(64)+"\"}";
        for(String m:List.of(base.replace("CalibrationOnly\":false","CalibrationOnly\":true"),base.replace("TrafficVerified\":false","TrafficVerified\":true"),base.replace("ecp_idp","browser_sso_idp"),base.replace(c.runId(),"run_11111111111111111111111111"))) {
            Files.writeString(owned.resolve("manifest.json"),m);assertTrue(r.evaluate(c).isEmpty());
        }
        Files.writeString(owned.resolve("manifest.json"),base);assertTrue(r.evaluate(ClockSkewEvidenceTestCaseTest.context(false)).isEmpty());
    }
    static class Fallback implements TestCase,BrowserFrontChannelScenario,ConfigurationPrompt,AttestationPrompt,ProtocolEvidenceCase,FallbackEvidenceCase {
        int starts,resumes;
        public String id(){return DefaultAlgorithmComparison.CASE;}public TargetRole role(){return TargetRole.IDP;}
        public CaseStep start(CaseContext c){starts++;return new CaseStep.Finish(CaseOutcome.notVerified("fallback","pending"));}
        public CaseStep resume(CaseContext c,CaseState s,CaseEvent e){resumes++;return start(c);}
        public String promptEn(){return "Approved prompt";}public List<AttestationOption> options(){return List.of();}
        public String instructionEn(){return "Native preparation";}public String instructionsEn(CaseState s){return "Six original inputs";}
        public EvidenceStatus evidenceStatus(CaseContext c){return new EvidenceStatus(false,List.of("original"),List.of(),Map.of());}
        public boolean resolvedFromExternalEvidence(CaseExecution e){return false;}
    }
    @Test void absentBindingPreservesScenarioButOwnedInvalidBlocksAttestationAndReevaluation()throws Exception {
        var r=reader();var fallback=new Fallback();var wrapper=new DefaultAlgorithmSourceRunTestCase(fallback,r);var c=ClockSkewEvidenceTestCaseTest.context(true);
        wrapper.start(c);assertEquals(1,fallback.starts);assertEquals("Six original inputs",wrapper.instructionsEn(CaseState.initial()));
        Files.createDirectories(folder.resolve("bindings"));Files.writeString(folder.resolve("bindings").resolve(c.runId()),"owned invalid");
        assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,wrapper.start(c)).outcome().outcome());
        wrapper.resume(c,CaseState.initial(),new CaseEvent.Attested("satisfied","cannot replace proof"));assertEquals(1,fallback.starts);assertEquals(0,fallback.resumes);
        assertFalse(wrapper.evidenceStatus(c).ready());assertTrue(wrapper.reevaluateRecordedEvidence(c,CaseOutcome.notVerified("pending","pending")).isEmpty());
    }
    @Test void productionFactoryOwnsInvalidBindingAndCannotUseManualFallback()throws Exception {
        folder=folder.toRealPath();var c=ClockSkewEvidenceTestCaseTest.context(true);
        var fallback=new Fallback();var test=ApprovedAttestedCaseRegistry.withNativeDefaultAlgorithms(fallback,folder,
                entry->{throw new AssertionError("Unqualified production binding read protocol evidence");},
                run->{throw new AssertionError("Unqualified production binding read target");},"sha256:"+"a".repeat(64));
        assertInstanceOf(DefaultAlgorithmSourceRunTestCase.class,test);
        Files.createDirectories(folder.resolve("default-algorithm-source-bindings"));Files.writeString(folder.resolve("default-algorithm-source-bindings").resolve(c.runId()),"invalid");
        assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,test.start(c)).outcome().outcome());
        assertEquals(0,fallback.starts);assertFalse(Files.exists(folder.resolve("keys")));
    }
}
