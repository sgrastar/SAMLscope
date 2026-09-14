package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.security.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;

class MultipleDecryptionKeysConfigurationTestCaseTest {
    static final String RUN="run_0123456789ABCDEFGHJKMNPQRS";
    static final Instant NOW=Instant.parse("2026-09-15T00:00:00Z");
    static final List<String> IDS=List.of(IdpBasicLogoutScenarioTestCase.ENCRYPTED_ID,IdpBasicLogoutScenarioTestCase.MULTI_KEY_ID);
    private final Map<String,CaseExecution> proofs=new HashMap<>();
    private final List<TranscriptEntry> entries=new ArrayList<>();
    private List<PublicKey> keys;
    private boolean complete=true;
    private MultipleDecryptionKeysConfigurationTestCase fixture() throws Exception {
        if(keys==null) { var generator=KeyPairGenerator.getInstance("RSA"); generator.initialize(2048); keys=List.of(generator.generateKeyPair().getPublic(),generator.generateKeyPair().getPublic()); }
        proofs.clear(); entries.clear();complete=true;
        for(var id:IDS) {
            var evidence=new ArrayList<EvidenceRef>();
            for(int i=0;i<4;i++) { var ref=id+"-"+i;evidence.add(new EvidenceRef("transcript",ref));entries.add(entry(ref,RUN,Direction.INBOUND,"decoded",10)); }
            var reason=id.equals(IDS.getFirst())?"slo.encrypted-id.decryption-observed":"slo.encrypted-id.multiple-keys.decryption-observed";
            proofs.put(id,execution(RUN,id,CaseOutcome.of(Outcome.SATISFIED,reason,evidence)));
        }
        var fallback=new ConfigurationGateTestCase(new AttestedOutcomeTestCase(MultipleDecryptionKeysConfigurationTestCase.ID,
                TargetRole.IDP,"evidence","Review capability",Duration.ofDays(1),
                List.of(AttestationOption.notVerified("unknown","configuration.evidence-unavailable","unknown"))),
                "keys","Configure keys",Duration.ofDays(1),ConfigurationFailureSemantics.NORMATIVE_CAPABILITY);
        return new MultipleDecryptionKeysConfigurationTestCase(fallback,ignored->keys,(run,id)->Optional.ofNullable(proofs.get(id)));
    }
    @Test void bothControlledDecryptionsProveCapabilityAndCanReplaceAnEarlierUnknown() throws Exception {
        var test=fixture();var previous=CaseOutcome.notVerified("unknown","configuration.evidence-unavailable");
        var result=assertInstanceOf(CaseStep.Finish.class,test.start(context())).outcome();
        assertEquals(Outcome.SATISFIED,result.outcome());assertEquals(8,result.evidence().size());
        assertTrue(test.evidenceStatus(context()).ready());
        assertTrue(test.reevaluateRecordedEvidence(context(),previous).isPresent());
        assertFalse(test.reevaluateRecordedEvidence(context(),result).isPresent());
        assertTrue(test.resolvedFromExternalEvidence(execution(RUN,test.id(),result)));
    }
    @Test void allEightProofReferencesMustBelongToReadableUniqueInboundRecords() throws Exception {
        for(var id:IDS)for(int index=0;index<4;index++)for(var fault:List.of("run","outbound","ref","size","missing","duplicate")) {
            var test=fixture();var ref=id+"-"+index;var original=entries.stream().filter(e->e.id().equals(ref)).findFirst().orElseThrow();
            entries.remove(original);
            if(!fault.equals("missing"))entries.add(entry(ref,fault.equals("run")?"other":RUN,
                    fault.equals("outbound")?Direction.OUTBOUND:Direction.INBOUND,fault.equals("ref")?null:"decoded",fault.equals("size")?0:10));
            if(fault.equals("duplicate"))entries.add(original);
            assertUnproven(test);
        }
    }
    @Test void MetadataOrOneSuccessfulCaseAloneNeverProvesMultipleKeys() throws Exception {
        var test=fixture();var saved=keys;
        for(var candidate:List.of(List.<PublicKey>of(),List.of(saved.getFirst()),List.of(saved.getFirst(),saved.getFirst()))) {
            keys=candidate;assertUnproven(test);
        }
        keys=saved;
        for(var id:IDS)for(var fault:List.of("missing","run","case","reason","note","violated","unknown","short","kind","repeated","running")) {
            test=fixture();var proof=proofs.get(id);var result=proof.outcome();var evidence=new ArrayList<>(result.evidence());
            if(fault.equals("short"))evidence.removeLast();
            if(fault.equals("kind"))evidence.set(0,new EvidenceRef("attestation",evidence.getFirst().reference()));
            if(fault.equals("repeated"))evidence.set(1,evidence.getFirst());
            var outcome=fault.equals("unknown")?CaseOutcome.notVerified("unknown",result.reasonCode())
                    :CaseOutcome.of(fault.equals("note")?Outcome.SATISFIED_WITH_NOTE:fault.equals("violated")?Outcome.VIOLATED:Outcome.SATISFIED,
                    fault.equals("reason")?"configuration.evidence-satisfies":result.reasonCode(),evidence);
            if(fault.equals("missing"))proofs.remove(id);
            else if(fault.equals("running"))proofs.put(id,new CaseExecution(RUN,id,0,CaseExecutionStatus.RUNNING,new CaseState("running",Map.of()),null,null,NOW));
            else proofs.put(id,execution(fault.equals("run")?"other":RUN,fault.equals("case")?"other":id,outcome));
            assertUnproven(test);
        }
        test=fixture();complete=false;assertUnproven(test);
    }
    private void assertUnproven(MultipleDecryptionKeysConfigurationTestCase test) {
        assertFalse(test.evidenceStatus(context()).ready());
        assertInstanceOf(CaseStep.AwaitConfig.class,test.start(context()));
        assertFalse(test.reevaluateRecordedEvidence(context(),CaseOutcome.notVerified("unknown","unknown")).isPresent());
        assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,test.resume(context(),new CaseState("waiting",Map.of()),new CaseEvent.TranscriptReady())).outcome().outcome());
    }
    private static CaseExecution execution(String run,String id,CaseOutcome outcome) {
        return new CaseExecution(run,id,1,CaseExecutionStatus.FINISHED,new CaseState("done",Map.of()),null,outcome,NOW);
    }
    private static TranscriptEntry entry(String id,String run,Direction direction,String path,int size) {
        return new TranscriptEntry(id,run,direction,NOW,"correlation","POST","https://suite.example/slo",200,Map.of(),null,0,path,size,null,null,Map.of());
    }
    private CaseContext context() {
        var history=new TranscriptRecorder() {
            public List<TranscriptEntry> list(String run) { return List.copyOf(entries); }
            public TranscriptEntry record(TranscriptInput input) { throw new UnsupportedOperationException(); }
            public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary) { throw new UnsupportedOperationException(); }
        };
        return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.fixed(NOW,ZoneOffset.UTC),new TestPlan.Parameters(180,300,""),
                new TestPlan.Interaction(true,false),Reachability.CONFIRMED,history,complete);
    }
}
