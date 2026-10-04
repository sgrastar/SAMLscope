package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.*;
import java.nio.file.Path;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class NativeSubjectPrincipalWiringTest {
    private static final String RUN="run_00000000000000000000000000";
    @TempDir Path directory;
    private TestCaseRegistry registry(TestCaseRegistry input) {
        return ApprovedBrowserCaseRegistry.withNativeEcSignature(input,
                entry -> { throw new AssertionError("Absent original evidence cannot be read"); },
                run -> new byte[0], directory.resolve("ec-signature-preparations"));
    }
    private DefaultCaseContext context() {
        return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(),Reachability.CONFIRMED,new TranscriptRecorder() {
                    public List<TranscriptEntry> list(String run){return List.of();}
                    public TranscriptEntry record(TranscriptInput input){throw new AssertionError("No manufactured transcript");}
                    public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary){throw new AssertionError("No transcript mutation");}
                },true);
    }
    @Test void runtimeRegistryIncludesThePassivePrincipalObserverWithoutPriorBrowserRegistration() {
        var once=registry(new TestCaseRegistry(List.of()));
        var test=assertInstanceOf(NativeSubjectPrincipalTestCase.class,once.require(SamlSubjectPrincipalTranscriptTestCase.CASE_ID));
        assertSame(test,registry(once).require(test.id()));
        assertFalse(test.evidenceStatus(context()).ready());
    }
    @Test void existingFinishedUnresolvedCaseIsEligibleButMissingOriginalsCannotUpdateOrSend() {
        var registry=registry(new TestCaseRegistry(List.of()));var test=registry.require(SamlSubjectPrincipalTranscriptTestCase.CASE_ID);
        var previous=CaseOutcome.notVerified("principal_undetermined","saml.subject-principal.undetermined");
        var repository=new ExistingExecution(previous);var transitions=new CaseExecutionService(repository);
        var existing=repository.execution;
        assertSame(existing,transitions.start(RUN,test,context()));
        var service=new ProtocolEvidenceAutomationService(repository,registry,transitions,run->context());
        assertEquals(1,service.status(RUN).eligibleCases());assertEquals(0,service.status(RUN).readyCases());
        assertTrue(service.evaluateReady(RUN).completed().isEmpty());
        assertSame(existing,repository.execution);assertEquals(0,repository.transitions);
    }
    @Test void anExistingConclusivePassiveResultIsNeverShadowedOrRestarted() {
        var registry=registry(new TestCaseRegistry(List.of()));var test=registry.require(SamlSubjectPrincipalTranscriptTestCase.CASE_ID);
        var repository=new ExistingExecution(CaseOutcome.of(Outcome.SATISFIED,"existing-native-proof",List.of()));
        var existing=repository.execution;var transitions=new CaseExecutionService(repository);
        assertSame(existing,transitions.start(RUN,test,context()));
        var service=new ProtocolEvidenceAutomationService(repository,registry,transitions,run->context());
        assertEquals(0,service.status(RUN).eligibleCases());assertTrue(service.evaluateReady(RUN).completed().isEmpty());
        assertSame(existing,repository.execution);assertEquals(0,repository.transitions);
    }
    private static final class ExistingExecution implements CaseExecutionRepository {
        private CaseExecution execution;private int transitions;
        ExistingExecution(CaseOutcome outcome){execution=new CaseExecution(RUN,SamlSubjectPrincipalTranscriptTestCase.CASE_ID,2,
                CaseExecutionStatus.FINISHED,CaseState.initial(),null,outcome,Instant.now());}
        public Optional<CaseExecution> find(String run,String id){return RUN.equals(run)&&execution.caseId().equals(id)?Optional.of(execution):Optional.empty();}
        public List<CaseExecution> list(String run){return RUN.equals(run)?List.of(execution):List.of();}
        public boolean apply(long revision,CaseExecution next,List<OutboundAction> actions){assertTrue(actions.isEmpty(),"No outbox action");if(revision!=execution.revision())return false;execution=next;transitions++;return true;}
        public List<OutboxEntry> listOutbox(String run){return List.of();}
        public Optional<OutboxEntry> findOutbox(String action){return Optional.empty();}
        public boolean transitionOutbox(String action,OutboxStatus expected,OutboxStatus next,Map<String,Object> result,String entry,Instant at){throw new AssertionError("No delivery operation");}
        public int recoverSendingAsUnknownDelivery(Instant at){return 0;}
    }
}
