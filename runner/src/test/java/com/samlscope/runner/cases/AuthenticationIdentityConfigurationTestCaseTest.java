package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.Path;
import java.nio.file.Files;
import java.time.*;
import java.util.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AuthenticationIdentityConfigurationTestCaseTest {
    private static final String RUN="run_0123456789ABCDEFGHJKMNPQRS";
    @TempDir Path data;

    @Test void confirmationAndDeclarationCannotReplaceNativeOriginals(){
        var test=implementation();var context=context();
        var waiting=assertInstanceOf(CaseStep.AwaitConfig.class,test.start(context));
        for(var event:List.<CaseEvent>of(new CaseEvent.ConfigConfirmed(),new CaseEvent.TranscriptReady(),
                new CaseEvent.Attested("evidence_satisfies","ambient authentication is disabled"),
                new CaseEvent.Attested("evidence_violates","browser success looked anonymous"))) {
            var finish=assertInstanceOf(CaseStep.Finish.class,test.resume(context,waiting.next(),event));
            assertEquals(Outcome.NOT_VERIFIED,finish.outcome().outcome());
            assertEquals("ambient_auth_not_excludable",finish.outcome().notVerifiedReason());
        }
        assertFalse(test.evidenceStatus(context).ready());
    }
    @Test void configurationUnavailableRemainsTestPreconditionRatherThanProductFailure(){
        var test=implementation();var context=context();var waiting=(CaseStep.AwaitConfig)test.start(context);
        var finish=assertInstanceOf(CaseStep.Finish.class,test.resume(context,waiting.next(),
            new CaseEvent.ConfigUnavailable(CaseEvent.ConfigurationIssue.CAPABILITY_ABSENT,"interactive mode unavailable")));
        assertEquals(Outcome.NOT_VERIFIED,finish.outcome().outcome());
        assertEquals("configuration.test-precondition-unavailable",finish.outcome().reasonCode());
    }
    @Test void missingOriginalsCannotUpgradeRecordedIncompleteResult(){
        var test=implementation();var previous=CaseOutcome.notVerified("case_pending_interaction","case.pending-interaction");
        assertTrue(test.supportsRecordedEvidenceReevaluation(previous));
        assertTrue(test.reevaluateRecordedEvidence(context(),previous).isEmpty());
    }
    @Test void malformedOwnedSspOriginalsCannotFallBackToDeclarations()throws Exception{
        var test=implementation();var context=context();
        var owned=data.resolve("simplesamlphp-authentication-identity-evidence").resolve(RUN);
        Files.createDirectories(owned);Files.writeString(owned.resolve("manifest.json"),"{}");
        assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,test.start(context)).outcome().outcome());
        for(var event:List.<CaseEvent>of(new CaseEvent.ConfigConfirmed(),new CaseEvent.TranscriptReady(),
                new CaseEvent.Attested("evidence_satisfies","all mechanisms disabled")))
            assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,test.resume(context,null,event)).outcome().outcome());
        assertFalse(test.evidenceStatus(context).ready());
        assertTrue(test.reevaluateRecordedEvidence(context,CaseOutcome.notVerified("pending","case.pending-interaction")).isEmpty());
    }
    @Test void competingProductOriginalsCannotCreateApparentSuccess()throws Exception{
        for(var dir:List.of("authentication-identity-evidence","simplesamlphp-authentication-identity-evidence")){
            var owned=data.resolve(dir).resolve(RUN);Files.createDirectories(owned);Files.writeString(owned.resolve("manifest.json"),"{}");
        }
        var test=implementation();var finish=assertInstanceOf(CaseStep.Finish.class,test.start(context()));
        assertEquals(Outcome.NOT_VERIFIED,finish.outcome().outcome());
        assertEquals("browser.authentication-identity.native-unproven",finish.outcome().reasonCode());
        assertFalse(test.evidenceStatus(context()).ready());
    }
    @Test void malformedKeycloakOriginalsCannotFallBackToDeclarations()throws Exception{
        var owned=data.resolve("keycloak-authentication-identity-evidence").resolve(RUN);
        Files.createDirectories(owned);Files.writeString(owned.resolve("manifest.json"),"{}");
        var test=implementation();var context=context();
        for(var event:List.<CaseEvent>of(new CaseEvent.ConfigConfirmed(),new CaseEvent.TranscriptReady(),
                new CaseEvent.Attested("evidence_satisfies","password-only browser flow")))
            assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,
                    test.resume(context,null,event)).outcome().outcome());
        assertFalse(test.evidenceStatus(context).ready());
        assertTrue(test.reevaluateRecordedEvidence(context,
                CaseOutcome.notVerified("pending","case.pending-interaction")).isEmpty());
    }
    @Test void keycloakAndOtherProductEvidenceCannotBeCombined()throws Exception{
        for(var other:List.of("authentication-identity-evidence","simplesamlphp-authentication-identity-evidence")){
            var keycloak=data.resolve("keycloak-authentication-identity-evidence").resolve(RUN);
            var competing=data.resolve(other).resolve(RUN);
            Files.createDirectories(keycloak);Files.writeString(keycloak.resolve("manifest.json"),"{}");
            Files.createDirectories(competing);Files.writeString(competing.resolve("manifest.json"),"{}");
            var test=implementation();var finish=assertInstanceOf(CaseStep.Finish.class,test.start(context()));
            assertEquals(Outcome.NOT_VERIFIED,finish.outcome().outcome());
            assertEquals("browser.authentication-identity.native-unproven",finish.outcome().reasonCode());
            Files.delete(competing.resolve("manifest.json"));Files.delete(competing);
        }
    }
    @Test void productionRegistryUsesTheNativeGateOnlyForApprovedIdentityCase(){
        var definition=new com.samlscope.core.casedef.CaseDefinitionCatalog.CaseDefinition(
            AuthenticationIdentityConfigurationTestCase.ID,"IIP-SSO01.ae",TargetRole.IDP,
            com.samlscope.core.casedef.CaseDefinitionCatalog.ExecutionMode.CONFIG,
            com.samlscope.core.casedef.CaseDefinitionCatalog.Milestone.M1,List.of(),Map.of(),List.of(),List.of(),List.of(),
            "Anonymous Success must not satisfy the case.",List.of(),
            new com.samlscope.core.casedef.CaseDefinitionCatalog.Requirements(List.of(),"none"),false,
            ConfigurationFailureSemantics.TEST_PRECONDITION,"sha256:"+"a".repeat(64));
        var registry=ApprovedConfigCaseRegistry.create(new com.samlscope.core.casedef.CaseDefinitionCatalog(List.of(definition)),
            com.samlscope.core.casedef.CaseDefinitionCatalog.Milestone.M1,r->new byte[0],e->new byte[0],r->Optional.empty());
        assertInstanceOf(AuthenticationIdentityConfigurationTestCase.class,registry.find(definition.id()).orElseThrow());
    }
    private AuthenticationIdentityConfigurationTestCase implementation(){
        var delegate=new AttestedOutcomeTestCase(AuthenticationIdentityConfigurationTestCase.ID,TargetRole.IDP,"identity.evidence",Duration.ofMinutes(1),
            List.of(AttestationOption.of("evidence_satisfies",Outcome.SATISFIED,"declaration.satisfies")));
        var fallback=new ConfigurationGateTestCase(delegate,"identity.config",Duration.ofMinutes(1),ConfigurationFailureSemantics.TEST_PRECONDITION);
        return new AuthenticationIdentityConfigurationTestCase(fallback,e->new byte[0],r->new byte[0],r->Optional.empty(),data.resolve("authentication-identity-evidence"));
    }
    private CaseContext context(){
        TranscriptRecorder recorder=new TranscriptRecorder(){
            public List<TranscriptEntry> list(String r){return List.of();}
            public TranscriptEntry record(TranscriptInput i){throw new UnsupportedOperationException();}
            public TranscriptEntry updateSamlAnalysis(String i,String c,Map<String,Object>s){throw new UnsupportedOperationException();}
        };
        return new com.samlscope.runner.DefaultCaseContext(RUN,TargetRole.IDP,Clock.systemUTC(),new TestPlan.Parameters(180,300,"reference-principal"),
            TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,true);
    }
}
