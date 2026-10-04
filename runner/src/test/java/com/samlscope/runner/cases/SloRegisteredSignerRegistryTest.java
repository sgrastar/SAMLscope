package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;

import com.samlscope.core.casedef.CaseDefinitionCatalog;
import com.samlscope.core.casedef.CaseDefinitionCatalog.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.runner.*;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SloRegisteredSignerRegistryTest {
    @TempDir Path directory;

    private AttestedOutcomeTestCase fallback() {
        return new AttestedOutcomeTestCase(SloRegisteredSignerEvidence.CASE,TargetRole.IDP,
                "approved-slo-signer-attestation","Approved SLO signer evidence",Duration.ofDays(7),
                List.of(AttestationOption.of("satisfied",Outcome.SATISFIED,"attestation.satisfied"),
                        AttestationOption.of("violated",Outcome.VIOLATED,"attestation.violated"),
                        AttestationOption.notVerified("unable_to_verify","attestation.unavailable","unavailable")));
    }

    private TestCase wired() {
        return ApprovedAttestedCaseRegistry.withNativeSloRegisteredSigner(fallback(),directory,
                entry->{throw new AssertionError("Unproven preparation must not read protocol bytes");},
                run->{throw new AssertionError("Unproven preparation must not resolve target metadata");});
    }
    private CaseContext attestationContext() {
        var c=SelfContainedMetadataTrustEvidenceTestCaseTest.context(true);
        return new DefaultCaseContext(c.runId(),c.targetRole(),c.clock(),c.parameters(),
                new com.samlscope.core.plan.TestPlan.Interaction(false,true),c.reachability(),c.transcript(),c.transcriptComplete());
    }

    @Test void absentNativePreparationRetainsTheApprovedAttestationWithoutRequestingLogin() {
        var disabled=SelfContainedMetadataTrustEvidenceTestCaseTest.context(true);var old=fallback();var test=wired();
        assertEquals(old.start(disabled),test.start(disabled));
        assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,test.start(disabled)).outcome().outcome());
        var context=attestationContext();
        assertEquals(old.start(context),test.start(context));
        var state=assertInstanceOf(CaseStep.AwaitAttestation.class,old.start(context)).next();
        var event=new CaseEvent.Attested("satisfied","");
        assertEquals(old.resume(context,state,event),test.resume(context,state,event));
        var campaign=assertInstanceOf(EvidenceCampaignCase.class,test);
        assertEquals(RunCampaignQuery.ActionKind.SELF_CHECK,campaign.evidenceActionKind());
        assertEquals(old.options(),assertInstanceOf(AttestationPrompt.class,test).options());
    }

    @Test void ownedUnprovenNativeInputsCannotProduceOutboxActionsOrManualSuccess()throws Exception {
        var context=attestationContext();
        Files.createDirectories(directory.resolve("slo-registered-signer-evidence").resolve(context.runId()));
        var test=wired();var result=assertInstanceOf(CaseStep.Finish.class,test.start(context)).outcome();
        assertEquals(Outcome.NOT_VERIFIED,result.outcome());
        var state=assertInstanceOf(CaseStep.AwaitAttestation.class,fallback().start(context)).next();
        assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,
                test.resume(context,state,new CaseEvent.Attested("satisfied",""))).outcome().outcome());
        assertFalse(assertInstanceOf(ProtocolEvidenceCase.class,test).evidenceStatus(context).ready());
    }

    @Test void aSharedSloSessionDoesNotRequestFreshAuthenticationForEveryFixture() {
        var scenario=assertInstanceOf(BrowserFrontChannelScenario.class,wired());
        assertFalse(scenario.plansFreshSessionBoundary());
        assertFalse(scenario.requiresFreshSession(new CaseState("await-fixture-local-other-signer",Map.of())));
        assertTrue(scenario.instructionsEn(new CaseState("await-fixture-local-normal",Map.of())).contains("ends the test session"));
    }

    @Test void theM3RegistryPreservesApprovedIdsAndManualFallbackForOtherCases() {
        var definitions=new CaseDefinitionCatalog(List.of(
                definition(SloRegisteredSignerEvidence.CASE,"IIP-IDP17.ab"),
                definition("IIP-IDP21-a-idp-01","IIP-IDP21.a")));
        var registry=ApprovedAttestedCaseRegistry.create(definitions,Milestone.M3);
        assertEquals(Set.of(SloRegisteredSignerEvidence.CASE,"IIP-IDP21-a-idp-01"),registry.ids());
        assertInstanceOf(SloRegisteredSignerObservationTestCase.class,registry.require(SloRegisteredSignerEvidence.CASE));
        assertInstanceOf(AttestedOutcomeTestCase.class,registry.require("IIP-IDP21-a-idp-01"));
    }

    private CaseDefinition definition(String id,String obligation) {
        return new CaseDefinition(id,obligation,TargetRole.IDP,ExecutionMode.ATTESTED,Milestone.M3,
                List.of(),Map.of(),List.of(),List.of(),List.of(),"Approved counterexample remains required",List.of(),
                new Requirements(List.of(),"none"),false,null,"sha256:"+"a".repeat(64));
    }
}
