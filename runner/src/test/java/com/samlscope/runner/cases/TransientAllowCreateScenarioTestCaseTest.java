package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.runner.TestCaseRegistry;
import com.samlscope.saml.normal.SecureXml;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class TransientAllowCreateScenarioTestCaseTest {
    private static final String RUN="run_00000000000000000000000000", P="urn:oasis:names:tc:SAML:2.0:protocol";
    @TempDir Path directory;
    private CaseContext context(boolean complete) {
        return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.fixed(Instant.parse("2026-10-01T00:00:00Z"),ZoneOffset.UTC),
                TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,
                new TranscriptRecorder(){
                    public List<TranscriptEntry> list(String run){return List.of();}
                    public TranscriptEntry record(TranscriptInput input){throw new AssertionError("Case must use outbox");}
                    public TranscriptEntry updateSamlAnalysis(String id,String c,Map<String,Object>s){throw new AssertionError("Unchanged originals");}
                },complete);
    }
    private static IdpErrorProbeConfiguration configuration() {
        return new IdpErrorProbeConfiguration(URI.create("https://idp.example/sso"),"https://suite.example/sp",
                URI.create("https://suite.example/acs"),Duration.ofMinutes(1),true,true,true);
    }
    private TransientAllowCreateScenarioTestCase scenario() {
        return new TransientAllowCreateScenarioTestCase(r->configuration(),r->Optional.empty());
    }
    private static CaseEvent.InboundMessage response(CaseStep.AwaitInbound waiting,boolean encrypted) {
        String assertion=encrypted ? "<saml:EncryptedAssertion/>" : "<saml:Assertion/>";
        byte[] raw=("<samlp:Response xmlns:samlp=\""+P+"\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" InResponseTo=\""
                +waiting.next().data().get("expected_response_correlation")+"\"><samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>"
                +assertion+"</samlp:Response>").getBytes(StandardCharsets.UTF_8);
        return new CaseEvent.InboundMessage(raw,new EvidenceRef("transcript","tx_"+waiting.next().data().get("fixture_index")));
    }
    @Test void sixExactPolicyInputsHaveDistinctDeterministicOutboxActions() {
        var test=scenario();CaseStep step=test.start(context(false));var inputs=new LinkedHashSet<String>();var actions=new HashSet<String>();
        var repeated=(CaseStep.AwaitInbound)test.start(context(false));var first=(CaseStep.AwaitInbound)step;
        assertEquals(first.next(),repeated.next());assertEquals(first.actions().getFirst().actionId(),repeated.actions().getFirst().actionId());
        assertArrayEquals(first.actions().getFirst().payload(),repeated.actions().getFirst().payload());
        while(step instanceof CaseStep.AwaitInbound waiting) {
            assertEquals(1,waiting.actions().size());var action=waiting.actions().getFirst();assertTrue(actions.add(action.actionId()));
            assertEquals(OutboundKind.AUTHN_REQUEST,action.kind());var request=SecureXml.parse(action.payload()).getDocumentElement();
            assertEquals("_"+action.actionId(),request.getAttribute("ID"));assertEquals(configuration().ssoEndpoint().toString(),request.getAttribute("Destination"));
            var policy=(org.w3c.dom.Element)request.getElementsByTagNameNS(P,"NameIDPolicy").item(0);
            assertNotNull(policy);assertFalse(policy.hasAttribute("SPNameQualifier"));
            inputs.add((policy.hasAttribute("Format")?policy.getAttribute("Format"):"implicit")+"|"+(policy.hasAttribute("AllowCreate")?policy.getAttribute("AllowCreate"):"omitted"));
            step=test.resume(context(false),waiting.next(),response(waiting,false));
        }
        assertEquals(6,actions.size());assertEquals(6,inputs.size());
        for(String format:List.of("urn:oasis:names:tc:SAML:2.0:nameid-format:transient","implicit"))
            for(String create:List.of("true","false","omitted"))assertTrue(inputs.contains(format+"|"+create));
        assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,step).outcome().outcome());
    }
    @Test void sixSuccessResponsesCannotProveNativePersistentStateBehavior() {
        var test=scenario();CaseStep step=test.start(context(false));
        while(step instanceof CaseStep.AwaitInbound waiting)step=test.resume(context(false),waiting.next(),response(waiting,true));
        var outcome=((CaseStep.Finish)step).outcome();assertEquals(Outcome.NOT_VERIFIED,outcome.outcome());
        assertEquals("idp.transient-allow-create.unproven",outcome.reasonCode());
        assertFalse(test.evidenceStatus(context(true)).ready());assertEquals(Outcome.NOT_VERIFIED,test.queuedEvidenceOutcome(context(true)).outcome());
    }
    @Test void queuedEvidenceNeverPreparesAnotherRequest() {
        var test=new TransientAllowCreateScenarioTestCase(r->{throw new AssertionError("No queued scenario");},r->Optional.empty());
        assertEquals(Outcome.NOT_VERIFIED,test.queuedEvidenceOutcome(context(true)).outcome());assertFalse(test.evidenceStatus(context(true)).ready());
    }
    @Test void unknownDeliveryAndCancellationRemainSuiteUncertainty() {
        var test=scenario();var waiting=(CaseStep.AwaitInbound)test.start(context(false));
        for(var event:List.<CaseEvent>of(new CaseEvent.TimedOut(Duration.ofMinutes(1)),new CaseEvent.Aborted("unknown delivery")))
            assertEquals(Outcome.NOT_VERIFIED,((CaseStep.Finish)test.resume(context(false),waiting.next(),event)).outcome().outcome());
    }
    @Test void legacyBrowserStateRequiresANewRunWithoutCreatingActions() {
        var test=scenario();var state=new CaseState("await-browser",Map.of());
        var result=((CaseStep.Finish)test.resume(context(true),state,new CaseEvent.TranscriptReady())).outcome();
        assertEquals("scenario_upgrade_requires_new_run",result.notVerifiedReason());assertTrue(test.instructionsEn(state).contains("new Run"));
    }
    @Test void malformedOwnedReceiptShadowsAllScenarioLifecyclePaths()throws Exception {
        var test=new TransientAllowCreateScenarioTestCase(r->{throw new AssertionError("Owned input cannot prepare actions");},r->Optional.empty())
                .withNativeEvidence(directory,e->{throw new AssertionError("No declared originals");},r->new byte[0]);
        Path owned=Files.createDirectory(directory.resolve(RUN));Files.writeString(owned.resolve("manifest.json"),"{}");
        for(boolean complete:List.of(true,false)) {
            assertEquals(Outcome.NOT_VERIFIED,((CaseStep.Finish)test.start(context(complete))).outcome().outcome());
            assertEquals(Outcome.NOT_VERIFIED,((CaseStep.Finish)test.resume(context(complete),null,new CaseEvent.TranscriptReady())).outcome().outcome());
            assertFalse(test.evidenceStatus(context(complete)).ready());assertEquals(Outcome.NOT_VERIFIED,test.queuedEvidenceOutcome(context(complete)).outcome());
        }
        assertTrue(test.reevaluateRecordedEvidence(context(true),CaseOutcome.notVerified("unproven","idp.transient-allow-create.unproven")).isEmpty());
    }
    @Test void completedOrUnrelatedCaseResultsCannotBeRewritten() {
        var test=scenario();assertFalse(test.supportsRecordedEvidenceReevaluation(CaseOutcome.of(Outcome.SATISFIED,"old",List.of())));
        assertFalse(test.supportsRecordedEvidenceReevaluation(CaseOutcome.notVerified("unknown","outbox.unknown-delivery")));
        assertTrue(test.supportsRecordedEvidenceReevaluation(CaseOutcome.notVerified("old","browser.oracle-unavailable")));
        assertTrue(test.supportsRecordedEvidenceReevaluation(CaseOutcome.notVerified("incomplete-native-receipt",
                "browser.nameid.transient-allow-create-native-unproven")));
    }
    @Test void ownedOtherProductOriginalsCannotFallBackToNewBrowserActions()throws Exception {
        for(String product:List.of("keycloak","shibboleth")) {
            Path root=Files.createDirectory(directory.resolve(product));
            Files.createDirectory(root.resolve(RUN+"."+product+"-transient-allow-create"));
            var test=new TransientAllowCreateScenarioTestCase(
                    r->{throw new AssertionError("Owned product evidence must not prepare another request");},r->Optional.empty())
                    .withNativeEvidence(root,e->{throw new AssertionError("No valid original reference");},r->new byte[0]);
            for(boolean complete:List.of(true,false)) {
                assertEquals(Outcome.NOT_VERIFIED,((CaseStep.Finish)test.start(context(complete))).outcome().outcome());
                assertEquals(Outcome.NOT_VERIFIED,((CaseStep.Finish)test.resume(context(complete),null,new CaseEvent.TranscriptReady())).outcome().outcome());
                assertEquals(Outcome.NOT_VERIFIED,test.queuedEvidenceOutcome(context(complete)).outcome());
                assertFalse(test.evidenceStatus(context(complete)).ready());
            }
            assertTrue(test.reevaluateRecordedEvidence(context(true),CaseOutcome.notVerified("old","browser.oracle-unavailable")).isEmpty());
        }
    }
    @Test void conflictingProductOwnershipRejectsBeforeReadingAnyEvidence()throws Exception {
        Files.createDirectory(directory.resolve(RUN));
        Files.writeString(directory.resolve(RUN+".keycloak-transient-allow-create.json"),"{}");
        Files.writeString(directory.resolve(RUN+".shibboleth-transient-allow-create.json"),"{}");
        var test=new TransientAllowCreateScenarioTestCase(
                r->{throw new AssertionError("Ambiguous product must not emit actions");},r->Optional.empty())
                .withNativeEvidence(directory,e->{throw new AssertionError("Ambiguous product must not read originals");},
                        r->{throw new AssertionError("Ambiguous product must not resolve target metadata");});
        assertEquals(Outcome.NOT_VERIFIED,((CaseStep.Finish)test.start(context(true))).outcome().outcome());
        assertEquals(Outcome.NOT_VERIFIED,test.queuedEvidenceOutcome(context(true)).outcome());
        assertFalse(test.evidenceStatus(context(true)).ready());
    }
    @Test void registryWiresOnlyTheApprovedTransientPolicyCase() {
        var other=new IdpNameIdPolicyScenarioTestCase(IdpNameIdPolicyScenarioTestCase.PROCESSING_CASE,r->configuration());
        var registry=ApprovedBrowserCaseRegistry.withNativeEcSignature(new TestCaseRegistry(List.of(scenario(),other)),
                e->new byte[0],r->new byte[0],directory.resolve("ec-signature-evidence"));
        assertInstanceOf(TransientAllowCreateScenarioTestCase.class,registry.require(TransientAllowCreateScenarioTestCase.CASE));assertSame(other,registry.require(other.id()));
    }
}
