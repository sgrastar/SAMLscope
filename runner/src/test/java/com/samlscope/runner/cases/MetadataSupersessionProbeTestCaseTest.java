package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.BrowserFrontChannelScenario;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.saml.normal.SamlLogoutRequestFactory;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Element;

class MetadataSupersessionProbeTestCaseTest {
    private static final String RUN="run_0123456789ABCDEFGHJKMNPQRS";
    private static final String PLAN="plan_0123456789ABCDEFGHJKMNPQRS";
    private static final Instant NOW=Instant.parse("2026-10-01T00:00:00Z");
    private static final String SP="http://suite.example/sp";
    private static final String P="urn:oasis:names:tc:SAML:2.0:protocol";
    @TempDir Path data;

    @Test void controlsUseDistinctOldRolloverAndNewKeysAndNeverAdoptBrowserSuccessAlone(){
        var env=environment(true);var test=env.test();CaseStep step=test.start(env.context());
        List<String> fixtures=new ArrayList<>();
        while(step instanceof CaseStep.AwaitInbound waiting){
            String fixture=(String)waiting.next().data().get("fixture_id");fixtures.add(fixture);
            Element xml=SecureXml.parse(waiting.actions().getFirst().payload()).getDocumentElement();
            String variant=switch(fixture){case "old-key-new-acs"->"control";case "rollover-first-key-new-acs"->"multiple-signing-keys-first";case "rollover-second-key-new-acs"->"multiple-signing-keys";default->"no-valid-until";};
            var verifier=new XmlSignatureVerifier();var expected=env.credentials().get(variant);
            assertEquals(!"new-key-invalid-signature".equals(fixture),verifier.hasValidEnvelopedSignature(xml,expected.certificate()),fixture);
            if("new-key-invalid-signature".equals(fixture))assertTrue(verifier.hasValidEnvelopedReferenceDigests(xml));
            for(var alternative:env.credentials().entrySet())if(!alternative.getKey().equals(variant))assertFalse(verifier.hasValidEnvelopedSignature(xml,alternative.getValue().certificate()),fixture);
            if("new-key-default-acs".equals(fixture))assertFalse(xml.hasAttribute("AssertionConsumerServiceURL"));
            else assertEquals(SP+"/acs/"+("new-key-second-acs".equals(fixture)?"1":"0")+"?mdv="+("new-key-old-acs".equals(fixture)?"control":"no-valid-until"),xml.getAttribute("AssertionConsumerServiceURL"));
            assertEquals(BrowserFrontChannelScenario.Binding.SIGNED_REDIRECT,test.outboundBinding(new CaseState("test",Map.of("fixture_id","new-key-redirect"))));
            step=test.resume(env.context(),waiting.next(),new CaseEvent.InboundMessage(("<samlp:Response xmlns:samlp=\""+P+"\"/>").getBytes(StandardCharsets.UTF_8),new EvidenceRef("transcript","transcript:tx-test")));
        }
        assertEquals(MetadataSupersessionProbeTestCase.FIXTURES,fixtures);
        var outcome=assertInstanceOf(CaseStep.Finish.class,step).outcome();
        assertEquals(Outcome.NOT_VERIFIED,outcome.outcome());assertEquals("metadata.supersession.awaiting-native-receipt",outcome.reasonCode());
    }
    @Test void unknownDeliveryAndNoResponseNeverDetermineProductFailure(){
        var env=environment(true);CaseStep step=env.test().start(env.context());
        while(step instanceof CaseStep.AwaitInbound waiting)step=env.test().resume(env.context(),waiting.next(),new CaseEvent.InboundUnavailable("no-response"));
        assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,step).outcome().outcome());
    }
    @Test void missingNativePreparationUsesApprovedConfigurationFallback(){
        var env=environment(false);
        assertInstanceOf(CaseStep.AwaitConfig.class,env.test().start(env.context()));
    }
    @Test void actionAndSignedPayloadRemainDeterministicAcrossRepeatedStart(){
        var env=environment(true);var first=(CaseStep.AwaitInbound)env.test().start(env.context());var again=(CaseStep.AwaitInbound)env.test().start(env.context());
        assertEquals(first.actions().getFirst().actionId(),again.actions().getFirst().actionId());
        assertArrayEquals(first.actions().getFirst().payload(),again.actions().getFirst().payload());
    }
    @Test void redirectSignerIsAvailableOnlyForDedicatedMetadataFixture(){
        var env=environment(true);
        assertEquals(env.credentials().get("no-valid-until").certificate(),env.test().redirectCredentials(RUN,new CaseState("test",Map.of("fixture_id","new-key-redirect"))).orElseThrow().certificate());
        assertTrue(env.test().redirectCredentials(RUN,new CaseState("test",Map.of("fixture_id","old-key-new-acs"))).isEmpty());
    }
    @Test void absentOrFabricatedReceiptCannotBecomeAConclusiveRecordedUpdate(){
        var env=environment(true);var previous=CaseOutcome.notVerified("absent","metadata.supersession.awaiting-native-receipt");
        assertTrue(env.test().reevaluateRecordedEvidence(env.context(),previous).isEmpty());
    }
    @Test void advertisedFullProfileAddsSignedUnknownSessionSloControlsWithoutProvingLogoutSuccess(){
        var env=environment(true,true);CaseStep step=env.test().start(env.context());var seen=new ArrayList<String>();
        while(step instanceof CaseStep.AwaitInbound waiting){
            String fixture=(String)waiting.next().data().get("fixture_id");seen.add(fixture);
            var action=waiting.actions().getFirst();var xml=SecureXml.parse(action.payload()).getDocumentElement();
            if(MetadataSupersessionProbeTestCase.SLO_FIXTURES.contains(fixture)){
                assertEquals(OutboundKind.LOGOUT_REQUEST,action.kind());assertEquals("LogoutRequest",xml.getLocalName());
                assertEquals("http://idp.example/slo/post",action.target().toString());
                assertEquals("_"+action.actionId(),xml.getAttribute("ID"));
                assertEquals("samlscope-unregistered-session-"+action.actionId(),xml.getElementsByTagNameNS(SamlLogoutRequestFactory.ASSERTION,"NameID").item(0).getTextContent());
                assertEquals("samlscope-unregistered-index-"+action.actionId(),xml.getElementsByTagNameNS(P,"SessionIndex").item(0).getTextContent());
                var cert=env.credentials().get("old-key-slo-route".equals(fixture)?"control":"no-valid-until").certificate();
                assertEquals(!fixture.startsWith("new-key-invalid-signature"),new XmlSignatureVerifier().hasValidEnvelopedSignature(xml,cert));
                assertTrue(new XmlSignatureVerifier().hasValidEnvelopedReferenceDigests(xml));
                assertEquals(BrowserFrontChannelScenario.Binding.HTTP_POST,env.test().outboundBinding(waiting.next()));
                // Even a correlated-looking native status cannot turn collection into a verdict.
                step=env.test().resume(env.context(),waiting.next(),new CaseEvent.InboundMessage(("<samlp:LogoutResponse xmlns:samlp=\""+P+"\" InResponseTo=\"_"+action.actionId()+"\"><samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Requester\"/></samlp:Status></samlp:LogoutResponse>").getBytes(StandardCharsets.UTF_8),new EvidenceRef("transcript","transcript:tx-route")));
            }else step=env.test().resume(env.context(),waiting.next(),new CaseEvent.InboundUnavailable("no-response"));
        }
        var expected=new ArrayList<>(MetadataSupersessionProbeTestCase.FIXTURES);expected.addAll(MetadataSupersessionProbeTestCase.SLO_FIXTURES);
        assertEquals(expected,seen);assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,step).outcome().outcome());
    }
    @Test void fullProfileWithoutNativeSloPrerequisiteNeverQueuesPartialSloActions(){
        var env=environment(true,true,false);
        assertInstanceOf(CaseStep.AwaitConfig.class,env.test().start(env.context()));
    }
    @Test void invalidNativeKeycloakReceiptOwnsTheBranchWithoutStartingNewRequests()throws Exception{
        var directory=data.resolve("metadata-rejection-evidence");java.nio.file.Files.createDirectories(directory);
        java.nio.file.Files.writeString(directory.resolve(RUN+".keycloak-supersession.json"),"{}");
        var env=environment(true);
        var finish=assertInstanceOf(CaseStep.Finish.class,env.test().start(env.context()));
        assertEquals(Outcome.NOT_VERIFIED,finish.outcome().outcome());
        assertFalse(env.test().evidenceStatus(env.context()).ready());
        assertTrue(env.test().reevaluateRecordedEvidence(env.context(),CaseOutcome.notVerified("pending","metadata.supersession.awaiting-native-receipt")).isEmpty());
    }
    @Test void invalidFullApplicationReceiptDoesNotFallBackToNewProtocolRequests()throws Exception{
        var directory=data.resolve("shibboleth-metadata-application-evidence").resolve(RUN);
        java.nio.file.Files.createDirectories(directory);
        java.nio.file.Files.writeString(directory.resolve("manifest.json"),"{}");
        var env=environment(true,true);
        var finish=assertInstanceOf(CaseStep.Finish.class,env.test().start(env.context()));
        assertEquals(Outcome.NOT_VERIFIED,finish.outcome().outcome());
        assertFalse(env.test().evidenceStatus(env.context()).ready());
        assertTrue(env.test().reevaluateRecordedEvidence(env.context(),CaseOutcome.notVerified(
            "pending","metadata.supersession.awaiting-native-receipt")).isEmpty());
    }
    @Test void conflictingNativeReceiptOwnersNeverSelectOneBranchOrSendAgain()throws Exception{
        var full=data.resolve("shibboleth-metadata-application-evidence").resolve(RUN);
        java.nio.file.Files.createDirectories(full);
        java.nio.file.Files.writeString(full.resolve("manifest.json"),"{}");
        var legacy=data.resolve("metadata-rejection-evidence");
        java.nio.file.Files.createDirectories(legacy);
        java.nio.file.Files.writeString(legacy.resolve(RUN+".keycloak-supersession.json"),"{}");
        var env=environment(true,true);
        var finish=assertInstanceOf(CaseStep.Finish.class,env.test().start(env.context()));
        assertEquals(Outcome.NOT_VERIFIED,finish.outcome().outcome());
        assertEquals("metadata.supersession.awaiting-native-receipt",finish.outcome().reasonCode());
        assertFalse(env.test().evidenceStatus(env.context()).ready());
        assertTrue(env.test().reevaluateRecordedEvidence(env.context(),CaseOutcome.notVerified(
            "pending","metadata.supersession.awaiting-native-receipt")).isEmpty());
    }
    @Test void productionConfigRegistryWiresBothCasesWithoutChangingApprovedCaseIdentity(){
        var ids=List.of(MetadataSupersessionProbeTestCase.APPLICATION,MetadataSupersessionProbeTestCase.SUPERSESSION);
        var definitions=ids.stream().map(id->new com.samlscope.core.casedef.CaseDefinitionCatalog.CaseDefinition(
            id,"IIP-MD06.test",TargetRole.IDP,com.samlscope.core.casedef.CaseDefinitionCatalog.ExecutionMode.CONFIG,
            com.samlscope.core.casedef.CaseDefinitionCatalog.Milestone.M2,List.of(),Map.of(),List.of(),List.of(),List.of(),
            "Retaining superseded metadata is a counterexample.",List.of(),
            new com.samlscope.core.casedef.CaseDefinitionCatalog.Requirements(List.of(),"none"),false,
            ConfigurationFailureSemantics.TEST_PRECONDITION,"sha256:"+"a".repeat(64))).toList();
        var registry=ApprovedConfigCaseRegistry.create(new com.samlscope.core.casedef.CaseDefinitionCatalog(definitions),
            com.samlscope.core.casedef.CaseDefinitionCatalog.Milestone.M2,r->target().getBytes(StandardCharsets.UTF_8),e->new byte[0],
            r->Optional.empty(),(r,v)->Optional.empty());
        for(String id:ids)assertInstanceOf(MetadataSupersessionProbeTestCase.class,registry.find(id).orElseThrow());
    }
    private Environment environment(boolean originals){
        return environment(originals,false);
    }
    private Environment environment(boolean originals,boolean fullProfile){
        return environment(originals,fullProfile,true);
    }
    private Environment environment(boolean originals,boolean fullProfile,boolean nativeSlo){
        var clock=Clock.fixed(NOW,ZoneOffset.UTC);var store=new FilePlanKeyStore(data,clock);var credentials=new LinkedHashMap<String,PlanCredentials>();
        for(String key:List.of("control","multiple-signing-keys-first","multiple-signing-keys","no-valid-until"))credentials.put(key,store.getOrCreate(PLAN,key));
        List<TranscriptEntry> entries=new ArrayList<>();Map<String,byte[]> content=new HashMap<>();
        if(originals)for(String variant:List.of("control","no-valid-until")){
            String id="tx-"+variant;String source=metadata(variant);if(fullProfile)source=source.replace("</md:SPSSODescriptor>",java.util.stream.Stream.of("HTTP-POST","HTTP-Redirect","SOAP").map(binding->"<md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:"+binding+"\" Location=\""+SP+"/slo?mdv="+variant+"\"/>").collect(java.util.stream.Collectors.joining())+"</md:SPSSODescriptor>");byte[] raw=source.getBytes(StandardCharsets.UTF_8);content.put(id,raw);
            entries.add(new TranscriptEntry(id,RUN,Direction.OUTBOUND,NOW.minusSeconds(2),null,"GET","http://suite.example/live",200,Map.of(),null,0,id,raw.length,"application/xml",null,Map.of("type","MetadataPrepared","variant",variant,"feed","live")));
        }
        TranscriptRecorder recorder=new TranscriptRecorder(){public TranscriptEntry record(TranscriptInput i){throw new UnsupportedOperationException();}public TranscriptEntry updateSamlAnalysis(String i,String c,Map<String,Object>s){throw new UnsupportedOperationException();}public List<TranscriptEntry> list(String r){return entries;}};
        CaseContext context=new CaseContext(){public String runId(){return RUN;}public TargetRole targetRole(){return TargetRole.IDP;}public Clock clock(){return clock;}public TestPlan.Parameters parameters(){return null;}public TestPlan.Interaction interaction(){return TestPlan.Interaction.defaults();}public Reachability reachability(){return null;}public TranscriptRecorder transcript(){return recorder;}public boolean transcriptComplete(){return true;}};
        TestCase fallback=new TestCase(){public String id(){return MetadataSupersessionProbeTestCase.SUPERSESSION;}public TargetRole role(){return TargetRole.IDP;}public CaseStep start(CaseContext c){return new CaseStep.AwaitConfig(new CaseState("await-config",Map.of()),List.of(),"native",Duration.ofMinutes(1));}public CaseStep resume(CaseContext c,CaseState s,CaseEvent e){return new CaseStep.Finish(CaseOutcome.notVerified("unavailable","configuration.evidence-unavailable"));}};
        String targetSource=target();if(fullProfile)targetSource=targetSource.replace("</md:IDPSSODescriptor>","<md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:SOAP\" Location=\"http://idp.example/ecp\"/>"+(nativeSlo?"<md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://idp.example/slo/post\"/>":"")+"</md:IDPSSODescriptor>");String fixedTarget=targetSource;
        var test=new MetadataSupersessionProbeTestCase(fallback,r->fixedTarget.getBytes(StandardCharsets.UTF_8),e->content.get(e.id()),(r,v)->Optional.ofNullable(credentials.get(v)),data.resolve("metadata-rejection-evidence"));
        return new Environment(test,context,credentials);
    }
    private static String metadata(String variant){return "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\""+SP+"\"><md:SPSSODescriptor protocolSupportEnumeration=\""+P+"\"><md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" index=\"0\" isDefault=\"true\" Location=\""+SP+"/acs/0?mdv="+variant+"\"/><md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" index=\"1\" Location=\""+SP+"/acs/1?mdv="+variant+"\"/></md:SPSSODescriptor></md:EntityDescriptor>";}
    private static String target(){return "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"http://idp.example\"><md:IDPSSODescriptor protocolSupportEnumeration=\""+P+"\"><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://idp.example/post\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://idp.example/redirect\"/></md:IDPSSODescriptor></md:EntityDescriptor>";}
    private record Environment(MetadataSupersessionProbeTestCase test,CaseContext context,Map<String,PlanCredentials> credentials){}
}
