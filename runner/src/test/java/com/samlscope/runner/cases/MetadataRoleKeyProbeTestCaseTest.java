package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.metadata.MetadataService;
import com.samlscope.saml.normal.*;
import java.net.URI;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class MetadataRoleKeyProbeTestCaseTest {
    private static final String RUN="run_0123456789ABCDEFGHJKMNPQRS",PLAN="plan_0123456789ABCDEFGHJKMNPQRS";
    @TempDir Path data;
    @Test void allProtocolControlsShareOneLoginAndCannotDetermineConformanceWithoutNativeOriginals(){
        var environment=environment(true);var test=environment.test();CaseStep step=test.start(environment.context());var observed=new ArrayList<String>();
        assertEquals(List.of("active-probe-login-1"),test.evidenceActionKeys());assertFalse(test.plansFreshSessionBoundary());
        while(step instanceof CaseStep.AwaitInbound waiting){String fixture=(String)waiting.next().data().get("fixture_id");observed.add(fixture);assertFalse(test.requiresFreshSession(waiting.next()));var raw=SecureXml.parse(waiting.actions().getFirst().payload()).getDocumentElement();var selected=fixture.endsWith("encryption-key")?"three-signing-keys":fixture.endsWith("peer-key")?(fixture.startsWith("explicit-b")||fixture.startsWith("omitted-b")?"three-signing-keys-first":"three-signing-keys-second"):(fixture.startsWith("explicit-b")||fixture.startsWith("omitted-b")?"three-signing-keys-second":"three-signing-keys-first");var key=environment.keys().get(selected);assertEquals(!fixture.endsWith("invalid-signature"),new XmlSignatureVerifier().hasValidEnvelopedSignature(raw,key.certificate()));assertTrue(new XmlSignatureVerifier().hasValidEnvelopedReferenceDigests(raw));assertEquals("_"+waiting.actions().getFirst().actionId(),raw.getAttribute("ID"));
            step=test.resume(environment.context(),waiting.next(),new CaseEvent.InboundUnavailable("no-response"));}
        assertEquals(MetadataRoleKeyProbeTestCase.FIXTURES,observed);assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,step).outcome().outcome());
    }
    @Test void missingPreparationUsesApprovedConfigAndOwnedMalformedProofNeverSends()throws Exception {
        var missing=environment(false);assertInstanceOf(CaseStep.AwaitConfig.class,missing.test().start(missing.context()));Files.createDirectories(data.resolve("proof").resolve(RUN));Files.writeString(data.resolve("proof").resolve(RUN).resolve("manifest.json"),"{}");var prepared=environment(true);assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,prepared.test().start(prepared.context())).outcome().outcome());assertFalse(prepared.test().evidenceStatus(prepared.context()).ready());assertTrue(prepared.test().reevaluateRecordedEvidence(prepared.context(),new CaseOutcome(Outcome.SATISFIED,null,"satisfied","satisfied",List.of(),Map.of())).isEmpty());
    }
    @Test void actionAndPayloadAreDeterministicWithRepeatedStart(){var env=environment(true);var first=(CaseStep.AwaitInbound)env.test().start(env.context());var second=(CaseStep.AwaitInbound)env.test().start(env.context());assertEquals(first.actions().getFirst().actionId(),second.actions().getFirst().actionId());assertArrayEquals(first.actions().getFirst().payload(),second.actions().getFirst().payload());}
    private Environment environment(boolean prepared){
        var clock=Clock.fixed(Instant.parse("2026-10-02T00:00:00Z"),ZoneOffset.UTC);var store=new FilePlanKeyStore(data.resolve("keys"),clock);var plan=new TestPlan(PLAN,"role keys",com.samlscope.core.profile.FunctionalProfile.METADATA_IDP,
            new TestPlan.Target(TargetKind.IDP,"http://target.example/idp",new TestPlan.MetadataSource(MetadataSourceKind.URL,"http://target.example/metadata")),MetadataDeliveryKind.HTTP_URL,Map.of(),new TestPlan.Parameters(180,30,"reference",TestPlan.RequestSigningMode.REQUIRED),TestPlan.Interaction.defaults(),clock.instant(),clock.instant());
        var service=new MetadataService(URI.create("http://suite.example"),store,new XmlSigner(),clock);var keys=new LinkedHashMap<String,PlanCredentials>();
        for(var token:List.of("three-signing-keys-first","three-signing-keys-second","three-signing-keys"))keys.put(token,service.credentialsForPollingVariant(plan,MetadataService.Variant.parse(token)));
        var entries=new ArrayList<TranscriptEntry>();var content=new HashMap<String,byte[]>();
        if(prepared)for(var variant:MetadataRoleKeyProbeTestCase.VARIANTS){String id="tx-"+variant;var raw=service.generatePolling(plan,MetadataService.Variant.parse(variant),RUN);content.put(id,raw);entries.add(new TranscriptEntry(id,RUN,Direction.OUTBOUND,clock.instant().minusSeconds(2),null,"GET","http://suite.example/live",200,Map.of(),null,0,id,raw.length,"application/xml",null,Map.of("type","MetadataPrepared","variant",variant,"feed","live")));}
        TranscriptRecorder recorder=new TranscriptRecorder(){public List<TranscriptEntry> list(String run){return entries;}public TranscriptEntry record(TranscriptInput i){throw new UnsupportedOperationException();}public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary){throw new UnsupportedOperationException();}};
        var context=new DefaultCaseContext(RUN,TargetRole.IDP,clock,plan.parameters(),plan.interaction(),Reachability.CONFIRMED,recorder,true);
        TestCase fallback=new TestCase(){public String id(){return MetadataRoleKeyProbeTestCase.CASE;}public TargetRole role(){return TargetRole.IDP;}public CaseStep start(CaseContext c){return new CaseStep.AwaitConfig(new CaseState("await-config",Map.of()),List.of(),"native",Duration.ofMinutes(1));}public CaseStep resume(CaseContext c,CaseState state,CaseEvent event){return new CaseStep.Finish(CaseOutcome.notVerified("unavailable","configuration.evidence-unavailable"));}};
        byte[] target=("<md:EntityDescriptor xmlns:md='urn:oasis:names:tc:SAML:2.0:metadata' entityID='http://target.example/idp'><md:IDPSSODescriptor><md:SingleSignOnService Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST' Location='http://target.example/sso'/></md:IDPSSODescriptor></md:EntityDescriptor>").getBytes();
        return new Environment(new MetadataRoleKeyProbeTestCase(fallback,r->target,e->content.get(e.id()),(r,v)->Optional.ofNullable(keys.get(v)),data.resolve("proof")),context,keys);
    }
    private record Environment(MetadataRoleKeyProbeTestCase test,CaseContext context,Map<String,PlanCredentials> keys){}
}
