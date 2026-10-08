package com.samlscope.runner.cases;
import static org.junit.jupiter.api.Assertions.*;
import java.net.URI;
import java.nio.file.Path;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.artifact.*;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.*;

class ArtifactProtocolBindingTestCaseTest {
    @TempDir Path folder;
    ArtifactBindingEvidenceTest f;ArtifactProtocolBindingTestCase test;
    final Map<String,OutboxEntry> rows=new HashMap<>();
    final URI acs=ArtifactBindingEvidenceTest.ACS.resolve("0");
    @BeforeEach void setup()throws Exception{
        f=new ArtifactBindingEvidenceTest();f.folder=folder;f.setup();
        var config=new IdpErrorProbeConfiguration(f.SSO,f.SUITE,acs,Duration.ofMinutes(2),true,true,true);
        var b=new IdpAcsSelectionScenarioTestCase(IdpAcsSelectionScenarioTestCase.BINDING_CASE,r->config,f.recorder,r->Optional.of(f.TARGET),r->List.of(f.target.certificate()),r->Optional.of(f.suite));
        test=new ArtifactProtocolBindingTestCase(b,r->config,f.reader,id->Optional.ofNullable(rows.get(id)),f.recorder);
    }
    CaseStep.AwaitInbound bMatrix(){
        var step=assertInstanceOf(CaseStep.AwaitInbound.class,test.start(f.context));
        for(String name:List.of("post-binding-control","redirect-binding","unsupported-binding")){
            assertEquals(name,step.next().data().get("fixture_id"));var action=step.actions().getFirst();var d=SecureXml.parse(action.payload());new XmlSigner().sign(d.getDocumentElement(),f.suite,null);var bytes=SecureXml.serialize(d);
            f.recorder.record(new TranscriptInput(f.RUN,Direction.OUTBOUND,f.context.clock().instant(),action.actionId(),"POST",f.SSO.toString(),null,Map.of(),new byte[0],"application/x-www-form-urlencoded",null,bytes,Map.of("type","AuthnRequest","active_probe",true,"action_id",action.actionId(),"scenario_case_id",test.id(),"fixture_id",name)));
            var reply=bResponse(action.actionId(),name.equals("post-binding-control"));var original=f.recorder.record(new TranscriptInput(f.RUN,Direction.INBOUND,f.context.clock().instant(),"_"+action.actionId(),"POST",acs.toString(),200,Map.of(),new byte[0],"application/x-www-form-urlencoded",null,reply,Map.of("type","Response")));
            step=assertInstanceOf(CaseStep.AwaitInbound.class,test.resume(f.context,step.next(),new CaseEvent.InboundMessage(reply,new EvidenceRef("transcript",original.id()))));
        }
        assertEquals(ArtifactBindingEvidence.PHASE,step.next().phase());return step;
    }
    CaseStep.AwaitInbound resolvedPending(CaseStep.AwaitInbound a)throws Exception{
        f.chain(false,false);rows.put(f.resolve.actionId(),f.outbox);
        var action=ActionIds.derive(f.RUN,test.id(),ArtifactBindingEvidence.PHASE,0);var source=f.recorder.list(f.RUN).stream().filter(e->e.direction()==Direction.OUTBOUND&&action.equals(e.correlationId())).findFirst().orElseThrow();
        rows.put(action,new OutboxEntry(f.RUN,test.id(),new OutboundAction(action,OutboundKind.AUTHN_REQUEST,f.recorder.readDecodedSaml(source),f.SSO,false,OutboundAction.RequestSigning.REQUIRE),OutboxStatus.SENT,Map.of(),f.received.id(),f.NOW,f.NOW.plusSeconds(2)));
        return assertInstanceOf(CaseStep.AwaitInbound.class,test.resume(f.context,a.next(),new CaseEvent.InboundMessage(f.artifact.bytes(),new EvidenceRef("transcript",f.received.id()))));
    }
    @Test void fullCaseRequiresBControlsAndActualOriginalArtifactResolution()throws Exception{
        var pending=resolvedPending(bMatrix());
        var result=assertInstanceOf(CaseStep.Finish.class,test.resume(f.context,pending.next(),new CaseEvent.InboundMessage(f.recorder.readDecodedSaml(f.reply),new EvidenceRef("transcript",f.reply.id())))).outcome();
        assertEquals(Outcome.SATISFIED,result.outcome());assertEquals("observed_supported",result.details().get("artifact_applicability"));assertEquals(10,result.evidence().size());
    }
    @Test void unknownDeliveryAndUnbackedArtifactEventsNeverFinishSuccessfully()throws Exception{
        var a=bMatrix();var wrong=assertInstanceOf(CaseStep.Finish.class,test.resume(f.context,a.next(),new CaseEvent.InboundMessage(new byte[44],new EvidenceRef("transcript","fabricated"))));assertEquals(Outcome.NOT_VERIFIED,wrong.outcome().outcome());
        var pending=resolvedPending(a);rows.put(f.resolve.actionId(),new OutboxEntry(f.RUN,test.id(),f.resolve,OutboxStatus.UNKNOWN_DELIVERY,f.outbox.sendResult(),f.reply.id(),f.outbox.createdAt(),f.outbox.updatedAt()));
        assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,test.resume(f.context,pending.next(),new CaseEvent.InboundMessage(f.recorder.readDecodedSaml(f.reply),new EvidenceRef("transcript",f.reply.id())))).outcome().outcome());
    }
    @Test void silenceAfterTheArtifactRequestKeepsTheWholeCaseUnverified(){var a=bMatrix();assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,test.resume(f.context,a.next(),new CaseEvent.TimedOut(Duration.ofMinutes(2)))).outcome().outcome());}
    byte[] bResponse(String action,boolean success){var d=SecureXml.newDocument();var root=d.createElementNS(SamlArtifact.P,"samlp:Response");root.setAttributeNS("http://www.w3.org/2000/xmlns/","xmlns:samlp",SamlArtifact.P);root.setAttributeNS("http://www.w3.org/2000/xmlns/","xmlns:saml",ArtifactResolutionProtocol.A);d.appendChild(root);f.attributes(root,"_b_"+action,"_"+action);root.setAttribute("Destination",acs.toString());f.issuer(root);var status=d.createElementNS(SamlArtifact.P,"samlp:Status");root.appendChild(status);var code=d.createElementNS(SamlArtifact.P,"samlp:StatusCode");status.appendChild(code);code.setAttribute("Value","urn:oasis:names:tc:SAML:2.0:status:"+(success?"Success":"Responder"));if(success){var assertion=d.createElementNS(ArtifactResolutionProtocol.A,"saml:Assertion");assertion.setAttribute("ID","_assert_"+action);root.appendChild(assertion);f.issuer(assertion);}new XmlSigner().sign(root,f.target,null);return SecureXml.serialize(d);}
}
