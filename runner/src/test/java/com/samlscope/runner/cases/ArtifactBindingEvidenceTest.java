package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.run.*;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.*;
import com.samlscope.runner.outbox.ArtifactResolutionOutboundSender;
import com.samlscope.saml.artifact.*;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.*;
import com.samlscope.store.*;
import org.w3c.dom.Element;

class ArtifactBindingEvidenceTest {
    @TempDir Path folder;
    static final String RUN="run_0123456789ABCDEFGHJKMNPQRS",PLAN="plan_0123456789ABCDEFGHJKMNPQRS",TARGET="https://idp.example/entity",SUITE="https://suite.example/sp";
    static final URI ACS=URI.create("https://suite.example/p/test/sp/acs/4"),SSO=URI.create("https://idp.example/sso"),ARS=URI.create("https://idp.example/resolve");
    static final Instant NOW=Instant.parse("2026-10-08T00:00:00Z");
    FileTranscriptRecorder recorder;PlanCredentials suite,target;byte[] metadata;ArtifactBindingEvidence reader;CaseContext context;
    TranscriptEntry received,sent,reply;OutboundAction resolve;OutboxEntry outbox;SamlArtifact artifact;
    @BeforeEach void setup()throws Exception{
        var db=new SqliteDatabase(folder);var json=new JsonCodec();var plan=new TestPlan(PLAN,"Artifact",FunctionalProfile.BROWSER_SSO_IDP,new TestPlan.Target(TargetKind.IDP,TARGET,new TestPlan.MetadataSource(MetadataSourceKind.URL,"https://idp.example/metadata")),MetadataDeliveryKind.MANUAL,Map.of(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),NOW,NOW);
        new SqlitePlanRepository(db,json).save(plan);new SqliteRunRepository(db,json).save(new TestRun(RUN,PLAN,RunStatus.RUNNING,Reachability.CONFIRMED,Map.of(),NOW,NOW));recorder=new FileTranscriptRecorder(db,json,folder);
        var keys=new FilePlanKeyStore(folder.resolve("keys"),Clock.fixed(NOW,ZoneOffset.UTC));suite=keys.getOrCreate(PLAN);target=keys.getOrCreate(PLAN,"target");
        var cert=Base64.getEncoder().encodeToString(target.certificate().getEncoded());metadata=("<md:EntityDescriptor xmlns:md=\""+SamlArtifact.MD+"\" xmlns:ds=\""+ArtifactResolutionProtocol.DS+"\" entityID=\""+TARGET+"\"><md:IDPSSODescriptor protocolSupportEnumeration=\""+SamlArtifact.P+"\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>"+cert+"</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:ArtifactResolutionService index=\"7\" Binding=\""+SamlArtifact.SOAP+"\" Location=\""+ARS+"\"/></md:IDPSSODescriptor></md:EntityDescriptor>").getBytes(StandardCharsets.UTF_8);
        reader=new ArtifactBindingEvidence(recorder,r->metadata,r->Optional.of(suite));context=new DefaultCaseContext(RUN,TargetRole.IDP,Clock.fixed(NOW.plusSeconds(3),ZoneOffset.UTC),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,false);
    }
    void chain(boolean get,boolean opaque)throws Exception{
        var source=MessageDigest.getInstance("SHA-1").digest(TARGET.getBytes(StandardCharsets.UTF_8));if(opaque)Arrays.fill(source,(byte)9);var handle=new byte[20];Arrays.fill(handle,(byte)17);artifact=SamlArtifact.parse(Base64.getEncoder().encodeToString(ByteBuffer.allocate(44).putShort((short)4).putShort((short)7).put(source).put(handle).array()));
        var action=ActionIds.derive(RUN,ArtifactBindingEvidence.CASE,ArtifactBindingEvidence.PHASE,0);
        var request=SecureXml.parse(new SamlAcsSelectionRequestFactory().build(SamlAcsSelectionRequestFactory.Fixture.ARTIFACT_BINDING,"_"+action,SSO,SUITE,ACS,ACS.resolve("1"),NOW));new XmlSigner().sign(request.getDocumentElement(),suite,null);var requestBytes=SecureXml.serialize(request);
        recorder.record(new TranscriptInput(RUN,Direction.OUTBOUND,NOW,action,"POST",SSO.toString(),null,Map.of(),new byte[0],"application/x-www-form-urlencoded",null,requestBytes,Map.of("type","AuthnRequest","action_id",action,"scenario_case_id",ArtifactBindingEvidence.CASE,"fixture_id",ArtifactBindingEvidence.FIXTURE)));
        String form="SAMLart="+url(artifact.base64())+"&RelayState="+url(ActiveProbeCorrelation.encode(RUN,action));byte[] body=get?new byte[0]:form.getBytes(StandardCharsets.UTF_8);
        received=recorder.record(new TranscriptInput(RUN,Direction.INBOUND,NOW.plusSeconds(1),action,get?"GET":"POST",ACS+(get?"?"+form:""),200,Map.of(),body,get?null:"application/x-www-form-urlencoded",get?form:null,new byte[0],Map.of("type","ArtifactReceived","scenario_case_id",ArtifactBindingEvidence.CASE,"authn_action_id",action,"artifact_sha256",artifact.sha256(),"target_metadata_sha256",ArtifactBindingEvidence.sha256(metadata))));
        resolve=reader.prepare(context,received,ACS);sent=recorder.record(new TranscriptInput(RUN,Direction.OUTBOUND,NOW.plusSeconds(3),resolve.actionId(),"POST",ARS.toString(),null,Map.of(),resolve.payload(),"text/xml",null,resolve.payload(),Map.of("type","ArtifactResolve","scenario_case_id",ArtifactBindingEvidence.CASE,"action_id",resolve.actionId(),"request_sha256",ArtifactBindingEvidence.sha256(resolve.payload()))));
        byte[] raw=response(resolve.actionId(),action);String hash=ArtifactBindingEvidence.sha256(raw);
        reply=recorder.record(new TranscriptInput(RUN,Direction.INBOUND,NOW.plusSeconds(4),resolve.actionId(),"POST",ARS.toString(),200,Map.of(),raw,"text/xml",null,raw,Map.of("type","ArtifactResponse","scenario_case_id",ArtifactBindingEvidence.CASE,"action_id",resolve.actionId(),"request_transcript",sent.id(),"response_sha256",hash)));
        outbox=new OutboxEntry(RUN,ArtifactBindingEvidence.CASE,resolve,OutboxStatus.SENT,Map.of("http_status",200,"request_transcript",sent.id(),"response_sha256",hash),reply.id(),NOW.plusSeconds(2),NOW.plusSeconds(4));
    }
    @Test void realGetAndPostOriginalsSupportSignedResolutionWithoutAFalseSha1Requirement()throws Exception{
        chain(false,true);var proof=reader.read(context,outbox,ACS).orElseThrow();assertEquals(4,proof.evidence().size());assertEquals(ArtifactResolutionProtocol.SUCCESS,proof.resolved().status());assertFalse(proof.recommendedSourceIdMapping());
    }
    @Test void getArtifactOriginalAndPreparedDeterministicUnsafeOutboxAreBound()throws Exception{
        chain(true,false);assertTrue(reader.read(context,outbox,ACS).isPresent());assertEquals(OutboundKind.Retry.UNSAFE,resolve.kind().retry());assertFalse(resolve.requiresEphemeralCredential());
    }
    @Test void unknownDeliveryForeignRunEndpointAndReceiptCannotBeAdopted()throws Exception{
        chain(false,false);
        assertTrue(reader.read(context,copy(outbox,"run_11111111111111111111111111",OutboxStatus.SENT,resolve,reply.id()),ACS).isEmpty());
        assertTrue(reader.read(context,copy(outbox,RUN,OutboxStatus.UNKNOWN_DELIVERY,resolve,reply.id()),ACS).isEmpty());
        assertTrue(reader.read(context,copy(outbox,RUN,OutboxStatus.SENT,new OutboundAction(resolve.actionId(),resolve.kind(),resolve.payload(),URI.create("https://other.example/resolve"),false),reply.id()),ACS).isEmpty());
        assertTrue(reader.read(context,copy(outbox,RUN,OutboxStatus.SENT,resolve,sent.id()),ACS).isEmpty());
    }
    @Test void duplicateOriginalsAndReplayAreNotOneResolution()throws Exception{
        chain(false,false);recorder.record(new TranscriptInput(RUN,Direction.INBOUND,received.timestamp(),received.correlationId(),received.method(),received.url(),received.status(),received.headers(),recorder.readBody(received),received.contentType(),received.rawQuery(),new byte[0],received.samlSummary()));assertTrue(reader.read(context,outbox,ACS).isEmpty());
    }
    @Test void metadataEpochArtifactIndexAndOriginalByteReplacementFailClosed()throws Exception{
        chain(false,false);byte[] original=metadata;metadata=new String(metadata,StandardCharsets.UTF_8).replace("index=\"7\"","index=\"8\"").getBytes(StandardCharsets.UTF_8);assertTrue(reader.read(context,outbox,ACS).isEmpty());metadata=original;
        var path=folder.resolve(sent.bodyRef());var bytes=Files.readAllBytes(path);bytes[0]='x';Files.write(path,bytes);assertTrue(reader.read(context,outbox,ACS).isEmpty());
    }
    @Test void callerDeclaredArtifactOrRelayAndMixedProtocolParametersAreRejected()throws Exception{
        chain(false,false);String a=ActionIds.derive(RUN,ArtifactBindingEvidence.CASE,ArtifactBindingEvidence.PHASE,0);
        for(String body:List.of("SAMLart="+url(artifact.base64())+"&RelayState=foreign", "SAMLart="+url(artifact.base64())+"&SAMLart="+url(artifact.base64())+"&RelayState="+url(ActiveProbeCorrelation.encode(RUN,a)),"SAMLart="+url(artifact.base64())+"&RelayState="+url(ActiveProbeCorrelation.encode(RUN,a))+"&SAMLResponse=other"))assertThrows(IllegalArgumentException.class,()->ArtifactBindingEvidence.delivery("POST",ACS.toString(),"application/x-www-form-urlencoded",body.getBytes(StandardCharsets.UTF_8),null,RUN,a,ACS));
    }
    @Test void aggregateMetadataSelectsOnlyTheConfiguredEntityAndRejectsDuplicatesOrAnotherTarget()throws Exception{
        var entity=new String(metadata,StandardCharsets.UTF_8);
        metadata=("<md:EntitiesDescriptor xmlns:md='"+SamlArtifact.MD+"'><md:EntitiesDescriptor>"+entity+"</md:EntitiesDescriptor></md:EntitiesDescriptor>").getBytes(StandardCharsets.UTF_8);
        reader=new ArtifactBindingEvidence(recorder,r->metadata,r->Optional.of(suite),r->Optional.of(TARGET));chain(false,false);
        assertTrue(reader.read(context,outbox,ACS).isPresent());
        var other=new ArtifactBindingEvidence(recorder,r->metadata,r->Optional.of(suite),r->Optional.of("https://other.example/entity"));
        assertTrue(other.read(context,outbox,ACS).isEmpty());
        metadata=("<md:EntitiesDescriptor xmlns:md='"+SamlArtifact.MD+"'>"+entity+entity+"</md:EntitiesDescriptor>").getBytes(StandardCharsets.UTF_8);
        assertThrows(IllegalArgumentException.class,()->reader.prepare(context,received,ACS));
    }
    static OutboxEntry copy(OutboxEntry e,String run,OutboxStatus status,OutboundAction action,String receipt){return new OutboxEntry(run,e.caseId(),action,status,e.sendResult(),receipt,e.createdAt(),e.updatedAt());}
    byte[] response(String resolveAction,String authnAction){
        var d=SecureXml.newDocument();var env=d.createElementNS(ArtifactResolutionProtocol.SOAP,"soap:Envelope");env.setAttributeNS("http://www.w3.org/2000/xmlns/","xmlns:soap",ArtifactResolutionProtocol.SOAP);d.appendChild(env);var body=d.createElementNS(ArtifactResolutionProtocol.SOAP,"soap:Body");env.appendChild(body);var outer=d.createElementNS(SamlArtifact.P,"samlp:ArtifactResponse");outer.setAttributeNS("http://www.w3.org/2000/xmlns/","xmlns:samlp",SamlArtifact.P);outer.setAttributeNS("http://www.w3.org/2000/xmlns/","xmlns:saml",ArtifactResolutionProtocol.A);body.appendChild(outer);attributes(outer,"_outer","_"+resolveAction);issuer(outer);status(outer);var inner=d.createElementNS(SamlArtifact.P,"samlp:Response");outer.appendChild(inner);attributes(inner,"_inner","_"+authnAction);inner.setAttribute("Destination",ACS.toString());issuer(inner);status(inner);var assertion=d.createElementNS(ArtifactResolutionProtocol.A,"saml:Assertion");assertion.setAttribute("ID","_assertion");inner.appendChild(assertion);issuer(assertion);new XmlSigner().sign(outer,target,null);return SecureXml.serialize(d);
    }
    void attributes(Element e,String id,String response){e.setAttribute("ID",id);e.setAttribute("Version","2.0");e.setAttribute("IssueInstant",NOW.plusSeconds(4).toString());e.setAttribute("InResponseTo",response);}
    void issuer(Element e){var i=e.getOwnerDocument().createElementNS(ArtifactResolutionProtocol.A,"saml:Issuer");i.setTextContent(TARGET);e.appendChild(i);}
    void status(Element e){var s=e.getOwnerDocument().createElementNS(SamlArtifact.P,"samlp:Status");e.appendChild(s);var code=e.getOwnerDocument().createElementNS(SamlArtifact.P,"samlp:StatusCode");code.setAttribute("Value",ArtifactResolutionProtocol.SUCCESS);s.appendChild(code);}
    static String url(String value){return URLEncoder.encode(value,StandardCharsets.UTF_8);}
}
