package com.samlscope.runner.cases;

import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.*;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.binding.RedirectSignatureVerifier;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.time.*;
import java.net.URI;
import java.util.*;
import org.w3c.dom.Element;

/** Replays the archived production G02 scenario without issuing any action. */
public final class VerifyShibbolethG02KnownSubject {
    static final JsonCodec JSON=new JsonCodec();
    static final String CASE="IIP-G02-a-idp-01",P="urn:oasis:names:tc:SAML:2.0:protocol",S="urn:oasis:names:tc:SAML:2.0:assertion",MD="urn:oasis:names:tc:SAML:2.0:metadata",DS="http://www.w3.org/2000/09/xmldsig#";
    static void require(boolean v){if(!v)throw new IllegalArgumentException("G02 original proof incomplete");}
    static String hash(byte[] b)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));}
    static class SelectedClock extends Clock {
        Instant at;SelectedClock(Instant at){this.at=at;}public ZoneId getZone(){return ZoneOffset.UTC;}public Clock withZone(ZoneId ignored){return this;}public Instant instant(){return at;}
    }
    static List<Element> children(Element e,String ns,String name){return MetadataAlgorithmEvidence.children(e,ns,name);}
    static String structure(Element e) {
        var attributes=new TreeMap<String,String>();var list=e.getAttributes();
        for(int i=0;i<list.getLength();i++){var a=list.item(i);if(!"http://www.w3.org/2000/xmlns/".equals(a.getNamespaceURI()))attributes.put(String.valueOf(a.getNamespaceURI())+"|"+a.getLocalName(),a.getNodeValue());}
        var values=new ArrayList<String>();for(var n=e.getFirstChild();n!=null;n=n.getNextSibling())
            if(n instanceof Element child){if(!(DS.equals(child.getNamespaceURI())&&"Signature".equals(child.getLocalName())))values.add(structure(child));}
            else if(n.getNodeType()==org.w3c.dom.Node.TEXT_NODE||n.getNodeType()==org.w3c.dom.Node.CDATA_SECTION_NODE)values.add("text:"+n.getNodeValue());
        return e.getNamespaceURI()+"|"+e.getLocalName()+"|"+attributes+"|"+values;
    }
    static List<X509Certificate> certificates(Element entity,String role)throws Exception {
        var result=new ArrayList<X509Certificate>();
        for(var sp:children(entity,MD,role))for(var key:children(sp,MD,"KeyDescriptor")) {
            if(!Set.of("","signing").contains(key.getAttribute("use")))continue;
            for(var info:children(key,DS,"KeyInfo"))for(var data:children(info,DS,"X509Data"))for(var cert:children(data,DS,"X509Certificate"))
                result.add((X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(Base64.getMimeDecoder().decode(cert.getTextContent()))));
        }require(!result.isEmpty());return result;
    }
    static CaseOutcome replay(String run,List<TranscriptEntry> requests,Map<String,TranscriptEntry> responses,Map<String,byte[]> originals,String mutation)throws Exception {
        var first=SecureXml.parse(originals.get(requests.getFirst().id())).getDocumentElement();
        var issuer=children(first,S,"Issuer").getFirst().getTextContent();var clock=new SelectedClock(Instant.parse(first.getAttribute("IssueInstant")));
        var recorder=new TranscriptRecorder(){public List<TranscriptEntry> list(String selected){return List.of();}public TranscriptEntry record(TranscriptInput input){throw new AssertionError("Replay recorded an action");}public TranscriptEntry updateSamlAnalysis(String id,String c,Map<String,Object> a){throw new AssertionError("Replay updated evidence");}};
        var context=new DefaultCaseContext(run,TargetRole.IDP,clock,TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,true);
        var configuration=new IdpErrorProbeConfiguration(URI.create(first.getAttribute("Destination")),issuer,URI.create(first.getAttribute("AssertionConsumerServiceURL")),Duration.ofHours(2),true,true,true);
        var test=new IdpExecutableBrowserFixtureScenarioTestCase(CASE,ignored->configuration);CaseStep step=test.start(context);
        for(int i=0;i<requests.size();i++) {
            if(!(step instanceof CaseStep.AwaitInbound awaiting))throw new IllegalArgumentException("Premature scenario finish");
            var request=requests.get(i);var rawRequest=SecureXml.parse(originals.get(request.id())).getDocumentElement();
            var fixture=String.valueOf(request.samlSummary().get("fixture_id"));require(fixture.equals(awaiting.next().data().get("fixture_id")));
            require(awaiting.actions().size()==1&&("_"+awaiting.actions().getFirst().actionId()).equals(rawRequest.getAttribute("ID")));
            var generated=SecureXml.parse(awaiting.actions().getFirst().payload()).getDocumentElement();
            require(structure(generated).equals(structure(rawRequest)));
            var response=responses.get(rawRequest.getAttribute("ID"));require(response!=null);
            byte[] body=originals.get(response.id());CaseEvent event=new CaseEvent.InboundMessage(body,new EvidenceRef("transcript",response.id()));
            boolean selected=fixture.equals("string-ascii-256");
            if(mutation.equals("missing-response")&&selected)event=new CaseEvent.InboundUnavailable("not-observed");
            else if((mutation.equals("wrong-correlation")||mutation.equals("unrecognized-status")||mutation.equals("reject-256")||mutation.equals("missing-assertion"))&&selected) {
                var changed=SecureXml.parse(body);var root=changed.getDocumentElement();
                if(mutation.equals("wrong-correlation"))root.setAttribute("InResponseTo","_different");
                if(mutation.equals("unrecognized-status")||mutation.equals("reject-256"))children(children(root,P,"Status").getFirst(),P,"StatusCode").getFirst().setAttribute("Value",mutation.equals("reject-256")?"urn:oasis:names:tc:SAML:2.0:status:Requester":"urn:samlscope:unknown-status");
                if(mutation.equals("missing-assertion"))for(var name:List.of("Assertion","EncryptedAssertion"))for(var a:children(root,S,name))root.removeChild(a);
                event=new CaseEvent.InboundMessage(SecureXml.serialize(changed),new EvidenceRef("transcript",response.id()));
            }else if(mutation.equals("unrelated-long-subject-error")&&fixture.equals("persistent-nameid-ascii-256")) {
                var changed=SecureXml.parse(body);var root=changed.getDocumentElement();children(children(root,P,"Status").getFirst(),P,"StatusCode").getFirst().setAttribute("Value","urn:oasis:names:tc:SAML:2.0:status:Requester");
                event=new CaseEvent.InboundMessage(SecureXml.serialize(changed),new EvidenceRef("transcript",response.id()));
            }
            if(i+1<requests.size())clock.at=Instant.parse(SecureXml.parse(originals.get(requests.get(i+1).id())).getDocumentElement().getAttribute("IssueInstant"));
            step=test.resume(context,awaiting.next(),event);
            if(step instanceof CaseStep.Finish finish&&i+1<requests.size())return finish.outcome();
        }
        require(step instanceof CaseStep.Finish);return ((CaseStep.Finish)step).outcome();
    }
    public static void main(String[]args)throws Exception {
        if(args.length!=2)throw new IllegalArgumentException("browser-folder report-path");
        JSON.mapper().enable(com.fasterxml.jackson.databind.SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);
        java.util.logging.Logger.getLogger("org.apache.xml.security.signature.XMLSignature").setLevel(java.util.logging.Level.SEVERE);
        var folder=Path.of(args[0]);var created=JSON.mapper().readTree(folder.resolve("created.json").toFile());var run=created.path("run").path("id").asText();
        var entries=List.of(JSON.mapper().readValue(folder.resolve("transcript.json").toFile(),TranscriptEntry[].class));var ids=new HashSet<String>();var originals=new HashMap<String,byte[]>();
        for(var row:JSON.mapper().readTree(folder.resolve("decoded-manifest.json").toFile())) {
            var raw=Files.readAllBytes(folder.resolve(row.path("file").asText()));require(hash(raw).equals(row.path("sha256").asText()));require(originals.put(row.path("id").asText(),raw)==null);
        }
        for(var e:entries){require(run.equals(e.runId())&&ids.add(e.id()));if(e.decodedSamlRef()!=null){require(("transcripts/"+run+"/"+e.id()+".saml.xml").equals(e.decodedSamlRef()));require(originals.containsKey(e.id())&&originals.get(e.id()).length==e.decodedSamlBytes());}}
        var targetRaw=Files.readAllBytes(folder.resolve("target-metadata.xml"));var target=SecureXml.parse(targetRaw).getDocumentElement();var keys=certificates(target,"IDPSSODescriptor");
        var sp=SecureXml.parse(Files.readAllBytes(folder.resolve("suite-sp-metadata.xml"))).getDocumentElement();var spKeys=certificates(sp,"SPSSODescriptor");
        var requests=entries.stream().filter(e->e.direction()==Direction.OUTBOUND&&CASE.equals(e.samlSummary().get("scenario_case_id"))&&"AuthnRequest".equals(e.samlSummary().get("type"))).sorted(Comparator.comparing(TranscriptEntry::timestamp)).toList();require(requests.size()==43);
        var responses=new HashMap<String,TranscriptEntry>();
        for(var e:entries)if(e.direction()==Direction.INBOUND&&"Response".equals(e.samlSummary().get("type"))) {var root=SecureXml.parse(originals.get(e.id())).getDocumentElement();require(responses.put(root.getAttribute("InResponseTo"),e)==null);}
        var exchanges=new ArrayList<Map<String,Object>>();
        for(var request:requests) {
            var raw=originals.get(request.id());var req=SecureXml.parse(raw).getDocumentElement();var response=responses.get(req.getAttribute("ID"));require(response!=null&&request.timestamp().isBefore(response.timestamp()));
            require(spKeys.stream().anyMatch(k->"GET".equals(request.method())
                    ?new RedirectSignatureVerifier().isValidForMessage(request.rawQuery(),k,raw)
                    :"POST".equals(request.method())&&new XmlSignatureVerifier().hasValidEnvelopedSignature(req,k)));
            var reply=SecureXml.parse(originals.get(response.id())).getDocumentElement();require(req.getAttribute("AssertionConsumerServiceURL").equals(reply.getAttribute("Destination"))&&reply.getAttribute("Destination").equals(response.url()));
            require(children(req,S,"Issuer").size()==1&&sp.getAttribute("entityID").equals(children(req,S,"Issuer").getFirst().getTextContent()));
            require(new VerifiedSignatureAlgorithms().read(reply,target.getAttribute("entityID"),keys).stream().anyMatch(s->s.element().equals("Response")));
            require(Boolean.TRUE.equals(response.samlSummary().get("activeProbeAccepted")));
            exchanges.add(Map.of("fixture",request.samlSummary().get("fixture_id"),"request",request.id(),"response",response.id(),"requestSignatureVerified",true,"responseSignatureVerified",true));
        }
        var actual=replay(run,requests,responses,originals,"none");require(actual.outcome()==Outcome.SATISFIED);
        var unknown=new ArrayList<Map<String,Object>>();
        for(var request:entries)if(request.direction()==Direction.OUTBOUND&&"IIP-SSO07-b-idp-01".equals(request.samlSummary().get("scenario_case_id"))
                &&"AuthnRequest".equals(request.samlSummary().get("type"))&&!"baseline-success".equals(request.samlSummary().get("fixture_id"))) {
            var raw=originals.get(request.id());var req=SecureXml.parse(raw).getDocumentElement();var response=responses.get(req.getAttribute("ID"));require(response!=null&&request.timestamp().isBefore(response.timestamp()));
            require(spKeys.stream().anyMatch(k->"GET".equals(request.method())?new RedirectSignatureVerifier().isValidForMessage(request.rawQuery(),k,raw):"POST".equals(request.method())&&new XmlSignatureVerifier().hasValidEnvelopedSignature(req,k)));
            var reply=SecureXml.parse(originals.get(response.id())).getDocumentElement();
            require(P.equals(reply.getNamespaceURI())&&"Response".equals(reply.getLocalName())&&req.getAttribute("AssertionConsumerServiceURL").equals(reply.getAttribute("Destination"))&&reply.getAttribute("Destination").equals(response.url()));
            require(new VerifiedSignatureAlgorithms().read(reply,target.getAttribute("entityID"),keys).stream().anyMatch(s->s.element().equals("Response")));
            require(children(reply,P,"Status").size()==1&&children(children(reply,P,"Status").getFirst(),P,"StatusCode").size()==1
                &&Set.of("urn:oasis:names:tc:SAML:2.0:status:Requester","urn:oasis:names:tc:SAML:2.0:status:Responder").contains(children(children(reply,P,"Status").getFirst(),P,"StatusCode").getFirst().getAttribute("Value"))
                &&children(reply,S,"Assertion").isEmpty()&&children(reply,S,"EncryptedAssertion").isEmpty());
            unknown.add(Map.of("fixture",request.samlSummary().get("fixture_id"),"request",request.id(),"response",response.id(),"requestSignatureVerified",true,"responseSignatureVerified",true,"explicitRejected",true));
        }
        var controls=new TreeMap<String,Object>();
        for(var mutation:List.of("missing-response","wrong-correlation","unrecognized-status","reject-256","missing-assertion","unrelated-long-subject-error")) {
            var outcome=replay(run,requests,responses,originals,mutation).outcome();require(outcome==(mutation.equals("reject-256")?Outcome.VIOLATED:Outcome.NOT_VERIFIED));controls.put(mutation,outcome.name());
        }
        var hashes=new TreeMap<String,String>();for(var row:originals.entrySet())hashes.put(row.getKey(),hash(row.getValue()));
        var report=new TreeMap<String,Object>();report.put("runId",run);report.put("caseId",CASE);report.put("outcome",actual);report.put("controls",controls);report.put("exchanges",exchanges);
        report.put("unknownSubjectControls",unknown);report.put("originalDecodedSha256",hashes);report.put("targetMetadataSha256",hash(targetRaw));report.put("productOperations",0);report.put("privateCredentialsPersisted",false);
        JSON.mapper().writerWithDefaultPrettyPrinter().writeValue(Path.of(args[1]).toFile(),report);
    }
}
