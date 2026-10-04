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
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.*;
import java.net.URI;
import java.util.*;
import org.w3c.dom.Element;

/** Replays the actual production exact-context scenario; private Run key stays in Suite memory. */
public final class VerifyShibbolethExactAuthnContext {
 static final JsonCodec JSON=new JsonCodec();
 static final String CASE="IIP-IDP08-a-idp-01",P="urn:oasis:names:tc:SAML:2.0:protocol",S="urn:oasis:names:tc:SAML:2.0:assertion",MD="urn:oasis:names:tc:SAML:2.0:metadata",DS="http://www.w3.org/2000/09/xmldsig#";
 static void require(boolean v){if(!v)throw new IllegalArgumentException("Exact-context original proof incomplete");}
 static String hash(byte[] b)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));}
 static List<Element> children(Element e,String ns,String name){return MetadataAlgorithmEvidence.children(e,ns,name);}
 static class SelectedClock extends Clock { Instant at;SelectedClock(Instant at){this.at=at;}public ZoneId getZone(){return ZoneOffset.UTC;}public Clock withZone(ZoneId ignored){return this;}public Instant instant(){return at;} }
 static String structure(Element e) {
  var attributes=new TreeMap<String,String>();var list=e.getAttributes();for(int i=0;i<list.getLength();i++){var a=list.item(i);if(!"http://www.w3.org/2000/xmlns/".equals(a.getNamespaceURI()))attributes.put(String.valueOf(a.getNamespaceURI())+"|"+a.getLocalName(),a.getNodeValue());}
  var values=new ArrayList<String>();for(var n=e.getFirstChild();n!=null;n=n.getNextSibling())if(n instanceof Element c){if(!(DS.equals(c.getNamespaceURI())&&"Signature".equals(c.getLocalName())))values.add(structure(c));}else if(n.getNodeType()==org.w3c.dom.Node.TEXT_NODE||n.getNodeType()==org.w3c.dom.Node.CDATA_SECTION_NODE)values.add("text:"+n.getNodeValue());return e.getNamespaceURI()+"|"+e.getLocalName()+"|"+attributes+"|"+values;
 }
 static List<X509Certificate> certificates(Element entity,String role)throws Exception {
  var result=new ArrayList<X509Certificate>();for(var r:children(entity,MD,role))for(var k:children(r,MD,"KeyDescriptor")){if(!Set.of("","signing").contains(k.getAttribute("use")))continue;for(var info:children(k,DS,"KeyInfo"))for(var data:children(info,DS,"X509Data"))for(var cert:children(data,DS,"X509Certificate"))result.add((X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(Base64.getMimeDecoder().decode(cert.getTextContent()))));}require(!result.isEmpty());return result;
 }
 static Element assertion(Element response,PrivateKey key) {
  var plain=children(response,S,"Assertion");var encrypted=children(response,S,"EncryptedAssertion");require(plain.size()+encrypted.size()==1);return plain.isEmpty()?new SamlXmlDecrypter().decrypt(encrypted.getFirst(),key):plain.getFirst();
 }
 static CaseOutcome replay(String run,List<TranscriptEntry> requests,Map<String,TranscriptEntry> responses,Map<String,byte[]> originals,PrivateKey key,String mutation)throws Exception {
  var first=SecureXml.parse(originals.get(requests.getFirst().id())).getDocumentElement();var issuer=children(first,S,"Issuer").getFirst().getTextContent();var clock=new SelectedClock(Instant.parse(first.getAttribute("IssueInstant")));
  var recorder=new TranscriptRecorder(){public List<TranscriptEntry> list(String selected){return List.of();}public TranscriptEntry record(TranscriptInput i){throw new AssertionError("Replay sent an action");}public TranscriptEntry updateSamlAnalysis(String id,String c,Map<String,Object>a){throw new AssertionError("Replay changed evidence");}};
  var context=new DefaultCaseContext(run,TargetRole.IDP,clock,TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,true);
  var config=new IdpErrorProbeConfiguration(URI.create(first.getAttribute("Destination")),issuer,URI.create(first.getAttribute("AssertionConsumerServiceURL")),Duration.ofHours(2),true,true,true);
  var test=new IdpAuthnContextScenarioTestCase(ignored->config,ignored->Optional.ofNullable(key));CaseStep step=test.start(context);
  for(int i=0;i<requests.size();i++) {
   require(step instanceof CaseStep.AwaitInbound);var awaiting=(CaseStep.AwaitInbound)step;var request=requests.get(i);var req=SecureXml.parse(originals.get(request.id())).getDocumentElement();var fixture=String.valueOf(request.samlSummary().get("fixture_id"));require(fixture.equals(awaiting.next().data().get("fixture_id"))&&awaiting.actions().size()==1&&("_"+awaiting.actions().getFirst().actionId()).equals(req.getAttribute("ID")));
   require(structure(SecureXml.parse(awaiting.actions().getFirst().payload()).getDocumentElement()).equals(structure(req)));
   var response=responses.get(req.getAttribute("ID"));require(response!=null);byte[] body=originals.get(response.id());CaseEvent event=new CaseEvent.InboundMessage(body,new EvidenceRef("transcript",response.id()));
   if(mutation.equals("missing-response")&&fixture.equals("satisfiable-declaration"))event=new CaseEvent.InboundUnavailable("not-observed");
   else if(mutation.equals("wrong-correlation")&&fixture.equals("satisfiable-declaration")){var changed=SecureXml.parse(body);changed.getDocumentElement().setAttribute("InResponseTo","_other");event=new CaseEvent.InboundMessage(SecureXml.serialize(changed),new EvidenceRef("transcript",response.id()));}
   else if(mutation.equals("wrong-class")&&fixture.equals("satisfiable-class")||mutation.equals("wrong-declaration")&&fixture.equals("satisfiable-declaration")) {
    var changed=SecureXml.parse(body);var root=changed.getDocumentElement();var a=assertion(root,key);var imported=(Element)changed.importNode(a,true);for(var e:children(root,S,"EncryptedAssertion"))root.removeChild(e);for(var e:children(root,S,"Assertion"))root.removeChild(e);root.appendChild(imported);var name=mutation.equals("wrong-class")?"AuthnContextClassRef":"AuthnContextDeclRef";var refs=imported.getElementsByTagNameNS(S,name);require(refs.getLength()>0);refs.item(0).setTextContent("urn:samlscope:synthetic-wrong-context");event=new CaseEvent.InboundMessage(SecureXml.serialize(changed),new EvidenceRef("transcript",response.id()));
   }else if(mutation.equals("accept-unavailable")&&fixture.equals("unsatisfiable-class")) {
    var changed=SecureXml.parse(body);var root=changed.getDocumentElement();children(children(root,P,"Status").getFirst(),P,"StatusCode").getFirst().setAttribute("Value","urn:oasis:names:tc:SAML:2.0:status:Success");
    var baselineReq=SecureXml.parse(originals.get(requests.getFirst().id())).getDocumentElement();
    var baselineResponse=SecureXml.parse(originals.get(responses.get(baselineReq.getAttribute("ID")).id())).getDocumentElement();
    root.appendChild(changed.importNode(assertion(baselineResponse,key),true));
    event=new CaseEvent.InboundMessage(SecureXml.serialize(changed),new EvidenceRef("transcript",response.id()));
   }else if(mutation.equals("unsatisfiable-requester")&&fixture.equals("unsatisfiable-class")) {
    var changed=SecureXml.parse(body);children(children(changed.getDocumentElement(),P,"Status").getFirst(),P,"StatusCode").getFirst().setAttribute("Value","urn:oasis:names:tc:SAML:2.0:status:Requester");
    event=new CaseEvent.InboundMessage(SecureXml.serialize(changed),new EvidenceRef("transcript",response.id()));
   }

   if(i+1<requests.size())clock.at=Instant.parse(SecureXml.parse(originals.get(requests.get(i+1).id())).getDocumentElement().getAttribute("IssueInstant"));step=test.resume(context,awaiting.next(),event);if(step instanceof CaseStep.Finish f&&i+1<requests.size())return f.outcome();
  }require(step instanceof CaseStep.Finish);return ((CaseStep.Finish)step).outcome();
 }
 static List<Map<String,Object>> verified(String run,List<TranscriptEntry> entries,Map<String,byte[]> originals,Element target,Element sp,PrivateKey key)throws Exception {
  var seen=new HashSet<String>();for(var e:entries)require(run.equals(e.runId())&&seen.add(e.id())&&(e.decodedSamlRef()==null||("transcripts/"+run+"/"+e.id()+".saml.xml").equals(e.decodedSamlRef())));
  var requests=entries.stream().filter(e->e.direction()==Direction.OUTBOUND&&CASE.equals(e.samlSummary().get("scenario_case_id"))&&"AuthnRequest".equals(e.samlSummary().get("type"))).sorted(Comparator.comparing(TranscriptEntry::timestamp)).toList();require(requests.size()==4);
  var targetKeys=certificates(target,"IDPSSODescriptor");var spKeys=certificates(sp,"SPSSODescriptor");var result=new ArrayList<Map<String,Object>>();var fixtureNames=new HashSet<String>();
  for(var request:requests){var raw=originals.get(request.id());var req=SecureXml.parse(raw).getDocumentElement();require(P.equals(req.getNamespaceURI())&&"AuthnRequest".equals(req.getLocalName())&&req.getAttribute("ID").equals("_"+request.samlSummary().get("action_id"))&&fixtureNames.add(String.valueOf(request.samlSummary().get("fixture_id"))));
   require(children(req,S,"Issuer").size()==1&&children(req,S,"Issuer").getFirst().getTextContent().equals(sp.getAttribute("entityID")));require(children(target,MD,"IDPSSODescriptor").stream().flatMap(r->children(r,MD,"SingleSignOnService").stream()).anyMatch(e->req.getAttribute("Destination").equals(e.getAttribute("Location"))));
   require(spKeys.stream().anyMatch(c->"GET".equals(request.method())?new RedirectSignatureVerifier().isValidForMessage(request.rawQuery(),c,raw):"POST".equals(request.method())&&new XmlSignatureVerifier().hasValidEnvelopedSignature(req,c)));
   var matching=entries.stream().filter(e->e.direction()==Direction.INBOUND&&"Response".equals(e.samlSummary().get("type"))&&originals.containsKey(e.id())&&req.getAttribute("ID").equals(SecureXml.parse(originals.get(e.id())).getDocumentElement().getAttribute("InResponseTo"))).toList();require(matching.size()==1);var response=matching.getFirst();var reply=SecureXml.parse(originals.get(response.id())).getDocumentElement();
   require(P.equals(reply.getNamespaceURI())&&"Response".equals(reply.getLocalName())&&request.timestamp().isBefore(response.timestamp())&&req.getAttribute("AssertionConsumerServiceURL").equals(reply.getAttribute("Destination"))&&response.url().equals(reply.getAttribute("Destination"))&&children(reply,S,"Issuer").getFirst().getTextContent().equals(target.getAttribute("entityID")));
   require(children(children(sp,MD,"SPSSODescriptor").getFirst(),MD,"AssertionConsumerService").stream().anyMatch(a->a.getAttribute("Location").equals(reply.getAttribute("Destination"))));require(new VerifiedSignatureAlgorithms().read(reply,target.getAttribute("entityID"),targetKeys).stream().anyMatch(s->s.element().equals("Response"))&&Boolean.TRUE.equals(response.samlSummary().get("activeProbeAccepted")));
   String fixture=String.valueOf(request.samlSummary().get("fixture_id"));boolean success=!fixture.equals("unsatisfiable-class");String status=children(children(reply,P,"Status").getFirst(),P,"StatusCode").getFirst().getAttribute("Value");require(status.equals("urn:oasis:names:tc:SAML:2.0:status:"+(success?"Success":"Responder")));
   boolean assertionSigned=false; if(success){var a=assertion(reply,key);assertionSigned=targetKeys.stream().anyMatch(c->new XmlSignatureVerifier().hasValidEnvelopedSignature(a,c));require(children(a,S,"Issuer").size()==1&&children(a,S,"Issuer").getFirst().getTextContent().equals(target.getAttribute("entityID"))&&(children(a,DS,"Signature").isEmpty()||assertionSigned)&&a.getElementsByTagNameNS(S,"Audience").getLength()==1&&sp.getAttribute("entityID").equals(a.getElementsByTagNameNS(S,"Audience").item(0).getTextContent()));}
   else require(children(reply,S,"Assertion").isEmpty()&&children(reply,S,"EncryptedAssertion").isEmpty());
   result.add(Map.of("fixture",fixture,"request",request.id(),"response",response.id(),"requestSignatureVerified",true,"responseSignatureVerified",true,"assertionSignatureVerified",assertionSigned,"decryptionVerified",success));
  }require(fixtureNames.equals(Set.of("baseline","satisfiable-class","satisfiable-declaration","unsatisfiable-class")));return result;
 }
 public static void main(String[]args)throws Exception {
  require(args.length==2);JSON.mapper().enable(com.fasterxml.jackson.databind.SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);java.util.logging.Logger.getLogger("org.apache.xml.security.signature.XMLSignature").setLevel(java.util.logging.Level.SEVERE);var folder=Path.of(args[0]);var created=JSON.mapper().readTree(folder.resolve("created.json").toFile()).path("run");String run=created.path("id").asText(),plan=created.path("planId").asText();require(run.matches("run_[0-9A-HJKMNP-TV-Z]{26}")&&plan.matches("plan_[0-9A-HJKMNP-TV-Z]{26}"));var entries=List.of(JSON.mapper().readValue(folder.resolve("transcript.json").toFile(),TranscriptEntry[].class));var originals=new HashMap<String,byte[]>();for(var row:JSON.mapper().readTree(folder.resolve("decoded-manifest.json").toFile())){var raw=Files.readAllBytes(folder.resolve(row.path("file").asText()));require(hash(raw).equals(row.path("sha256").asText())&&originals.put(row.path("id").asText(),raw)==null);}
  var targetRaw=Files.readAllBytes(folder.resolve("target-metadata.xml"));var target=SecureXml.parse(targetRaw).getDocumentElement();var sp=SecureXml.parse(Files.readAllBytes(folder.resolve("suite-sp-metadata.xml"))).getDocumentElement();var keyRaw=Files.readAllBytes(Path.of("/data/keys/"+plan+"/signing-key.pk8"));PrivateKey key=KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(keyRaw));Arrays.fill(keyRaw,(byte)0);
  var exchanges=verified(run,entries,originals,target,sp,key);var requests=entries.stream().filter(e->e.direction()==Direction.OUTBOUND&&CASE.equals(e.samlSummary().get("scenario_case_id"))&&"AuthnRequest".equals(e.samlSummary().get("type"))).sorted(Comparator.comparing(TranscriptEntry::timestamp)).toList();var responses=new HashMap<String,TranscriptEntry>();for(var row:exchanges){var r=entries.stream().filter(e->e.id().equals(row.get("request"))).findFirst().orElseThrow();var response=entries.stream().filter(e->e.id().equals(row.get("response"))).findFirst().orElseThrow();responses.put(SecureXml.parse(originals.get(r.id())).getDocumentElement().getAttribute("ID"),response);}
  var actual=replay(run,requests,responses,originals,key,"none");require(actual.outcome()==Outcome.SATISFIED);var semantics=new TreeMap<String,String>();for(String mutation:List.of("missing-response","wrong-correlation","wrong-class","wrong-declaration","accept-unavailable","unsatisfiable-requester")){var outcome=replay(run,requests,responses,originals,key,mutation).outcome();require(outcome==(Set.of("wrong-class","wrong-declaration","accept-unavailable","unsatisfiable-requester").contains(mutation)?Outcome.VIOLATED:Outcome.NOT_VERIFIED));semantics.put(mutation,outcome.name());}
  var binding=new TreeMap<String,String>();for(String mutation:List.of("foreign-run","duplicate-entry","missing-response","tampered-request","tampered-response","wrong-decryption-key")){var selected=new ArrayList<>(entries);var bytes=new HashMap<>(originals);PrivateKey k=key;switch(mutation){case "foreign-run"->{var e=selected.getFirst();selected.set(0,new TranscriptEntry(e.id(),"run_00000000000000000000000000",e.direction(),e.timestamp(),e.correlationId(),e.method(),e.url(),e.status(),e.headers(),e.bodyRef(),e.bodyBytes(),e.decodedSamlRef(),e.decodedSamlBytes(),e.contentType(),e.rawQuery(),e.samlSummary()));}case "duplicate-entry"->selected.add(selected.getFirst());case "missing-response"->selected.removeIf(e->e.id().equals(exchanges.getFirst().get("response")));case "tampered-request","tampered-response"->{String id=String.valueOf(exchanges.getFirst().get(mutation.equals("tampered-request")?"request":"response"));var x=SecureXml.parse(bytes.get(id));x.getDocumentElement().setAttribute("ID","_tampered");bytes.put(id,SecureXml.serialize(x));}case "wrong-decryption-key"->k=KeyPairGenerator.getInstance("RSA").generateKeyPair().getPrivate();}boolean rejected=false;try{verified(run,selected,bytes,target,sp,k);}catch(Exception invalid){rejected=true;}require(rejected);binding.put(mutation,"NOT_VERIFIED");}
  var report=new TreeMap<String,Object>();report.put("runId",run);report.put("caseId",CASE);report.put("targetMetadataSha256",hash(targetRaw));report.put("outcome",actual);report.put("exchanges",exchanges);report.put("semanticControls",semantics);report.put("bindingControls",binding);report.put("productOperations",0);report.put("privateCredentialsPersisted",false);report.put("decryptedAssertionPersisted",false);JSON.mapper().writerWithDefaultPrettyPrinter().writeValue(Path.of(args[1]).toFile(),report);
 }
}
