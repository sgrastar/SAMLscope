package com.samlscope.runner.cases;
import com.samlscope.store.JsonCodec;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.SecureXml;
import java.nio.file.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import org.w3c.dom.Element;

/** Public boolean diagnostic only. Decryption and identifier values stay inside the Suite JVM. */
public final class DiagnoseShibbolethRequestedSubject {
 static final String S="urn:oasis:names:tc:SAML:2.0:assertion",P="urn:oasis:names:tc:SAML:2.0:protocol";
 static Map<String,String> attributes(Element e){var result=new TreeMap<String,String>();var attrs=e.getAttributes();for(int i=0;i<attrs.getLength();i++){var a=attrs.item(i);if(!"http://www.w3.org/2000/xmlns/".equals(a.getNamespaceURI()))result.put(String.valueOf(a.getNamespaceURI())+"|"+a.getLocalName(),a.getNodeValue());}return result;}
 public static void main(String[]args)throws Exception {
  var json=new JsonCodec().mapper();var folder=Path.of(args[0]);var created=json.readTree(folder.resolve("created.json").toFile());var run=created.path("run").path("id").asText();var plan=created.path("run").path("planId").asText();
  if(!run.matches("run_[0-9A-HJKMNP-TV-Z]{26}")||!plan.matches("plan_[0-9A-HJKMNP-TV-Z]{26}"))throw new IllegalArgumentException("Unsafe diagnostic scope");
  var entries=List.of(json.readValue(folder.resolve("transcript.json").toFile(),TranscriptEntry[].class));var originals=new HashMap<String,byte[]>();
  for(var e:entries)if(e.decodedSamlRef()!=null){if(!run.equals(e.runId())||!("transcripts/"+run+"/"+e.id()+".saml.xml").equals(e.decodedSamlRef()))throw new IllegalArgumentException("Foreign original");originals.put(e.id(),Files.readAllBytes(Path.of("/data").resolve(e.decodedSamlRef())));}
  var target=SecureXml.parse(Files.readAllBytes(Path.of("/data/target-metadata/"+run+".xml"))).getDocumentElement();var trusted=MetadataAlgorithmEvidence.signingKeys(target);
  var sp=SecureXml.parse(Files.readAllBytes(folder.resolve("suite-sp-metadata.xml"))).getDocumentElement();var cert=VerifyShibbolethG02KnownSubject.certificates(sp,"SPSSODescriptor").getFirst();
  var raw=Files.readAllBytes(Path.of("/data/keys/"+plan+"/signing-key.pk8"));var key=KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(raw));Arrays.fill(raw,(byte)0);
  var proof=new ArrayList<Map<String,Object>>();
  for(var request:entries)if(request.direction()==Direction.OUTBOUND&&"IIP-G02-a-idp-01".equals(request.samlSummary().get("scenario_case_id"))&&Set.of("persistent-nameid-ascii-256","transient-nameid-ascii-256").contains(request.samlSummary().get("fixture_id"))) {
   var req=SecureXml.parse(originals.get(request.id())).getDocumentElement();var subjects=MetadataAlgorithmEvidence.children(req,S,"Subject");var requested=MetadataAlgorithmEvidence.children(subjects.getFirst(),S,"NameID").getFirst();
   var responses=entries.stream().filter(e->e.direction()==Direction.INBOUND&&req.getAttribute("ID").equals(e.correlationId())&&"Response".equals(e.samlSummary().get("type"))).toList();if(responses.size()!=1)throw new IllegalArgumentException("Ambiguous response");var response=responses.getFirst();
   var reply=SecureXml.parse(originals.get(response.id())).getDocumentElement();var assertion=VerifiedResponseAssertion.read(reply,target.getAttribute("entityID"),trusted,sp,Optional.of(new PlanCredentials(key,cert)),req.getAttribute("ID"),req.getAttribute("AssertionConsumerServiceURL"));
   var returned=MetadataAlgorithmEvidence.children(MetadataAlgorithmEvidence.children(assertion,S,"Subject").getFirst(),S,"NameID").getFirst();
   proof.add(Map.of("fixture",request.samlSummary().get("fixture_id"),"request",request.id(),"response",response.id(),"requestedFormat",requested.getAttribute("Format"),"returnedFormat",returned.getAttribute("Format"),"identifierStronglyMatches",requested.getTextContent().equals(returned.getTextContent())&&attributes(requested).equals(attributes(returned)),"NameIDPolicyAbsent",MetadataAlgorithmEvidence.children(req,P,"NameIDPolicy").isEmpty(),"signedDecryptedAssertionVerified",true));
  }
  json.writerWithDefaultPrettyPrinter().writeValue(Path.of(args[1]).toFile(),Map.of("runId",run,"observations",proof,"privateKeyPersisted",false,"decryptedIdentifierPersisted",false,"productOperations",0));
 }
}
