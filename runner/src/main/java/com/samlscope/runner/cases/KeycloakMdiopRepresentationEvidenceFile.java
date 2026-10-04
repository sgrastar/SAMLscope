package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.normal.*;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.cert.*;
import java.time.Instant;
import java.util.*;
import org.w3c.dom.Element;

/** Native structural MDIOP admission only. Later key interpretation belongs to MD06.a. */
final class KeycloakMdiopRepresentationEvidenceFile {
 static final String ID="IIP-MD05-c-idp-01";
 static final List<String> REQUIRED=List.of("control","entity-root","entities-root-one","keyvalue-only","keyvalue-and-x509",
  "certificate-expired","certificate-not-yet-valid","certificate-empty-subject","certificate-unknown-ca","certificate-critical-extension",
  "certificate-noncritical-extension","certificate-no-digital-signature","certificate-unrelated-eku","key-use-omitted",
  "multiple-signing-keys-first","multiple-signing-keys","multiple-omitted-keys-first","multiple-omitted-keys-second","multiple-encryption-keys");
 private static final String MD="urn:oasis:names:tc:SAML:2.0:metadata",DS="http://www.w3.org/2000/09/xmldsig#",ADMIN="http://localhost:18180/admin/realms/samlscope";
 private static final ObjectMapper JSON=new ObjectMapper();
 private final Path directory;private final TranscriptContentReader content;
 KeycloakMdiopRepresentationEvidenceFile(Path directory,TranscriptContentReader content){this.directory=directory;this.content=content;}
 boolean exists(String run){return run.matches("run_[0-9A-HJKMNP-TV-Z]{26}")&&Files.isRegularFile(path(run));}
 private Path path(String run){return directory.resolve(run+".mdiop-representation.json");}
 private static void require(boolean value){if(!value)throw new IllegalArgumentException("native_admission_originals_invalid");}
 private static String sha(byte[] bytes)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));}
 private record Original(TranscriptEntry entry,JsonNode json){}
 private Original original(JsonNode ref,String run,String targetHash,Map<String,TranscriptEntry> entries,List<EvidenceRef> evidence)throws Exception{
  require(ref.isObject()&&ref.path("reference").asText().matches("tx_[0-9A-HJKMNP-TV-Z]{26}"));var e=entries.get(ref.path("reference").asText());require(e!=null&&e.direction()==Direction.INBOUND&&run.equals(e.runId()));
  var bytes=content.readDecodedSaml(e);require(bytes!=null&&bytes.length==e.decodedSamlBytes()&&sha(bytes).equals(ref.path("sha256").asText()));
  var json=JSON.readTree(bytes);require(run.equals(json.path("runId").asText())&&targetHash.equals(json.path("targetMetadataSha256").asText()));evidence.add(new EvidenceRef("transcript",e.id()));return new Original(e,json);
 }
 private static JsonNode nativeBody(JsonNode original,String method,String url)throws Exception{
  var nativeNode=original.path("native");require(method.equals(nativeNode.path("method").asText())&&url.equals(nativeNode.path("url").asText())&&nativeNode.path("status").isInt()&&nativeNode.path("status").asInt()==200);
  var bytes=Base64.getDecoder().decode(nativeNode.path("response_base64").asText());require(sha(bytes).equals(nativeNode.path("response_sha256").asText()));var value=JSON.readTree(bytes);
  require(!value.has("secret")&&!value.has("registrationAccessToken"));return value;
 }
 private static Element entity(Element root,String entityId){var all=new ArrayList<Element>();if(MD.equals(root.getNamespaceURI())&&"EntityDescriptor".equals(root.getLocalName()))all.add(root);
  var nested=root.getElementsByTagNameNS(MD,"EntityDescriptor");for(int i=0;i<nested.getLength();i++)all.add((Element)nested.item(i));var selected=all.stream().filter(e->e.getAttribute("entityID").equals(entityId)).toList();require(selected.size()==1);return selected.getFirst();}
 static void representation(String variant,Element root,String entityId,Instant observed)throws Exception{
  require(SamlSchemaValidation.isValid(root,SamlSchemaValidation.SchemaKind.METADATA));require(MD.equals(root.getNamespaceURI())&&Set.of("EntityDescriptor","EntitiesDescriptor").contains(root.getLocalName()));
  if(variant.equals("entities-root-one"))require(root.getLocalName().equals("EntitiesDescriptor"));else require(root.getLocalName().equals("EntityDescriptor"));
  var roles=MetadataAlgorithmEvidence.children(entity(root,entityId),MD,"SPSSODescriptor");require(roles.size()==1);var keys=MetadataAlgorithmEvidence.children(roles.getFirst(),MD,"KeyDescriptor");require(!keys.isEmpty());
  var certs=new ArrayList<X509Certificate>();var descriptorsWithValues=0;var values=new ArrayList<Element>();
  for(var key:keys){var infos=MetadataAlgorithmEvidence.children(key,DS,"KeyInfo");require(infos.size()==1);var xml=infos.getFirst();var raw=xml.getElementsByTagNameNS(DS,"X509Certificate");for(int i=0;i<raw.getLength();i++)certs.add((X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(Base64.getMimeDecoder().decode(raw.item(i).getTextContent()))));
   var keyValues=xml.getElementsByTagNameNS(DS,"RSAKeyValue");if(keyValues.getLength()>0)descriptorsWithValues++;for(int i=0;i<keyValues.getLength();i++)values.add((Element)keyValues.item(i));}
  if(variant.equals("keyvalue-only"))require(certs.isEmpty()&&descriptorsWithValues==1);
  else require(!certs.isEmpty());
  if(variant.equals("keyvalue-and-x509")){require(values.size()==1&&certs.size()==1);var rsa=(java.security.interfaces.RSAPublicKey)certs.getFirst().getPublicKey();var key=values.getFirst();require(rsa.getModulus().equals(new java.math.BigInteger(1,Base64.getMimeDecoder().decode(key.getElementsByTagNameNS(DS,"Modulus").item(0).getTextContent())))&&rsa.getPublicExponent().equals(new java.math.BigInteger(1,Base64.getMimeDecoder().decode(key.getElementsByTagNameNS(DS,"Exponent").item(0).getTextContent()))));}
  if(variant.startsWith("certificate-")){var c=certs.getFirst();switch(variant){case "certificate-expired"->require(c.getNotAfter().toInstant().isBefore(observed));case "certificate-not-yet-valid"->require(c.getNotBefore().toInstant().isAfter(observed));case "certificate-empty-subject"->require(c.getSubjectX500Principal().getName().isBlank());case "certificate-unknown-ca"->require(!c.getIssuerX500Principal().equals(c.getSubjectX500Principal()));case "certificate-critical-extension"->require(c.hasUnsupportedCriticalExtension());case "certificate-noncritical-extension"->require(c.getNonCriticalExtensionOIDs()!=null&&!c.getNonCriticalExtensionOIDs().isEmpty());case "certificate-no-digital-signature"->require(c.getKeyUsage()!=null&&!c.getKeyUsage()[0]);case "certificate-unrelated-eku"->require(c.getExtendedKeyUsage()!=null&&c.getExtendedKeyUsage().contains("1.3.6.1.5.5.7.3.3"));default->throw new IllegalArgumentException();}}
  if(variant.equals("key-use-omitted"))require(keys.stream().anyMatch(e->!e.hasAttribute("use")));
  if(variant.startsWith("multiple-signing-keys"))require(keys.stream().filter(e->e.getAttribute("use").equals("signing")).count()==2);
  if(variant.startsWith("multiple-omitted-keys"))require(keys.stream().filter(e->!e.hasAttribute("use")).count()==2);
  if(variant.equals("multiple-encryption-keys"))require(keys.stream().filter(e->e.getAttribute("use").equals("encryption")).count()==2&&certs.stream().map(c->Base64.getEncoder().encodeToString(c.getPublicKey().getEncoded())).distinct().count()==2);
  var signatures=MetadataAlgorithmEvidence.children(root,DS,"Signature");require(signatures.size()==1);var sig=signatures.getFirst().getElementsByTagNameNS(DS,"X509Certificate");require(sig.getLength()==1);var signer=(X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(Base64.getMimeDecoder().decode(sig.item(0).getTextContent())));require(new XmlSignatureVerifier().hasValidEnvelopedSignature(root,signer));
 }
 CaseOutcome evaluate(CaseContext context,byte[] target){var evidence=new ArrayList<EvidenceRef>();try{
  require(context.transcriptComplete()&&exists(context.runId()));var receipt=JSON.readTree(Files.readAllBytes(path(context.runId())));var targetHash=sha(target);var targetEntity=SecureXml.parse(target).getDocumentElement().getAttribute("entityID");
  require("http://localhost:18180/realms/samlscope".equals(targetEntity)&&receipt.path("schema").asText().equals("samlscope-keycloak-mdiop-representation-v1")&&receipt.path("adapter").asText().equals("keycloak-console-native-admission-v1")&&context.runId().equals(receipt.path("runId").asText())&&targetHash.equals(receipt.path("targetMetadataSha256").asText())&&targetEntity.equals(receipt.path("targetEntityId").asText())&&receipt.path("campaignId").asText().equals("metadata-fixture-refresh"));
  var entries=new HashMap<String,TranscriptEntry>();for(var e:context.transcript().list(context.runId()))require(context.runId().equals(e.runId())&&entries.put(e.id(),e)==null);
  var control=MetadataAlgorithmEvidence.collect(List.of("control"),context,content,target);require(control.issues().isEmpty()&&control.exchanges().size()==1);evidence.addAll(control.exchanges().getFirst().evidence());var peer=control.exchanges().getFirst().metadata().getAttribute("entityID");
  var members=receipt.path("members");require(members.isArray()&&members.size()==REQUIRED.size());var seen=new HashSet<String>();var clientIds=new HashSet<String>();Instant first=null,last=null;
  for(var member:members){var variant=member.path("variant").asText();require(REQUIRED.contains(variant)&&seen.add(variant));var prepared=entries.get(member.path("preparedReference").asText());require(prepared!=null&&prepared.direction()==Direction.OUTBOUND&&prepared.samlSummary().get("type").equals("MetadataPrepared")&&variant.equals(prepared.samlSummary().get("variant"))&&Integer.valueOf(200).equals(prepared.status()));
   var raw=content.readDecodedSaml(prepared);var hash=sha(raw);require(hash.equals(prepared.samlSummary().get("metadataSha256"))&&hash.equals(member.path("fixtureSha256").asText()));var fetch=entries.get(String.valueOf(prepared.samlSummary().get("fetchTranscriptId")));require(fetch!=null&&fetch.direction()==Direction.INBOUND&&"MetadataFetch".equals(fetch.samlSummary().get("type"))&&Integer.valueOf(200).equals(fetch.status())&&variant.equals(fetch.samlSummary().get("variant"))&&fetch.id().equals(prepared.correlationId())&&Objects.equals(fetch.url(),prepared.url())&&!prepared.timestamp().isBefore(fetch.timestamp()));representation(variant,SecureXml.parse(raw).getDocumentElement(),peer,prepared.timestamp());evidence.add(new EvidenceRef("transcript",prepared.id()));evidence.add(new EvidenceRef("transcript",fetch.id()));
   var converted=original(member.path("converter"),context.runId(),targetHash,entries,evidence);var persisted=original(member.path("persisted"),context.runId(),targetHash,entries,evidence);
   for(var node:List.of(converted,persisted))require(node.json().path("schema").asText().equals("samlscope-keycloak-mdiop-native-original-v1")&&node.json().path("phase").asText().equals("before-policy-change")&&hash.equals(node.json().path("fixtureSha256").asText())&&!node.entry().timestamp().isBefore(prepared.timestamp()));
   require(hash.equals(converted.json().path("native").path("request_sha256").asText())&&converted.json().path("native").path("request_matches_original_fixture").isBoolean()&&converted.json().path("native").path("request_matches_original_fixture").asBoolean());
   var converter=nativeBody(converted.json(),"POST",ADMIN+"/client-description-converter");var savedRaw=Base64.getDecoder().decode(persisted.json().path("native").path("response_base64").asText());var saved=JSON.readTree(savedRaw);var client=saved.path("id").asText();require(client.matches("[0-9a-f-]{36}")&&clientIds.add(client));nativeBody(persisted.json(),"GET",ADMIN+"/clients/"+client);
   require(peer.equals(converter.path("clientId").asText())&&peer.equals(saved.path("clientId").asText())&&"saml".equals(converter.path("protocol").asText())&&"saml".equals(saved.path("protocol").asText())&&saved.path("enabled").asBoolean());
   var attributes=converter.path("attributes");require(attributes.isObject()&&saved.path("attributes").isObject());var fields=attributes.fields();while(fields.hasNext()){var attr=fields.next();if(attr.getKey().startsWith("saml"))require(attr.getValue().equals(saved.path("attributes").get(attr.getKey())));}
   if(first==null||prepared.timestamp().isBefore(first))first=prepared.timestamp();if(last==null||persisted.entry().timestamp().isAfter(last))last=persisted.entry().timestamp();
  }
  require(seen.equals(new HashSet<>(REQUIRED)));var before=original(receipt.path("originalClients"),context.runId(),targetHash,entries,evidence);var after=original(receipt.path("restoredClients"),context.runId(),targetHash,entries,evidence);
  for(var state:List.of(before,after)){require(state.json().path("schema").asText().equals("samlscope-keycloak-mdiop-client-inventory-v1")&&peer.equals(state.json().path("peerEntityId").asText()));var inventory=nativeBody(state.json(),"GET",ADMIN+"/clients?clientId="+java.net.URLEncoder.encode(peer,java.nio.charset.StandardCharsets.UTF_8));require(inventory.isArray()&&inventory.isEmpty());}
  require(!before.entry().timestamp().isAfter(first)&&!after.entry().timestamp().isBefore(last));var runtimeBefore=original(receipt.path("runtimeBefore"),context.runId(),targetHash,entries,evidence);var runtimeAfter=original(receipt.path("runtimeAfter"),context.runId(),targetHash,entries,evidence);require(runtimeBefore.json().path("runtime").equals(runtimeAfter.json().path("runtime"))&&runtimeBefore.json().path("globalPolicy").equals(runtimeAfter.json().path("globalPolicy"))&&runtimeBefore.json().path("runtime").path("running").asBoolean()&&!runtimeBefore.entry().timestamp().isAfter(first)&&!runtimeAfter.entry().timestamp().isBefore(last));
  return new CaseOutcome(Outcome.SATISFIED,null,"metadata.mdiop.native-representation-admission-observed","metadata.mdiop.native-representation-admission-observed",evidence.stream().distinct().toList(),Map.of("native_admitted_variants",REQUIRED,"runtime_key_interpretation_proven",false,"product_policy_writes",0,"restoration_verified",true,"receipt_sha256",sha(Files.readAllBytes(path(context.runId())))));
 }catch(Exception unavailable){return new CaseOutcome(Outcome.NOT_VERIFIED,"native_mdiop_admission_incomplete","metadata.mdiop.native-representation-admission-incomplete","metadata.mdiop.native-representation-admission-incomplete",List.of(),Map.of("runtime_key_interpretation_proven",false));}}
}
