package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import com.samlscope.saml.normal.SecureXml;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.net.*;
import java.security.*;
import java.security.cert.*;
import java.time.Instant;
import java.util.*;
import java.util.function.Function;
import java.util.zip.ZipFile;
import org.w3c.dom.*;

/**
 * Stock 26.7.2 bearer factory in this Run's exact effective configuration only.
 * SamlProtocol builds one subject confirmation through SAML2LoginResponseBuilder /
 * SAML2Response. All installed mapper factories and the complete native classpath
 * are pinned; the three stock Response mappers only alter audience/AuthnContext.
 * Four ephemeral signed models calibrate the oracle; they are never product traffic
 * or product-signing evidence, and their signer must be disjoint from target keys.
 */
final class KeycloakSubjectConfirmationEvidence {
 static final String SCHEMA="samlscope-keycloak-subject-confirmation-v1",FR="IIP-SSO01-fr-idp-01",GD="IIP-SSO01-gd-idp-01";
 static final String REASON="browser.subject-confirmation.native-no-opportunity";
 private static final String TARGET="http://localhost:18180/realms/samlscope",ADMIN="http://localhost:18180/admin/realms/samlscope",S="urn:oasis:names:tc:SAML:2.0:assertion",P="urn:oasis:names:tc:SAML:2.0:protocol",DS="http://www.w3.org/2000/09/xmldsig#",BEARER="urn:oasis:names:tc:SAML:2.0:cm:bearer";
 private static final String IMAGE="sha256:9d1f1b2b7261ff53c66cb1092dfcdc34a5fb77e81f9e6a6e75b8b6a795de8067",INVENTORY="6c395042caae9cd300d9c0d989a58c5aaca4510dec2e1c1c9daeedfe3da5261e",PROCESS="75df757278ed67ca753b388fd3b6212db0dd085eee3cf75e6cd26dc4dbfe110d";
 private static final ObjectMapper JSON=new ObjectMapper();
 private static final Map<String,Set<String>> MAPPERS=Map.ofEntries(
  Map.entry("saml-user-attribute-nameid-mapper",Set.of("mapper.nameid.format","user.attribute")),Map.entry("saml-authn-context-class-ref-mapper",Set.of()),Map.entry("saml-audience-resolve-mapper",Set.of()),Map.entry("saml-organization-membership-mapper",Set.of()),Map.entry("saml-user-session-note-mapper",Set.of("note","friendly.name","attribute.name","attribute.nameformat")),Map.entry("saml-audience-mapper",Set.of("included.client.audience","included.custom.audience")),Map.entry("saml-group-membership-mapper",Set.of("attribute.name","friendly.name","attribute.nameformat","single","full.path")),Map.entry("saml-role-name-mapper",Set.of("role","new.role.name")),Map.entry("saml-user-property-mapper",Set.of("user.attribute","friendly.name","attribute.name","attribute.nameformat")),Map.entry("saml-role-list-mapper",Set.of("attribute.name","friendly.name","attribute.nameformat","single")),Map.entry("saml-hardcode-attribute-mapper",Set.of("friendly.name","attribute.name","attribute.nameformat","attribute.value")),Map.entry("saml-user-attribute-mapper",Set.of("user.attribute","friendly.name","attribute.name","attribute.nameformat","aggregate.attrs")),Map.entry("saml-organization-group-membership-mapper",Set.of("addGroupRoleMappings")),Map.entry("saml-hardcode-role-mapper",Set.of("role")));
 private final Path directory;
  private final TranscriptContentReader content;
  private final Function<String,String> profiles;
 KeycloakSubjectConfirmationEvidence(Path directory,TranscriptContentReader content,Function<String,String> profiles){this.directory=Objects.requireNonNull(directory).toAbsolutePath().normalize();
  this.content=Objects.requireNonNull(content);
  this.profiles=Objects.requireNonNull(profiles);
  }
 private Path receipt(String run){return directory.resolve(run+".keycloak-subject-confirmation.json");
  }
 boolean exists(String run){return run!=null&&run.matches("run_[0-9A-HJKMNP-TV-Z]{26}")&&(Files.exists(receipt(run),LinkOption.NOFOLLOW_LINKS)||Files.exists(directory.resolve(run+".keycloak-subject-confirmation"),LinkOption.NOFOLLOW_LINKS));
  }
 static void require(boolean value){if(!value)throw new IllegalArgumentException("Native subject confirmation original proof incomplete");
  }
 static String hash(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));
  }
 private static String text(JsonNode n,String field){var value=n.path(field);
  require(value.isTextual()&&!value.asText().isBlank());
  return value.asText();
  }
 private static Path safe(Path p)throws Exception{for(var x=p.toAbsolutePath().normalize();x!=null;x=x.getParent())require(!Files.isSymbolicLink(x));
  require(Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS));
  return p;
  }
 private byte[] original(Path folder,JsonNode files,String name)throws Exception{require(name.matches("[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*")&&Arrays.stream(name.split("/")).noneMatch(x->Set.of(".","..").contains(x)));
  var path=folder.resolve(name).normalize();
  require(path.startsWith(folder));
  var raw=Files.readAllBytes(safe(path));
  require(hash(raw).equals(text(files,name)));
  return raw;
  }
 JsonNode json(Path folder,JsonNode files,String name)throws Exception{return JSON.readTree(original(folder,files,name));
  }
 static JsonNode http(JsonNode row,String method,String url,int status)throws Exception{
  require(method.equals(text(row,"method"))&&url.equals(text(row,"url"))&&row.path("status").isInt()&&status==row.path("status").asInt());
  var raw=Base64.getDecoder().decode(text(row,"response_base64"));
  require(hash(raw).equals(text(row,"response_sha256")));
  return JSON.readTree(raw);
 }
 private static List<Element> children(Element root,String ns,String name){return MetadataAlgorithmEvidence.children(root,ns,name);
  }
 static boolean signed(Element e,List<X509Certificate> keys){var verifier=new XmlSignatureVerifier();
  return verifier.hasValidEnvelopedReferenceDigests(e)&&keys.stream().anyMatch(c->verifier.hasValidEnvelopedSignature(e,c));
  }
 static String issuer(Element e){var values=children(e,S,"Issuer");
  require(values.size()==1);
  return values.getFirst().getTextContent();
  }
 static Element verifyResponse(byte[] raw,List<X509Certificate> keys,String peer,String request,String recipient){var root=SecureXml.parse(raw).getDocumentElement();
  require(P.equals(root.getNamespaceURI())&&"Response".equals(root.getLocalName())&&request.equals(root.getAttribute("InResponseTo"))&&recipient.equals(root.getAttribute("Destination"))&&TARGET.equals(issuer(root))&&signed(root,keys));
  var statuses=children(root,P,"Status");
  require(statuses.size()==1);
  var codes=children(statuses.getFirst(),P,"StatusCode");
  require(codes.size()==1&&"urn:oasis:names:tc:SAML:2.0:status:Success".equals(codes.getFirst().getAttribute("Value")));
  var assertions=children(root,S,"Assertion");
  require(assertions.size()==1&&children(root,S,"EncryptedAssertion").isEmpty());
  var a=assertions.getFirst();
  require(TARGET.equals(issuer(a))&&signed(a,keys));
  var audiences=a.getElementsByTagNameNS(S,"Audience");
  require(audiences.getLength()==1&&peer.equals(audiences.item(0).getTextContent()));
  for(var subject:children(a,S,"Subject"))for(var sc:children(subject,S,"SubjectConfirmation")){var data=children(sc,S,"SubjectConfirmationData");
  require(data.size()==1&&request.equals(data.getFirst().getAttribute("InResponseTo"))&&recipient.equals(data.getFirst().getAttribute("Recipient")));
  }return root;
  }
 static String structure(Element e){if(DS.equals(e.getNamespaceURI())&&"Signature".equals(e.getLocalName())||S.equals(e.getNamespaceURI())&&"SubjectConfirmation".equals(e.getLocalName()))return "";
  var attrs=new TreeMap<String,String>();
  for(int i=0;i<e.getAttributes().getLength();i++){var a=e.getAttributes().item(i);
  if(!"http://www.w3.org/2000/xmlns/".equals(a.getNamespaceURI()))attrs.put("{"+a.getNamespaceURI()+"}"+(a.getLocalName()==null?a.getNodeName():a.getLocalName()),a.getNodeValue());
  }var parts=new ArrayList<String>();
  for(var n=e.getFirstChild();n!=null;n=n.getNextSibling())if(n instanceof Element c){var part=structure(c);
  if(!part.isEmpty())parts.add(part);
  }else if(n.getNodeType()==Node.TEXT_NODE&&!n.getNodeValue().isBlank())parts.add(n.getNodeValue());
  return "{"+e.getNamespaceURI()+"}"+e.getLocalName()+attrs+parts;
  }
 private static Element assertion(Element root){var values=children(root,S,"Assertion");
  require(values.size()==1);
  return values.getFirst();
  }
 private static TranscriptEntry entry(JsonNode receipt,String field,Map<String,TranscriptEntry> entries,String type,Direction direction){var e=entries.get(text(receipt,field));
  require(e!=null&&e.direction()==direction&&type.equals(e.samlSummary().get("type")));
  return e;
  }
 void validateEnvironment(Path folder,JsonNode files,String phase)throws Exception{var env=json(folder,files,"environment-"+phase+".json");
  require(IMAGE.equals(text(env.path("runtime"),"image"))&&env.path("runtime").path("running").asBoolean(false)&&text(env.path("runtime"),"version").startsWith("Keycloak 26.7.2\n")&&INVENTORY.equals(hash(original(folder,files,phase+".native-classpath.txt")))&&INVENTORY.equals(text(env,"nativeClasspathSha256"))&&PROCESS.equals(hash(JSON.writeValueAsBytes(env.path("publicProcessArguments"))))&&env.path("processRedactions").isEmpty());
  for(var mount:env.path("mounts"))require("/opt/keycloak/data/import/realm-samlscope.json".equals(text(mount,"destination"))&&!mount.path("rw").asBoolean(true));
  }
 void validateMapperFactories(Path folder,JsonNode files,String phase)throws Exception{var info=http(json(folder,files,"server-info-"+phase+".json"),"GET","http://localhost:18180/admin/serverinfo",200).path("protocolMapperTypes").path("saml");
  require(info.isArray()&&info.size()==MAPPERS.size());
  var seen=new HashSet<String>();
  for(var mapper:info){var id=text(mapper,"id");
  require(MAPPERS.containsKey(id)&&seen.add(id));
  var fields=new HashSet<String>();
  for(var property:mapper.path("properties"))require(fields.add(text(property,"name")));
  require(fields.equals(MAPPERS.get(id)));
  }}
 static boolean sensitive(JsonNode node){if(node.isObject()){var fields=node.fields();
  while(fields.hasNext()){var field=fields.next();
  if(field.getKey().matches("(?i).*(private|password|secret|credential|token).*")&&!(field.getKey().equals("client.secret.creation.time")&&field.getValue().isTextual()&&field.getValue().asText().matches("[0-9]+")))return true;
  if(sensitive(field.getValue()))return true;
  }}else if(node.isArray())for(var n:node)if(sensitive(n))return true;
  return false;
  }
 void validateScopes(Path folder,JsonNode files,String phase,String nativeId)throws Exception{
  var scopes=json(folder,files,"native-scopes-"+phase+".json");
  var direct=http(scopes.path("clientMappers"),"GET",ADMIN+"/clients/"+nativeId+"/protocol-mappers/models",200);
  require(direct.isArray()&&direct.isEmpty());
  for(String kind:List.of("default","optional")){var group=scopes.path(kind);
  var index=http(group.path("index"),"GET",ADMIN+"/clients/"+nativeId+"/"+kind+"-client-scopes",200);
  require(index.isArray()&&index.size()==group.path("members").size());
  var seen=new HashSet<String>();
  for(var member:group.path("members")){var scopeRow=member.path("scope");
  String url=text(scopeRow,"url");
  require(url.startsWith(ADMIN+"/client-scopes/"));
  String id=url.substring((ADMIN+"/client-scopes/").length());
  require(id.matches("[0-9a-f-]{36}")&&seen.add(id));
  var scope=http(scopeRow,"GET",url,200);
  require(id.equals(text(scope,"id"))&&"saml".equals(text(scope,"protocol")));
  require(java.util.stream.StreamSupport.stream(index.spliterator(),false).anyMatch(n->n.size()==2&&id.equals(n.path("id").asText())&&scope.path("name").equals(n.path("name"))));
  var mappers=http(member.path("mappers"),"GET",url+"/protocol-mappers/models",200);
  require(mappers.equals(scope.path("protocolMappers")));
  for(var mapper:mappers)require("saml".equals(text(mapper,"protocol"))&&MAPPERS.containsKey(text(mapper,"protocolMapper"))&&!sensitive(mapper));
  }if(kind.equals("optional"))require(index.isEmpty());
  }
 }
 static JsonNode scopeState(JsonNode node)throws Exception {if(node.isObject()&&node.has("response_base64"))return JSON.readTree(Base64.getDecoder().decode(text(node,"response_base64")));
  if(node.isObject()){var result=JSON.createObjectNode();
  var fields=node.fields();
  while(fields.hasNext()){var f=fields.next();
  result.set(f.getKey(),scopeState(f.getValue()));
  }return result;
  }if(node.isArray()){var result=JSON.createArrayNode();
  for(var n:node)result.add(scopeState(n));
  return result;
  }return node;
  }
 private static JsonNode attributes(JsonNode converter,JsonNode application,JsonNode saved)throws Exception{var original=converter.path("attributes");
  var applied=application.path("attributes");
  var actual=saved.path("attributes");
  require(original.isObject()&&applied.isObject()&&actual.isObject());
  var expected=original.deepCopy();
  ((com.fasterxml.jackson.databind.node.ObjectNode)expected).put("saml.encrypt","false");
  require(expected.equals(applied));
  var defaults=Map.of("saml.force.post.binding","true","realm_client","false","saml_force_name_id_format","false","saml_name_id_format","username","saml.allow.ecp.flow","false","saml_signature_canonicalization_method","http://www.w3.org/2001/10/xml-exc-c14n#");
  var fields=actual.fields();
  var seen=new HashSet<String>();
  while(fields.hasNext()){var f=fields.next();
  require(seen.add(f.getKey())&&f.getValue().isTextual());
  if(expected.has(f.getKey()))require(expected.get(f.getKey()).equals(f.getValue()));
  else if(defaults.containsKey(f.getKey()))require(defaults.get(f.getKey()).equals(f.getValue().asText()));
  else if(f.getKey().equals("client.secret.creation.time"))require(f.getValue().asText().matches("[0-9]+"));
  else if(f.getKey().equals("saml.artifact.binding.identifier"))require(Base64.getDecoder().decode(f.getValue().asText()).length==20);
  else require(false);
  }require(actual.size()==expected.size()+defaults.size()+2);
  for(String key:List.of("saml.client.signature","saml.server.signature","saml.assertion.signature"))require("true".equals(text(actual,key)));
  require("false".equals(text(actual,"saml.encrypt")));
  return actual;
  }
 private void nativeFactory(Path folder,JsonNode files,String peer,String request,String recipient)throws Exception{
  var pins=new LinkedHashMap<String,String>(KeycloakNativeSchemaAdmissionEvidence.NATIVE_JARS);
  pins.put("org.keycloak.keycloak-common-26.7.2.jar","35bc21c9d131ad43d29cf3b1a0cec60e67775b2bb239616b0b1022d9adef847b");
  var urls=new ArrayList<URL>();
  for(var pin:pins.entrySet()){byte[] raw=original(folder,files,"native-runtime/"+pin.getKey());
  require(hash(raw).equals(pin.getValue()));
  if(!pin.getKey().contains("services"))urls.add(folder.resolve("native-runtime/"+pin.getKey()).toUri().toURL());
  }
  try(var services=new ZipFile(folder.resolve("native-runtime/org.keycloak.keycloak-services-26.7.2.jar").toFile())){for(String path:List.of("org/keycloak/protocol/saml/SamlProtocol.class","org/keycloak/protocol/saml/SamlClient.class","org/keycloak/protocol/saml/mappers/SAMLAudienceProtocolMapper.class","org/keycloak/protocol/saml/mappers/SAMLAudienceResolveProtocolMapper.class","org/keycloak/protocol/saml/mappers/AuthnContextClassRefMapper.class","META-INF/services/org.keycloak.protocol.ProtocolMapper"))require(services.getEntry(path)!=null);
  }
  try(var loader=new URLClassLoader(urls.toArray(URL[]::new),ClassLoader.getPlatformClassLoader())){var cls=loader.loadClass("org.keycloak.saml.SAML2LoginResponseBuilder");
  var builder=cls.getConstructor().newInstance();
  for(var args:List.of(new String[]{"requestID",request},new String[]{"destination",recipient},new String[]{"issuer",TARGET},new String[]{"requestIssuer",peer}))cls.getMethod(args[0],String.class).invoke(builder,args[1]);
  cls.getMethod("nameIdentifier",String.class,String.class).invoke(builder,"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified","native-calibration-subject");
  var response=cls.getMethod("buildModel").invoke(builder);
  var assertions=(List<?>)response.getClass().getMethod("getAssertions").invoke(response);
  require(assertions.size()==1);
  var a=assertions.getFirst().getClass().getMethod("getAssertion").invoke(assertions.getFirst());
  var subject=a.getClass().getMethod("getSubject").invoke(a);
  var scs=(List<?>)subject.getClass().getMethod("getConfirmation").invoke(subject);
  require(scs.size()==1);
  var sc=scs.getFirst();
  require(BEARER.equals(sc.getClass().getMethod("getMethod").invoke(sc)));
  for(String method:List.of("getBaseID","getNameID","getEncryptedID"))require(sc.getClass().getMethod(method).invoke(sc)==null);
  }
 }
 Optional<CaseOutcome> evaluate(CaseContext context,String id,byte[] targetRaw){if(!Set.of(FR,GD).contains(id)||!exists(context.runId()))return Optional.empty();
  String stage="native_subject_confirmation_originals_unproven";
  try{
   require(context.targetRole()==com.samlscope.core.plan.TargetRole.IDP&&context.transcriptComplete()&&"browser_sso_idp".equals(profiles.apply(context.runId())));
  var receiptRaw=Files.readAllBytes(safe(receipt(context.runId())));
  var receipt=JSON.readTree(receiptRaw);
  require(SCHEMA.equals(text(receipt,"schema"))&&context.runId().equals(text(receipt,"runId"))&&"native-subject-confirmation".equals(text(receipt,"campaignId"))&&TARGET.equals(text(receipt,"targetEntityId"))&&hash(targetRaw).equals(text(receipt,"targetMetadataSha256")));
  var folder=directory.resolve(context.runId()+".keycloak-subject-confirmation");
  var files=receipt.path("files");
  require(files.isObject());
  var entries=new LinkedHashMap<String,TranscriptEntry>();
  for(var e:context.transcript().list(context.runId())){require(context.runId().equals(e.runId())&&entries.put(e.id(),e)==null);
  if(e.decodedSamlRef()!=null)require(("transcripts/"+context.runId()+"/"+e.id()+".saml.xml").equals(e.decodedSamlRef())&&content.readDecodedSaml(e)!=null&&content.readDecodedSaml(e).length==e.decodedSamlBytes());
  }require(entries.size()==5);
   var prepared=entry(receipt,"metadataReference",entries,"MetadataPrepared",Direction.OUTBOUND);
  var fetch=entry(receipt,"fetchReference",entries,"MetadataFetch",Direction.INBOUND);
  require(fetch.id().equals(prepared.samlSummary().get("fetchTranscriptId"))&&!prepared.timestamp().isBefore(fetch.timestamp())&&"control".equals(prepared.samlSummary().get("variant")));
  byte[] fixture=original(folder,files,"fixture.xml");
  require(Arrays.equals(fixture,content.readDecodedSaml(prepared))&&hash(fixture).equals(prepared.samlSummary().get("metadataSha256")));
  var peer=SecureXml.parse(fixture).getDocumentElement();
  String entity=peer.getAttribute("entityID");
  require(entity.equals(text(receipt,"peerEntityId")));
  var peerKeys=MetadataAlgorithmEvidence.signingKeys(peer);
  require(!peerKeys.isEmpty()&&signed(peer,peerKeys));
   var request=entry(receipt,"requestReference",entries,"AuthnRequest",Direction.OUTBOUND);
  var negative=entry(receipt,"negativeReference",entries,"AuthnRequest",Direction.OUTBOUND);
  var response=entry(receipt,"responseReference",entries,"Response",Direction.INBOUND);
  var req=SecureXml.parse(content.readDecodedSaml(request)).getDocumentElement();
  String requestId=req.getAttribute("ID"),recipient=req.getAttribute("AssertionConsumerServiceURL");
  require(!requestId.isBlank()&&!recipient.isBlank()&&entity.equals(issuer(req))&&TARGET.concat("/protocol/saml").equals(req.getAttribute("Destination"))&&signed(req,peerKeys)&&!negative.timestamp().isBefore(prepared.timestamp())&&!request.timestamp().isBefore(negative.timestamp())&&!response.timestamp().isBefore(request.timestamp()));
  var rejected=SecureXml.parse(content.readDecodedSaml(negative)).getDocumentElement();
  require(!rejected.getAttribute("ID").equals(requestId)&&entity.equals(issuer(rejected))&&new XmlSignatureVerifier().hasValidEnvelopedReferenceDigests(rejected)&&!signed(rejected,peerKeys));
  for(var e:entries.values())if(e.direction()==Direction.INBOUND&&"Response".equals(e.samlSummary().get("type")))require(!rejected.getAttribute("ID").equals(SecureXml.parse(content.readDecodedSaml(e)).getDocumentElement().getAttribute("InResponseTo")));
   var target=SecureXml.parse(targetRaw).getDocumentElement();
  require(TARGET.equals(target.getAttribute("entityID")));
  var targetKeys=MetadataAlgorithmEvidence.signingKeys(target);
  require(!targetKeys.isEmpty());
  byte[] actualRaw=content.readDecodedSaml(response);
  var actual=verifyResponse(actualRaw,targetKeys,entity,requestId,recipient);
  require(SimpleSamlPhpSubjectConfirmationEvidence.ordinaryBearer(assertion(actual)));
   stage="native_subject_confirmation_effective_factory_unproven";
  validateEnvironment(folder,files,"before");
  validateEnvironment(folder,files,"after");
  var before=json(folder,files,"environment-before.json");
  var after=json(folder,files,"environment-after.json");
  for(String field:List.of("runtime","mounts","publicProcessArguments","processRedactions","nativeClasspathSha256"))require(before.path(field).equals(after.path(field)));
  require(Instant.parse(text(before,"recordedAt")).isBefore(fetch.timestamp())&&Instant.parse(text(after,"recordedAt")).isAfter(response.timestamp()));
  validateMapperFactories(folder,files,"before");
  validateMapperFactories(folder,files,"after");
  String lookup=ADMIN+"/clients?clientId="+java.net.URLEncoder.encode(entity,StandardCharsets.UTF_8);
  for(String phase:List.of("before","after")){var inventory=http(json(folder,files,"client-inventory-"+phase+".json"),"GET",lookup,200);
  require(inventory.isArray()&&inventory.isEmpty());
  var policies=json(folder,files,"global-policy-"+phase+".json");
  for(String kind:List.of("policies","profiles")){var policy=http(policies.path(kind),"GET",ADMIN+"/client-policies/"+kind,200);
  require(policy.size()==1&&policy.path(kind).isArray()&&policy.path(kind).isEmpty());
  }}
   var converterRow=json(folder,files,"native-converter.json");
  var converter=http(converterRow,"POST",ADMIN+"/client-description-converter",200);
  require(Arrays.equals(fixture,Base64.getDecoder().decode(text(converterRow,"request_base64")))&&hash(fixture).equals(text(converterRow,"request_sha256"))&&entity.equals(text(converter,"clientId"))&&"saml".equals(text(converter,"protocol")));
  var application=json(folder,files,"native-client-application.json");
  require("saml.encrypt=false".equals(text(application,"only_native_override")));
  var app=application.path("native");
  require("POST".equals(text(app,"method"))&&(ADMIN+"/clients").equals(text(app,"url"))&&app.path("status").asInt()==201);
  var applied=JSON.readTree(Base64.getDecoder().decode(text(app,"request_base64")));
  require(hash(Base64.getDecoder().decode(text(app,"request_base64"))).equals(text(app,"request_sha256"))&&entity.equals(text(applied,"clientId"))&&"saml".equals(text(applied,"protocol")));
   var clientBeforeRow=json(folder,files,"native-client-before.json");
  String clientUrl=text(clientBeforeRow,"url");
  require(clientUrl.matches(java.util.regex.Pattern.quote(ADMIN)+"/clients/[0-9a-f-]{36}"));
  String nativeId=clientUrl.substring((ADMIN+"/clients/").length());
  var clientBefore=http(clientBeforeRow,"GET",clientUrl,200);
  var clientAfterRow=json(folder,files,"native-client-after.json");
  var clientAfter=http(clientAfterRow,"GET",clientUrl,200);
  require(clientBefore.equals(clientAfter)&&entity.equals(text(clientBefore,"clientId"))&&"saml".equals(text(clientBefore,"protocol"))&&nativeId.equals(text(clientBefore,"id"))&&clientBefore.path("enabled").asBoolean(false)&&!sensitive(clientBefore)&&clientBefore.path("authenticationFlowBindingOverrides").isEmpty());
  for(var clientRow:List.of(clientBeforeRow,clientAfterRow)){require("native-client-public-readback-v1".equals(text(clientRow,"response_projection"))&&clientRow.path("redactions").isArray());
  var seen=new HashSet<String>();
  for(var removed:clientRow.path("redactions"))require(Set.of("$.secret","$.registrationAccessToken").contains(removed.asText())&&seen.add(removed.asText()));
  }attributes(converter,applied,clientBefore);
  validateScopes(folder,files,"before",nativeId);
  validateScopes(folder,files,"after",nativeId);
  require(scopeState(json(folder,files,"native-scopes-before.json")).equals(scopeState(json(folder,files,"native-scopes-after.json"))));
  require(Instant.parse(text(clientBeforeRow,"recordedAt")).isBefore(negative.timestamp())&&Instant.parse(text(clientAfterRow,"recordedAt")).isAfter(response.timestamp()));
  var removal=json(folder,files,"native-client-removal.json");
  require(removal.path("status").asInt()==204&&clientUrl.equals(text(removal,"url"))&&"DELETE".equals(text(removal,"method")));
  var restoration=json(folder,files,"restoration.json");
  require(restoration.path("restored").asBoolean(false)&&restoration.path("originally_absent").asBoolean(false)&&restoration.path("client_removed").asBoolean(false)&&restoration.path("remaining_clients").isEmpty()&&restoration.path("recovery_failures").asInt(-1)==0);
  nativeFactory(folder,files,entity,requestId,recipient);
   stage="native_subject_confirmation_calibration_unproven";
  require("d2e30186186c5b3e2685efadd9899f366eca44f1b9da72e5dafb939c754dde31".equals(hash(original(folder,files,"ProduceKeycloakSubjectConfirmationControls.java"))));
  var calibration=json(folder,files,"calibration/calibration.json");
  require("oracle-calibration-only".equals(text(calibration,"purpose"))&&!calibration.path("nativePrivateKeyRead").asBoolean(true)&&!calibration.path("ephemeralPrivateKeyPersisted").asBoolean(true)&&calibration.path("productNetworkOperations").asInt(-1)==0&&calibration.path("targetTrustChanges").asInt(-1)==0&&hash(actualRaw).equals(text(calibration,"baseResponseSha256")));
  var controlKey=(X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(original(folder,files,"calibration/control-signer.der")));
  require(targetKeys.stream().noneMatch(k->Arrays.equals(k.getPublicKey().getEncoded(),controlKey.getPublicKey().getEncoded())));
  var attesters=List.of("urn:samlscope:attester-control:one","urn:samlscope:attester-control:two");
  require(calibration.path("attesters").equals(JSON.valueToTree(attesters)));
  for(String kind:List.of("foreign-positive","foreign-missing-identifier","multiple-positive","multiple-packed-identifiers")){var controlled=verifyResponse(original(folder,files,"calibration/"+kind+".xml"),List.of(controlKey),entity,requestId,recipient);
  require(structure(actual).equals(structure(controlled)));
  var permitted=kind.startsWith("foreign")?attesters.subList(0,1):attesters;
  require(SimpleSamlPhpSubjectConfirmationEvidence.identifiesSeparateAttesters(assertion(controlled),permitted)==kind.endsWith("positive")&&calibration.path("expected").path(kind).isBoolean()&&calibration.path("expected").path(kind).asBoolean()==kind.endsWith("positive"));
  }
   var refs=new ArrayList<EvidenceRef>();
  for(var e:entries.values())refs.add(new EvidenceRef("transcript",e.id()));
  refs.add(new EvidenceRef("native-keycloak-subject-confirmation",context.runId()+".keycloak-subject-confirmation.json#"+hash(receiptRaw)));
  var details=new LinkedHashMap<String,Object>();
  details.put("product","keycloak");
  details.put("evidence_adapter",SCHEMA);
  details.put("case_id",id);
  details.put("run_id",context.runId());
  details.put("subject_confirmation_count",1);
  details.put("attester_identifier_count",0);
  details.put("no_observation_opportunity",true);
  details.put("scope","this-run-stock-native-bearer-factory-installed-mappers-and-effective-client");
  details.put("custom_provider_capability_asserted",false);
  details.put("oracle_calibration_controls",4);
  details.put("calibration_product_evidence",false);
  return Optional.of(new CaseOutcome(Outcome.SATISFIED_WITH_NOTE,null,REASON,"Stock native bearer factory and all installed mapper/config paths admit only the ordinary subject attester in this Run.",refs,details));
  }catch(Exception unproven){if(Boolean.getBoolean("samlscope.keycloakSubjectConfirmation.debug"))unproven.printStackTrace();
  return Optional.of(CaseOutcome.notVerified(stage,"browser.subject-confirmation.native-unproven"));
  }
 }
}
