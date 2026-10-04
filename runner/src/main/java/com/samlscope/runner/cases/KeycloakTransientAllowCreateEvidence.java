package com.samlscope.runner.cases;

import static com.samlscope.runner.cases.KeycloakSubjectConfirmationEvidence.*;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import com.samlscope.saml.normal.SecureXml;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import java.util.function.Function;
import java.net.*;
import java.lang.reflect.Proxy;
import org.w3c.dom.*;

/** Fixed stock-native transient path; ordinary authentication/logout session state may exist. */
final class KeycloakTransientAllowCreateEvidence {
    static final String CASE="IIP-SSO01-fp-idp-01", SCHEMA="samlscope-keycloak-transient-allow-create-v1";
    static final List<String> KEYS=SimpleSamlPhpTransientAllowCreateEvidence.KEYS;
    private static final String TARGET="http://localhost:18180/realms/samlscope", ADMIN="http://localhost:18180/admin/realms/samlscope";
    private static final String S="urn:oasis:names:tc:SAML:2.0:assertion", P="urn:oasis:names:tc:SAML:2.0:protocol", DS="http://www.w3.org/2000/09/xmldsig#";
    private static final String TRANSIENT="urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
    private static final ObjectMapper JSON=new ObjectMapper();
    private static final Map<String,String> EXTRA_JARS=Map.ofEntries(
        Map.entry("org.keycloak.keycloak-core-26.7.2.jar","7486c2cd0bc59a6beb85dfb2f7e9b36659a50f15853e25162637ffcab2570d53"),
        Map.entry("org.keycloak.keycloak-common-26.7.2.jar","35bc21c9d131ad43d29cf3b1a0cec60e67775b2bb239616b0b1022d9adef847b"),
        Map.entry("org.keycloak.keycloak-server-spi-26.7.2.jar","04142eb6f4f2195a23ebbf785aaf8c05bcf308fa5dc6ad33b5326711b2ee536d"),
        Map.entry("org.keycloak.keycloak-server-spi-private-26.7.2.jar","a9541ffb99d572a487afdbd0ce112f3038f8d58119857219306e14d3af400afa"),
        Map.entry("jakarta.ws.rs.jakarta.ws.rs-api-3.1.0.jar","6b3b3628b8b4aedda0d24c3354335e985497d8ef3c510b8f3028e920d5b8663d"),
        Map.entry("jakarta.xml.soap.jakarta.xml.soap-api-3.0.0.jar","33124e98d724b69e1673a61675c205b58c372605f4254d455b12b37398219a37"),
        Map.entry("org.apache.httpcomponents.httpclient-4.5.14.jar","c8bc7e1c51a6d4ce72f40d2ebbabf1c4b68bfe76e732104b04381b493478e9d6"),
        Map.entry("org.apache.httpcomponents.httpcore-4.4.16.jar","6c9b3dd142a09dc468e23ad39aad6f75a0f2b85125104469f026e52a474e464f"));
    private final Path directory;
    private final TranscriptContentReader content;
    private final Function<String,byte[]> metadata;
    private final KeycloakSubjectConfirmationEvidence stock;
    KeycloakTransientAllowCreateEvidence(Path directory, TranscriptContentReader content, Function<String,byte[]> metadata) {
        this.directory=Objects.requireNonNull(directory).toAbsolutePath().normalize();this.content=Objects.requireNonNull(content);
        this.metadata=Objects.requireNonNull(metadata);this.stock=new KeycloakSubjectConfirmationEvidence(directory,content,r->"browser_sso_idp");
    }
    private Path receipt(String run){return directory.resolve(run+".keycloak-transient-allow-create.json");}
    boolean exists(String run){return run!=null&&run.matches("run_[0-9A-HJKMNP-TV-Z]{26}")&&(Files.exists(receipt(run),LinkOption.NOFOLLOW_LINKS)||Files.exists(directory.resolve(run+".keycloak-transient-allow-create"),LinkOption.NOFOLLOW_LINKS));}
    private static String text(JsonNode value,String field){require(value.path(field).isTextual()&&!value.path(field).asText().isBlank());return value.path(field).asText();}
    private static byte[] raw(Path path)throws Exception{for(Path p=path.toAbsolutePath().normalize();p!=null;p=p.getParent())require(!Files.isSymbolicLink(p));require(Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS));return Files.readAllBytes(path);}
    private byte[] original(Path folder,JsonNode files,String name)throws Exception{require(name.matches("[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*")&&Arrays.stream(name.split("/")).noneMatch(s->Set.of(".","..").contains(s)));var path=folder.resolve(name).normalize();require(path.startsWith(folder));var bytes=raw(path);require(hash(bytes).equals(text(files,name)));return bytes;}
    private JsonNode json(Path folder,JsonNode files,String name)throws Exception{return JSON.readTree(original(folder,files,name));}
    private static List<Element> children(Element root,String ns,String name){return MetadataAlgorithmEvidence.children(root,ns,name);}
    private static Element one(Element root,String ns,String name){var result=children(root,ns,name);require(result.size()==1);return result.getFirst();}
    private byte[] body(TranscriptEntry entry)throws Exception{require(entry!=null&&entry.decodedSamlRef()!=null&&("transcripts/"+entry.runId()+"/"+entry.id()+".saml.xml").equals(entry.decodedSamlRef()));var raw=content.readDecodedSaml(entry);require(raw!=null&&raw.length==entry.decodedSamlBytes());return raw;}
    private static String requestShape(Element request){var copy=(Element)request.cloneNode(true);copy.removeAttribute("ID");copy.removeAttribute("IssueInstant");for(var e:children(copy,DS,"Signature"))copy.removeChild(e);for(var e:children(copy,P,"NameIDPolicy"))copy.removeChild(e);return KeycloakSubjectConfirmationEvidence.structure(copy);}
    private static JsonNode apply(JsonNode record,String method,String path)throws Exception{require(method.equals(text(record,"method"))&&path.equals(text(record,"url"))&&record.path("status").asInt()==(method.equals("POST")?201:204));var bytes=Base64.getDecoder().decode(text(record,"request_base64"));require(hash(bytes).equals(text(record,"request_sha256")));var value=JSON.readTree(bytes);require(!sensitive(value));return value;}
    private static void attributes(JsonNode converter,JsonNode applied,JsonNode saved)throws Exception{
        var expected=converter.path("attributes").deepCopy();require(expected.isObject());((com.fasterxml.jackson.databind.node.ObjectNode)expected).put("saml.encrypt","false").put("saml_name_id_format","transient");
        require(expected.equals(applied.path("attributes")));var expectedModel=converter.deepCopy();((com.fasterxml.jackson.databind.node.ObjectNode)expectedModel).set("attributes",expected);require(expectedModel.equals(applied));var actual=saved.path("attributes");require(actual.isObject());
        var defaults=Map.of("saml.force.post.binding","true","realm_client","false","saml_force_name_id_format","false","saml.allow.ecp.flow","false","saml_signature_canonicalization_method","http://www.w3.org/2001/10/xml-exc-c14n#");
        var it=actual.fields();while(it.hasNext()){var f=it.next();require(f.getValue().isTextual());if(expected.has(f.getKey()))require(expected.get(f.getKey()).equals(f.getValue()));else if(defaults.containsKey(f.getKey()))require(defaults.get(f.getKey()).equals(f.getValue().asText()));else if(f.getKey().equals("client.secret.creation.time"))require(f.getValue().asText().matches("[0-9]+"));else if(f.getKey().equals("saml.artifact.binding.identifier"))require(Base64.getDecoder().decode(f.getValue().asText()).length==20);else require(false);}
        require(actual.size()==expected.size()+defaults.size()+2);for(String key:List.of("saml.client.signature","saml.server.signature","saml.assertion.signature"))require("true".equals(text(actual,key)));
    }
    private static JsonNode client(JsonNode row,String url,String peer,String nativeId)throws Exception{
        require("native-client-public-readback-v1".equals(text(row,"response_projection")));var removed=new HashSet<String>();for(var value:row.path("redactions"))require(Set.of("$.secret","$.registrationAccessToken").contains(value.asText())&&removed.add(value.asText()));
        var value=http(row,"GET",url,200);require(!sensitive(value)&&nativeId.equals(text(value,"id"))&&peer.equals(text(value,"clientId"))&&"saml".equals(text(value,"protocol"))&&value.path("enabled").asBoolean(false)&&value.path("authenticationFlowBindingOverrides").isEmpty());return value;
    }
    private static JsonNode principal(JsonNode row,String uid,String username)throws Exception{
        var userRecord=row.path("user");require("native-user-association-input-public-readback-v1".equals(text(userRecord,"response_projection")));
        var user=http(userRecord,"GET",ADMIN+"/users/"+uid,200);require(uid.equals(text(user,"id"))&&username.equals(text(user,"username"))&&user.size()==(user.has("attributes")?3:2)&&!sensitive(user));
        require(http(row.path("federatedIdentities"),"GET",ADMIN+"/users/"+uid+"/federated-identity",200).isEmpty());return user;
    }
    private static JsonNode session(JsonNode row,String uid,String username,String nativeId,String peer)throws Exception{
        var values=http(row.path("sessions"),"GET",ADMIN+"/users/"+uid+"/sessions",200);var found=new ArrayList<JsonNode>();for(var value:values){require(!sensitive(value));if(value.path("clients").path(nativeId).asText().equals(peer))found.add(value);}
        require(found.size()==1&&uid.equals(text(found.getFirst(),"userId"))&&username.equals(text(found.getFirst(),"username")));return found.getFirst();
    }
    private static Instant recorded(JsonNode record){return Instant.parse(text(record,"recordedAt"));}
    /** Executes the pinned generator with null state models and the exact native session-index formatter. */
    private String nativePath(Path folder,JsonNode files,String sessionId,String nativeId)throws Exception{
        var pins=new LinkedHashMap<String,String>(KeycloakNativeSchemaAdmissionEvidence.NATIVE_JARS);pins.putAll(EXTRA_JARS);var urls=new ArrayList<URL>();
        for(var pin:pins.entrySet()){require(pin.getValue().equals(hash(original(folder,files,"native-runtime/"+pin.getKey()))));urls.add(folder.resolve("native-runtime/"+pin.getKey()).toUri().toURL());}
        try(var loader=new URLClassLoader(urls.toArray(URL[]::new),ClassLoader.getPlatformClassLoader())){
            var type=loader.loadClass("org.keycloak.protocol.saml.SamlProtocol");var instance=type.getConstructor().newInstance();var userType=loader.loadClass("org.keycloak.models.UserSessionModel");var commonType=loader.loadClass("org.keycloak.sessions.CommonClientSessionModel");
            var generator=type.getDeclaredMethod("getNameId",String.class,commonType,userType);generator.setAccessible(true);var value=generator.invoke(instance,TRANSIENT,null,null);require(value instanceof String&&!((String)value).isBlank());
            var chain=type.getDeclaredMethod("getSAMLNameId",List.class,String.class,loader.loadClass("org.keycloak.models.KeycloakSession"),userType,loader.loadClass("org.keycloak.models.AuthenticatedClientSessionModel"));chain.setAccessible(true);var again=chain.invoke(instance,List.of(),TRANSIENT,null,null,null);require(again instanceof String&&!((String)again).isBlank());
            var user=Proxy.newProxyInstance(loader,new Class<?>[]{userType},(p,m,a)->{require(m.getName().equals("getId"));return sessionId;});var clientType=loader.loadClass("org.keycloak.models.ClientModel");var client=Proxy.newProxyInstance(loader,new Class<?>[]{clientType},(p,m,a)->{require(m.getName().equals("getId"));return nativeId;});var authenticatedType=loader.loadClass("org.keycloak.models.AuthenticatedClientSessionModel");
            var authenticated=Proxy.newProxyInstance(loader,new Class<?>[]{authenticatedType},(p,m,a)->switch(m.getName()){case "getUserSession"->user;case "getClient"->client;default->throw new IllegalArgumentException();});
            return (String)loader.loadClass("org.keycloak.protocol.saml.SamlSessionUtils").getMethod("getSessionIndex",authenticatedType).invoke(null,authenticated);
        }
    }
    Optional<CaseOutcome> evaluate(CaseContext context){if(!exists(context.runId()))return Optional.empty();String stage="native_transient_originals_unproven";
        try {
            require(context.targetRole()==com.samlscope.core.plan.TargetRole.IDP&&context.transcriptComplete());var receiptRaw=raw(receipt(context.runId()));var receipt=JSON.readTree(receiptRaw);byte[] targetRaw=metadata.apply(context.runId());
            require(SCHEMA.equals(text(receipt,"schema"))&&context.runId().equals(text(receipt,"runId"))&&"native-transient-allow-create".equals(text(receipt,"campaignId"))&&TARGET.equals(text(receipt,"targetEntityId"))&&hash(targetRaw).equals(text(receipt,"targetMetadataSha256")));
            var folder=directory.resolve(context.runId()+".keycloak-transient-allow-create");var files=receipt.path("files");require(files.isObject());var history=new LinkedHashMap<String,TranscriptEntry>();for(var e:context.transcript().list(context.runId())){require(context.runId().equals(e.runId())&&history.put(e.id(),e)==null);if(e.decodedSamlRef()!=null)body(e);}
            var created=json(folder,files,"created.json").path("run");var plan=json(folder,files,"plan.json").at("/plan/plan");String peer="http://localhost:18080/p/"+text(created,"planId");require(context.runId().equals(text(created,"id"))&&"browser_sso_idp".equals(text(plan,"profile"))&&peer.equals(text(receipt,"peerEntityId")));
            for(String phase:List.of("before","after")){stock.validateEnvironment(folder,files,phase);stock.validateMapperFactories(folder,files,phase);var inventory=http(json(folder,files,"client-inventory-"+phase+".json"),"GET",ADMIN+"/clients?clientId="+java.net.URLEncoder.encode(peer,java.nio.charset.StandardCharsets.UTF_8),200);require(inventory.isEmpty());for(String kind:List.of("policies","profiles")){var policy=http(json(folder,files,"global-policy-"+phase+".json").path(kind),"GET",ADMIN+"/client-policies/"+kind,200);require(policy.size()==1&&policy.path(kind).isEmpty());}}
            var scopeBefore=json(folder,files,"environment-before.json");var scopeAfter=json(folder,files,"environment-after.json");for(String field:List.of("runtime","mounts","publicProcessArguments","processRedactions","nativeClasspathSha256"))require(scopeBefore.path(field).equals(scopeAfter.path(field)));
            var restoration=json(folder,files,"restoration.json");require(restoration.path("restored").asBoolean(false)&&restoration.path("originally_absent").asBoolean(false)&&restoration.path("client_removed").asBoolean(false)&&restoration.path("remaining_clients").isEmpty());
            byte[] controlRaw=original(folder,files,"fixture.xml");var control=SecureXml.parse(controlRaw).getDocumentElement();require(peer.equals(control.getAttribute("entityID")));var controlKeys=MetadataAlgorithmEvidence.signingKeys(control);require(signed(control,controlKeys));
            var prepared=history.get(text(receipt,"metadataReference"));require(prepared!=null&&"MetadataPrepared".equals(prepared.samlSummary().get("type"))&&"control".equals(prepared.samlSummary().get("variant"))&&Arrays.equals(body(prepared),controlRaw));
            var normal=history.get(text(receipt,"controlRequestReference"));var negative=history.get(text(receipt,"negativeReference"));var normalResponse=history.get(text(receipt,"controlResponseReference"));var request=SecureXml.parse(body(normal)).getDocumentElement();var rejected=SecureXml.parse(body(negative)).getDocumentElement();
            require(normal.direction()==Direction.OUTBOUND&&negative.direction()==Direction.OUTBOUND&&normalResponse.direction()==Direction.INBOUND&&"AuthnRequest".equals(normal.samlSummary().get("type"))&&"AuthnRequest".equals(negative.samlSummary().get("type"))&&"Response".equals(normalResponse.samlSummary().get("type")));
            require(peer.equals(issuer(request))&&peer.equals(issuer(rejected))&&TARGET.concat("/protocol/saml").equals(request.getAttribute("Destination"))&&request.getAttribute("Destination").equals(rejected.getAttribute("Destination"))&&requestShape(request).equals(requestShape(rejected))&&signed(request,controlKeys)&&new XmlSignatureVerifier().hasValidEnvelopedReferenceDigests(rejected)&&!signed(rejected,controlKeys)&&!request.getAttribute("ID").equals(rejected.getAttribute("ID"))&&!negative.timestamp().isBefore(prepared.timestamp())&&!normal.timestamp().isBefore(negative.timestamp())&&!normalResponse.timestamp().isBefore(normal.timestamp()));
            var targetKeys=MetadataAlgorithmEvidence.signingKeys(SecureXml.parse(targetRaw).getDocumentElement());verifyResponse(body(normalResponse),targetKeys,peer,request.getAttribute("ID"),request.getAttribute("AssertionConsumerServiceURL"));
            for(var e:history.values())if(e.direction()==Direction.INBOUND&&"Response".equals(e.samlSummary().get("type")))require(!rejected.getAttribute("ID").equals(SecureXml.parse(body(e)).getDocumentElement().getAttribute("InResponseTo")));
            String nativeId=text(receipt,"nativeClientId"),clientUrl=ADMIN+"/clients/"+nativeId;require(nativeId.matches("[0-9a-f-]{36}"));
            var converted=http(json(folder,files,"native-converter.json"),"POST",ADMIN+"/client-description-converter",200);var application=json(folder,files,"native-client-application.json");var applied=apply(application.path("native"),"POST",ADMIN+"/clients");require(application.path("only_native_overrides").equals(JSON.valueToTree(List.of("saml.encrypt=false","saml_name_id_format=transient"))));
            require(Arrays.equals(controlRaw,Base64.getDecoder().decode(text(json(folder,files,"native-converter.json"),"request_base64"))));var controlClient=client(json(folder,files,"native-client-before.json"),clientUrl,peer,nativeId);attributes(converted,applied,controlClient);require(controlClient.equals(client(json(folder,files,"control-client-after.json"),clientUrl,peer,nativeId)));
            byte[] matrixRaw=original(folder,files,"suite-sp-metadata.xml");var matrixMetadata=SecureXml.parse(matrixRaw).getDocumentElement();require(peer.equals(matrixMetadata.getAttribute("entityID")));var matrixKeys=MetadataAlgorithmEvidence.signingKeys(matrixMetadata);require(signed(matrixMetadata,matrixKeys));
            var matrixConversion=json(folder,files,"native-matrix-converter.json");require(Arrays.equals(matrixRaw,Base64.getDecoder().decode(text(matrixConversion,"request_base64")))&&hash(matrixRaw).equals(text(matrixConversion,"request_sha256")));
            var matrixConverted=http(matrixConversion,"POST",ADMIN+"/client-description-converter",200);var matrixApplied=apply(json(folder,files,"native-matrix-application.json"),"PUT",clientUrl);var matrixClient=client(json(folder,files,"native-matrix-client-before.json"),clientUrl,peer,nativeId);attributes(matrixConverted,matrixApplied,matrixClient);require(matrixClient.equals(client(json(folder,files,"native-matrix-client-after.json"),clientUrl,peer,nativeId)));
            stock.validateScopes(folder,files,"before",nativeId);stock.validateScopes(folder,files,"after",nativeId);require(scopeState(json(folder,files,"native-scopes-before.json")).equals(scopeState(json(folder,files,"native-scopes-after.json"))));
            for(String phase:List.of("before","after")){var scopes=json(folder,files,"native-scopes-"+phase+".json");for(var member:scopes.path("default").path("members"))for(var mapper:JSON.readTree(Base64.getDecoder().decode(text(member.path("mappers"),"response_base64"))))require(!"saml-user-attribute-nameid-mapper".equals(text(mapper,"protocolMapper")));}
            stage="native_transient_state_and_session_unproven";String uid=text(receipt,"nativeUserId"),username=text(receipt,"username");var principalBefore=json(folder,files,"matrix-before.principal.json");var principalAfter=json(folder,files,"matrix-after.principal.json");require(principal(principalBefore,uid,username).equals(principal(principalAfter,uid,username)));
            var sessionBefore=session(principalBefore,uid,username,nativeId,peer);var sessionAfter=session(principalAfter,uid,username,nativeId,peer);require(text(sessionBefore,"id").equals(text(sessionAfter,"id")));String index=nativePath(folder,files,text(sessionBefore,"id"),nativeId);
            var members=receipt.path("members");require(members.isArray()&&members.size()==KEYS.size());var requestIds=new HashSet<String>();var shapes=new HashSet<String>();var contexts=new HashSet<String>();var refs=new ArrayList<EvidenceRef>();Instant last=normalResponse.timestamp();
            for(int i=0;i<KEYS.size();i++){
                var member=members.get(i);String key=text(member,"key");require(KEYS.get(i).equals(key));var sent=history.get(text(member,"requestReference"));var received=history.get(text(member,"responseReference"));require(sent!=null&&received!=null&&sent.direction()==Direction.OUTBOUND&&received.direction()==Direction.INBOUND&&"AuthnRequest".equals(sent.samlSummary().get("type"))&&"Response".equals(received.samlSummary().get("type")));
                var rq=SecureXml.parse(body(sent)).getDocumentElement();String requestId=rq.getAttribute("ID"),recipient=rq.getAttribute("AssertionConsumerServiceURL");require(requestIds.add(requestId)&&peer.equals(issuer(rq))&&TARGET.concat("/protocol/saml").equals(rq.getAttribute("Destination"))&&signed(rq,matrixKeys)&&SimpleSamlPhpTransientAllowCreateEvidence.policyMatchesRequest(rq,key)&&"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".equals(rq.getAttribute("ProtocolBinding"))&&!Set.of("true","1").contains(rq.getAttribute("ForceAuthn"))&&!Set.of("true","1").contains(rq.getAttribute("IsPassive")));
                require(!sent.timestamp().isBefore(last)&&!received.timestamp().isBefore(sent.timestamp()));last=received.timestamp();shapes.add(requestShape(rq));var response=verifyResponse(body(received),targetKeys,peer,requestId,recipient);var assertion=one(response,S,"Assertion");require(SimpleSamlPhpTransientAllowCreateEvidence.transientAssertion(assertion));var auth=one(assertion,S,"AuthnStatement");require(index.equals(auth.getAttribute("SessionIndex")));contexts.add(KeycloakSubjectConfirmationEvidence.structure(one(auth,S,"AuthnContext")));
                require(recorded(principalBefore.path("sessions")).isBefore(sent.timestamp())&&recorded(principalAfter.path("sessions")).isAfter(received.timestamp())&&recorded(json(folder,files,"native-matrix-client-before.json")).isBefore(sent.timestamp())&&recorded(json(folder,files,"native-matrix-client-after.json")).isAfter(received.timestamp()));
                refs.add(new EvidenceRef("transcript",sent.id()));refs.add(new EvidenceRef("transcript",received.id()));
            }
            require(shapes.size()==1&&contexts.size()==1&&recorded(scopeBefore).isBefore(prepared.timestamp())&&recorded(scopeAfter).isAfter(last));var removal=json(folder,files,"native-client-removal.json");require("DELETE".equals(text(removal,"method"))&&clientUrl.equals(text(removal,"url"))&&removal.path("status").asInt()==204);
            for(var e:List.of(prepared,negative,normal,normalResponse))refs.add(new EvidenceRef("transcript",e.id()));refs.add(new EvidenceRef("native-keycloak-transient-allow-create",context.runId()+".keycloak-transient-allow-create.json#"+hash(receiptRaw)));
            return Optional.of(new CaseOutcome(Outcome.SATISFIED,null,"browser.nameid.transient-allow-create-ignored","Six signed fixed-policy transient flows and the actual native null-state generator prove AllowCreate has no persistence dependency in this stock path.",refs,Map.of("adapter",SCHEMA,"case_id",CASE,"run_id",context.runId(),"required_conditions",KEYS,"configuration_restored",true,"allow_create_persistence_dependency_absent",true,"ordinary_session_storage_asserted_absent",false,"scope","this-run-stock-native-transient-factory-and-effective-configuration","native_state_models_read_by_generator",false)));
        } catch(Exception|LinkageError unproven){if(Boolean.getBoolean("samlscope.keycloakTransient.debug"))unproven.printStackTrace();return Optional.of(CaseOutcome.notVerified(stage,"browser.nameid.transient-allow-create-native-unproven"));}
    }
}
