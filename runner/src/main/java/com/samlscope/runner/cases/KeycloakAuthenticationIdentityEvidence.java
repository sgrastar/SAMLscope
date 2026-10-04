package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.binding.RedirectSignatureVerifier;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.*;
import java.util.function.Function;
import java.util.jar.JarInputStream;
import org.w3c.dom.Element;
import static com.samlscope.runner.cases.MetadataAlgorithmEvidence.children;

/** An applied password-only client flow, fresh challenge and signed identity controls.
 * The native implementation closes the selected flow, while actual protocol originals prove
 * authentication behavior. This does not claim that every realm trust/authentication store is empty.
 * Browser observations contain public form structure only; credentials and session values are never retained.
 */
final class KeycloakAuthenticationIdentityEvidence {
    static final String CASE="IIP-SSO01-ae-idp-01", SCHEMA="samlscope-keycloak-authentication-identity-v1";
    static final String ADAPTER="keycloak-native-password-only-v1";
    private static final String TARGET="http://localhost:18180/realms/samlscope",ADMIN="http://localhost:18180/admin/realms/samlscope";
    private static final String S="urn:oasis:names:tc:SAML:2.0:assertion",P="urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String MD="urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String COLLECTOR="f8e686a809c30395bfb2fec564cff66fbeeb2bdfce218a770e9542b36e3a4537";
    private static final Map<String,String> EXTRA_JARS=Map.of(
        "org.keycloak.keycloak-server-spi-private-26.7.2.jar","a9541ffb99d572a487afdbd0ce112f3038f8d58119857219306e14d3af400afa",
        "org.keycloak.keycloak-server-spi-26.7.2.jar","04142eb6f4f2195a23ebbf785aaf8c05bcf308fa5dc6ad33b5326711b2ee536d",
        "org.keycloak.keycloak-core-26.7.2.jar","7486c2cd0bc59a6beb85dfb2f7e9b36659a50f15853e25162637ffcab2570d53");
    private final Path directory;
    private final String expectedCollector;
    private final String expectedNativeClasspath;
    private final TranscriptContentReader content;
    private final Function<String,byte[]> metadata;
    KeycloakAuthenticationIdentityEvidence(Path directory,TranscriptContentReader content,
            Function<String,byte[]> metadata,SamlDecryptionKeyProvider keys) {
        this(directory,content,metadata,keys,COLLECTOR,"6c395042caae9cd300d9c0d989a58c5aaca4510dec2e1c1c9daeedfe3da5261e");
    }
    KeycloakAuthenticationIdentityEvidence(Path directory,TranscriptContentReader content,
            Function<String,byte[]> metadata,SamlDecryptionKeyProvider keys,String collector,String nativeClasspath) {
        require(collector!=null&&collector.matches("[0-9a-f]{64}")&&nativeClasspath!=null&&nativeClasspath.matches("[0-9a-f]{64}"));
        this.expectedCollector=collector;this.expectedNativeClasspath=nativeClasspath;
        this.directory=Objects.requireNonNull(directory).toAbsolutePath().normalize();
        this.content=Objects.requireNonNull(content);this.metadata=Objects.requireNonNull(metadata);Objects.requireNonNull(keys);
    }
    boolean exists(String run) { return run!=null&&run.matches("run_[0-9A-HJKMNP-TV-Z]{26}")
        &&Files.exists(directory.resolve(run),LinkOption.NOFOLLOW_LINKS); }
    private static void require(boolean condition){if(!condition)throw new IllegalArgumentException("native_identity_unproven");}
    static String hash(byte[] bytes)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));}
    private byte[] raw(Path folder,String name)throws Exception {
        require(!name.isBlank()&&!Path.of(name).isAbsolute());var path=folder.resolve(name).toAbsolutePath().normalize();
        require(path.startsWith(folder)&&!path.equals(folder));
        for(var at=path;at!=null;at=at.getParent())require(!Files.isSymbolicLink(at));
        require(Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS));return Files.readAllBytes(path);
    }
    private byte[] original(Path folder,JsonNode files,String name)throws Exception {
        var bytes=raw(folder,name);require(hash(bytes).equals(text(files,name)));return bytes;
    }
    private static JsonNode json(byte[] bytes)throws Exception{return new JsonCodec().mapper().readTree(bytes);}
    private static String text(JsonNode node,String field){var value=node.path(field);require(value.isTextual()&&!value.asText().isBlank());return value.asText();}
    private static Instant at(JsonNode node){return Instant.parse(text(node,"recordedAt"));}
    private JsonNode node(Path folder,JsonNode files,String name)throws Exception{return json(original(folder,files,name));}
    private JsonNode nativeRecord(Path folder,JsonNode files,String label)throws Exception{return node(folder,files,"originals/"+label+".json");}
    private static JsonNode reply(JsonNode record,String method,String path,int status)throws Exception {
        require(method.equals(text(record,"method"))&&(ADMIN+path).equals(text(record,"url"))&&record.path("status").isInt()&&status==record.path("status").asInt());
        if(record.has("response_projection")||record.has("redactions")){
            require("GET".equals(method)&&status==200&&path.matches("/clients/[0-9a-f-]{36}")&&"native-client-public-readback-v1".equals(text(record,"response_projection"))&&record.path("redactions").isArray());
            var removed=new HashSet<String>();for(var redaction:record.path("redactions"))require(redaction.isTextual()&&Set.of("$.secret","$.registrationAccessToken").contains(redaction.asText())&&removed.add(redaction.asText()));
        }
        require(record.path("response_base64").isTextual());byte[] bytes=Base64.getDecoder().decode(record.path("response_base64").asText());require(hash(bytes).equals(text(record,"response_sha256")));
        var value=json(bytes);require(value==null||!KeycloakSubjectConfirmationEvidence.sensitive(value));return value;
    }
    private static byte[] requestBody(JsonNode record)throws Exception {
        var bytes=Base64.getDecoder().decode(text(record,"request_base64"));require(hash(bytes).equals(text(record,"request_sha256")));return bytes;
    }
    private record Exchange(TranscriptEntry request,TranscriptEntry response,Element requestXml,Element responseXml,byte[] requestRaw){}
    private Exchange exchange(Map<String,TranscriptEntry> entries,JsonNode receipt,String label,Element peer,Element target)throws Exception {
        var request=entries.get(text(receipt,label+"RequestReference"));var response=entries.get(text(receipt,label+"ResponseReference"));
        require(request!=null&&response!=null&&request.direction()==Direction.OUTBOUND&&response.direction()==Direction.INBOUND
            &&request.timestamp().isBefore(response.timestamp())&&request.decodedSamlRef()!=null&&response.decodedSamlRef()!=null);
        byte[] rq=content.readDecodedSaml(request),rs=content.readDecodedSaml(response);
        require(rq!=null&&rs!=null&&rq.length==request.decodedSamlBytes()&&rs.length==response.decodedSamlBytes());
        var req=SecureXml.parse(rq).getDocumentElement();var res=SecureXml.parse(rs).getDocumentElement();String id=req.getAttribute("ID");
        require(P.equals(req.getNamespaceURI())&&"AuthnRequest".equals(req.getLocalName())&&!id.isBlank()
            &&peer.getAttribute("entityID").equals(KeycloakSubjectConfirmationEvidence.issuer(req))
            &&TARGET.concat("/protocol/saml").equals(req.getAttribute("Destination")));
        String acs=req.getAttribute("AssertionConsumerServiceURL");require(!acs.isBlank()&&acs.equals(response.url()));
        var roles=children(peer,MD,"SPSSODescriptor");require(roles.size()==1&&children(roles.getFirst(),MD,"AssertionConsumerService")
            .stream().anyMatch(e->acs.equals(e.getAttribute("Location"))));
        var peerKeys=MetadataAlgorithmEvidence.signingKeys(peer);require(!peerKeys.isEmpty());
        if("GET".equals(request.method()))require(request.rawQuery()!=null&&peerKeys.stream().anyMatch(c->new RedirectSignatureVerifier().isValidForMessage(request.rawQuery(),c,rq)));
        else require("POST".equals(request.method())&&KeycloakSubjectConfirmationEvidence.signed(req,peerKeys));
        boolean passive=label.equals("passive");require(passive==truth(req.getAttribute("IsPassive"))&&passive==truth(req.getAttribute("ForceAuthn")));
        if(passive)require("force-authn-passive".equals(request.samlSummary().get("fixture_id"))&&"IIP-IDP06-c-idp-01".equals(request.samlSummary().get("scenario_case_id")));
        var targetKeys=MetadataAlgorithmEvidence.signingKeys(target);require(!targetKeys.isEmpty());
        require(P.equals(res.getNamespaceURI())&&"Response".equals(res.getLocalName())&&id.equals(res.getAttribute("InResponseTo"))&&acs.equals(res.getAttribute("Destination"))
            &&TARGET.equals(KeycloakSubjectConfirmationEvidence.issuer(res))&&KeycloakSubjectConfirmationEvidence.signed(res,targetKeys));
        require(entries.values().stream().filter(e->e.direction()==Direction.INBOUND&&id.equals(e.samlSummary().get("inResponseTo"))).count()==1);
        return new Exchange(request,response,req,res,rq);
    }
    private static boolean truth(String value){return "true".equals(value)||"1".equals(value);}
    private static byte[] clazz(byte[] jar,String name)throws Exception {
        try(var stream=new JarInputStream(new java.io.ByteArrayInputStream(jar))) {for(var e=stream.getNextJarEntry();e!=null;e=stream.getNextJarEntry())if(e.getName().equals(name))return stream.readAllBytes();}
        throw new IllegalArgumentException("Missing operative class");
    }
    private static boolean contains(byte[] source,String token){return new String(source,StandardCharsets.ISO_8859_1).contains(token);}
    private void nativeScope(Path folder,JsonNode files,String flowId,Instant first,Instant last)throws Exception {
        byte[] inventory=original(folder,files,"originals/before.native-classpath.txt");
        require(hash(inventory).equals(expectedNativeClasspath)&&Arrays.equals(inventory,original(folder,files,"originals/after.native-classpath.txt")));
        var before=node(folder,files,"originals/before.environment.json");var after=node(folder,files,"originals/after.environment.json");
        require(before.path("runtime").equals(after.path("runtime"))&&before.at("/runtime/running").asBoolean(false)
            &&hash(inventory).equals(text(before,"nativeClasspathSha256"))&&hash(inventory).equals(text(after,"nativeClasspathSha256"))
            &&at(before).isBefore(first)&&at(after).isAfter(last));
        String installed=new String(inventory,StandardCharsets.UTF_8);var pins=new HashMap<>(KeycloakNativeSchemaAdmissionEvidence.NATIVE_JARS);pins.putAll(EXTRA_JARS);
        for(var pin:pins.entrySet()){byte[] jar=original(folder,files,"originals/native-runtime/"+pin.getKey());require(hash(jar).equals(pin.getValue())
            &&installed.lines().anyMatch(line->line.equals(pin.getValue()+"  /opt/keycloak/lib/lib/"+(pin.getKey().startsWith("org.jboss.logging")?"boot/":"main/")+pin.getKey())));}
        byte[] resolver=clazz(original(folder,files,"originals/native-runtime/org.keycloak.keycloak-server-spi-private-26.7.2.jar"),"org/keycloak/models/utils/AuthenticationFlowResolver.class");
        require(contains(resolver,"resolveBrowserFlow")&&contains(resolver,"resolveBindingOverrideFlowForClient")&&contains(resolver,"getAuthenticationFlowBindingOverride")&&contains(resolver,"getAuthenticationFlowById"));
        byte[] services=original(folder,files,"originals/native-runtime/org.keycloak.keycloak-services-26.7.2.jar");
        require(contains(clazz(services,"org/keycloak/protocol/AuthorizationEndpointBase.class"),"resolveBrowserFlow")
            &&contains(clazz(services,"org/keycloak/protocol/saml/SamlService.class"),"handleBrowserAuthenticationRequest")
            &&contains(clazz(services,"org/keycloak/authentication/authenticators/browser/UsernamePasswordForm.class"),"validateUserAndPassword"));
        for(String kind:List.of("policies","profiles")) {
            var a=nativeRecord(folder,files,"policy-"+kind+"-before");var b=nativeRecord(folder,files,"policy-"+kind+"-after");
            var old=reply(a,"GET","/client-policies/"+kind,200);require(old.equals(reply(b,"GET","/client-policies/"+kind,200))&&old.path(kind).isArray()&&old.path(kind).isEmpty()
                &&at(a).isBefore(first)&&at(b).isAfter(last));
        }
    }
    Optional<CaseOutcome> evaluate(CaseContext context){
        if(!exists(context.runId()))return Optional.empty();String stage="native-authentication-identity-originals-unproven";
        try {
            require(context.transcriptComplete());var folder=directory.resolve(context.runId());require(Files.isDirectory(folder,LinkOption.NOFOLLOW_LINKS));
            var receipt=json(raw(folder,"manifest.json"));var files=receipt.path("files");byte[] targetRaw=metadata.apply(context.runId());
            require(SCHEMA.equals(text(receipt,"schema"))&&CASE.equals(text(receipt,"caseId"))&&context.runId().equals(text(receipt,"runId"))
                &&ADAPTER.equals(text(receipt,"adapter"))&&"native-authentication-identity".equals(text(receipt,"campaignId"))&&TARGET.equals(text(receipt,"targetEntityId"))
                &&hash(targetRaw).equals(text(receipt,"targetMetadataSha256"))&&expectedCollector.equals(hash(original(folder,files,"originals/collector.py"))));
            var created=node(folder,files,"created.json").path("run");var plan=node(folder,files,"plan.json").at("/plan/plan");
            require(context.runId().equals(text(created,"id"))&&text(created,"planId").equals(text(plan,"id"))&&"browser_sso_idp".equals(text(plan,"profile"))
                &&TARGET.equals(text(plan.path("target"),"entityId")));String entity="http://localhost:18080/p/"+text(created,"planId");
            var peerRaw=original(folder,files,"fixture.xml");var peer=SecureXml.parse(peerRaw).getDocumentElement();var target=SecureXml.parse(targetRaw).getDocumentElement();
            require(entity.equals(peer.getAttribute("entityID"))&&TARGET.equals(target.getAttribute("entityID"))&&KeycloakSubjectConfirmationEvidence.signed(peer,MetadataAlgorithmEvidence.signingKeys(peer)));
            var entries=new HashMap<String,TranscriptEntry>();for(var e:context.transcript().list(context.runId()))require(context.runId().equals(e.runId())&&entries.put(e.id(),e)==null);
            var positive=exchange(entries,receipt,"positive",peer,target);var passive=exchange(entries,receipt,"passive",peer,target);
            require("GET".equals(positive.request().method())&&positive.response().timestamp().isBefore(passive.request().timestamp()));
            Instant first=positive.request().timestamp(),last=passive.response().timestamp();
            stage="native-password-only-configuration-unproven";
            var flowCreation=nativeRecord(folder,files,"flow-creation");reply(flowCreation,"POST","/authentication/flows",201);var flow=json(requestBody(flowCreation));
            String alias="samlscope-password-only-"+context.runId().substring(4);require(alias.equals(text(flow,"alias"))&&"basic-flow".equals(text(flow,"providerId"))&&flow.path("topLevel").asBoolean(false)&&!flow.path("builtIn").asBoolean(true));
            var creation=nativeRecord(folder,files,"client-creation");reply(creation,"POST","/clients",201);var requested=json(requestBody(creation));String flowId=text(requested.path("authenticationFlowBindingOverrides"),"browser");
            require(flowId.matches("[0-9a-f-]{36}")&&requested.path("authenticationFlowBindingOverrides").size()==1&&entity.equals(text(requested,"clientId"))&&"saml".equals(text(requested,"protocol")));
            var converter=nativeRecord(folder,files,"native-converter");var converted=reply(converter,"POST","/client-description-converter",200);
            require(Arrays.equals(peerRaw,requestBody(converter)));var expected=converted.deepCopy();((com.fasterxml.jackson.databind.node.ObjectNode)expected.path("attributes")).put("saml.encrypt","false");
            ((com.fasterxml.jackson.databind.node.ObjectNode)expected).set("authenticationFlowBindingOverrides",requested.path("authenticationFlowBindingOverrides"));require(expected.equals(requested));
            var clientBeforeRecord=nativeRecord(folder,files,"native-client-before");var clientBefore=json(Base64.getDecoder().decode(text(clientBeforeRecord,"response_base64")));String clientId=text(clientBefore,"id");
            require(clientId.matches("[0-9a-f-]{36}")&&clientBefore.equals(reply(clientBeforeRecord,"GET","/clients/"+clientId,200))
                &&clientBefore.path("authenticationFlowBindingOverrides").equals(requested.path("authenticationFlowBindingOverrides"))&&entity.equals(text(clientBefore,"clientId"))&&"saml".equals(text(clientBefore,"protocol")));
            for(var fields=requested.path("attributes").fields();fields.hasNext();){var field=fields.next();require(field.getValue().equals(clientBefore.path("attributes").path(field.getKey())));}
            require("true".equals(clientBefore.at("/attributes/saml.client.signature").asText())&&"true".equals(clientBefore.at("/attributes/saml.server.signature").asText())&&"false".equals(clientBefore.at("/attributes/saml.encrypt").asText()));
            var clientAfterRecord=nativeRecord(folder,files,"native-client-after");require(clientBefore.equals(reply(clientAfterRecord,"GET","/clients/"+clientId,200))&&at(clientBeforeRecord).isBefore(first)&&at(clientAfterRecord).isAfter(last));
            var executionBefore=nativeRecord(folder,files,"flow-executions-before");var executions=reply(executionBefore,"GET","/authentication/flows/"+alias+"/executions",200);
            require(executions.isArray()&&executions.size()==1&&"auth-username-password-form".equals(text(executions.get(0),"providerId"))&&"REQUIRED".equals(text(executions.get(0),"requirement"))&&executions.get(0).path("level").asInt(-1)==0);
            var executionAfter=nativeRecord(folder,files,"flow-executions-after");require(executions.equals(reply(executionAfter,"GET","/authentication/flows/"+alias+"/executions",200))&&at(executionBefore).isBefore(first)&&at(executionAfter).isAfter(last));
            require(at(flowCreation).isBefore(at(converter))&&at(converter).isBefore(at(creation))&&at(creation).isBefore(at(clientBeforeRecord)));
            nativeScope(folder,files,flowId,first,last);
            stage="native-identity-controls-unproven";
            var normal=positive.responseXml();require(children(normal,P,"Status").size()==1&&children(children(normal,P,"Status").getFirst(),P,"StatusCode").size()==1
                &&"urn:oasis:names:tc:SAML:2.0:status:Success".equals(children(children(normal,P,"Status").getFirst(),P,"StatusCode").getFirst().getAttribute("Value")));
            require(children(normal,S,"EncryptedAssertion").isEmpty()&&children(normal,S,"Assertion").size()==1);var assertion=children(normal,S,"Assertion").getFirst();
            require(KeycloakSubjectConfirmationEvidence.signed(assertion,MetadataAlgorithmEvidence.signingKeys(target))&&TARGET.equals(KeycloakSubjectConfirmationEvidence.issuer(assertion)));
            var subjects=children(assertion,S,"Subject");require(subjects.size()==1&&children(subjects.getFirst(),S,"NameID").size()==1
                &&"samlscope-m0-user".equals(children(subjects.getFirst(),S,"NameID").getFirst().getTextContent()));
            require(children(assertion,S,"AuthnStatement").size()==1&&assertion.getElementsByTagNameNS(S,"Audience").getLength()==1
                &&entity.equals(assertion.getElementsByTagNameNS(S,"Audience").item(0).getTextContent()));
            var sc=assertion.getElementsByTagNameNS(S,"SubjectConfirmationData");require(sc.getLength()==1&&positive.requestXml().getAttribute("ID").equals(((Element)sc.item(0)).getAttribute("InResponseTo"))&&positive.response().url().equals(((Element)sc.item(0)).getAttribute("Recipient")));
            var error=passive.responseXml();var statuses=children(error,P,"Status");require(statuses.size()==1);var codes=children(statuses.getFirst(),P,"StatusCode");require(codes.size()==1&&"urn:oasis:names:tc:SAML:2.0:status:Responder".equals(codes.getFirst().getAttribute("Value"))
                &&children(codes.getFirst(),P,"StatusCode").size()==1&&"urn:oasis:names:tc:SAML:2.0:status:NoPassive".equals(children(codes.getFirst(),P,"StatusCode").getFirst().getAttribute("Value"))
                &&children(error,S,"Assertion").isEmpty()&&children(error,S,"EncryptedAssertion").isEmpty());
            var observations=node(folder,files,"native-observations.json");require(observations.isArray()&&observations.size()==3);var arrival=observations.get(0);var challenge=observations.get(1);var fresh=observations.get(2);
            for(var pair:List.of(Map.entry(arrival,positive),Map.entry(fresh,passive))){var row=pair.getKey();var ex=pair.getValue();require("native-saml-arrival".equals(text(row,"kind"))&&ex.requestXml().getAttribute("ID").equals(text(row,"requestId"))&&hash(ex.requestRaw()).equals(text(row,"requestSha256"))
                &&ex.request().method().equals(text(row,"method"))&&TARGET.concat("/protocol/saml").equals(text(row,"requestUrl"))&&row.path("cookieCountBefore").asInt(-1)==0&&row.path("credentialPostsBefore").asInt(-1)==0&&at(row).isAfter(ex.request().timestamp())&&at(row).isBefore(ex.response().timestamp()));}
            require("normal".equals(text(arrival,"label"))&&"passive".equals(text(fresh,"label"))&&hash(positive.request().rawQuery().getBytes(StandardCharsets.US_ASCII)).equals(text(arrival,"rawQuerySha256")));
            require("native-password-challenge".equals(text(challenge,"kind"))&&"normal".equals(text(challenge,"label"))&&positive.requestXml().getAttribute("ID").equals(text(challenge,"requestId"))
                &&challenge.path("status").asInt(-1)==200&&challenge.path("credentialPostsBefore").asInt(-1)==0&&!challenge.path("credentialsAndStateValuesPersisted").asBoolean(true)
                &&"/realms/samlscope/protocol/saml".equals(text(challenge,"publicResponsePath"))&&challenge.path("inputNames").isArray()&&challenge.path("inputNames").size()==3
                &&challenge.path("inputNames").toString().equals("[\"credentialId\",\"password\",\"username\"]")&&text(challenge,"originalResponseSha256").matches("[0-9a-f]{64}")&&at(challenge).isAfter(at(arrival))&&at(challenge).isBefore(positive.response().timestamp()));
            var actions=node(folder,files,"credential-actions.json");require(actions.isArray()&&actions.size()==1);var action=actions.get(0);require("credential-post".equals(text(action,"kind"))&&"normal".equals(text(action,"label"))&&positive.requestXml().getAttribute("ID").equals(text(action,"requestId"))&&!action.path("valuesPersisted").asBoolean(true)
                &&at(action).isAfter(at(challenge))&&at(action).isBefore(positive.response().timestamp()));
            stage="native-restoration-unproven";
            var restored=node(folder,files,"restoration.json");require(restored.path("restored").asBoolean(false)&&restored.path("originalClientAbsent").asBoolean(false)&&restored.path("remainingClients").isEmpty()&&restored.path("flowInventoryRestored").asBoolean(false)&&restored.path("recoveryFailures").isEmpty());
            for(String kind:List.of("client","flow")){var removal=nativeRecord(folder,files,kind+"-removal");reply(removal,"DELETE",kind.equals("client")?"/clients/"+clientId:"/authentication/flows/"+flowId,204);require(at(removal).isAfter(last));}
            String lookup="/clients?clientId="+java.net.URLEncoder.encode(entity,StandardCharsets.UTF_8).replace("+","%20");
            var inventoryBefore=nativeRecord(folder,files,"client-inventory-before");var inventoryAfter=nativeRecord(folder,files,"client-inventory-after");require(reply(inventoryBefore,"GET",lookup,200).isEmpty()&&reply(inventoryAfter,"GET",lookup,200).isEmpty()&&at(inventoryBefore).isBefore(first)&&at(inventoryAfter).isAfter(last));
            var flowsBefore=nativeRecord(folder,files,"flow-inventory-before");var flowsAfter=nativeRecord(folder,files,"flow-inventory-after");var originalFlows=reply(flowsBefore,"GET","/authentication/flows",200);
            require(originalFlows.isArray()&&originalFlows.equals(reply(flowsAfter,"GET","/authentication/flows",200))&&at(flowsBefore).isBefore(first)&&at(flowsAfter).isAfter(last));
            for(var originalFlow:originalFlows)require(!flowId.equals(originalFlow.path("id").asText())&&!alias.equals(originalFlow.path("alias").asText()));
            var counts=node(folder,files,"operation-counts.json");require(counts.path("product_setting_writes").asInt(-1)==6&&counts.path("product_setting_write_attempts").asInt(-1)==6&&counts.path("administrator_preparation_writes").asInt(-1)==4&&counts.path("administrator_restoration_writes").asInt(-1)==2
                &&counts.path("protocol_operations_attempted").asInt(-1)==2&&counts.path("automated_credential_submissions").asInt(-1)==1&&counts.path("human_operations").asInt(-1)==0&&counts.path("test_user_operations").asInt(-1)==0&&counts.path("product_restarts").asInt(-1)==0&&counts.path("restored").asBoolean(false));
            var evidence=new ArrayList<EvidenceRef>();for(var e:List.of(positive.request(),positive.response(),passive.request(),passive.response()))evidence.add(new EvidenceRef("transcript",e.id()));
            evidence.add(new EvidenceRef("native-authentication-identity",context.runId()+"/manifest.json#"+hash(raw(folder,"manifest.json"))));
            return Optional.of(new CaseOutcome(Outcome.SATISFIED,null,"browser.authentication-identity.native-observed","browser.authentication-identity.native-observed",evidence,
                Map.of("adapter",ADAPTER,"ambient_authentication_excluded",true,"normal_native_challenge",true,"native_identity_error_no_assertion",true,"configuration_restored",true,"test_user_operations",0,"automated_credential_submissions",1,"administrator_preparation_writes",4,"administrator_restoration_writes",2)));
        }catch(Exception unproven){return Optional.of(CaseOutcome.notVerified(stage,"browser.authentication-identity.native-unproven"));}
    }
}
