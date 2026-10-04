package com.samlscope.runner.cases;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.binding.RedirectSignatureVerifier;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.jar.JarFile;
import static com.samlscope.runner.cases.MetadataAlgorithmEvidence.children;

/** Scoped real native construction, actual saved attribute and signed Response; never universal user opacity. */
final class KeycloakPersistentIdentifierEvidence {
    static final String SCHEMA="samlscope-keycloak-persistent-identifier-v1";
    static final Map<String,String> DIGESTS=Map.of("IIP-SSO05-a1-idp-01","sha256:eb4cdd50dca77f8e286b3f6e7f5166bd4e4723a4e0f4a73589486d871106c4c0",
        "IIP-SSO05-a8-idp-01","sha256:acd9b10dc4e281800ebc2ebdefbe189e3267a5b5e9f135fa953530b17756c466");
    static final String HELPER="9cc6de8d438003d0221984c99c927285e79075d14f68e20bc9e23ec874e4dd74";
    static final String CLASSPATH="3073a5b0513586ca9faa3319c459204209038e2c1dfe9044a77645465a98d68e";
    static final String COLLECTOR="884658fecea2b4dc9486d6c1c4431496a1f71b051b70c268dd3c48561bbcdfb7";
    private static final String RESOURCE="b104705d67028ef77d2f771978719ca7360c06bc16e1506d652377aefea57512";
    private static final Map<String,String> HELPER_CLASSES=Map.of(
        "ProbeKeycloakPersistentIdentifier$1.class","c9ac84d02c31a310fda11dba27ca30ccc780b39b50581ebe1a6bb90ef84d3533",
        "ProbeKeycloakPersistentIdentifier$Call.class","e27ad412b16cd86ef122cc6c8a5144a6f2d54b990357cd2d728868bbbe2c1a37",
        "ProbeKeycloakPersistentIdentifier$Exchange.class","b7d8177080e24ba1e379b1094b1c205f244d4fefd4025f0d556c51a0d76be764",
        "ProbeKeycloakPersistentIdentifier.class","516dfedd93840147a52b8f12c58226267ad79f17e7c060752633ac45597a3724");
    private static final String ADMIN="http://localhost:18180/admin/realms/samlscope",TARGET="http://localhost:18180/realms/samlscope";
    private static final String P="urn:oasis:names:tc:SAML:2.0:protocol",S="urn:oasis:names:tc:SAML:2.0:assertion",MD="urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String FORMAT="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",PREFIX="saml.persistent.name.id.for.";
    private final Path directory;private final TranscriptContentReader content;private final Function<String,byte[]> metadata;
    private final Map<String,DefaultAlgorithmSourceRunStore> stores;
    private final ObjectMapper json=new JsonCodec().mapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION).enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    KeycloakPersistentIdentifierEvidence(Path directory,TranscriptContentReader content,Function<String,byte[]> metadata,Map<String,DefaultAlgorithmSourceRunStore> stores) {
        this.directory=directory.toAbsolutePath().normalize();this.content=Objects.requireNonNull(content);this.metadata=Objects.requireNonNull(metadata);this.stores=Map.copyOf(stores);
        require(stores.keySet().equals(DIGESTS.keySet()));for(var e:stores.entrySet())require(e.getKey().equals(e.getValue().approvedCaseId())&&DIGESTS.get(e.getKey()).equals(e.getValue().approvedCaseDigest()));
    }
    private Path folder(String run){return directory.resolve(run+".keycloak-native-identifier");}
    boolean exists(String run){return run!=null&&run.matches("run_[0-9A-HJKMNP-TV-Z]{26}")&&Files.exists(folder(run),LinkOption.NOFOLLOW_LINKS);}
    Optional<CaseOutcome> read(CaseContext context,String id) {
        if(!exists(context.runId()))return Optional.empty();String stage="approved-source-run";
        try {
            require(DIGESTS.containsKey(id)&&context.transcriptComplete()&&context.targetRole()==TargetRole.IDP);
            Path f=folder(context.runId());byte[] manifestBytes=raw(f,"manifest.json");var manifest=json.readTree(manifestBytes);var files=manifest.path("files");
            require(SCHEMA.equals(text(manifest,"schema"))&&context.runId().equals(text(manifest,"runId"))&&json.valueToTree(DIGESTS).equals(manifest.path("caseDigests"))&&files.isObject()&&files.size()>500&&files.size()<1000);
            var iterator=files.fieldNames();while(iterator.hasNext()){String name=iterator.next();checked(f,files,name);}
            var entries=context.transcript().list(context.runId());var history=new HashMap<String,TranscriptEntry>();
            for(var entry:entries)require(context.runId().equals(entry.runId())&&history.put(entry.id(),entry)==null);
            DefaultAlgorithmSourceRunStore.Binding binding=null;
            for(var store:stores.entrySet()) {
                var source=store.getValue().execution(context.runId());if(binding==null)binding=source;
                require("browser_sso_idp".equals(source.plan().profile().id())&&text(manifest,"planId").equals(source.plan().id())&&TARGET.equals(source.plan().target().entityId())
                    &&stable(source.snapshot()).equals(json.readTree(checked(f,files,"source-store-"+store.getKey()+".json")))
                    &&store.getValue().history(context.runId(),entries,content).equals(json.readTree(checked(f,files,"source-history.json"))));
            }
            require(binding!=null);String peer="http://localhost:18080/p/"+binding.plan().id();
            require(Arrays.equals(metadata.apply(context.runId()),checked(f,files,"target-metadata.xml"))&&hash(metadata.apply(context.runId())).equals(text(manifest,"targetMetadataSha256"))
                &&COLLECTOR.equals(hash(checked(f,files,"originals/collector.py")))&&HELPER.equals(hash(checked(f,files,"native-helper.java"))));
            var membership=json.readTree(checked(f,files,"approved-membership.json"));require(membership.path("cases").isArray()&&membership.path("cases").size()==2);
            var members=new HashSet<String>();for(var member:membership.path("cases")){String caseId=text(member,"caseId");require(members.add(caseId)&&DIGESTS.containsKey(caseId)&&DIGESTS.get(caseId).equals(text(member,"caseDigest"))
                &&context.runId().equals(text(member,"runId"))&&binding.plan().id().equals(text(member,"planId"))&&"browser_sso_idp".equals(text(member,"profile"))
                &&json.valueToTree(binding.plan().definitionIdentity()).equals(member.path("definitionIdentity"))&&TARGET.equals(text(member,"targetEntityId"))&&member.path("approvedMembership").asBoolean(false));}
            stage="actual-source-native-configuration";
            var client=reply(f,files,"native-client-before","GET",null,200);String clientId=text(client,"id");
            require((ADMIN+"/clients/"+clientId).equals(text(node(f,files,"originals/native-client-before.json"),"url")));
            require(peer.equals(text(client,"clientId"))&&"saml".equals(text(client,"protocol"))&&"true".equals(client.at("/attributes/saml_force_name_id_format").asText())
                &&"persistent".equals(client.at("/attributes/saml_name_id_format").asText())&&"false".equals(client.at("/attributes/saml.encrypt").asText())
                &&"true".equals(client.at("/attributes/saml.client.signature").asText())&&"true".equals(client.at("/attributes/saml.server.signature").asText())
                &&client.equals(reply(f,files,"native-client-after","GET","/clients/"+clientId,200)));
            stage="actual-source-profile-and-principal";
            var profile=reply(f,files,"user-profile-visible","GET","/users/profile",200);require("ADMIN_EDIT".equals(text(profile,"unmanagedAttributePolicy")));
            var before=reply(f,files,"native-user-before","GET",null,200);String userId=text(before,"id"),principal=text(before,"username");
            require((ADMIN+"/users/"+userId).equals(text(node(f,files,"originals/native-user-before.json"),"url")));
            require(userId.matches("[a-f0-9-]{36}")&&principal.matches("samlscope-opaque-[0-9a-f]{20}")&&(!before.has("attributes")||before.path("attributes").isObject()&&before.path("attributes").isEmpty()));
            var after=reply(f,files,"native-user-after","GET","/users/"+userId,200);var mutant=reply(f,files,"native-user-mutant-before","GET","/users/"+userId,200);
            require(withoutAttributes(before).equals(withoutAttributes(after))&&withoutAttributes(before).equals(withoutAttributes(mutant)));
            stage="actual-source-own-user-creation";
            var creation=node(f,files,"originals/user-creation.json");require("POST".equals(text(creation,"method"))&&(ADMIN+"/users").equals(text(creation,"url"))&&creation.path("status").asInt(-1)==201
                &&creation.path("credentialInputRetained").isBoolean()&&!creation.path("credentialInputRetained").booleanValue()&&!creation.has("request_base64")&&!creation.has("request_sha256")
                &&principal.equals(text(creation.path("publicRecipe"),"username"))&&!creation.path("publicRecipe").has("attributes")&&!creation.path("publicRecipe").has("credentials"));
            stage="actual-source-native-conversion";
            var conversion=node(f,files,"originals/native-converter.json");var converted=reply(f,files,"native-converter","POST","/client-description-converter",200);
            byte[] peerRaw=checked(f,files,"suite-sp-metadata.xml");require(Arrays.equals(peerRaw,request(conversion))&&peer.equals(text(converted,"clientId"))&&converted.path("protocolMappers").isArray()&&converted.path("protocolMappers").isEmpty());
            stage="actual-source-client-application";
            var application=node(f,files,"originals/native-client-creation.json");reply(f,files,"native-client-creation","POST","/clients",201);var requested=json.readTree(request(application));
            var expected=(ObjectNode)converted.deepCopy();((ObjectNode)expected.path("attributes")).put("saml.encrypt","false").put("saml_force_name_id_format","true").put("saml_name_id_format","persistent");
            expected.putArray("protocolMappers").add(json.readTree("{\"name\":\"samlscope-native-principal-username\",\"protocol\":\"saml\",\"protocolMapper\":\"saml-user-property-mapper\",\"consentRequired\":false,\"config\":{\"user.attribute\":\"username\",\"attribute.name\":\"samlscope.native.username\",\"attribute.nameformat\":\"Basic\"}}"));
            require(expected.equals(requested));for(var fields=requested.path("attributes").fields();fields.hasNext();){var field=fields.next();require(field.getValue().equals(client.path("attributes").path(field.getKey())));}
            stage="signed-native-persistent-originals";
            var sp=SecureXml.parse(peerRaw).getDocumentElement();require(MD.equals(sp.getNamespaceURI())&&"EntityDescriptor".equals(sp.getLocalName())&&peer.equals(sp.getAttribute("entityID")));
            var target=SecureXml.parse(metadata.apply(context.runId())).getDocumentElement();var signing=MetadataAlgorithmEvidence.signingKeys(target);
            var normal=exchange(f,files,manifest,history,"normal",peer,principal,sp,signing);var negative=exchange(f,files,manifest,history,"mutant",peer,principal,sp,signing);
            require(normal.response().timestamp().isBefore(negative.request().timestamp()));String key=PREFIX+peer;
            require(attributes(after).equals(json.valueToTree(Map.of(key,List.of(normal.value()))))&&attributes(mutant).equals(json.valueToTree(Map.of(key,List.of(principal))))&&principal.equals(negative.value()));
            verifyEpoch(f,files,clientId,userId,peer,principal,profile,before,after,normal,negative);
            stage="actual-native-construction-replay";
            var recorded=node(f,files,"native-helper-replay.json");var actual=replay(f,files);require(normalize(actual,peer).equals(normalize(recorded,peer)));verifyOrigins(f,files,actual);
            var traces=actual.path("traces");require(traces.isArray()&&traces.size()==3&&normal.value().equals(text(traces.get(1),"nativeValue"))&&negative.value().equals(text(traces.get(2),"nativeValue"))
                &&traces.get(1).path("setSingleAttributeEffects").isEmpty()&&traces.get(2).path("setSingleAttributeEffects").isEmpty());
            var identifiers=new HashSet<String>();for(String field:List.of("username","email","id"))if(before.path(field).isTextual()&&!before.path(field).asText().isBlank())identifiers.add(before.path(field).asText());
            require(NativeIdentifierConstructionComparison.compare(true,negative.value(),identifiers)==Outcome.VIOLATED);
            Outcome outcome=NativeIdentifierConstructionComparison.compare(true,normal.value(),identifiers);
            var details=new LinkedHashMap<String,Object>();details.put("evidence_adapter",SCHEMA);details.put("approved_mode","ATTESTED");details.put("attested",false);
            details.put("scope","native-construction-and-original-saved-attribute-reuse");details.put("run_id",context.runId());details.put("native_producer_replayed",true);
            details.put("pseudorandom_construction_source","unchanged-native-UUID.randomUUID");details.put("principal_identifiers_read_by_construction",false);details.put("positive_randomness_seeded",false);
            details.put("actual_saved_attribute_matches_signed_response",true);details.put("principal_valued_control_diagnostic_only",true);details.put("universal_user_opacity_claimed",false);details.put("configuration_restored",true);
            String reason=outcome==Outcome.SATISFIED?"idp.persistent-identifier.native-proven":"idp.persistent-identifier.non-opaque";
            var evidence=List.of(new EvidenceRef("transcript",normal.request().id()),new EvidenceRef("transcript",normal.response().id()),
                new EvidenceRef("native-persistent-identifier",context.runId()+".keycloak-native-identifier/manifest.json#"+hash(manifestBytes)));
            return Optional.of(new CaseOutcome(outcome,null,reason,reason,evidence,details));
        }catch(Exception unproven){return Optional.of(new CaseOutcome(Outcome.NOT_VERIFIED,"native_identifier_construction_unproven","idp.persistent-identifier.native-unproven","idp.persistent-identifier.native-unproven",List.of(),Map.of("evidence_adapter",SCHEMA,"stage",stage)));}
    }
    private record Exchange(TranscriptEntry request,TranscriptEntry response,String value){}
    private Exchange exchange(Path f,JsonNode files,JsonNode manifest,Map<String,TranscriptEntry> history,String label,String peer,String principal,org.w3c.dom.Element sp,List<java.security.cert.X509Certificate> signing)throws Exception {
        var binding=node(f,files,label+"-exchange.json");var request=history.get(text(binding,"requestReference"));var response=history.get(text(binding,"responseReference"));
        require(request!=null&&response!=null&&request.direction()==Direction.OUTBOUND&&response.direction()==Direction.INBOUND&&request.timestamp().isBefore(response.timestamp())
            &&binding.path("diagnosticOnly").isBoolean()&&binding.path("diagnosticOnly").asBoolean()==label.equals("mutant"));
        byte[] requestRaw=content.readDecodedSaml(request),responseRaw=content.readDecodedSaml(response);require(Arrays.equals(requestRaw,checked(f,files,label+"-request.xml"))&&Arrays.equals(responseRaw,checked(f,files,label+"-response.xml")));
        var requestXml=SecureXml.parse(requestRaw).getDocumentElement();require(P.equals(requestXml.getNamespaceURI())&&"AuthnRequest".equals(requestXml.getLocalName())&&text(binding,"requestId").equals(requestXml.getAttribute("ID"))
            &&children(requestXml,S,"Issuer").size()==1&&peer.equals(children(requestXml,S,"Issuer").getFirst().getTextContent())&&TARGET.concat("/protocol/saml").equals(requestXml.getAttribute("Destination"))
            &&"GET".equals(request.method())&&request.rawQuery()!=null);
        var roles=children(sp,MD,"SPSSODescriptor");require(roles.size()==1);var keys=new ArrayList<java.security.cert.X509Certificate>();
        for(var descriptor:children(roles.getFirst(),MD,"KeyDescriptor"))if(List.of("","signing").contains(descriptor.getAttribute("use"))){var certs=descriptor.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#","X509Certificate");for(int i=0;i<certs.getLength();i++)keys.add((java.security.cert.X509Certificate)java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(Base64.getMimeDecoder().decode(certs.item(i).getTextContent()))));}
        require(keys.stream().anyMatch(key->new RedirectSignatureVerifier().isValidForMessage(request.rawQuery(),key,requestRaw)));
        String recipient=requestXml.getAttribute("AssertionConsumerServiceURL");require(!recipient.isBlank()&&recipient.equals(response.url())&&children(roles.getFirst(),MD,"AssertionConsumerService").stream().anyMatch(acs->recipient.equals(acs.getAttribute("Location"))));
        var assertion=VerifiedResponseAssertion.read(SecureXml.parse(responseRaw).getDocumentElement(),TARGET,signing,sp,Optional.empty(),requestXml.getAttribute("ID"),recipient);
        var subjects=children(assertion,S,"Subject");require(subjects.size()==1&&children(subjects.getFirst(),S,"NameID").size()==1);var name=children(subjects.getFirst(),S,"NameID").getFirst();
        require(FORMAT.equals(name.getAttribute("Format"))&&(!name.hasAttribute("SPNameQualifier")||peer.equals(name.getAttribute("SPNameQualifier")))&&(!name.hasAttribute("NameQualifier")||TARGET.equals(name.getAttribute("NameQualifier"))));
        var principals=new ArrayList<String>();for(var statement:children(assertion,S,"AttributeStatement"))for(var attribute:children(statement,S,"Attribute"))if("samlscope.native.username".equals(attribute.getAttribute("Name")))for(var value:children(attribute,S,"AttributeValue"))principals.add(value.getTextContent());
        require(principals.equals(List.of(principal)));return new Exchange(request,response,name.getTextContent());
    }
    private void verifyEpoch(Path f,JsonNode files,String clientId,String userId,String peer,String principal,JsonNode profile,JsonNode before,JsonNode after,Exchange normal,Exchange negative)throws Exception {
        var oldProfile=reply(f,files,"user-profile-before","GET","/users/profile",200);var configured=(ObjectNode)oldProfile.deepCopy();configured.put("unmanagedAttributePolicy","ADMIN_EDIT");require(configured.equals(profile));
        var applied=node(f,files,"originals/user-profile-visibility-application.json");reply(f,files,"user-profile-visibility-application","PUT","/users/profile",200);require(json.readTree(request(applied)).equals(profile));
        require(at(node(f,files,"originals/user-profile-visible.json")).isBefore(at(node(f,files,"originals/user-creation.json")))&&at(node(f,files,"originals/native-user-before.json")).isBefore(normal.request().timestamp())
            &&normal.response().timestamp().isBefore(at(node(f,files,"originals/native-user-after.json")))&&at(node(f,files,"originals/native-user-mutant-before.json")).isBefore(negative.request().timestamp()));
        var diagnostic=node(f,files,"originals/diagnostic-principal-attribute-application.json");reply(f,files,"diagnostic-principal-attribute-application","PUT","/users/"+userId,204);
        var expected=(ObjectNode)after.deepCopy();expected.putObject("attributes").putArray(PREFIX+peer).add(principal);require(expected.equals(json.readTree(request(diagnostic))));
        require(at(node(f,files,"originals/native-user-after.json")).isBefore(at(diagnostic))&&at(diagnostic).isBefore(at(node(f,files,"originals/native-user-mutant-before.json"))));
        var restore=node(f,files,"originals/native-user-attribute-restoration.json");reply(f,files,"native-user-attribute-restoration","PUT","/users/"+userId,204);
        require(json.readTree(request(restore)).equals(after)&&after.equals(reply(f,files,"native-user-positive-restored","GET","/users/"+userId,200))&&negative.response().timestamp().isBefore(at(restore)));
        var scopes=reply(f,files,"client-scopes-before","GET","/client-scopes",200);require(scopes.isArray()&&scopes.equals(reply(f,files,"client-scopes-after","GET","/client-scopes",200))&&scopes.equals(reply(f,files,"client-scopes-restored","GET","/client-scopes",200)));
        for(String kind:List.of("default","optional"))require(reply(f,files,"client-"+kind+"-scopes-before","GET","/clients/"+clientId+"/"+kind+"-client-scopes",200).equals(reply(f,files,"client-"+kind+"-scopes-after","GET","/clients/"+clientId+"/"+kind+"-client-scopes",200)));
        for(var removal:Map.of("native-client-removal","/clients/"+clientId,"native-user-removal","/users/"+userId).entrySet()){reply(f,files,removal.getKey(),"DELETE",removal.getValue(),204);require(at(node(f,files,"originals/"+removal.getKey()+".json")).isAfter(negative.response().timestamp()));}
        var profileRestore=node(f,files,"originals/user-profile-restoration.json");reply(f,files,"user-profile-restoration","PUT","/users/profile",200);require(json.readTree(request(profileRestore)).equals(oldProfile)&&oldProfile.equals(reply(f,files,"user-profile-restored","GET","/users/profile",200)));
        String clientLookup="/clients?clientId="+java.net.URLEncoder.encode(peer,java.nio.charset.StandardCharsets.UTF_8),userLookup="/users?username="+java.net.URLEncoder.encode(principal,java.nio.charset.StandardCharsets.UTF_8)+"&exact=true";
        for(String suffix:List.of("before","restored")){require(reply(f,files,"client-inventory-"+suffix,"GET",clientLookup,200).isEmpty()&&reply(f,files,"user-inventory-"+suffix,"GET",userLookup,200).isEmpty());}
        var beforeEnvironment=node(f,files,"originals/before.environment.json");var afterEnvironment=node(f,files,"originals/after.environment.json");require(beforeEnvironment.path("runtime").equals(afterEnvironment.path("runtime"))
            &&CLASSPATH.equals(text(beforeEnvironment,"nativeClasspathSha256"))&&CLASSPATH.equals(text(afterEnvironment,"nativeClasspathSha256"))&&Arrays.equals(checked(f,files,"originals/before.native-classpath.txt"),checked(f,files,"originals/after.native-classpath.txt")));
        var restored=node(f,files,"restoration.json");require(restored.isObject()&&restored.size()==8);for(var values=restored.elements();values.hasNext();){var value=values.next();require(value.isBoolean()&&value.booleanValue());}
        var counts=node(f,files,"operation-counts.json");require(counts.path("productSettingWriteAttempts").asInt(-1)==8&&counts.path("successfulProductSettingWrites").asInt(-1)==8&&counts.path("protocolOperationsAttempted").asInt(-1)==2
            &&counts.path("protocolOperationsRecorded").asInt(-1)==2&&counts.path("credentialPosts").asInt(-1)==1&&counts.path("restored").asBoolean(false)&&counts.path("diagnosticPrincipalControlOnly").asBoolean(false));
        var operations=node(f,files,"operations.json");require(operations.isArray()&&operations.size()==counts.path("nativeHttpAttempts").asInt(-1));long writes=0;for(var operation:operations){require(operation.path("status").asInt(-1)>=200&&operation.path("status").asInt(-1)<300);if(operation.path("productSettingWrite").asBoolean())writes++;}require(writes==8);
    }
    private JsonNode replay(Path f,JsonNode files)throws Exception {
        byte[] resource;try(var input=getClass().getResourceAsStream("native-keycloak-persistent-helper.json")){require(input!=null);resource=input.readNBytes(100_001);require(resource.length<100_001&&RESOURCE.equals(hash(resource)));}
        var packaged=json.readTree(resource);require(HELPER.equals(text(packaged,"sourceSha256"))&&CLASSPATH.equals(text(packaged,"nativeClasspathSha256"))&&packaged.path("classes").size()==HELPER_CLASSES.size());
        Path temporary=Files.createTempDirectory("kc-persistent-native-replay-");Process process=null;
        try {
            Path classes=Files.createDirectory(temporary.resolve("classes")),originals=Files.createDirectory(temporary.resolve("originals"));
            for(var entry:HELPER_CLASSES.entrySet()){var row=packaged.path("classes").path(entry.getKey());byte[] raw=Base64.getDecoder().decode(text(row,"base64"));require(entry.getValue().equals(text(row,"sha256"))&&entry.getValue().equals(hash(raw)));Files.write(classes.resolve(entry.getKey()),raw);}
            for(String name:List.of("native-client-before","native-client-after","client-scopes-before","client-scopes-after","native-user-before","native-user-after","native-user-mutant-before","user-profile-visible"))Files.write(originals.resolve(name+".json"),checked(f,files,"originals/"+name+".json"));
            Files.write(temporary.resolve("native-helper.java"),checked(f,files,"native-helper.java"));for(String name:List.of("normal-request.xml","normal-response.xml","mutant-request.xml","mutant-response.xml"))Files.write(temporary.resolve(name),checked(f,files,name));
            var jars=new ArrayList<String>();jars.add(classes.toString());var canonical=new HashMap<String,String>();
            byte[] inventory=checked(f,files,"originals/before.native-classpath.txt");require(CLASSPATH.equals(hash(inventory)));
            for(String line:new String(inventory,java.nio.charset.StandardCharsets.UTF_8).lines().toList()){var parts=line.split("  ",-1);require(parts.length==2&&parts[1].startsWith("/opt/keycloak/lib/")&&parts[0].matches("[0-9a-f]{64}"));String name="native-complete/"+parts[1].substring("/opt/keycloak/lib/".length());require(parts[0].equals(hash(checked(f,files,name))));String jar=f.resolve(name).toString();require(canonical.put(jar,parts[1])==null);jars.add(jar);}
            require(canonical.size()==471);Path executable=Path.of(System.getProperty("java.home"),"bin","java");require(Files.isExecutable(executable));
            var launch=new ProcessBuilder(executable.toString(),"-Xmx512m","-Dsamlscope.probe.source="+temporary.resolve("native-helper.java"),"-cp",String.join(java.io.File.pathSeparator,jars),"ProbeKeycloakPersistentIdentifier",temporary.toString(),
                temporary.resolve("normal-request.xml").toString(),temporary.resolve("normal-response.xml").toString(),temporary.resolve("mutant-request.xml").toString(),temporary.resolve("mutant-response.xml").toString(),temporary.resolve("report.json").toString())
                .directory(temporary.toFile()).redirectErrorStream(true).redirectOutput(temporary.resolve("process.log").toFile());launch.environment().clear();process=launch.start();require(process.waitFor(20,TimeUnit.SECONDS)&&process.exitValue()==0);
            var report=json.readTree(raw(temporary,"report.json"));for(var group:List.of(report.path("classes"),report.path("mapperClosure").path("factories")))for(var origin:group){if(origin.has("jarPath")){String name=canonical.get(text(origin,"jarPath"));require(name!=null);((ObjectNode)origin).put("jarPath",name);}}
            return report;
        }finally{if(process!=null&&process.isAlive()){process.destroyForcibly();process.waitFor(5,TimeUnit.SECONDS);}try(var paths=Files.walk(temporary)){for(var path:paths.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(path);}}
    }
    static JsonNode normalize(JsonNode report,String peer) {
        require("samlscope-keycloak-persistent-native-instrumentation-v1".equals(text(report,"schema"))&&"isolated-unchanged-native-persistent-construction-and-original-saved-state-reuse".equals(text(report,"scope"))&&HELPER.equals(text(report,"helperSha256")));
        for(String flag:List.of("nativeClassOverridden","randomnessSeededOrReplaced","signatureValidationPerformed","universalUserOpacityClaimed","verdictAdopted"))require(report.path(flag).isBoolean()&&!report.path(flag).booleanValue());
        for(String count:List.of("protocolSubmissions","credentialPosts","productSettingWrites","nativeStoreWrites"))require(report.path(count).isInt()&&report.path(count).asInt(-1)==0);
        var trace=report.path("traces").get(0);String key=PREFIX+peer,value=text(trace,"nativeValue");require("empty-construction".equals(text(trace,"mode"))&&trace.path("attributesBefore").isObject()&&trace.path("attributesBefore").isEmpty()
            &&trace.path("attributesAfter").equals(new JsonCodec().mapper().valueToTree(Map.of(key,List.of(value))))&&trace.path("setSingleAttributeEffects").equals(new JsonCodec().mapper().valueToTree(List.of(Map.of("attribute",key,"value",value))))) ;
        require(value.startsWith("G-"));var uuid=UUID.fromString(value.substring(2));require(uuid.version()==4&&uuid.variant()==2);
        var accesses=trace.path("userMethodAccesses");require(accesses.equals(new JsonCodec().mapper().valueToTree(List.of(Map.of("method","getFirstAttribute","arguments",List.of(key)),Map.of("method","getFirstAttribute","arguments",List.of(PREFIX+"*")),Map.of("method","setSingleAttribute","arguments",List.of(key,value))))));
        var normalized=report.deepCopy();var row=(ObjectNode)normalized.path("traces").get(0);row.put("nativeValue","<fresh-native-random-value>");((ArrayNode)row.path("attributesAfter").path(key)).set(0,TextNode.valueOf("<fresh-native-random-value>"));
        ((ObjectNode)row.path("setSingleAttributeEffects").get(0)).put("value","<fresh-native-random-value>");((ArrayNode)row.path("userMethodAccesses").get(2).path("arguments")).set(1,TextNode.valueOf("<fresh-native-random-value>"));return normalized;
    }
    private void verifyOrigins(Path f,JsonNode files,JsonNode report)throws Exception {
        require(report.path("classes").isArray()&&report.path("classes").size()==18&&report.path("mapperClosure").path("factories").isArray()
            &&report.path("mapperClosure").path("allConfiguredSamlScopesIncluded").asBoolean(false)&&report.path("mapperClosure").path("selectedNameIdMapperPresent").isBoolean()&&!report.path("mapperClosure").path("selectedNameIdMapperPresent").booleanValue());
        var requested=new LinkedHashMap<String,JsonNode>();
        for(var group:List.of(report.path("classes"),report.path("mapperClosure").path("factories")))for(var origin:group) {
            if(!origin.has("jarPath")){require("java.util.UUID".equals(text(origin,"class"))&&"java.base".equals(text(origin,"module")));continue;}
            String nativePath=text(origin,"jarPath"),className=text(origin,"class");require(nativePath.startsWith("/opt/keycloak/lib/"));String name="native-complete/"+nativePath.substring("/opt/keycloak/lib/".length());require(hash(checked(f,files,name)).equals(text(origin,"jarSha256")));
            require(requested.put(className,origin)==null);
        }
        var counts=new HashMap<String,Integer>();
        for(String line:new String(checked(f,files,"originals/before.native-classpath.txt"),java.nio.charset.StandardCharsets.UTF_8).lines().toList()) {
            String path=line.split("  ",-1)[1];try(var archive=new JarFile(f.resolve("native-complete/"+path.substring("/opt/keycloak/lib/".length())).toFile())) {
                for(var row:requested.entrySet()){var entry=archive.getJarEntry(row.getKey().replace('.','/')+".class");if(entry!=null){counts.merge(row.getKey(),1,Integer::sum);try(var input=archive.getInputStream(entry)){require(path.equals(text(row.getValue(),"jarPath"))&&hash(input.readAllBytes()).equals(text(row.getValue(),"classSha256")));}}}
            }
        }
        require(counts.keySet().equals(requested.keySet())&&counts.values().stream().allMatch(count->count==1));
    }
    static JsonNode stable(JsonNode snapshot){var result=((ObjectNode)snapshot).deepCopy();result.remove(List.of("runDocumentSha256","caseExecutionSha256"));return result;}
    private JsonNode node(Path f,JsonNode files,String name)throws Exception{return json.readTree(checked(f,files,name));}
    private JsonNode reply(Path f,JsonNode files,String name,String method,String path,int status)throws Exception {var record=node(f,files,"originals/"+name+".json");require(method.equals(text(record,"method"))&&record.path("status").asInt(-1)==status&&(path==null||ADMIN.concat(path).equals(text(record,"url")))&&record.path("response_base64").isTextual());byte[] bytes=Base64.getDecoder().decode(record.path("response_base64").asText());require(hash(bytes).equals(text(record,"response_sha256")));return bytes.length==0?json.nullNode():json.readTree(bytes);}
    private static byte[] request(JsonNode record)throws Exception {byte[] bytes=Base64.getDecoder().decode(text(record,"request_base64"));require(hash(bytes).equals(text(record,"request_sha256")));return bytes;}
    private static java.time.Instant at(JsonNode record){return java.time.Instant.parse(text(record,"recordedAt"));}
    private JsonNode withoutAttributes(JsonNode user){var copy=((ObjectNode)user).deepCopy();copy.remove("attributes");return copy;}
    private JsonNode attributes(JsonNode user){return user.has("attributes")?user.path("attributes"):json.createObjectNode();}
    private static String text(JsonNode n,String key){return DefaultAlgorithmPreventionEvidence.text(n,key);}
    private static String hash(byte[] bytes)throws Exception{return DefaultAlgorithmPreventionEvidence.hash(bytes);}
    private static void require(boolean value){DefaultAlgorithmPreventionEvidence.require(value);}
    private static byte[] checked(Path f,JsonNode files,String name)throws Exception {byte[] bytes=raw(f,name);require(hash(bytes).equals(text(files,name)));return bytes;}
    private static byte[] raw(Path f,String name)throws Exception {require(name!=null&&!Path.of(name).isAbsolute());Path path=f.resolve(name).toAbsolutePath().normalize();require(path.startsWith(f.toAbsolutePath().normalize())&&!path.equals(f));for(var at=path;at!=null;at=at.getParent())require(!Files.isSymbolicLink(at));require(Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS)&&Files.size(path)<=67_108_864);return Files.readAllBytes(path);}
}
