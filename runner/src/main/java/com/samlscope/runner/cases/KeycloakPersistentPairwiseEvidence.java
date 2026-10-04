package com.samlscope.runner.cases;

import static com.samlscope.runner.cases.MetadataAlgorithmEvidence.children;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.binding.RedirectSignatureVerifier;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.cert.*;
import java.time.Instant;
import java.util.*;
import java.util.function.Function;
import java.util.zip.ZipFile;
import org.w3c.dom.Element;

/** Two fresh native peers and one fresh native principal; decrypted identifiers never leave memory. */
final class KeycloakPersistentPairwiseEvidence {
    static final String CASE="IIP-SSO05-a3-idp-01", SCHEMA="samlscope-keycloak-persistent-pairwise-v1";
    private static final String TARGET="http://localhost:18180/realms/samlscope", P="urn:oasis:names:tc:SAML:2.0:protocol",
            S="urn:oasis:names:tc:SAML:2.0:assertion", MD="urn:oasis:names:tc:SAML:2.0:metadata", DS="http://www.w3.org/2000/09/xmldsig#",
            FORMAT="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", ADMIN="http://localhost:18180/admin/realms/samlscope",
            RUN="run_[0-9A-HJKMNP-TV-Z]{26}", PREFIX="saml.persistent.name.id.for.", SERVICES="213c45bb357e0881ead8284f12308e3c9fd8e09e7f0b6ec816f95f8b0921bea9";
    private static final JsonCodec JSON=new JsonCodec();
    private static final Map<String,String> PINS=Map.of(
            "org/keycloak/protocol/saml/SamlProtocol.class","4ad89b08f6d37e00a02e3cb0a4563883935f7d66b3f3bb717f9da8c316104100",
            "org/keycloak/protocol/saml/SamlService.class","9595db004ef39dfa3e560ae4817d30646c15d117dbff08737283d14f0fbc7f45",
            "org/keycloak/protocol/saml/SamlService$BindingProtocol.class","1567d07d08492c6a80587e50e1db84ce5a4aab8a32ead70f043a7b8648ce172d",
            "org/keycloak/protocol/saml/SamlClient.class","b06ad9303baf1ca1a8702604b3424cf6a82497d6eb72fb29d60ce33baa3b3fa6",
            "org/keycloak/protocol/saml/EntityDescriptorDescriptionConverter.class","f12ac7fc23ddaec03f2b0d61c47368dae8038b478a4972a66d0ff7f3415de4ec",
            "org/keycloak/protocol/saml/mappers/UserPropertyAttributeStatementMapper.class","81fedb25c98e2b14c345ac42d8f295611af797668a0deb41464dbde5486ac554",
            "org/keycloak/protocol/saml/mappers/RoleListMapper.class","7a6b4728a2819e19ddf57b0a06430cfba4ecab729aba6e0ffd04e5232b070161",
            "org/keycloak/protocol/saml/mappers/AuthnContextClassRefMapper.class","917c2f22b0c00df175357450922d6abbcd322fe26a3871579f2f77244de9de63",
            "org/keycloak/organization/protocol/mappers/saml/OrganizationMembershipMapper.class","0b8cc9e9d39f3c654d1df68567fd98480bf4021dab85165059b3df207b0ca4ad");
    private static final Map<String,Object> USERNAME_MAPPER=Map.of("name","samlscope-native-principal-username","protocol","saml","protocolMapper","saml-user-property-mapper","consentRequired",false,
            "config",Map.of("user.attribute","username","attribute.name","samlscope.native.username","attribute.nameformat","Basic"));
    private final Path directory; private final TranscriptContentReader content;
    private final Function<String,byte[]> metadata; private final SamlDecryptionKeyProvider keys;
    KeycloakPersistentPairwiseEvidence(Path directory,TranscriptContentReader content,Function<String,byte[]> metadata,SamlDecryptionKeyProvider keys) {
        this.directory=Objects.requireNonNull(directory).toAbsolutePath().normalize();this.content=Objects.requireNonNull(content);
        this.metadata=Objects.requireNonNull(metadata);this.keys=Objects.requireNonNull(keys);
    }
    boolean exists(String run){return run!=null&&run.matches(RUN)&&Files.exists(directory.resolve(run+".keycloak-pairwise.json"),LinkOption.NOFOLLOW_LINKS);}
    Optional<CaseOutcome> evaluate(CaseContext context) {
        if(!exists(context.runId()))return Optional.empty();String stage="receipt";
        try {
            require(context.transcriptComplete());var receipt=JSON.mapper().readTree(safe(directory.resolve(context.runId()+".keycloak-pairwise.json"),262144));
            require(SCHEMA.equals(text(receipt,"schema"))&&context.runId().equals(text(receipt,"runId"))&&"native-persistent-pairwise".equals(text(receipt,"campaignId")));
            var targetRaw=metadata.apply(context.runId());require(sha(targetRaw).equals(text(receipt,"targetMetadataSha256")));
            var target=SecureXml.parse(targetRaw).getDocumentElement();require(TARGET.equals(target.getAttribute("entityID"))&&MD.equals(target.getNamespaceURI()));
            var signing=MetadataAlgorithmEvidence.signingKeys(target);require(!signing.isEmpty());source(context.runId());
            var peers=receipt.path("peers");require(peers.isArray()&&peers.size()==2);
            var evidence=new LinkedHashSet<EvidenceRef>();var requestIds=new HashSet<String>();var runs=new HashSet<String>();var entities=new HashSet<String>();
            var observations=new ArrayList<Peer>();String principal=null;JsonNode freshUser=null,lastUser=null,scope=null;
            for(int i=0;i<2;i++) {
                var peer=peers.get(i);String run=text(peer,"runId"),entity=text(peer,"entityId");stage="peer-"+i;
                require(run.matches(RUN)&&runs.add(run)&&entity.matches("http://localhost:18080/p/plan_[0-9A-HJKMNP-TV-Z]{26}")&&entities.add(entity)
                        &&Arrays.equals(targetRaw,metadata.apply(run))&&(i!=0||context.runId().equals(run)));
                var history=new LinkedHashMap<String,TranscriptEntry>();for(var e:context.transcript().list(run))require(run.equals(e.runId())&&history.put(e.id(),e)==null);
                var fixture=safe(directory.resolve(context.runId()+".keycloak-pairwise").resolve(i==0?"primary.xml":"secondary.xml"),1048576);
                require(sha(fixture).equals(text(peer,"metadataSha256")));var sp=SecureXml.parse(fixture).getDocumentElement();
                require(MD.equals(sp.getNamespaceURI())&&"EntityDescriptor".equals(sp.getLocalName())&&entity.equals(sp.getAttribute("entityID"))&&children(sp,MD,"AffiliationDescriptor").isEmpty());
                var roles=children(sp,MD,"SPSSODescriptor");require(roles.size()==1);var role=roles.getFirst();var requestCertificates=certificates(role,"signing");var encryptionCertificates=certificates(role,"encryption");
                require(!requestCertificates.isEmpty()&&encryptionCertificates.size()==1);
                var initial=original(peer.path("initial"),run,entity,"initial-inventory",targetRaw,history,evidence);
                require(initial.json.path("clients").isArray()&&initial.json.path("clients").isEmpty()&&initial.json.at("/usersBefore/users").isArray()&&initial.json.at("/usersBefore/users").isEmpty());
                var creation=initial.json.path("publicUserCreation");var user=initial.json.path("userCreated");
                require(creation.path("credentialInputRetained").isBoolean()&&!creation.path("credentialInputRetained").asBoolean()&&!creation.path("native").has("requestSha256")
                        &&nativeStatus(creation.path("native"),"POST",ADMIN+"/users",201)&&creation.path("publicRecipe").path("requiredActions").isArray()&&creation.path("publicRecipe").path("requiredActions").isEmpty()
                        &&text(user,"username").equals(text(creation.path("publicRecipe"),"username")));
                require(text(user,"id").matches("[a-f0-9-]{36}")&&text(user,"username").matches("samlscope-pairwise-[a-f0-9]{20}")&&user.path("enabled").asBoolean()&&user.path("requiredActions").isEmpty()&&!user.has("credentials"));
                require(attributes(user).equals(attributes(creation.path("publicRecipe"))));
                if(freshUser==null){freshUser=user;principal=text(user,"id");}else require(freshUser.equals(user));
                var converter=original(peer.path("converter"),run,entity,"native-converter",targetRaw,history,evidence);var nativeConversion=converter.json.path("native");
                require(nativeStatus(nativeConversion,"POST",ADMIN+"/client-description-converter",200)&&sha(fixture).equals(text(nativeConversion,"requestSha256"))&&sha(fixture).equals(text(converter.json,"fixtureSha256")));
                nativeTime(nativeConversion,converter);nativeTime(creation.path("native"),initial);require(initial.entry.timestamp().isBefore(converter.entry.timestamp()));
                var converted=JSON.mapper().readTree(nativeBody(nativeConversion));require(entity.equals(text(converted,"clientId"))&&"saml".equals(text(converted,"protocol")));
                var applied=original(peer.path("application"),run,entity,"native-client-application",targetRaw,history,evidence);var application=applied.json.path("native");
                var configured=(ObjectNode)converted.deepCopy();configured.putArray("protocolMappers").add(mapperRecipe());
                require(JSON.mapper().valueToTree(USERNAME_MAPPER).equals(applied.json.path("identifyingAttributeMapper"))&&nativeStatus(application,"POST",ADMIN+"/clients",201)&&sha(fixture).equals(text(applied.json,"fixtureSha256"))&&sha(JSON.mapper().writeValueAsBytes(configured)).equals(text(application,"requestSha256")));
                nativeTime(application,applied);
                var before=original(peer.path("before"),run,entity,"operative-pairwise-state",targetRaw,history,evidence);var after=original(peer.path("after"),run,entity,"operative-pairwise-state",targetRaw,history,evidence);
                require(before.json.path("client").equals(after.json.path("client"))&&before.json.path("scope").equals(after.json.path("scope")));
                client(converted,before.json.path("client"),entity);nativeScope(before.json.path("scope"));
                if(scope==null)scope=before.json.path("scope");else require(scope.equals(before.json.path("scope")));
                var beforeUser=before.json.path("user");var afterUser=after.json.path("user");require(principal.equals(text(beforeUser,"id"))&&principal.equals(text(afterUser,"id"))&&withoutAttributes(freshUser).equals(withoutAttributes(beforeUser))&&withoutAttributes(freshUser).equals(withoutAttributes(afterUser)));
                require(i==0?freshUser.equals(beforeUser):lastUser.equals(beforeUser));
                var baseline=exchange(peer.path("baseline"),run,entity,text(user,"username"),sp,targetRaw,signing,requestCertificates,encryptionCertificates,history,requestIds,evidence,false);
                var persistent=exchange(peer.path("persistent"),run,entity,text(user,"username"),sp,targetRaw,signing,requestCertificates,encryptionCertificates,history,requestIds,evidence,true);
                require(converter.entry.timestamp().isBefore(applied.entry.timestamp())&&applied.entry.timestamp().isBefore(before.entry.timestamp())&&before.entry.timestamp().isBefore(baseline.request.timestamp())
                        &&baseline.response.timestamp().isBefore(persistent.request.timestamp())&&persistent.response.timestamp().isBefore(after.entry.timestamp()));
                // The public Admin UserRepresentation hides native unmanaged attributes. Do not
                // claim their absence. The pinned native property mapper exposes the same actual
                // UserModel.username in each verified signed/decrypted Assertion instead.
                require(beforeUser.equals(afterUser));lastUser=afterUser;
                var restore=original(peer.path("restoration"),run,entity,"restoration",targetRaw,history,evidence);
                require(after.entry.timestamp().isBefore(restore.entry.timestamp())&&restore.json.path("clients").isArray()&&restore.json.path("clients").isEmpty()
                        &&restore.json.path("users").isArray()&&restore.json.path("users").isEmpty()&&SERVICES.equals(text(restore.json,"sourceJarSha256")));
                var originalScope=initial.json.path("originalScope");
                if(originalScope.isMissingNode()){require(attributes(user).isEmpty()&&scope.equals(restore.json.path("scope")));}
                else {require(originalScope.equals(restore.json.path("scope")));nativeScope(originalScope);
                    require(Instant.parse(text(initial.json,"originalScopeCapturedAt")).isBefore(Instant.parse(text(creation.path("native"),"startedAt"))));
                    if(attributes(user).isEmpty()){require(scope.equals(originalScope)&&initial.json.path("profileControl").isNull());}
                    else {var attrs=attributes(user);require(attrs.size()==1&&attrs.path(PREFIX+"*").isArray()&&attrs.path(PREFIX+"*").size()==1&&attrs.path(PREFIX+"*").get(0).isTextual());
                        var configuredScope=(ObjectNode)originalScope.deepCopy();((ObjectNode)configuredScope.path("userProfile")).put("unmanagedAttributePolicy","ADMIN_EDIT");require(scope.equals(configuredScope));
                        var control=initial.json.path("profileControl");require(nativeStatus(control,"PUT",ADMIN+"/users/profile",200));nativeTime(control,initial);
                        require(JSON.mapper().readTree(nativeBody(control)).equals(scope.path("userProfile"))&&Instant.parse(text(initial.json,"originalScopeCapturedAt")).isBefore(Instant.parse(text(control,"startedAt")))&&Instant.parse(text(control,"finishedAt")).isBefore(Instant.parse(text(creation.path("native"),"startedAt"))));
                        var reset=restore.json.path("profileRestoration");require(nativeStatus(reset,"PUT",ADMIN+"/users/profile",200));nativeTime(reset,restore);require(after.entry.timestamp().isBefore(Instant.parse(text(reset,"startedAt")))&&JSON.mapper().readTree(nativeBody(reset)).equals(originalScope.path("userProfile")));}
                }
                observations.add(new Peer(run,entity,persistent.name,baseline.request.timestamp(),persistent.response.timestamp()));
            }
            stage="pairwise-qualifiers";
            require(observations.get(0).last.isBefore(observations.get(1).first));var violations=new ArrayList<String>();
            for(var peer:observations){var name=peer.name;if(name.hasAttribute("NameQualifier")&&!TARGET.equals(name.getAttribute("NameQualifier")))violations.add("name-qualifier");if(name.hasAttribute("SPNameQualifier")&&!peer.entity.equals(name.getAttribute("SPNameQualifier")))violations.add("sp-name-qualifier");if(name.hasAttribute("SPProvidedID"))violations.add("unexpected-sp-provided-id");}
            if(observations.get(0).name.getTextContent().equals(observations.get(1).name.getTextContent()))violations.add("non-pairwise-value");
            if(!violations.isEmpty())return Optional.of(new CaseOutcome(Outcome.VIOLATED,null,"idp.persistent-pairwise.violation","case.idp.persistent-pairwise.violation",List.copyOf(evidence),Map.of("adapter","keycloak-native-persistent-pairwise","violations",List.copyOf(violations),"same_principal_proven",true,"native_restoration_proven",true)));
            return Optional.of(new CaseOutcome(Outcome.SATISFIED,null,"idp.persistent-pairwise.observed","case.idp.persistent-pairwise.observed",List.copyOf(evidence),
                    Map.of("adapter","keycloak-native-persistent-pairwise","peer_count",2,"same_principal_proven",true,"principal_source","signed-native-username-property","secondary_run",observations.get(1).run,"native_restoration_proven",true)));
        }catch(Exception unproven){return Optional.of(new CaseOutcome(Outcome.NOT_VERIFIED,"native_pairwise_evidence_unproven","idp.persistent-pairwise.unproven","idp.persistent-pairwise.unproven",List.of(),Map.of("evidence_issue",stage)));}
    }
    private record Original(TranscriptEntry entry,JsonNode json){}
    private record Exchange(TranscriptEntry request,TranscriptEntry response,Element name){}
    private record Peer(String run,String entity,Element name,Instant first,Instant last){}
    private Original original(JsonNode ref,String run,String entity,String kind,byte[] target,Map<String,TranscriptEntry> entries,Set<EvidenceRef> evidence)throws Exception {
        var e=entries.get(text(ref,"reference"));require(e!=null&&e.direction()==Direction.INBOUND&&run.equals(e.runId()));var raw=content.readDecodedSaml(e);
        require(raw!=null&&raw.length==e.decodedSamlBytes()&&sha(raw).equals(text(ref,"sha256")));var value=JSON.mapper().readTree(raw);
        require("samlscope-keycloak-persistent-pairwise-original-v1".equals(text(value,"schema"))&&run.equals(text(value,"runId"))&&entity.equals(text(value,"peerEntityId"))&&sha(target).equals(text(value,"targetMetadataSha256"))
                &&"native-persistent-pairwise".equals(text(value,"campaignId"))&&kind.equals(text(value,"kind"))&&!Instant.parse(text(value,"recordedAt")).isAfter(e.timestamp()));
        evidence.add(new EvidenceRef("transcript",e.id()));return new Original(e,value);
    }
    private Exchange exchange(JsonNode refs,String run,String entity,String username,Element sp,byte[] target,List<X509Certificate> signing,List<X509Certificate> requestCertificates,List<X509Certificate> encryptionCertificates,
            Map<String,TranscriptEntry> entries,Set<String> requestIds,Set<EvidenceRef> evidence,boolean persistent)throws Exception {
        require(refs.path("transcript_ids").isArray()&&refs.path("transcript_ids").size()==2);var request=entries.get(refs.path("transcript_ids").get(0).asText());var response=entries.get(refs.path("transcript_ids").get(1).asText());
        require(request!=null&&response!=null&&request.direction()==Direction.OUTBOUND&&response.direction()==Direction.INBOUND&&request.timestamp().isBefore(response.timestamp()));
        var raw=content.readDecodedSaml(request);require(raw!=null&&raw.length==request.decodedSamlBytes()&&sha(raw).equals(text(refs,"requestSha256")));var authn=SecureXml.parse(raw).getDocumentElement();String id=authn.getAttribute("ID");
        require(P.equals(authn.getNamespaceURI())&&"AuthnRequest".equals(authn.getLocalName())&&requestIds.add(id)&&!id.isBlank()&&id.equals(text(refs,"requestId"))&&entity.equals(one(authn,S,"Issuer").getTextContent())&&children(authn,S,"Subject").isEmpty());
        require(requestCertificates.stream().anyMatch(c->"GET".equals(request.method())?new RedirectSignatureVerifier().isValidForMessage(request.rawQuery(),c,raw):"POST".equals(request.method())&&new XmlSignatureVerifier().hasValidEnvelopedSignature(authn,c)));
        if(persistent)require(FORMAT.equals(one(authn,P,"NameIDPolicy").getAttribute("Format"))&&"true".equals(one(authn,P,"NameIDPolicy").getAttribute("AllowCreate")));
        String recipient=authn.getAttribute("AssertionConsumerServiceURL");require(!recipient.isBlank()&&children(one(sp,MD,"SPSSODescriptor"),MD,"AssertionConsumerService").stream().anyMatch(a->recipient.equals(a.getAttribute("Location"))));
        require(id.equals(response.samlSummary().get("inResponseTo"))&&Boolean.TRUE.equals(response.samlSummary().get(persistent?"activeProbeAccepted":"normalFlowAccepted"))&&recipient.equals(response.url())
                &&entries.values().stream().filter(e->e.direction()==Direction.INBOUND&&id.equals(e.samlSummary().get("inResponseTo"))).count()==1);
        var responseRaw=content.readDecodedSaml(response);require(responseRaw!=null&&responseRaw.length==response.decodedSamlBytes());var document=SecureXml.parse(responseRaw).getDocumentElement();
        var assertion=VerifiedResponseAssertion.read(document,TARGET,signing,sp,Optional.of(new PlanCredentials(keys.keyFor(run).orElseThrow(),encryptionCertificates.getFirst())),id,recipient);
        var values=new ArrayList<String>();for(var statement:children(assertion,S,"AttributeStatement"))for(var attribute:children(statement,S,"Attribute"))if("samlscope.native.username".equals(attribute.getAttribute("Name")))for(var value:children(attribute,S,"AttributeValue"))values.add(value.getTextContent());require(values.equals(List.of(username)));
        var name=one(one(assertion,S,"Subject"),S,"NameID");require(!name.getTextContent().isBlank()&&(!persistent||FORMAT.equals(name.getAttribute("Format"))));
        evidence.add(new EvidenceRef("transcript",request.id()));evidence.add(new EvidenceRef("transcript",response.id()));return new Exchange(request,response,name);
    }
    private void source(String run)throws Exception {var path=directory.resolve(run+".keycloak-pairwise").resolve("native-services.jar");require(SERVICES.equals(sha(safe(path,33554432))));try(var zip=new ZipFile(path.toFile())){for(var pin:PINS.entrySet()){var e=zip.getEntry(pin.getKey());require(e!=null);try(var in=zip.getInputStream(e)){require(pin.getValue().equals(sha(in.readNBytes(1048577))));}}}}
    private static void nativeScope(JsonNode scope){var r=scope.path("runtime");require(r.path("running").asBoolean()&&"sha256:9d1f1b2b7261ff53c66cb1092dfcdc34a5fb77e81f9e6a6e75b8b6a795de8067".equals(text(r,"image"))&&text(r,"containerId").matches("[a-f0-9]{64}")&&text(r,"version").startsWith("Keycloak 26.7.2\n"));Instant.parse(text(r,"startedAt"));require(scope.at("/policies/policies/policies").isArray()&&scope.at("/policies/policies/policies").isEmpty()&&scope.at("/policies/profiles/profiles").isArray()&&scope.at("/policies/profiles/profiles").isEmpty());
        var expected=Map.of("role_list","saml-role-list-mapper","saml_organization","saml-organization-membership-mapper","AuthnContextClassRef","saml-authn-context-class-ref-mapper");var scopes=scope.path("samlClientScopes");require(scopes.isArray()&&scopes.size()==3);var seen=new HashSet<String>();for(var s:scopes){String name=text(s,"name");require(seen.add(name)&&expected.containsKey(name)&&"saml".equals(text(s,"protocol"))&&s.path("protocolMappers").size()==1&&expected.get(name).equals(text(s.path("protocolMappers").get(0),"protocolMapper")));var m=s.path("protocolMappers").get(0);require("saml".equals(text(m,"protocol"))&&!m.path("consentRequired").asBoolean());
        var cfg=name.equals("role_list")?Map.of("single","false","attribute.nameformat","Basic","attribute.name","Role"):Map.of();require(JSON.mapper().valueToTree(cfg).equals(m.path("config")));}}
    private static ObjectNode mapperRecipe(){var m=JSON.mapper().createObjectNode();m.put("name","samlscope-native-principal-username");m.put("protocol","saml");m.put("protocolMapper","saml-user-property-mapper");m.put("consentRequired",false);var cfg=m.putObject("config");cfg.put("user.attribute","username");cfg.put("attribute.name","samlscope.native.username");cfg.put("attribute.nameformat","Basic");return m;}
    private static void client(JsonNode converted,JsonNode saved,String entity){require(entity.equals(text(saved,"clientId"))&&"saml".equals(text(saved,"protocol"))&&saved.path("enabled").asBoolean()&&!saved.path("consentRequired").asBoolean()&&saved.path("authenticationFlowBindingOverrides").isEmpty()&&!saved.has("secret")&&!saved.has("registrationAccessToken")&&set(saved.path("defaultClientScopes")).equals(Set.of("role_list","saml_organization","AuthnContextClassRef"))&&saved.path("optionalClientScopes").isEmpty());
        var fields=converted.fields();while(fields.hasNext()){var f=fields.next();if(f.getKey().equals("attributes")){var attrs=f.getValue().fields();while(attrs.hasNext()){var a=attrs.next();require(a.getValue().equals(saved.path("attributes").get(a.getKey())));}defaults(f.getValue(),saved.path("attributes"));}else if(f.getKey().equals("redirectUris"))require(set(f.getValue()).equals(set(saved.path(f.getKey()))));else if(f.getKey().equals("protocolMappers")){require(f.getValue().isArray()&&f.getValue().isEmpty()&&saved.path("protocolMappers").size()==1);var mapper=(ObjectNode)saved.path("protocolMappers").get(0).deepCopy();require(text(mapper,"id").matches("[a-f0-9-]{36}"));mapper.remove("id");require(JSON.mapper().valueToTree(USERNAME_MAPPER).equals(mapper));}else require(f.getValue().equals(saved.get(f.getKey())));}
        require("true".equals(text(saved.path("attributes"),"saml.client.signature"))&&"true".equals(text(saved.path("attributes"),"saml.encrypt"))&&"false".equals(text(saved.path("attributes"),"saml_force_name_id_format")));
    }
    private static void defaults(JsonNode converted,JsonNode saved){var fixed=Map.of("saml.force.post.binding","true","realm_client","false","saml_force_name_id_format","false","saml_name_id_format","username","saml.allow.ecp.flow","false","saml_signature_canonicalization_method","http://www.w3.org/2001/10/xml-exc-c14n#");var fields=saved.fields();int n=0;while(fields.hasNext()){var f=fields.next();if(converted.has(f.getKey()))continue;n++;if(fixed.containsKey(f.getKey()))require(fixed.get(f.getKey()).equals(f.getValue().asText()));else if(f.getKey().equals("client.secret.creation.time"))require(f.getValue().asText().matches("[0-9]{10}"));else if(f.getKey().equals("saml.artifact.binding.identifier"))require(Base64.getDecoder().decode(f.getValue().asText()).length==20);else require(false);}require(n==8);}
    private byte[] safe(Path path,long maximum)throws Exception {require(path.normalize().startsWith(directory)&&Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS)&&Files.size(path)>0&&Files.size(path)<=maximum);for(var p=path;p!=null&&p.startsWith(directory);p=p.getParent())require(!Files.isSymbolicLink(p));return Files.readAllBytes(path);}
    private static ObjectNode attributes(JsonNode user){var attrs=user.path("attributes");require(attrs.isMissingNode()||attrs.isObject());return attrs.isMissingNode()?JSON.mapper().createObjectNode():(ObjectNode)attrs;}
    private static ObjectNode withoutAttributes(JsonNode user){var value=(ObjectNode)user.deepCopy();value.remove("attributes");return value;}
    private static void nativeTime(JsonNode nativeValue,Original original)throws Exception {var start=Instant.parse(text(nativeValue,"startedAt"));var end=Instant.parse(text(nativeValue,"finishedAt"));require(!start.isAfter(end)&&!end.isAfter(Instant.parse(text(original.json,"recordedAt")))&&!end.isAfter(original.entry.timestamp()));nativeBody(nativeValue);}
    private static boolean nativeStatus(JsonNode v,String method,String url,int status){return method.equals(text(v,"method"))&&url.equals(text(v,"url"))&&v.path("status").asInt(-1)==status;}
    private static byte[] nativeBody(JsonNode value)throws Exception {var raw=Base64.getDecoder().decode(text(value,"responseBase64"));require(sha(raw).equals(text(value,"responseSha256")));return raw;}
    private static List<X509Certificate> certificates(Element role,String use)throws Exception {var values=new ArrayList<X509Certificate>();for(var kd:children(role,MD,"KeyDescriptor")){if(!List.of("",use).contains(kd.getAttribute("use")))continue;var nodes=kd.getElementsByTagNameNS(DS,"X509Certificate");for(int i=0;i<nodes.getLength();i++)values.add((X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(Base64.getMimeDecoder().decode(nodes.item(i).getTextContent()))));}return values;}
    private static Set<String> set(JsonNode values){require(values.isArray());var result=new HashSet<String>();for(var v:values)require(v.isTextual()&&result.add(v.asText()));return result;}
    private static Element one(Element root,String ns,String name){var values=children(root,ns,name);require(values.size()==1);return values.getFirst();}
    private static String text(JsonNode node,String field){return node.path(field).asText("");}
    private static String sha(byte[] raw)throws Exception {require(raw!=null);return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
    private static void require(boolean yes){if(!yes)throw new IllegalArgumentException("Native pairwise original unproven");}
}
