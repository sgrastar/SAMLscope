package com.samlscope.runner.cases;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.*;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import com.samlscope.saml.metadata.TargetMetadataParser;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import java.util.function.Function;
import org.w3c.dom.Element;

/** Actual selected UserPassBase stage, read before credentials; never infers access from AuthnInstant. */
final class SimpleSamlPhpForceAuthnMechanismEvidence implements NativeForceAuthnMechanismEvidence {
    static final String SCHEMA="samlscope-simplesamlphp-forceauthn-mechanism-v1";
    static final String REASON="idp.force-authn.mechanism-reachability.native-proven";
    private static final String PROTOCOL="urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String ASSERTION="urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String IMAGE="sha256:9ae050473c68ce13c5451839cb64257eaa17be3a4d2c9a3f87996bbe0cebb0aa";
    private static final String COMMAND="a5cf582fbabbbe5c4d0838567e0cd0e1468a74c5442eab86c81f917c88582b5a";
    private static final String COLLECTOR="31d6b96fc16d01e469350c62269755bec80c7249bb5e9d256a145e4697645452";
    private static final Map<String,String> SOURCES=Map.of(
        "idp-saml2","ae55fc922431d29ca6e87654ae2071500a4c3d7185ed80a6fcc5b26eed12495d",
        "idp","313760d280f557ffbba61fd4622fbf7e9892b21425d8d24d26d9f08eb9312888",
        "auth-source","5e58ab08d8d03d6720b1bade592119e353fdf8ac1f96a97234575234e57a58d0",
        "userpass","8465e71fabec88578369eaf780dfe86c6ab3f0f2cdf4b24eb52bf134918f9b48",
        "userpass-base","cb69bac6366c580fd3dd41dcdae37831119cecc8897b62d0b8d22efd129f2169",
        "login-controller","56fd31e89b2272e56b08861fc748704a96d0772c3fc4635f11f54967463c8ed5",
        "auth-state","59576819feb0d08c19ff34bdee6f239b8edc94e1806fc056ff83b69e6b39ec8a");
    private final Path directory;
    private final TranscriptContentReader content;
    private final Function<String,byte[]> metadata;
    private final Function<String,String> profiles;
    private final ObjectMapper json=new JsonCodec().mapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
        .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    SimpleSamlPhpForceAuthnMechanismEvidence(Path directory,TranscriptContentReader content,
            Function<String,byte[]> metadata,Function<String,String> profiles) {
        this.directory=Objects.requireNonNull(directory).toAbsolutePath().normalize();
        this.content=Objects.requireNonNull(content);this.metadata=Objects.requireNonNull(metadata);this.profiles=Objects.requireNonNull(profiles);
    }
    private Path folder(String run){return directory.resolve(run+".simplesamlphp-forceauthn-mechanism");}
    public boolean exists(String run){return run!=null&&run.matches("run_[0-9A-HJKMNP-TV-Z]{26}")
        &&Files.exists(folder(run),LinkOption.NOFOLLOW_LINKS);}
    public NativeForceAuthnMechanismEvidence withKeys(SamlDecryptionKeyProvider ignored){return this;}
    public Optional<CaseOutcome> read(CaseContext context) {
        if(!exists(context.runId()))return Optional.empty();String stage="originals";
        try {
            require(context.transcriptComplete()&&context.targetRole()==com.samlscope.core.plan.TargetRole.IDP
                &&"browser_sso_idp".equals(profiles.apply(context.runId())));
            Path f=folder(context.runId());byte[] raw=original(f,"manifest.json");var m=json.readTree(raw);
            require(SCHEMA.equals(text(m,"schema"))&&context.runId().equals(text(m,"runId"))
                &&IdpForceAuthnScenarioTestCase.MECHANISM_ACCESS_CASE.equals(text(m,"caseId"))
                &&"native-authentication-mechanism".equals(text(m,"campaignId")));
            var requiredFiles=new HashSet<String>();
            requiredFiles.addAll(List.of("collector.py","native-state-command.php","profile.json","scope-before.json",
                "native-mechanism-observations.json","native-http-observations.json","mechanism-operation-counts.json",
                "target-metadata.xml","suite-sp-metadata.xml","created.json","native-configuration.json","restoration.json",
                "restoration-resolution-readback.json","original-sp-config.php","final-sp-config.php","configured-sp-config.php",
                "fixture.xml","operation-counts.json"));
            for(String source:SOURCES.keySet()){requiredFiles.add("native-"+source+".php");requiredFiles.add("native-"+source+"-after.php");}
            for(String phase:List.of("start","end")){requiredFiles.add("target-container-inspect-"+phase+".json");requiredFiles.add("target-runtime-"+phase+".json");}
            for(String label:List.of("baseline","forced"))for(String suffix:List.of(".html",".request.xml",".request.body"))requiredFiles.add(label+suffix);
            var files=m.path("files");require(files.isObject()&&files.size()==requiredFiles.size());var names=files.fieldNames();
            while(names.hasNext()){String name=names.next();require(requiredFiles.remove(name)&&hash(original(f,name)).equals(text(files,name)));}
            require(requiredFiles.isEmpty());
            require(COLLECTOR.equals(hash(original(f,"collector.py")))&&COMMAND.equals(hash(original(f,"native-state-command.php"))));
            byte[] target=metadata.apply(context.runId());require(Arrays.equals(target,original(f,"target-metadata.xml"))
                &&hash(target).equals(text(m,"targetMetadataSha256")));
            String entity=text(m,"targetEntityId"),requester=text(m,"requesterEntityId");
            var targetKeys=new TargetMetadataParser().parse(target,entity).signingCertificates();
            var requesterKeys=new TargetMetadataParser().parse(original(f,"suite-sp-metadata.xml"),requester).signingCertificates();
            require(!targetKeys.isEmpty()&&!requesterKeys.isEmpty());
            var created=json.readTree(original(f,"created.json"));require(context.runId().equals(created.path("run").path("id").asText())
                &&text(m,"planId").equals(created.path("run").path("planId").asText())
                &&requester.endsWith("/p/"+text(m,"planId")));
            var scope=json.readTree(original(f,"scope-before.json"));require(text(scope,"case").equals(text(m,"caseId"))
                &&"sha256:7642c77cfa0d640d1cc6baf96d91301709754a1a4597db479114c855e26bd671".equals(scope.path("caseDigests").path(text(m,"caseId")).asText())
                &&hash(original(f,"profile.json")).equals(text(scope,"profileSha256")));
            var profile=json.readTree(original(f,"profile.json"));int planned=0;
            for(var c:profile.path("cases"))if(text(m,"caseId").equals(c.path("id").asText())){
                require(scope.path("caseDigests").path(text(m,"caseId")).asText().equals(c.path("digest").asText()));planned++;}
            require(planned==1);
            stage="native-code-and-runtime";
            for(var source:SOURCES.entrySet()){byte[] before=original(f,"native-"+source.getKey()+".php");
                require(source.getValue().equals(hash(before))&&Arrays.equals(before,original(f,"native-"+source.getKey()+"-after.php")));}
            var before=json.readTree(original(f,"target-container-inspect-start.json"));var after=json.readTree(original(f,"target-container-inspect-end.json"));
            require(before.equals(after)&&before.size()==1&&IMAGE.equals(before.get(0).path("Image").asText())
                &&before.get(0).path("State").path("Running").asBoolean());
            for(String phase:List.of("start","end")){var runtime=json.readTree(original(f,"target-runtime-"+phase+".json"));
                require(IMAGE.equals(runtime.path("binding").path("image_id").asText())
                    &&hash(original(f,"target-container-inspect-"+phase+".json")).equals(runtime.path("docker_inspect_sha256").asText())
                    &&"2.5.0".equals(runtime.path("runtime_version").path("value").asText()));}
            stage="configuration-and-restoration";
            var restoration=json.readTree(original(f,"restoration.json"));var configured=json.readTree(original(f,"native-configuration.json"));
            byte[] original=original(f,"original-sp-config.php"),finalState=original(f,"final-sp-config.php");
            require(restoration.path("restored").isBoolean()&&restoration.path("restored").asBoolean()
                &&restoration.path("failures").isArray()&&restoration.path("failures").isEmpty()
                &&Arrays.equals(original,finalState)&&hash(original).equals(text(restoration,"original_sha256"))
                &&hash(finalState).equals(text(restoration,"final_sha256"))
                &&hash(original(f,"configured-sp-config.php")).equals(text(restoration,"configured_sha256"))
                &&text(restoration,"configured_sha256").equals(text(configured,"configured_sha256"))
                &&requester.equals(text(configured,"requester_entity"))&&configured.path("validate_authnrequest").asBoolean()
                &&hash(original(f,"fixture.xml")).equals(text(configured,"fixture_sha256")));
            var restoredResolution=json.readTree(original(f,"restoration-resolution-readback.json"));
            require(restoredResolution.path("entity_absent").isBoolean()&&restoredResolution.path("entity_absent").asBoolean()
                &&text(restoredResolution,"result").startsWith("UNRESOLVED SimpleSAML\\Error\\MetadataNotFound"));
            var observations=json.readTree(original(f,"native-mechanism-observations.json")).path("observations");
            var records=json.readTree(original(f,"native-http-observations.json")).path("records");
            require(observations.isArray()&&observations.size()==3&&records.isArray()&&records.size()==4);
            var history=new HashMap<String,TranscriptEntry>();for(var e:context.transcript().list(context.runId()))
                require(context.runId().equals(e.runId())&&history.put(e.id(),e)==null);
            stage="signed-requests-and-mechanism-state";var refs=new ArrayList<EvidenceRef>();String mechanism=null;
            for(String label:List.of("baseline","forced")){
                stage=label+"-request-correlation";
                boolean force=label.equals("forced");var row=m.path(label);var out=history.get(text(row,"requestReference"));var in=history.get(text(row,"responseReference"));
                require(out!=null&&in!=null&&out.direction()==Direction.OUTBOUND&&in.direction()==Direction.INBOUND
                    &&out.timestamp().isBefore(in.timestamp())&&"IIP-IDP06-a-idp-01".equals(out.samlSummary().get("scenario_case_id")));
                byte[] requestBytes=content.readDecodedSaml(out),responseBytes=content.readDecodedSaml(in);
                require(hash(requestBytes).equals(text(row,"requestSha256"))&&hash(responseBytes).equals(text(row,"responseSha256")));
                var request=SecureXml.parse(requestBytes).getDocumentElement();var response=SecureXml.parse(responseBytes).getDocumentElement();
                require(PROTOCOL.equals(request.getNamespaceURI())&&"AuthnRequest".equals(request.getLocalName())
                    &&force=="true".equals(request.getAttribute("ForceAuthn"))&&!"true".equals(request.getAttribute("IsPassive"))
                    &&requester.equals(issuer(request))&&entity.equals(issuer(response))
                    &&PROTOCOL.equals(response.getNamespaceURI())&&"Response".equals(response.getLocalName())
                    &&request.getAttribute("ID").equals(response.getAttribute("InResponseTo"))
                    &&request.getAttribute("AssertionConsumerServiceURL").equals(response.getAttribute("Destination")));
                var signature=new XmlSignatureVerifier();require(requesterKeys.stream().anyMatch(k->signature.hasValidEnvelopedSignature(request,k))
                    &&targetKeys.stream().anyMatch(k->signature.hasValidEnvelopedSignature(response,k)));
                stage=label+"-native-state";
                var statuses=response.getElementsByTagNameNS(PROTOCOL,"StatusCode");require(statuses.getLength()>=1
                    &&"urn:oasis:names:tc:SAML:2.0:status:Success".equals(((Element)statuses.item(0)).getAttribute("Value")));
                var states=new ArrayList<JsonNode>();for(var observation:observations)
                    if(request.getAttribute("ID").equals(observation.path("state").path("requestId").asText()))states.add(observation);
                require(states.size()==1);var observation=states.getFirst();var state=observation.path("state");
                require(state.path("forceAuthn").isBoolean()&&state.path("isPassive").isBoolean()&&!state.path("isPassive").asBoolean()
                    &&state.path("stateHandlePersisted").isBoolean()&&!state.path("stateHandlePersisted").asBoolean()
                    &&state.path("credentialsPersisted").isBoolean()&&!state.path("credentialsPersisted").asBoolean()
                    &&observation.path("stateHandlePersisted").isBoolean()&&!observation.path("stateHandlePersisted").asBoolean()
                    &&"SimpleSAML\\Module\\exampleauth\\Auth\\Source\\UserPass".equals(text(state,"mechanismClass"))
                    &&"SimpleSAML\\Module\\core\\Auth\\UserPassBase".equals(text(state,"declaringClass"))
                    &&"\\SimpleSAML\\Module\\core\\Auth\\UserPassBase.state".equals(text(state,"stateStage"))
                    &&SOURCES.get("userpass-base").equals(text(state,"mechanismSourceSha256"))
                    &&request.getAttribute("AssertionConsumerServiceURL").equals(text(state,"consumerURL"))
                    &&request.getAttribute("ProtocolBinding").equals(text(state,"binding")));
                String selected=text(state,"mechanismId");if(mechanism==null)mechanism=selected;require(mechanism.equals(selected));
                var comparison=new NativeMechanismStateComparison.Observation(request.getAttribute("ID"),force,
                    text(state,"requestId"),state.path("forceAuthn").booleanValue(),mechanism,selected);
                require(NativeMechanismStateComparison.compare(comparison)==Outcome.SATISFIED);
                Instant observed=Instant.parse(text(observation,"recordedAt"));require(out.timestamp().isBefore(observed)&&observed.isBefore(in.timestamp()));
                stage=label+"-native-http-originals";
                var matches=new ArrayList<JsonNode>();for(var record:records)if(request.getAttribute("ID").equals(record.path("request_id").asText()))matches.add(record);
                require(matches.size()==1);var record=matches.getFirst();
                require(hash(requestBytes).equals(text(record,"request_sha256"))&&record.path("response_status").asInt()==200
                    &&text(record,"response_url").endsWith("/core/loginuserpass")
                    &&Instant.parse(text(record,"observed_at")).isBefore(observed)
                    &&text(record,"request_url").equals(request.getAttribute("Destination"))
                    &&hash(original(f,label+".request.xml")).equals(hash(requestBytes))
                    &&hash(original(f,label+".request.body")).equals(text(record,"request_body_sha256"))
                    &&hash(original(f,label+".html")).equals(text(record,"persisted_body_sha256")));
                if(force){require(NativeMechanismStateComparison.compare(new NativeMechanismStateComparison.Observation(
                    comparison.requestId(),true,comparison.stateRequestId(),null,mechanism,selected))==Outcome.VIOLATED);
                    require(NativeMechanismStateComparison.compare(new NativeMechanismStateComparison.Observation(
                    comparison.requestId(),true,comparison.stateRequestId(),false,mechanism,selected))==Outcome.VIOLATED);
                    require(NativeMechanismStateComparison.compare(new NativeMechanismStateComparison.Observation(
                    comparison.requestId(),true,"unrelated",true,mechanism,selected))==Outcome.NOT_VERIFIED);}
                refs.add(new EvidenceRef("transcript",out.id()));refs.add(new EvidenceRef("transcript",in.id()));
            }
            refs.add(new EvidenceRef("native-force-authn-mechanism",context.runId()+".simplesamlphp-forceauthn-mechanism/manifest.json#"+hash(raw)));
            var details=new LinkedHashMap<String,Object>();details.put("evidence_adapter",SCHEMA);details.put("run_id",context.runId());
            details.put("approved_mode","ATTESTED");details.put("attested",false);details.put("scope","selected-native-password-mechanism-login-stage");
            details.put("selected_mechanism",mechanism);details.put("native_state_observed_before_credentials",true);
            details.put("configuration_restored",true);details.put("native_code_unchanged",true);details.put("authentication_instant_inference",false);
            details.put("counterfactual_controls",List.of("missing-indicator","lost-true-indicator","unrelated-state"));
            details.put("counterfactual_controls_are_product_behavior",false);
            return Optional.of(new CaseOutcome(Outcome.SATISFIED,null,REASON,REASON,refs,details));
        }catch(Exception unavailable){return Optional.of(new CaseOutcome(Outcome.NOT_VERIFIED,"native_mechanism_reachability_unproven",
            "idp.force-authn.mechanism-reachability.unproven","idp.force-authn.mechanism-reachability.unproven",List.of(),Map.of("evidence_adapter",SCHEMA,"stage",stage)));}
    }
    private static String issuer(Element root){for(var n=root.getFirstChild();n!=null;n=n.getNextSibling())
        if(n instanceof Element e&&ASSERTION.equals(e.getNamespaceURI())&&"Issuer".equals(e.getLocalName()))return e.getTextContent();return "";}
    static byte[] original(Path folder,String name)throws Exception {
        require(name!=null&&name.matches("[A-Za-z0-9_.-]+")&&!name.equals(".")&&!name.equals(".."));
        for(Path p=folder;p!=null;p=p.getParent())require(!Files.isSymbolicLink(p));
        Path file=folder.resolve(name);require(Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS)&&Files.size(file)<=4_194_304);return Files.readAllBytes(file);
    }
    static String hash(byte[] bytes)throws Exception{return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(bytes));}
    static String text(JsonNode value,String key){var n=value.path(key);require(n.isTextual()&&!n.textValue().isBlank());return n.textValue();}
    static void require(boolean value){if(!value)throw new IllegalArgumentException("Native mechanism evidence unproven");}
}
