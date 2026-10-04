package com.samlscope.runner.cases;

import static com.samlscope.runner.cases.MetadataAlgorithmEvidence.children;
import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.time.Instant;
import java.util.*;
import org.w3c.dom.Element;

/** Native, request-bound Chromium consent observations. Never concludes from DOM absence. */
final class SimpleSamlPhpConsentUiEvidence {
    private static final String TARGET="http://localhost:18380/idp", MD="urn:oasis:names:tc:SAML:2.0:metadata", UI="urn:oasis:names:tc:SAML:metadata:ui",
        DS="http://www.w3.org/2000/09/xmldsig#", P="urn:oasis:names:tc:SAML:2.0:protocol", S="urn:oasis:names:tc:SAML:2.0:assertion";
    private static final Map<String,String> PINS=Map.ofEntries(
        Map.entry("native-consent-controller.txt","815e1d6c3bb477fc8cdc9456de68beeab6032a2ee786c701d19fd9d5b3d1b0b6"),
        Map.entry("native-consent-filter.txt","2f7ddccbc0bf04043cf3bf0edf6785a2bbf598da25d50c1694e389c54b638a6c"),
        Map.entry("native-consent-template.txt","6dd16b4ac0084b3d3dfa7169274b5720cf9eb88af79d60ab0fc048d7b3eb3c34"),
        Map.entry("native-template.txt","b7327d4036356a044ce509041ef899e85fe599ebbcc95f647433cdfadd863160"),
        Map.entry("native-parser.txt","8620bb26fd41d2be29d2611883839a4cfde0b6c8458c274e2d40a002678fd93d"),
        Map.entry("native-auth-state.txt","59576819feb0d08c19ff34bdee6f239b8edc94e1806fc056ff83b69e6b39ec8a"),
        Map.entry("native-base-template.txt","ad2450845062951c9e8dffa9acf0bc3b065e58dbef2180218dee767816060e7d"),
        Map.entry("native-header-template.txt","621049cf3add34a1fccc82be657080fe49d0c713c8b50a0110c37f826522cafe"),
        Map.entry("native-policy-command.php","5c63d5136dd8276b117762b1c5da0482f9dd16caa09d56bcac5354dd1a70f0af"),
        Map.entry("native-state-command.php","cdcb7b281cbde1f4694b1a571bb9300b673190364d4c822575604f8c0dd3624e"),
        Map.entry("native-parser-command.php","5008495fba0e65487a4849cf46f592c577215f96d5b4f3fd87321ebc6930edf9"),
        Map.entry("native-readback-command.php","f84064049b9bc6ef0339b9b1874e86b6e36e89fe8770a502d5735200b15ed756"),
        Map.entry("collector.py","9c339615b8a0cb48e2d192648b42ed2a88d5e28de2a4d46cb8f8f16d75f35316"),
        Map.entry("browser.mjs","43ae1400ee3923e4c3385ef5e56efe67eeba4af0082b8ab74b9bc797962c6651"));
    private final Path directory; private final TranscriptContentReader content;
    SimpleSamlPhpConsentUiEvidence(Path directory,TranscriptContentReader content){this.directory=directory.toAbsolutePath().normalize();this.content=content;}
    boolean exists(String run){return run!=null&&run.matches("run_[0-9A-HJKMNP-TV-Z]{26}")&&Files.exists(directory.resolve(run),LinkOption.NOFOLLOW_LINKS);}
    Optional<CaseOutcome> evaluate(CaseContext context,byte[] targetRaw){
        if(!exists(context.runId()))return Optional.empty();
        String stage="native-consent-originals-unproven";
        try{
            require(context.transcriptComplete()&&Files.isDirectory(directory,LinkOption.NOFOLLOW_LINKS));
            Path folder=directory.resolve(context.runId());require(Files.isDirectory(folder,LinkOption.NOFOLLOW_LINKS));var manifest=json(original(folder,"manifest.json"));var files=manifest.path("files");
            require("samlscope-simplesamlphp-consent-ui-v1".equals(text(manifest,"schema"))&&context.runId().equals(text(manifest,"runId"))
                &&"metadata-ui-display-comparison".equals(text(manifest,"campaignId"))&&TARGET.equals(text(manifest,"targetEntityId"))&&hash(targetRaw).equals(text(manifest,"targetMetadataSha256")));
            for(var pin:PINS.entrySet())require(pin.getValue().equals(hash(checked(folder,files,pin.getKey()))));
            var target=SecureXml.parse(targetRaw).getDocumentElement();require(TARGET.equals(target.getAttribute("entityID")));var targetCert=certificate(one(one(one(children(one(target,MD,"IDPSSODescriptor"),MD,"KeyDescriptor").stream().filter(e->!"encryption".equals(e.getAttribute("use"))).findFirst().orElseThrow(),DS,"KeyInfo"),DS,"X509Data"),DS,"X509Certificate").getTextContent());
            var identity=json(checked(folder,files,"identity-before.json"));require(identity.equals(json(checked(folder,files,"identity-after.json")))&&identity.path("running").asBoolean(false)
                &&"sha256:9ae050473c68ce13c5451839cb64257eaa17be3a4d2c9a3f87996bbe0cebb0aa".equals(text(identity,"imageId")));
            var restore=json(checked(folder,files,"restoration.json"));var baseline=new HashMap<String,byte[]>();for(var label:List.of("remote","hosted","override")){
                byte[] raw=checked(folder,files,label+"-original.php");require(Arrays.equals(raw,checked(folder,files,label+"-final.php"))&&restore.path(label).path("restored").asBoolean(false)
                    &&hash(raw).equals(text(restore.path(label),"original_sha256"))&&hash(raw).equals(text(restore.path(label),"final_sha256")));baseline.put(label,raw);}
            var created=json(checked(folder,files,"created.json")).path("run");require(context.runId().equals(text(created,"id")));String entity="http://localhost:18080/p/"+text(created,"planId");
            var transcript=new HashMap<String,TranscriptEntry>();for(var entry:context.transcript().list(context.runId()))require(context.runId().equals(entry.runId())&&transcript.put(entry.id(),entry)==null);
            var observations=json(checked(folder,files,"native-ui-observations.json"));require(context.runId().equals(text(observations,"runId"))&&!observations.path("productVerdictAssigned").asBoolean(true)&&observations.path("observations").size()==4);
            var http=json(checked(folder,files,"native-http-observations.json"));require(context.runId().equals(text(http,"runId"))&&!http.path("productVerdictAssigned").asBoolean(true)&&http.path("records").size()==8);
            var operation=json(checked(folder,files,"operations.json"));require(operation.size()==4&&operation.findValuesAsText("status").stream().allMatch("correlated-success"::equals));
            require(manifest.path("conditions").size()==4);var variants=new HashSet<String>();var samples=new ArrayList<UiDisplayComparison.Sample>();var policies=new HashSet<JsonNode>();
            for(var row:manifest.path("conditions")){
                String variant=text(row,"variant");require(variants.add(variant)&&Set.of("control","ui-consumer-display-all","ui-consumer-display-service","ui-consumer-display-entity").contains(variant));
                stage="native-consent-condition-"+variant;
                var prepared=entry(transcript,row,"metadataReference","MetadataPrepared",Direction.OUTBOUND,variant);var fetch=entry(transcript,row,"fetchReference","MetadataFetch",Direction.INBOUND,variant);
                require(fetch.id().equals(prepared.samlSummary().get("fetchTranscriptId"))&&!prepared.timestamp().isBefore(fetch.timestamp()));
                byte[] fixture=checked(folder,files,variant+".fixture.xml");require(Arrays.equals(fixture,content.readDecodedSaml(prepared))&&hash(fixture).equals(prepared.samlSummary().get("metadataSha256")));
                var metadata=SecureXml.parse(fixture).getDocumentElement();require(entity.equals(metadata.getAttribute("entityID")));var role=one(metadata,MD,"SPSSODescriptor");
                var suiteCert=certificate(one(one(one(one(metadata,DS,"Signature"),DS,"KeyInfo"),DS,"X509Data"),DS,"X509Certificate").getTextContent());require(new XmlSignatureVerifier().hasValidEnvelopedSignature(metadata,suiteCert));
                var parsed=json(checked(folder,files,variant+".parser.stdout"));require(entity.equals(text(parsed,"entity_id"))&&parsed.path("validate_authnrequest").asBoolean(false)&&checked(folder,files,variant+".parser.stderr").length==0);
                byte[] expected=(new String(baseline.get("remote"),StandardCharsets.UTF_8)+"\n"+text(parsed,"php")+"\n").getBytes(StandardCharsets.UTF_8);
                JsonNode active=null;for(var phase:List.of("before","after")){
                    require(Arrays.equals(expected,checked(folder,files,variant+"."+phase+".remote.php")));
                    for(var label:List.of("hosted","override"))require(Arrays.equals(checked(folder,files,"control.before."+label+".php"),checked(folder,files,variant+"."+phase+"."+label+".php")));
                    var policy=json(checked(folder,files,variant+"."+phase+".policy.json"));require(TARGET.equals(text(policy,"entityId"))&&policy.path("consentEnabled").asBoolean(false)
                        &&"default".equals(text(policy,"theme"))&&"en".equals(text(policy,"defaultLanguage"))&&"consent:Consent".equals(text(policy.path("authproc").path("90"),"class"))
                        &&"uid".equals(text(policy.path("authproc").path("90"),"identifyingAttribute")));policies.add(policy);
                    var readback=json(checked(folder,files,variant+"."+phase+".metadata.json"));require(entity.equals(text(readback,"entityId"))&&hash(expected).equals(text(readback,"remoteSha256"))&&readback.path("metadata").path("validate.authnrequest").asBoolean(false));
                    if(active==null)active=readback.path("metadata");else require(active.equals(readback.path("metadata")));
                }
                stage="native-consent-requests-"+variant;
                var positive=entry(transcript,row.path("positive"),"requestReference","AuthnRequest",Direction.OUTBOUND,variant);var negative=entry(transcript,row.path("negative"),"requestReference","AuthnRequest",Direction.OUTBOUND,variant);
                require(!MetadataProbeCorrelation.signatureControl(positive)&&MetadataProbeCorrelation.signatureControl(negative)&&prepared.timestamp().isBefore(positive.timestamp()));
                var requested=SecureXml.parse(content.readDecodedSaml(positive)).getDocumentElement();String requestId=requested.getAttribute("ID");require(requestId.equals(positive.samlSummary().get("id"))&&entity.equals(one(requested,S,"Issuer").getTextContent())&&positive.url().equals(requested.getAttribute("Destination"))
                    &&new XmlSignatureVerifier().hasValidEnvelopedSignature(requested,suiteCert));
                var rejected=SecureXml.parse(content.readDecodedSaml(negative)).getDocumentElement();require(new XmlSignatureVerifier().hasValidEnvelopedReferenceDigests(rejected)&&!new XmlSignatureVerifier().hasValidEnvelopedSignature(rejected,suiteCert));
                stage="native-consent-response-"+variant;
                var response=entry(transcript,row.path("positive"),"responseReference","Response",Direction.INBOUND,variant);var responded=SecureXml.parse(content.readDecodedSaml(response)).getDocumentElement();require(requestId.equals(responded.getAttribute("InResponseTo"))&&TARGET.equals(one(responded,S,"Issuer").getTextContent())
                    &&children(role,MD,"AssertionConsumerService").stream().anyMatch(e->e.getAttribute("Location").equals(responded.getAttribute("Destination")))
                    &&"urn:oasis:names:tc:SAML:2.0:status:Success".equals(one(one(responded,P,"Status"),P,"StatusCode").getAttribute("Value"))&&new XmlSignatureVerifier().hasValidEnvelopedSignature(responded,targetCert));
                stage="native-consent-negative-control-"+variant;
                String rejectedId=rejected.getAttribute("ID");JsonNode rejection=null;for(var item:http.path("records"))if(rejectedId.equals(text(item,"request_id"))){require(rejection==null);rejection=item;}
                require(rejection!=null&&"signature-value-invalid".equals(text(rejection,"native_signature_rejection"))&&rejection.path("response_status").asInt()==500
                    &&hash(content.readDecodedSaml(negative)).equals(text(rejection,"request_sha256"))&&hash(checked(folder,files,"native-http-originals."+rejectedId+".html")).equals(text(rejection,"response_body_sha256")));
                for(var entry:transcript.values())if(entry.direction()==Direction.INBOUND&&"Response".equals(entry.samlSummary().get("type")))require(!rejectedId.equals(SecureXml.parse(content.readDecodedSaml(entry)).getDocumentElement().getAttribute("InResponseTo")));
                stage="native-consent-public-state-"+variant;
                JsonNode observed=null;for(var item:observations.path("observations"))if(requestId.equals(text(item,"requestId"))){require(observed==null);observed=item;}
                require(observed!=null&&observed.path("bodySanitized").asBoolean(false)&&observed.path("status").asInt()==200&&"en-US".equals(text(observed,"preferredLanguage")));
                var stateRaw=checked(folder,files,variant+".ui."+requestId+".state.json");var state=json(stateRaw);require(hash(stateRaw).equals(text(observed,"stateSha256"))&&requestId.equals(text(state,"requestId"))
                    &&TARGET.equals(text(state,"sourceEntityId"))&&active.equals(state.path("destination"))&&text(state,"stateIdSha256").equals(text(observed,"stateIdSha256")));
                stage="native-consent-browser-"+variant;
                var browserRaw=checked(folder,files,variant+".ui."+requestId+".browser.json");var browser=json(browserRaw);require(hash(browserRaw).equals(text(observed,"browserSha256"))&&"chromium".equals(text(browser,"browser"))&&"http://localhost:18380".equals(text(browser,"origin"))
                    &&browser.path("status").asInt()==200&&"en-US".equals(text(browser,"preferredLanguage")));
                byte[] html=checked(folder,files,variant+".ui."+requestId+".html");require(hash(html).equals(text(observed,"bodySha256"))&&new String(html,StandardCharsets.UTF_8).contains("id=\"consent-yes\""));
                Instant observedAt=Instant.parse(text(browser,"recordedAt"));require(positive.timestamp().isBefore(observedAt)&&observedAt.isBefore(response.timestamp())&&Instant.parse(metadata.getAttribute("validUntil")).isAfter(observedAt));
                Instant configurationBefore=Instant.parse(text(json(checked(folder,files,variant+".before.observed.json")),"recordedAt")),configurationAfter=Instant.parse(text(json(checked(folder,files,variant+".after.observed.json")),"recordedAt"));
                require(!negative.timestamp().isBefore(configurationBefore)&&negative.timestamp().isBefore(positive.timestamp())&&!configurationAfter.isBefore(response.timestamp()));
                if(!"control".equals(variant)){
                    var condition=switch(variant){case "ui-consumer-display-all"->UiDisplayComparison.Condition.ALL;case "ui-consumer-display-service"->UiDisplayComparison.Condition.SERVICE;default->UiDisplayComparison.Condition.ENTITY;};
                    var displays=role.getElementsByTagNameNS(UI,"DisplayName");var services=role.getElementsByTagNameNS(MD,"ServiceName");require(displays.getLength()==(condition==UiDisplayComparison.Condition.ALL?1:0)&&services.getLength()==(condition==UiDisplayComparison.Condition.ENTITY?0:1));
                    var candidates=new HashMap<String,UiDisplayComparison.Selection>();candidates.put(entity,UiDisplayComparison.Selection.ENTITY);String service=null;
                    if(displays.getLength()>0)candidates.put(displays.item(0).getTextContent(),UiDisplayComparison.Selection.DISPLAY);
                    if(services.getLength()>0){service=services.item(0).getTextContent();candidates.put(service,UiDisplayComparison.Selection.SERVICE);}
                    String first=text(browser,"firstParagraph"),header=text(browser,"attributeHeader");var chosen=candidates.entrySet().stream().filter(e->first.equals(e.getKey()+" requires that the information below is transferred.")&&header.equals("Information that will be sent to "+e.getKey())).map(Map.Entry::getValue).findFirst().orElse(UiDisplayComparison.Selection.UNOBSERVED);
                    String fixed=new JsonCodec().mapper().writeValueAsString(UiDisplayEvidenceFile.fixedMetadata(metadata,variant,context.runId()));
                    samples.add(new UiDisplayComparison.Sample(context.runId(),entity,condition,hash((entity+policies.iterator().next().toString()+fixed).getBytes(StandardCharsets.UTF_8)),hash(fixture),service,positive.timestamp(),observedAt,chosen,
                        List.of(new EvidenceRef("transcript",fetch.id()),new EvidenceRef("transcript",prepared.id()),new EvidenceRef("transcript",positive.id()),new EvidenceRef("browser-observation",context.runId()+"/"+variant+".ui."+requestId+".browser.json"))));
                }
            }
            require(variants.size()==4&&policies.size()==1);var compared=UiDisplayComparison.evaluate(samples,List.of());var refs=new ArrayList<>(compared.evidence());refs.add(new EvidenceRef("native-consent-ui",context.runId()+"/manifest.json"));
            return Optional.of(new CaseOutcome(compared.outcome(),compared.notVerifiedReason(),compared.reasonCode(),compared.reasonMessageKey(),List.copyOf(refs),compared.details()));
        }catch(Exception incomplete){return Optional.of(UiDisplayComparison.evaluate(List.of(),List.of(stage)));}
    }
    private static TranscriptEntry entry(Map<String,TranscriptEntry> entries,JsonNode row,String field,String type,Direction direction,String variant){var value=entries.get(text(row,field));require(value!=null&&value.direction()==direction&&type.equals(value.samlSummary().get("type"))&&("Response".equals(type)||variant.equals(value.samlSummary().get("variant"))));return value;}
    private static Element one(Element root,String ns,String name){var values=children(root,ns,name);require(values.size()==1);return values.getFirst();}
    private static X509Certificate certificate(String value)throws Exception{return (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(Base64.getMimeDecoder().decode(value)));}
    private static byte[] checked(Path folder,JsonNode files,String name)throws Exception{var raw=original(folder,name);require(hash(raw).equals(files.path(name).asText()));return raw;}
    private static byte[] original(Path folder,String name)throws Exception{require(name.matches("[A-Za-z0-9._-]+")&&!Set.of(".","..").contains(name));Path file=folder.resolve(name);require(Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS)&&Files.size(file)<4194304);return Files.readAllBytes(file);}
    private static JsonNode json(byte[] raw)throws Exception{return new JsonCodec().mapper().readTree(raw);}
    private static String text(JsonNode node,String field){var value=node.path(field);require(value.isTextual()&&!value.asText().isBlank());return value.asText();}
    private static String hash(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
    private static void require(boolean value){if(!value)throw new IllegalArgumentException("Native consent observation unproven");}
}
