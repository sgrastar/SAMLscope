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
final class SimpleSamlPhpConsentUriEvidence {
    private static final String TARGET="http://localhost:18380/idp", MD="urn:oasis:names:tc:SAML:2.0:metadata", UI="urn:oasis:names:tc:SAML:metadata:ui",
        DS="http://www.w3.org/2000/09/xmldsig#", P="urn:oasis:names:tc:SAML:2.0:protocol", S="urn:oasis:names:tc:SAML:2.0:assertion";
    private static final Map<String,String> PINS=Map.ofEntries(
        Map.entry("native-assertion.txt","b935848a17dcfdb4c113618d3460dd1aa1645118f75876dce90ea92d97d33003"),
        Map.entry("native-attribute-limit.txt","e3dbf076807713125373a0cf6ab2495e9181685dbd5d29b7344bc31a748f361f"),
        Map.entry("native-auth-processing.txt","e6d5023490fbc94dc1a743bb5105f1d093f4eec0a8c48fe030353029e7ea5c5d"),
        Map.entry("native-auth-source.txt","5e58ab08d8d03d6720b1bade592119e353fdf8ac1f96a97234575234e57a58d0"),
        Map.entry("native-auth-state.txt","59576819feb0d08c19ff34bdee6f239b8edc94e1806fc056ff83b69e6b39ec8a"),
        Map.entry("native-authentication-policy-command.php","a5801c78f58f96e114e9e76a7e87c3efdf5f59d936bb14787a4e96ff4a949a18"),
        Map.entry("native-authentication-state-command.php","f3bf3a3f462dd658794b6472cc6bafc1723c3e84beb0f285dbb20616072b3759"),
        Map.entry("native-base-script.txt","3740001aa99872d77d11fb06613ea23d7f896d63d69491a2fa5cb977d4cefe32"),
        Map.entry("native-base-stylesheet.txt","dca29391ef3ba31e42ef5527305889a11a3f707389f4c678ef8dbaa886e78469"),
        Map.entry("native-base-template.txt","ad2450845062951c9e8dffa9acf0bc3b065e58dbef2180218dee767816060e7d"),
        Map.entry("native-configuration.txt","53837359cd60433082d3968843605a864bab97f23be482447bcfef37e7f6946e"),
        Map.entry("native-consent-controller.txt","815e1d6c3bb477fc8cdc9456de68beeab6032a2ee786c701d19fd9d5b3d1b0b6"),
        Map.entry("native-consent-filter.txt","2f7ddccbc0bf04043cf3bf0edf6785a2bbf598da25d50c1694e389c54b638a6c"),
        Map.entry("native-consent-stylesheet.txt","170a8eb7f876cb5217776728d8494483c5c4038c7e9959ed479441e0bee31930"),
        Map.entry("native-consent-template.txt","6dd16b4ac0084b3d3dfa7169274b5720cf9eb88af79d60ab0fc048d7b3eb3c34"),
        Map.entry("native-core-base-template.txt","b997f9c0e741eb40cbbc2ab00d637545e515cba61f58d3c3c45edf134380210b"),
        Map.entry("native-footer-image.txt","22d9aab5c4f5bcdfc6132d231404fc328a81138e94c3610c8aba70331346b8e1"),
        Map.entry("native-footer-template.txt","ca1b88e479336d8fba9b03a43d6c5588af43fdf0f43f15ef1461400e53bf8ae5"),
        Map.entry("native-header-template.txt","621049cf3add34a1fccc82be657080fe49d0c713c8b50a0110c37f826522cafe"),
        Map.entry("native-idp-saml2.txt","ae55fc922431d29ca6e87654ae2071500a4c3d7185ed80a6fcc5b26eed12495d"),
        Map.entry("native-idp.txt","313760d280f557ffbba61fd4622fbf7e9892b21425d8d24d26d9f08eb9312888"),
        Map.entry("native-language-adaptor.txt","f74d170f691a90b5281e77dabfbb026db2ec4eae5ee57a6badf990544622a7ba"),
        Map.entry("native-login-controller.txt","56fd31e89b2272e56b08861fc748704a96d0772c3fc4635f11f54967463c8ed5"),
        Map.entry("native-login-template.txt","7dfdfdadc33fd4b8a305c0cb5bdfddcc8127374c848f9224575545781863b171"),
        Map.entry("native-logo-model.txt","92bf891b2fa7e34f10a3bcc0dc8b2f445265829ca27cbe29c5f8fd7c955db02d"),
        Map.entry("native-message.txt","ab017ee6cf9fb66db1037e40ed50feff0b277b1a5d43fd8ca774a3d27ce355d2"),
        Map.entry("native-module-entry.txt","66a0b632dc183c053389f79dbeed3ef775a8d2a26b48108090ef92de79a56ae0"),
        Map.entry("native-noconsent-template.txt","3811b9ca2ca4cc02a6d012e49ec2febbc7983a0ce61c7aabed7b05941836bbe8"),
        Map.entry("native-parser-command.php","5008495fba0e65487a4849cf46f592c577215f96d5b4f3fd87321ebc6930edf9"),
        Map.entry("native-parser.txt","8620bb26fd41d2be29d2611883839a4cfde0b6c8458c274e2d40a002678fd93d"),
        Map.entry("native-policy-command.php","5d0b80c0f5664cb6505b5e9b4573d8c6e0df5f445242bb002473e7e65ec7ce58"),
        Map.entry("native-readback-command.php","f84064049b9bc6ef0339b9b1874e86b6e36e89fe8770a502d5735200b15ed756"),
        Map.entry("native-response.txt","27d7f1d4a5ea73b22107b7615c230b156f3dcaa012e843f380d879f53826a64a"),
        Map.entry("native-security-configuration.txt","53837359cd60433082d3968843605a864bab97f23be482447bcfef37e7f6946e"),
        Map.entry("native-state-command.php","cdcb7b281cbde1f4694b1a571bb9300b673190364d4c822575604f8c0dd3624e"),
        Map.entry("native-subject-confirmation-data.txt","79ab1c7623b0fa5c0507c55541afdae4e533f35c5664049541c0500220fca048"),
        Map.entry("native-subject-confirmation.txt","40746d3785ee55fa4999d49cd19c32625e415d0a37e0f193508138485a5a6a0e"),
        Map.entry("native-table-template.txt","3cb7cac88eb54c7adf17b803a2abc660c6cc47b637023af490ba3e9824e9c061"),
        Map.entry("native-template-loader.txt","77a9931f897429de28f75f98a9a61144b2dba6f365b58df10bab8701d5a1c73b"),
        Map.entry("native-template.txt","b7327d4036356a044ce509041ef899e85fe599ebbcc95f647433cdfadd863160"),
        Map.entry("native-ui-privacy.py","944e9a5345e4c714740bdbf87d69cbb61015d0cd37b8ac61a7109a929851ab05"),
        Map.entry("native-uiinfo-model.txt","78c685a2b15fa441d7bf98043e89c9517109d752accc19204ea86cf94b8d5903"),
        Map.entry("native-userpass-base.txt","cb69bac6366c580fd3dd41dcdae37831119cecc8897b62d0b8d22efd129f2169"),
        Map.entry("native-userpass.txt","8465e71fabec88578369eaf780dfe86c6ab3f0f2cdf4b24eb52bf134918f9b48"),
        Map.entry("native-web-browser-sso.txt","47ddeecace975b77645aa91a4b4551429dc60d02dc1b9baa6c633c30bf1e75f4"),
        Map.entry("native-xml-signer.txt","5845e28158c7641d5ce1e6b9205e8005b6d9c090e1888ea46416abb8fdf0018d"),
        Map.entry("collector.py","83788a8f58ec898ab366583ee026be53c801c0c79bc80b9a6ec8c9c512d6be21"),
        Map.entry("browser.mjs","6f1e521061823fe9294eb4c4064cc42792da0751e6564f949481d20b406ebed9"));
    private final Path directory; private final TranscriptContentReader content;
    SimpleSamlPhpConsentUriEvidence(Path directory,TranscriptContentReader content){this.directory=directory.toAbsolutePath().normalize();this.content=content;}
    boolean exists(String run){return run!=null&&run.matches("run_[0-9A-HJKMNP-TV-Z]{26}")&&Files.exists(directory.resolve(run),LinkOption.NOFOLLOW_LINKS);}
    Optional<CaseOutcome> evaluate(CaseContext context,byte[] targetRaw){return evaluate(context,targetRaw,false);}
    Optional<CaseOutcome> evaluateDiscovery(CaseContext context,byte[] targetRaw){return evaluate(context,targetRaw,true);}
    private Optional<CaseOutcome> evaluate(CaseContext context,byte[] targetRaw,boolean discovery){
        if(!exists(context.runId()))return Optional.empty();
        String stage="native-consent-originals-unproven";
        try{
            require(context.transcriptComplete()&&Files.isDirectory(directory,LinkOption.NOFOLLOW_LINKS));
            Path folder=directory.resolve(context.runId());require(Files.isDirectory(folder,LinkOption.NOFOLLOW_LINKS));var manifest=json(original(folder,"manifest.json"));var files=manifest.path("files");
            require("samlscope-simplesamlphp-consent-uri-v1".equals(text(manifest,"schema"))&&context.runId().equals(text(manifest,"runId"))
                &&"metadata-ui-uri-policy".equals(text(manifest,"campaignId"))&&TARGET.equals(text(manifest,"targetEntityId"))&&hash(targetRaw).equals(text(manifest,"targetMetadataSha256")));
            for(var pin:PINS.entrySet()){
                byte[] original=checked(folder,files,pin.getKey());require(pin.getValue().equals(hash(original)));
                if(pin.getKey().startsWith("native-")&&pin.getKey().endsWith(".txt"))require(Arrays.equals(original,checked(folder,files,pin.getKey().replace(".txt","-after.txt"))));
            }
            var target=SecureXml.parse(targetRaw).getDocumentElement();require(TARGET.equals(target.getAttribute("entityID")));var targetCert=certificate(one(one(one(children(one(target,MD,"IDPSSODescriptor"),MD,"KeyDescriptor").stream().filter(e->!"encryption".equals(e.getAttribute("use"))).findFirst().orElseThrow(),DS,"KeyInfo"),DS,"X509Data"),DS,"X509Certificate").getTextContent());
            var identity=json(checked(folder,files,"identity-before.json"));require(identity.equals(json(checked(folder,files,"identity-after.json")))&&identity.path("running").asBoolean(false)
                &&"sha256:9ae050473c68ce13c5451839cb64257eaa17be3a4d2c9a3f87996bbe0cebb0aa".equals(text(identity,"imageId")));
            var restore=json(checked(folder,files,"restoration.json"));var baseline=new HashMap<String,byte[]>();for(var label:List.of("remote","hosted","override")){
                byte[] raw=checked(folder,files,label+"-original.php");require(Arrays.equals(raw,checked(folder,files,label+"-final.php"))&&restore.path(label).path("restored").asBoolean(false)
                    &&hash(raw).equals(text(restore.path(label),"original_sha256"))&&hash(raw).equals(text(restore.path(label),"final_sha256")));baseline.put(label,raw);}
            var created=json(checked(folder,files,"created.json")).path("run");require(context.runId().equals(text(created,"id")));String entity="http://localhost:18080/p/"+text(created,"planId");
            var transcript=new HashMap<String,TranscriptEntry>();for(var entry:context.transcript().list(context.runId())){
                require(context.runId().equals(entry.runId())&&entry.id().matches("tx_[0-9A-HJKMNP-TV-Z]{26}")&&transcript.put(entry.id(),entry)==null);
                if(entry.decodedSamlRef()!=null)require(("transcripts/"+context.runId()+"/"+entry.id()+".saml.xml").equals(entry.decodedSamlRef())&&content.readDecodedSaml(entry)!=null&&entry.decodedSamlBytes()==content.readDecodedSaml(entry).length);
            }
            var observations=json(checked(folder,files,"native-ui-observations.json"));require(context.runId().equals(text(observations,"runId"))&&!observations.path("productVerdictAssigned").asBoolean(true)&&observations.path("observations").size()==16);
            var http=json(checked(folder,files,"native-http-observations.json"));require(context.runId().equals(text(http,"runId"))&&!http.path("productVerdictAssigned").asBoolean(true)&&http.path("records").size()==32);
            var operation=json(checked(folder,files,"operations.json"));require(operation.size()==16&&operation.findValuesAsText("status").stream().allMatch("correlated-success"::equals));
            require(manifest.path("conditions").size()==16);var variants=new HashSet<String>();var refs=new ArrayList<EvidenceRef>();var policies=new HashSet<JsonNode>();var fixedInputs=new HashSet<String>();var samples=new ArrayList<UiUrlComparison.Sample>();
            for(var row:manifest.path("conditions")){
                String variant=text(row,"variant");require(variants.add(variant)&&("control".equals(variant)||variant.matches("ui-url-(logo|information|privacy)-(http|https|data|javascript|file)")));
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
                        &&policy.path("themeController").isNull()&&!policy.path("optionalHeadExists").asBoolean(true)&&"default".equals(text(policy,"theme"))&&"en".equals(text(policy,"defaultLanguage"))&&"consent:Consent".equals(text(policy.path("authproc").path("90"),"class"))
                        &&policy.path("authproc").size()==1&&"uid".equals(text(policy.path("authproc").path("90"),"identifyingAttribute"))&&policy.path("authproc").path("90").path("includeValues").isBoolean()&&!policy.path("authproc").path("90").path("includeValues").asBoolean(true));policies.add(policy);
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
                String rejectedHtml=new String(checked(folder,files,"native-http-originals."+rejectedId+".html"),StandardCharsets.UTF_8);
                require(rejectedHtml.contains("NOTVALIDCERTSIGNATURE")&&rejectedHtml.replace("\\/","/").contains(entity)&&rejection.path("redirect_hops").asInt(-1)==0
                    &&negative.url().equals(text(rejection,"request_url"))&&negative.url().equals(text(rejection,"response_url"))&&rejection.path("response_url_exact_match").asBoolean(false));
                byte[] submitted=checked(folder,files,"native-http-originals."+rejectedId+".request.body");require(hash(submitted).equals(text(rejection,"request_body_sha256"))
                    &&Arrays.equals(checked(folder,files,"native-http-originals."+rejectedId+".request.xml"),content.readDecodedSaml(negative)));
                byte[] submittedSaml=null;for(String part:new String(submitted,StandardCharsets.UTF_8).split("&")){String[] pair=part.split("=",2);if("SAMLRequest".equals(java.net.URLDecoder.decode(pair[0],StandardCharsets.UTF_8))){require(pair.length==2&&submittedSaml==null);submittedSaml=Base64.getDecoder().decode(java.net.URLDecoder.decode(pair[1],StandardCharsets.UTF_8));}}
                require(Arrays.equals(submittedSaml,content.readDecodedSaml(negative))&&Instant.parse(text(rejection,"observed_at")).isAfter(Instant.parse(text(rejection,"started_at")))&&Instant.parse(text(rejection,"observed_at")).isBefore(positive.timestamp()));
                for(var entry:transcript.values())if(entry.direction()==Direction.INBOUND&&"Response".equals(entry.samlSummary().get("type")))require(!rejectedId.equals(SecureXml.parse(content.readDecodedSaml(entry)).getDocumentElement().getAttribute("InResponseTo")));
                stage="native-consent-public-state-"+variant;
                JsonNode observed=null;for(var item:observations.path("observations"))if(requestId.equals(text(item,"requestId"))){require(observed==null);observed=item;}
                require(observed!=null&&observed.path("bodySanitized").asBoolean(false)&&observed.path("status").asInt()==200&&"en-US".equals(text(observed,"preferredLanguage")));
                var stateRaw=checked(folder,files,variant+".ui."+requestId+".state.json");var state=json(stateRaw);require(hash(stateRaw).equals(text(observed,"stateSha256"))&&requestId.equals(text(state,"requestId"))
                    &&TARGET.equals(text(state,"sourceEntityId"))&&active.equals(state.path("destination"))&&text(state,"stateIdSha256").equals(text(observed,"stateIdSha256")));
                require(state.equals(json(checked(folder,files,variant+".ui."+requestId+".state-after.json")))&&hash(checked(folder,files,variant+".ui."+requestId+".state-after.json")).equals(text(observed,"stateAfterSha256")));
                stage="native-consent-browser-"+variant;
                var browserRaw=checked(folder,files,variant+".ui."+requestId+".browser.json");var browser=json(browserRaw);require(hash(browserRaw).equals(text(observed,"browserSha256"))&&"chromium".equals(text(browser,"browser"))&&"http://localhost:18380".equals(text(browser,"origin"))
                    &&browser.path("status").asInt()==200&&"en-US".equals(text(browser,"preferredLanguage")));
                byte[] html=checked(folder,files,variant+".ui."+requestId+".html");require(hash(html).equals(text(observed,"bodySha256"))&&new String(html,StandardCharsets.UTF_8).contains("id=\"consent-yes\""));
                Instant observedAt=Instant.parse(text(browser,"recordedAt"));require(positive.timestamp().isBefore(observedAt)&&observedAt.isBefore(response.timestamp())&&Instant.parse(metadata.getAttribute("validUntil")).isAfter(observedAt));
                Instant configurationBefore=Instant.parse(text(json(checked(folder,files,variant+".before.observed.json")),"recordedAt")),configurationAfter=Instant.parse(text(json(checked(folder,files,variant+".after.observed.json")),"recordedAt"));
                require(!negative.timestamp().isBefore(configurationBefore)&&negative.timestamp().isBefore(positive.timestamp())&&!configurationAfter.isBefore(response.timestamp()));
                require("campaign-shared-browser".equals(text(browser,"browserInstance"))&&browser.path("observationIndex").asInt(-1)==observationIndex(variant));
                noLogoBrowser(browser,folder,files);
                String service=variant.equals("control")?entity:"SAMLscope URL policy control";
                require(text(browser,"firstParagraph").equals(service+" requires that the information below is transferred.")&&text(browser,"attributeHeader").equals("Information that will be sent to "+service));
                if(!"control".equals(variant)){
                    var condition=condition(variant);String candidate=urlInputs(metadata,active,condition);
                    var fixed=noUrlFixedMetadata(metadata,variant,context.runId());fixedInputs.add(new JsonCodec().mapper().writeValueAsString(fixed));
                    var use=condition.element()==UiUrlComparison.Element.LOGO?UiUrlComparison.Use.VERIFIED_NONUSE:nativeLinkUse(browser,candidate,condition,observedAt);
                    var provenance=new ArrayList<EvidenceRef>(List.of(new EvidenceRef("transcript",fetch.id()),new EvidenceRef("transcript",prepared.id()),new EvidenceRef("transcript",positive.id()),new EvidenceRef("browser-observation",context.runId()+"/"+variant+".ui."+requestId+".browser.json")));
                    if(use==UiUrlComparison.Use.VERIFIED_NONUSE)provenance.add(new EvidenceRef("native-ui-policy",context.runId()+"/"+variant+".before.policy.json"));
                    samples.add(new UiUrlComparison.Sample(context.runId(),entity,condition,hash(new JsonCodec().mapper().writeValueAsBytes(fixed)),hash(fixture),positive.timestamp(),observedAt,use,List.copyOf(provenance)));
                }
            }
            var counts=json(checked(folder,files,"operation-counts.json"));require(counts.path("credentialPosts").asInt(-1)==1&&counts.path("chromeLaunches").asInt(-1)==1&&counts.path("browserObservations").asInt(-1)==16&&counts.path("browserObservationAttempts").asInt(-1)==16&&counts.path("protocolOperationsAttempted").asInt(-1)==32&&counts.path("nativeParserInvocations").asInt(-1)==16&&counts.path("humanOperations").asInt(-1)==0&&counts.path("productRestarts").asInt(-1)==0&&counts.path("restored").asBoolean(false));
            require(variants.size()==16&&policies.size()==1&&fixedInputs.size()==1);
            if(discovery)return Optional.of(noDiscovery(context,folder,files,manifest,transcript,entity,samples));
            return Optional.of(UiUrlComparison.evaluate(List.copyOf(samples),List.of()));
        }catch(Exception incomplete){if(Boolean.getBoolean("samlscope.nativeConsentUri.debug"))incomplete.printStackTrace();return Optional.of(UiUrlComparison.evaluate(List.of(),List.of(stage)));}
    }
    private CaseOutcome noDiscovery(CaseContext context,Path folder,JsonNode files,JsonNode manifest,Map<String,TranscriptEntry> transcript,String entity,List<UiUrlComparison.Sample> samples)throws Exception{
        JsonNode fixed=null;for(var row:manifest.path("conditions")){
            String variant=text(row,"variant");JsonNode before=json(checked(folder,files,variant+".before.authentication-policy.json")),after=json(checked(folder,files,variant+".after.authentication-policy.json"));require(before.equals(after));
            require(TARGET.equals(text(before,"targetEntityId"))&&entity.equals(text(before,"spEntityId"))&&"a1b218b29003289e01e4154a9d5d7cbffa33a3b9629057d0ae51d652d0393cf3".equals(text(before,"configSha256"))&&"ea23df120a13b50435b97c71e1aa5c5194fe619e3d2eeeb24ce9a09cb44c99ad".equals(text(before,"authsourceSha256"))&&!before.path("proxyAuthnContext").asBoolean(true));
            require(before.path("authsource").equals(json("{\"id\":\"example-userpass\",\"class\":\"exampleauth:UserPass\",\"authproc\":null}".getBytes(StandardCharsets.UTF_8)))&&before.path("globalAuthproc").equals(json("{\"30\":\"core:LanguageAdaptor\",\"50\":\"core:AttributeLimit\",\"99\":\"core:LanguageAdaptor\"}".getBytes(StandardCharsets.UTF_8))));
            require(before.path("metadataSources").equals(json("[{\"type\":\"flatfile\"}]".getBytes(StandardCharsets.UTF_8)))&&"example-userpass".equals(text(before.path("hosted"),"auth"))&&before.path("hosted").path("authproc").size()==1&&"consent:Consent".equals(text(before.path("hosted").path("authproc").path("90"),"class"))&&!before.path("peer").has("authproc"));
            require(before.path("hosted").equals(json(checked(folder,files,"control.before.authentication-policy.json")).path("hosted")));
            var readback=json(checked(folder,files,variant+".before.metadata.json"));require(before.path("peer").equals(readback.path("metadata")));
            if(fixed==null)fixed=before.path("hosted");else require(fixed.equals(before.path("hosted")));
        }
        var control=manifest.path("conditions").get(0);require("control".equals(text(control,"variant")));var positive=entry(transcript,control.path("positive"),"requestReference","AuthnRequest",Direction.OUTBOUND,"control");var response=entry(transcript,control.path("positive"),"responseReference","Response",Direction.INBOUND,"control");
        String requestId=SecureXml.parse(content.readDecodedSaml(positive)).getDocumentElement().getAttribute("ID");var observations=json(checked(folder,files,"native-authentication-observations.json"));require(context.runId().equals(text(observations,"runId"))&&!observations.path("productVerdictAssigned").asBoolean(true)&&observations.path("observations").size()==1);
        var challenge=observations.path("observations").get(0);var state=challenge.path("state");require(!challenge.path("stateHandlePersisted").asBoolean(true)&&!challenge.path("credentialSubmitted").asBoolean(true)&&"/simplesaml/module.php/core/loginuserpass".equals(text(challenge,"urlPath"))&&requestId.equals(text(state,"requestId")));
        require(state.path("responder").equals(json("[\"\\\\SimpleSAML\\\\Module\\\\saml\\\\IdP\\\\SAML2\",\"sendResponse\"]".getBytes(StandardCharsets.UTF_8)))&&state.path("returnCall").isNull()&&!state.path("forceAuthn").asBoolean(true)&&!state.path("isPassive").asBoolean(true));
        var policy=json(checked(folder,files,"control.before.authentication-policy.json"));require(state.path("idpMetadata").equals(policy.path("hosted"))&&state.path("spMetadata").equals(policy.path("peer"))&&"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".equals(text(state,"binding")));
        Instant at=Instant.parse(text(challenge,"recordedAt"));require(positive.timestamp().isBefore(at)&&at.isBefore(response.timestamp()));
        String html=new String(checked(folder,files,"native-http-originals."+requestId+".html"),StandardCharsets.UTF_8);require(html.contains("name=\"username\"")&&html.contains("name=\"password\"")&&html.contains("name=\"AuthState\"")&&!html.matches("(?s).*name=[\"']password[\"'][^>]*value=[\"'][^\"']+.*"));
        var refs=new ArrayList<EvidenceRef>();for(var sample:samples)refs.addAll(sample.evidence());refs.add(new EvidenceRef("native-discovery-policy",context.runId()+"/manifest.json"));refs.add(new EvidenceRef("transcript",positive.id()));refs.add(new EvidenceRef("transcript",response.id()));
        return new CaseOutcome(Outcome.SATISFIED_WITH_NOTE,null,"browser.ui-native-feature.no-discovery-ui","browser.ui-native-feature.no-discovery-ui",List.copyOf(refs),Map.of("product","simplesamlphp","native_password_authentication",true,"scope","this-run-stock-native-password-authsource-and-effective-configuration","no_discovery_ui",true,"custom_php_capability_asserted",false));
    }
    private static void noLogoBrowser(JsonNode browser,Path folder,JsonNode files)throws Exception{
        require("/simplesaml/module.php/consent/noconsent".equals(text(browser.path("noConsent"),"path")));
        for(var view:List.of(browser,browser.path("noConsent"))){
            var images=view.path("images");require(images.isArray()&&images.size()==1);var image=images.get(0);
            require(text(image,"src").matches("/simplesaml/assets/base/icons/ssplogo-fish-small\\.png(?:\\?tag=[0-9]+)?")&&"Small fish logo".equals(text(image,"alt"))&&image.path("naturalWidth").asInt(-1)==60&&image.path("naturalHeight").asInt(-1)==41);
        }
        var resources=browser.path("resources");require(resources.isArray());var observed=new HashSet<String>();
        var required=Map.of("/simplesaml/assets/base/css/stylesheet.css","native-base-stylesheet.txt","/simplesaml/module.php/consent/assets/css/consent.css","native-consent-stylesheet.txt","/simplesaml/assets/base/js/bundle.js","native-base-script.txt","/simplesaml/assets/base/icons/ssplogo-fish-small.png","native-footer-image.txt");
        for(var resource:resources){String path=text(resource,"path");if(required.containsKey(path)){require(resource.path("status").asInt(-1)==200&&hash(checked(folder,files,required.get(path))).equals(text(resource,"sha256"))&&checked(folder,files,required.get(path)).length==resource.path("bytes").asInt(-1));observed.add(path);}}
        require(observed.equals(required.keySet()));
    }
    static UiUrlComparison.Condition condition(String variant){String[] parts=variant.split("-");require(parts.length==4&&"ui".equals(parts[0])&&"url".equals(parts[1]));return new UiUrlComparison.Condition(UiUrlComparison.Element.valueOf(parts[2].toUpperCase(Locale.ROOT)),UiUrlComparison.Scheme.valueOf(parts[3].toUpperCase(Locale.ROOT)));}
    private static int observationIndex(String variant){if(variant.equals("control"))return 1;var c=condition(variant);return 2+c.element().ordinal()*5+c.scheme().ordinal();}
    private static String name(UiUrlComparison.Element element){return switch(element){case LOGO->"Logo";case INFORMATION->"InformationURL";case PRIVACY->"PrivacyStatementURL";};}
    private static String urlInputs(Element metadata,JsonNode active,UiUrlComparison.Condition condition)throws Exception{
        var info=one(one(one(metadata,MD,"SPSSODescriptor"),MD,"Extensions"),UI,"UIInfo");require(children(info,UI,"DisplayName").size()==1&&"SAMLscope URL policy control".equals(one(info,UI,"DisplayName").getTextContent())&&"en".equals(one(info,UI,"DisplayName").getAttributeNS("http://www.w3.org/XML/1998/namespace","lang")));
        String selected=name(condition.element());for(String other:List.of("Logo","InformationURL","PrivacyStatementURL"))require(children(info,UI,other).size()==(selected.equals(other)?1:0));var node=one(info,UI,selected);String candidate=node.getTextContent();require(condition.scheme().name().toLowerCase(Locale.ROOT).equals(java.net.URI.create(candidate).getScheme()));
        if(condition.element()==UiUrlComparison.Element.LOGO){require("180".equals(node.getAttribute("width"))&&"48".equals(node.getAttribute("height")));var logo=active.path("UIInfo").path("Logo");require(logo.size()==1&&candidate.equals(text(logo.get(0),"url"))&&logo.get(0).path("width").asInt()==180&&logo.get(0).path("height").asInt()==48);}else require(candidate.equals(text(active.path("UIInfo").path(selected),"en")));
        return candidate;
    }
    static Object noUrlFixedMetadata(Element original,String variant,String run){
        var metadata=(Element)original.cloneNode(true);require(metadata.getElementsByTagNameNS(UI,"DisplayName").getLength()==1&&metadata.getElementsByTagNameNS(MD,"ServiceName").getLength()==0);var info=one(one(one(metadata,MD,"SPSSODescriptor"),MD,"Extensions"),UI,"UIInfo");
        for(String child:List.of("Logo","InformationURL","PrivacyStatementURL"))for(var node:children(info,UI,child))info.removeChild(node);
        require("SAMLscope URL policy control".equals(one(info,UI,"DisplayName").getTextContent()));
        var certificates=metadata.getElementsByTagNameNS(DS,"X509Certificate");require(certificates.getLength()>0);for(int i=0;i<certificates.getLength();i++)certificates.item(i).setTextContent("independently-verified-condition-certificate");
        return UiDisplayEvidenceFile.fixedMetadata(metadata,variant,run);
    }
    static UiUrlComparison.Use nativeLinkUse(JsonNode browser,String candidate,UiUrlComparison.Condition condition,Instant observedAt){
        var link=browser.path("nativeLinkUse");String element=name(condition.element());require(element.equals(text(link,"element"))&&candidate.equals(text(link,"href"))&&"only-exact-fixture-url-network;native-state-pages-unmodified".equals(text(browser,"transportAbortPolicy")));
        var anchor=SecureXml.parse(text(link,"anchorOuterHtml").getBytes(StandardCharsets.UTF_8)).getDocumentElement();require("a".equals(anchor.getTagName())&&candidate.equals(anchor.getAttribute("href")));
        String expectedLabel=condition.element()==UiUrlComparison.Element.INFORMATION?"Go to information page for the service":"Privacy policy for the service SAMLscope URL policy control";
        require(expectedLabel.equals(anchor.getTextContent().strip().replaceAll("\\s+"," ")));
        String pagePath=condition.element()==UiUrlComparison.Element.INFORMATION?"/simplesaml/module.php/consent/noconsent":"/simplesaml/module.php/consent/getconsent";require(pagePath.equals(text(link,"pagePath")));
        Instant clicked=Instant.parse(text(link,"clickedAt")),completed=Instant.parse(text(link,"completedAt"));require(!completed.isBefore(clicked)&&!observedAt.isBefore(completed));
        boolean used=false;for(var request:browser.path("urlRequests"))if(candidate.equals(text(request,"url"))){Instant at=Instant.parse(text(request,"recordedAt"));require(!at.isBefore(clicked)&&!at.isAfter(completed)&&"GET".equals(text(request,"method")));used=true;}
        for(var navigation:browser.path("urlNavigations"))if(candidate.equals(text(navigation,"url"))){Instant at=Instant.parse(text(navigation,"recordedAt"));require(!at.isBefore(clicked)&&!at.isAfter(completed));used=true;}
        for(var open:browser.path("urlWindowOpens"))if(candidate.equals(text(open,"url"))){Instant at=Instant.parse(text(open,"recordedAt"));require(!at.isBefore(clicked)&&!at.isAfter(completed)&&open.path("userGesture").asBoolean(false)&&"native-chromium-page-window-open".equals(text(open,"source")));used=true;}
        // Browser rejection is evidence of an actual native link attempt, never of filtering/nonuse.
        if(condition.scheme()==UiUrlComparison.Scheme.JAVASCRIPT)for(var block:browser.path("nativeSecurityBlocks")){Instant at=Instant.parse(text(block,"recordedAt"));String source=text(block,"source"),message=text(block,"message");if(!at.isBefore(clicked)&&!at.isAfter(completed)&&source.startsWith("native-")&&message.toLowerCase(Locale.ROOT).contains("javascript")&&message.toLowerCase(Locale.ROOT).contains("policy"))used=true;}
        if(Set.of(UiUrlComparison.Scheme.FILE,UiUrlComparison.Scheme.DATA).contains(condition.scheme()))for(var diagnostic:browser.path("urlConsole")){Instant at=Instant.parse(text(diagnostic,"recordedAt"));String message=text(diagnostic,"message");if(!at.isBefore(clicked)&&!at.isAfter(completed)&&message.contains(candidate)&&(message.toLowerCase(Locale.ROOT).contains("not allowed")||message.toLowerCase(Locale.ROOT).contains("local resource")))used=true;}
        return used?UiUrlComparison.Use.USED:UiUrlComparison.Use.UNOBSERVED;
    }
    private static TranscriptEntry entry(Map<String,TranscriptEntry> entries,JsonNode row,String field,String type,Direction direction,String variant){var value=entries.get(text(row,field));require(value!=null&&value.direction()==direction&&type.equals(value.samlSummary().get("type"))&&("Response".equals(type)||variant.equals(value.samlSummary().get("variant"))));return value;}
    private static Element one(Element root,String ns,String name){var values=children(root,ns,name);require(values.size()==1);return values.getFirst();}
    private static X509Certificate certificate(String value)throws Exception{return (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(Base64.getMimeDecoder().decode(value)));}
    private static byte[] checked(Path folder,JsonNode files,String name)throws Exception{var raw=original(folder,name);require(hash(raw).equals(files.path(name).asText()));return raw;}
    private static byte[] original(Path folder,String name)throws Exception{require(name.matches("[A-Za-z0-9._-]+")&&!Set.of(".","..").contains(name));Path file=folder.resolve(name);for(Path ancestor=file;ancestor!=null;ancestor=ancestor.getParent())require(!Files.isSymbolicLink(ancestor));require(Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS)&&Files.size(file)<4194304);return Files.readAllBytes(file);}
    private static JsonNode json(byte[] raw)throws Exception{return new JsonCodec().mapper().readTree(raw);}
    private static String text(JsonNode node,String field){var value=node.path(field);require(value.isTextual()&&!value.asText().isBlank());return value.asText();}
    private static String hash(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
    private static void require(boolean value){if(!value)throw new IllegalArgumentException("Native consent observation unproven");}
}
