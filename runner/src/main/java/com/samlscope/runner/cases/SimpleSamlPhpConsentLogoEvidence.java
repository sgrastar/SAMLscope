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
final class SimpleSamlPhpConsentLogoEvidence {
    private static final String TARGET="http://localhost:18380/idp", MD="urn:oasis:names:tc:SAML:2.0:metadata", UI="urn:oasis:names:tc:SAML:metadata:ui",
        DS="http://www.w3.org/2000/09/xmldsig#", P="urn:oasis:names:tc:SAML:2.0:protocol", S="urn:oasis:names:tc:SAML:2.0:assertion";
    private static final Map<String,String> PINS=Map.ofEntries(
        Map.entry("native-auth-state.txt","59576819feb0d08c19ff34bdee6f239b8edc94e1806fc056ff83b69e6b39ec8a"),
        Map.entry("native-base-script.txt","3740001aa99872d77d11fb06613ea23d7f896d63d69491a2fa5cb977d4cefe32"),
        Map.entry("native-base-stylesheet.txt","dca29391ef3ba31e42ef5527305889a11a3f707389f4c678ef8dbaa886e78469"),
        Map.entry("native-base-template.txt","ad2450845062951c9e8dffa9acf0bc3b065e58dbef2180218dee767816060e7d"),
        Map.entry("native-consent-controller.txt","815e1d6c3bb477fc8cdc9456de68beeab6032a2ee786c701d19fd9d5b3d1b0b6"),
        Map.entry("native-consent-filter.txt","2f7ddccbc0bf04043cf3bf0edf6785a2bbf598da25d50c1694e389c54b638a6c"),
        Map.entry("native-consent-stylesheet.txt","170a8eb7f876cb5217776728d8494483c5c4038c7e9959ed479441e0bee31930"),
        Map.entry("native-consent-template.txt","6dd16b4ac0084b3d3dfa7169274b5720cf9eb88af79d60ab0fc048d7b3eb3c34"),
        Map.entry("native-core-base-template.txt","b997f9c0e741eb40cbbc2ab00d637545e515cba61f58d3c3c45edf134380210b"),
        Map.entry("native-footer-image.txt","22d9aab5c4f5bcdfc6132d231404fc328a81138e94c3610c8aba70331346b8e1"),
        Map.entry("native-footer-template.txt","ca1b88e479336d8fba9b03a43d6c5588af43fdf0f43f15ef1461400e53bf8ae5"),
        Map.entry("native-header-template.txt","621049cf3add34a1fccc82be657080fe49d0c713c8b50a0110c37f826522cafe"),
        Map.entry("native-idp-saml2.txt","ae55fc922431d29ca6e87654ae2071500a4c3d7185ed80a6fcc5b26eed12495d"),
        Map.entry("native-login-controller.txt","56fd31e89b2272e56b08861fc748704a96d0772c3fc4635f11f54967463c8ed5"),
        Map.entry("native-login-template.txt","7dfdfdadc33fd4b8a305c0cb5bdfddcc8127374c848f9224575545781863b171"),
        Map.entry("native-logo-model.txt","92bf891b2fa7e34f10a3bcc0dc8b2f445265829ca27cbe29c5f8fd7c955db02d"),
        Map.entry("native-noconsent-template.txt","3811b9ca2ca4cc02a6d012e49ec2febbc7983a0ce61c7aabed7b05941836bbe8"),
        Map.entry("native-parser.txt","8620bb26fd41d2be29d2611883839a4cfde0b6c8458c274e2d40a002678fd93d"),
        Map.entry("native-table-template.txt","3cb7cac88eb54c7adf17b803a2abc660c6cc47b637023af490ba3e9824e9c061"),
        Map.entry("native-template-loader.txt","77a9931f897429de28f75f98a9a61144b2dba6f365b58df10bab8701d5a1c73b"),
        Map.entry("native-template.txt","b7327d4036356a044ce509041ef899e85fe599ebbcc95f647433cdfadd863160"),
        Map.entry("native-uiinfo-model.txt","78c685a2b15fa441d7bf98043e89c9517109d752accc19204ea86cf94b8d5903"),
        Map.entry("native-policy-command.php","b8ec53642a17d41f642133c8e500139963f0d2b44ff2aa4378c06449057fbcb3"),
        Map.entry("native-state-command.php","cdcb7b281cbde1f4694b1a571bb9300b673190364d4c822575604f8c0dd3624e"),
        Map.entry("native-parser-command.php","5008495fba0e65487a4849cf46f592c577215f96d5b4f3fd87321ebc6930edf9"),
        Map.entry("native-readback-command.php","f84064049b9bc6ef0339b9b1874e86b6e36e89fe8770a502d5735200b15ed756"),
        Map.entry("collector.py","b2ec26258157cbfb87e88c775adea3d6729515e77bf23fbc557250b5b316cb3f"),
        Map.entry("browser.mjs","7b1451301bed7e5f0575fa8bf4ee02b38d8cdad6a54de3f9f3afaf3bdfac3db0"),
        Map.entry("native-ui-privacy.py","944e9a5345e4c714740bdbf87d69cbb61015d0cd37b8ac61a7109a929851ab05"));
    private final Path directory; private final TranscriptContentReader content;
    SimpleSamlPhpConsentLogoEvidence(Path directory,TranscriptContentReader content){this.directory=directory.toAbsolutePath().normalize();this.content=content;}
    boolean exists(String run){return run!=null&&run.matches("run_[0-9A-HJKMNP-TV-Z]{26}")&&Files.exists(directory.resolve(run),LinkOption.NOFOLLOW_LINKS);}
    Optional<CaseOutcome> evaluate(CaseContext context,byte[] targetRaw){
        if(!exists(context.runId()))return Optional.empty();
        String stage="native-consent-originals-unproven";
        try{
            require(context.transcriptComplete()&&Files.isDirectory(directory,LinkOption.NOFOLLOW_LINKS));
            Path folder=directory.resolve(context.runId());require(Files.isDirectory(folder,LinkOption.NOFOLLOW_LINKS));var manifest=json(original(folder,"manifest.json"));var files=manifest.path("files");
            require("samlscope-simplesamlphp-consent-logo-v1".equals(text(manifest,"schema"))&&context.runId().equals(text(manifest,"runId"))
                &&"metadata-ui-logo-comparison".equals(text(manifest,"campaignId"))&&TARGET.equals(text(manifest,"targetEntityId"))&&hash(targetRaw).equals(text(manifest,"targetMetadataSha256")));
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
            var transcript=new HashMap<String,TranscriptEntry>();for(var entry:context.transcript().list(context.runId()))require(context.runId().equals(entry.runId())&&transcript.put(entry.id(),entry)==null);
            var observations=json(checked(folder,files,"native-ui-observations.json"));require(context.runId().equals(text(observations,"runId"))&&!observations.path("productVerdictAssigned").asBoolean(true)&&observations.path("observations").size()==3);
            var http=json(checked(folder,files,"native-http-observations.json"));require(context.runId().equals(text(http,"runId"))&&!http.path("productVerdictAssigned").asBoolean(true)&&http.path("records").size()==6);
            var operation=json(checked(folder,files,"operations.json"));require(operation.size()==3&&operation.findValuesAsText("status").stream().allMatch("correlated-success"::equals));
            require(manifest.path("conditions").size()==3);var variants=new HashSet<String>();var refs=new ArrayList<EvidenceRef>();var policies=new HashSet<JsonNode>();var fixedInputs=new HashSet<String>();
            for(var row:manifest.path("conditions")){
                String variant=text(row,"variant");require(variants.add(variant)&&Set.of("control","ui-consumer-logo-localized","ui-consumer-logo-fallback").contains(variant));
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
                require("campaign-shared-browser".equals(text(browser,"browserInstance"))&&browser.path("observationIndex").asInt(-1)==(variant.equals("control")?1:variant.endsWith("localized")?2:3));
                noLogoBrowser(browser,folder,files);
                require(text(browser,"firstParagraph").equals(entity+" requires that the information below is transferred.")&&text(browser,"attributeHeader").equals("Information that will be sent to "+entity));
                if(!"control".equals(variant)){
                    logoInputs(metadata,active,variant);
                    // The approved no-display waiver is proven by the closed native renderer,
                    // not by a difference in logo selection. Each fixture's own keys remain bound
                    // above to native readback, valid target/Suite signatures and rejection controls.
                    // Normalize only per-condition certificates after those independent checks;
                    // entity, endpoint/binding, UI strings, image bytes/dimensions and other policy
                    // remain in the structural comparison. Keys cannot select a logo in this renderer.
                    fixedInputs.add(new JsonCodec().mapper().writeValueAsString(noLogoFixedMetadata(metadata,variant,context.runId())));
                }
                refs.addAll(List.of(new EvidenceRef("transcript",fetch.id()),new EvidenceRef("transcript",prepared.id()),new EvidenceRef("transcript",positive.id()),new EvidenceRef("transcript",response.id()),new EvidenceRef("transcript",negative.id()),new EvidenceRef("browser-observation",context.runId()+"/"+variant+".ui."+requestId+".browser.json")));
            }
            var counts=json(checked(folder,files,"operation-counts.json"));require(counts.path("credentialPosts").asInt(-1)==1&&counts.path("chromeLaunches").asInt(-1)==1&&counts.path("browserObservations").asInt(-1)==3&&counts.path("browserObservationAttempts").asInt(-1)==3&&counts.path("protocolOperationsAttempted").asInt(-1)==6&&counts.path("nativeParserInvocations").asInt(-1)==3&&counts.path("humanOperations").asInt(-1)==0&&counts.path("productRestarts").asInt(-1)==0&&counts.path("restored").asBoolean(false));
            require(variants.size()==3&&policies.size()==1&&fixedInputs.size()==1);refs.add(new EvidenceRef("native-consent-logo",context.runId()+"/manifest.json"));
            return Optional.of(new CaseOutcome(Outcome.SATISFIED_WITH_NOTE,null,"browser.ui-logo.native-consumer-not-used","browser.ui-logo.native-consumer-not-used",List.copyOf(refs),Map.of("product","simplesamlphp","native_closed_render_policy",true,"full_required_conditions",List.of("PREFERRED_AVAILABLE","PREFERRED_UNAVAILABLE"),"one_authenticated_session",true,"same_state_consent_and_noconsent",true)));
        }catch(Exception incomplete){return Optional.of(UiLogoComparison.evaluate(List.of(),List.of(stage)));}
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
    private static void logoInputs(Element metadata,JsonNode active,String variant)throws Exception{
        var info=one(one(one(metadata,MD,"SPSSODescriptor"),MD,"Extensions"),UI,"UIInfo");var logos=children(info,UI,"Logo");require(logos.size()==2&&active.path("UIInfo").path("Logo").size()==2);
        String xml="http://www.w3.org/XML/1998/namespace";var neutral=logos.stream().filter(e->!e.hasAttributeNS(xml,"lang")).toList();var localized=logos.stream().filter(e->e.hasAttributeNS(xml,"lang")).toList();require(neutral.size()==1&&localized.size()==1);
        String language=localized.getFirst().getAttributeNS(xml,"lang");require(variant.endsWith("localized")?"en".equals(language):"ja".equals(language));require(!neutral.getFirst().getTextContent().equals(localized.getFirst().getTextContent()));
        for(var logo:logos){require("180".equals(logo.getAttribute("width"))&&"48".equals(logo.getAttribute("height"))&&logo.getTextContent().startsWith("data:image/svg+xml;base64,"));
            var svg=SecureXml.parse(Base64.getDecoder().decode(logo.getTextContent().substring("data:image/svg+xml;base64,".length()))).getDocumentElement();require("http://www.w3.org/2000/svg".equals(svg.getNamespaceURI())&&"180".equals(svg.getAttribute("width"))&&"48".equals(svg.getAttribute("height")));
            int matches=0;for(var actual:active.path("UIInfo").path("Logo"))if(logo.getTextContent().equals(text(actual,"url"))&&actual.path("width").asInt(-1)==180&&actual.path("height").asInt(-1)==48&&(logo.hasAttributeNS(xml,"lang")?language.equals(text(actual,"lang")):!actual.has("lang")))matches++;
            require(matches==1);
        }
    }
    static Object noLogoFixedMetadata(Element original,String variant,String run){
        var metadata=(Element)original.cloneNode(true);require(metadata.getElementsByTagNameNS(UI,"DisplayName").getLength()==0&&metadata.getElementsByTagNameNS(MD,"ServiceName").getLength()==0);
        var logos=metadata.getElementsByTagNameNS(UI,"Logo");require(logos.getLength()==2);for(int i=0;i<logos.getLength();i++)((Element)logos.item(i)).removeAttributeNS("http://www.w3.org/XML/1998/namespace","lang");
        var certificates=metadata.getElementsByTagNameNS(DS,"X509Certificate");require(certificates.getLength()>0);for(int i=0;i<certificates.getLength();i++)certificates.item(i).setTextContent("independently-verified-condition-certificate");
        return UiDisplayEvidenceFile.fixedMetadata(metadata,variant,run);
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
