package com.samlscope.runner.cases;

import static com.samlscope.runner.cases.MetadataAlgorithmEvidence.children;

import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.transcript.Direction;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.core.transcript.TranscriptEntry;
import com.samlscope.saml.binding.RedirectSignatureVerifier;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.TreeMap;
import org.w3c.dom.Element;

/** Original-bound native Password login UI observations for the pinned reference Shibboleth.
 * Missing DOM nodes alone never establish nonuse: the native consumer class, unchanged native
 * view, effective metadata, actual signed fresh request and full native flow configuration
 * must agree. This reader sends nothing and does not accept an uploaded outcome/boolean.
 */
public final class ShibbolethUiConsumerEvidence {
    public static final Set<String> SUPPORTED=Set.of("IIP-MD05-fb-idp-01","IIP-MD05-fg-idp-01",
        "IIP-MD05-fh-idp-01","IIP-MD05-fj-idp-01");
    private static final String MD="urn:oasis:names:tc:SAML:2.0:metadata",UI="urn:oasis:names:tc:SAML:metadata:ui",
        P="urn:oasis:names:tc:SAML:2.0:protocol",S="urn:oasis:names:tc:SAML:2.0:assertion",
        DS="http://www.w3.org/2000/09/xmldsig#",B="http://www.springframework.org/schema/beans",
        U="http://www.springframework.org/schema/util",SP="http://www.springframework.org/schema/p";
    private static final String IMAGE="sha256:3c1b1fa64c58258aefc9e38d4ae60e9f0340731318a472110ea56ce88c18a11a";
    private static final String CLASS="60b9260e0e352862843c00a314c875cd67d10d9cff0a2e75d99937036cd35b01";
    private static final String TEMPLATE="8c09b9a9aa6871e42685bcddcbc7af802e56645e12eb221ffbcdff6c2c722540";
    private static final String GETTER_SOURCE="054d049bffc049369703fbeebd3e49748fff155f29388e8a18f699ae47f908b6";
    private static final String UI_JAR="3ff58097ce1159a68b51cd9f2213460f9c2c8cc2ab8b479ea2b680f33c50a5b9";
    private static final Set<String> CONFIG=Set.of("login-template","authn-properties","password-config",
        "relying-party","global","parent-ui-authn-properties");
    private static final Set<String> DISPLAYS=Set.of("ui-consumer-display-all","ui-consumer-display-service","ui-consumer-display-entity");
    private static final Set<String> SAFETY=Set.of("ui-safety-logo-data","ui-safety-information-javascript","ui-safety-privacy-javascript");
    private final Path directory;
    private final TranscriptContentReader content;

    public ShibbolethUiConsumerEvidence(Path directory,TranscriptContentReader content) {
        this.directory=Objects.requireNonNull(directory).toAbsolutePath().normalize();this.content=Objects.requireNonNull(content);
    }
    public boolean exists(String runId) {
        return runId!=null&&runId.matches("run_[0-9A-HJKMNP-TV-Z]{26}")
            &&Files.exists(directory.resolve(runId),LinkOption.NOFOLLOW_LINKS);
    }
    public Optional<CaseOutcome> read(CaseContext context,byte[] targetMetadata,String caseId) {
        if(!SUPPORTED.contains(caseId)||!exists(context.runId()))return Optional.empty();
        try {
            require(context.transcriptComplete());var folder=directory.resolve(context.runId());
            require(Files.isDirectory(folder,LinkOption.NOFOLLOW_LINKS));
            var manifest=tree(raw(folder,"manifest.json"));
            require("samlscope-shibboleth-native-ui-v1".equals(text(manifest,"schema"))
                &&context.runId().equals(text(manifest,"runId"))&&hash(targetMetadata).equals(text(manifest,"targetMetadataSha256")));
            var target=SecureXml.parse(targetMetadata).getDocumentElement();
            require(MD.equals(target.getNamespaceURI())&&"EntityDescriptor".equals(target.getLocalName())
                &&text(manifest,"targetEntityId").equals(target.getAttribute("entityID")));
            var entries=entries(context);var runtime=runtime(folder,manifest);
            configuration(folder,manifest);
            var nativeRows=nativeValues(folder,manifest);
            var rows=manifest.path("observations");require(rows.isArray());var observations=new LinkedHashMap<String,Observation>();
            var references=new ArrayList<EvidenceRef>();
            for(var row:rows) {
                String variant=text(row,"variant");require(!observations.containsKey(variant));
                var observation=observation(folder,row,context,target,entries);
                var nativeRow=nativeRows.get(variant);require(nativeRow!=null);
                require(nativeRow.equals(List.of(text(observation.nativeValues(),"nativeMetadataSha256"),
                    text(observation.nativeValues(),"serviceName"),text(observation.nativeValues(),"logo"))));
                observations.put(variant,observation);references.addAll(observation.refs());
            }
            // The normal control is a genuinely correlated successful SAML flow under this setup.
            references.add(normalControl(context,targetMetadata,target,entries,observations.get("control")));
            references.add(new EvidenceRef("native-ui-policy",context.runId()+"/manifest.json#"+hash(raw(folder,"manifest.json"))));
            Outcome outcome;String suffix;Map<String,Object> details=new HashMap<>();
            if(caseId.equals("IIP-MD05-fb-idp-01")) {
                var full=required(observations,"full-ui-info");require(full.browser()!=null);
                require(full.fixture().getElementsByTagNameNS(UI,"IPHint").getLength()>0
                    &&full.fixture().getElementsByTagNameNS(UI,"DomainHint").getLength()>0
                    &&full.fixture().getElementsByTagNameNS(UI,"GeolocationHint").getLength()>0);
                // The fixed native Password-only flow has no discovery selection stage.
                // This is the approved no-discovery-UI path, not inferred from absent page text.
                outcome=Outcome.SATISFIED_WITH_NOTE;suffix="discovery-not-used";
                details.put("feature","discovery-ui");
            }else if(caseId.equals("IIP-MD05-fj-idp-01")) {
                for(var variant:DISPLAYS)required(observations,variant);
                require(displaySelected(required(observations,"ui-consumer-display-all"),"display")
                    &&displaySelected(required(observations,"ui-consumer-display-service"),"service"));
                var last=required(observations,"ui-consumer-display-entity");
                require(last.fixture().getElementsByTagNameNS(UI,"DisplayName").getLength()==0
                    &&last.fixture().getElementsByTagNameNS(MD,"ServiceName").getLength()==0);
                if(displaySelected(last,"entity")||displaySelected(last,"hostname")) {
                    outcome=Outcome.SATISFIED;suffix="display-precedence-observed";
                }else {
                    // A known native suppression branch is distinct from unknown/missing DOM.
                    // The native getter falls back to the entityID, and the unchanged template
                    // explicitly suppresses precisely that value. The two display controls prove
                    // this is an active display-name consumer, not the approved nonuse waiver.
                    require(last.browser().path("dom").path("headings").isArray()
                        &&last.browser().path("dom").path("headings").isEmpty());
                    require(Set.of("entity","hostname").contains(text(last.nativeValues(),"serviceName")));
                    outcome=Outcome.VIOLATED;suffix="display-fallback-suppressed";
                }
                details.put("observed_conditions",List.of("display","service","entity"));
            }else if(caseId.equals("IIP-MD05-fh-idp-01")) {
                for(var element:List.of("logo","information","privacy"))for(var scheme:List.of("http","https","data","javascript","file")) {
                    var sample=required(observations,"ui-url-"+element+"-"+scheme);
                    require(displaySelected(sample,"control"));
                    if(element.equals("logo")) {
                        boolean allowed=Set.of("http","https","data").contains(scheme);
                        require(allowed?logoUsed(sample):logoAbsent(sample));
                        require((allowed?"candidate":"null").equals(text(sample.nativeValues(),"logo")));
                    }else require(unusedLinks(sample));
                }
                outcome=Outcome.SATISFIED_WITH_NOTE;suffix="url-schemes-and-native-nonuse";
                details.put("verified_nonuse",List.of("information-url","privacy-statement-url"));
            }else {
                for(var variant:SAFETY)required(observations,variant);
                var logo=required(observations,"ui-safety-logo-data");require(displaySelected(logo,"control")&&logoAssigned(logo));
                var logoNodes=logo.fixture().getElementsByTagNameNS(UI,"Logo");require(logoNodes.getLength()==1);
                String uri=logoNodes.item(0).getTextContent();require(uri.startsWith("data:image/svg+xml;base64,"));
                var svg=Base64.getDecoder().decode(uri.substring("data:image/svg+xml;base64,".length()));
                var svgRoot=SecureXml.parse(svg).getDocumentElement();
                require("http://www.w3.org/2000/svg".equals(svgRoot.getNamespaceURI())&&"svg".equals(svgRoot.getLocalName())
                    &&svgRoot.getElementsByTagNameNS("http://www.w3.org/2000/svg","script").getLength()==1
                    &&svgRoot.getTextContent().contains("alert('SAMLscope-UI-safety-v1')"));
                activeControl(folder,logo,svg);
                require(logoLoaded(logo)&&logo.browser().path("dialogs").isArray());
                boolean execution=logo.browser().path("dialogs").size()>0;
                if(execution)for(var dialog:logo.browser().path("dialogs"))require("alert".equals(text(dialog,"type"))
                    &&dialog.path("probeToken").asBoolean(false));
                else require(logo.browser().path("dom").path("executableProbeNodes").asInt(-1)==0);
                for(var variant:List.of("ui-safety-information-javascript","ui-safety-privacy-javascript")) {
                    var sample=required(observations,variant);require(displaySelected(sample,"control")&&unusedLinks(sample));
                    String element=variant.contains("information")?"InformationURL":"PrivacyStatementURL";
                    var urls=sample.fixture().getElementsByTagNameNS(UI,element);require(urls.getLength()==1
                        &&"javascript:alert('SAMLscope-UI-safety-v1')".equals(urls.item(0).getTextContent()));
                }
                outcome=execution?Outcome.VIOLATED:Outcome.SATISFIED_WITH_NOTE;
                suffix=execution?"unsafe-metadata-url-executed":"url-safety-and-native-nonuse";
                details.put("verified_nonuse",List.of("information-url","privacy-statement-url"));
            }
            details.put("product","shibboleth");details.put("native_image",runtime);
            details.put("evidence_adapter","shibboleth-native-password-ui-v1");
            return Optional.of(new CaseOutcome(outcome,null,"browser.shibboleth-ui."+suffix,
                "browser.shibboleth-ui."+suffix,List.copyOf(references),Map.copyOf(details)));
        }catch(Exception unproven){return Optional.empty();}
    }

    private record Observation(String variant,Element fixture,TranscriptEntry request,JsonNode browser,
        JsonNode nativeValues,JsonNode slotControl,String challenge,List<EvidenceRef> refs) {}
    private Map<String,TranscriptEntry> entries(CaseContext context) {
        var entries=new HashMap<String,TranscriptEntry>();
        for(var entry:context.transcript().list(context.runId()))require(context.runId().equals(entry.runId())&&entries.put(entry.id(),entry)==null);
        return entries;
    }
    private Observation observation(Path folder,JsonNode row,CaseContext context,Element target,Map<String,TranscriptEntry> entries)throws Exception {
        String variant=text(row,"variant");require(variant.equals("control")||variant.equals("full-ui-info")||DISPLAYS.contains(variant)
            ||SAFETY.contains(variant)||variant.matches("ui-url-(logo|information|privacy)-(http|https|data|javascript|file)"));
        var prepared=entry(entries,row,"metadataReference","MetadataPrepared",Direction.OUTBOUND,variant);
        var fetch=entry(entries,row,"fetchReference","MetadataFetch",Direction.INBOUND,variant);
        require(fetch.id().equals(prepared.samlSummary().get("fetchTranscriptId"))&&!prepared.timestamp().isBefore(fetch.timestamp()));
        var fixtureRaw=content.readDecodedSaml(prepared);require(hash(fixtureRaw).equals(text(row,"fixtureSha256")));
        var fixture=SecureXml.parse(fixtureRaw).getDocumentElement();
        require(MD.equals(fixture.getNamespaceURI())&&"EntityDescriptor".equals(fixture.getLocalName()));
        var effective=checked(folder,row,"nativeMetadataFile","nativeMetadataSha256");
        var nativeMetadata=SecureXml.parse(effective).getDocumentElement();
        require(fixture.getAttribute("entityID").equals(nativeMetadata.getAttribute("entityID"))
            &&structural(one(fixture,MD,"SPSSODescriptor")).equals(structural(one(nativeMetadata,MD,"SPSSODescriptor"))));
        var request=entry(entries,row,"requestReference","AuthnRequest",Direction.OUTBOUND,variant);
        var requestRaw=content.readDecodedSaml(request);var authn=SecureXml.parse(requestRaw).getDocumentElement();
        require(P.equals(authn.getNamespaceURI())&&"AuthnRequest".equals(authn.getLocalName())
            &&!authn.getAttribute("ID").isBlank()&&!request.timestamp().isBefore(prepared.timestamp())
            &&fixture.getAttribute("entityID").equals(one(authn,S,"Issuer").getTextContent()));
        var keys=signingKeys(one(fixture,MD,"SPSSODescriptor"));
        if("GET".equals(request.method()))require(keys.stream().anyMatch(cert->
            new RedirectSignatureVerifier().isValidForMessage(request.rawQuery(),cert,requestRaw)));
        else {
            require("POST".equals(request.method()));var verifier=new com.samlscope.saml.crypto.XmlSignatureVerifier();
            require(verifier.hasValidEnvelopedReferenceDigests(authn)&&keys.stream().anyMatch(cert->verifier.hasValidEnvelopedSignature(authn,cert)));
        }
        String endpoint=authn.getAttribute("Destination");require(request.url().equals(endpoint)
            &&children(one(target,MD,"IDPSSODescriptor"),MD,"SingleSignOnService").stream()
                .anyMatch(e->endpoint.equals(e.getAttribute("Location"))));
        require(children(one(fixture,MD,"SPSSODescriptor"),MD,"AssertionConsumerService").stream()
            .anyMatch(acs->authn.getAttribute("AssertionConsumerServiceURL").equals(acs.getAttribute("Location"))));
        var refs=new ArrayList<EvidenceRef>(List.of(new EvidenceRef("transcript",fetch.id()),
            new EvidenceRef("transcript",prepared.id()),new EvidenceRef("transcript",request.id())));
        JsonNode browser=null,slotControl=null;String challengeBody=null;Instant first=request.timestamp(),last=request.timestamp();
        if(!variant.equals("control")) {
            browser=tree(checked(folder,row,"browserFile","browserSha256"));
            require("samlscope-shibboleth-native-ui-browser-v1".equals(text(browser,"schema"))
                &&context.runId().equals(text(browser,"runId"))&&variant.equals(text(browser,"variant"))
                &&"captured".equals(text(browser,"status"))&&browser.path("initialCookieCount").asInt(-1)==0);
            var requests=browser.path("requests");require(requests.isArray()&&requests.size()==1);var sent=requests.get(0);
            require(authn.getAttribute("ID").equals(text(sent,"requestId"))&&hash(requestRaw).equals(text(sent,"sha256"))
                &&endpoint.equals(text(sent,"targetUrl"))&&request.method().equals(text(sent,"method"))
                &&text(sent,"acceptLanguage").startsWith("en-US"));
            require("GET".equals(request.method())?Objects.equals(request.rawQuery(),text(sent,"rawQuery")):sent.path("rawQuery").isNull());
            var at=Instant.parse(text(sent,"observedAt"));require(!at.isBefore(request.timestamp()));
            var challenge=browser.path("challenge");require(challenge.path("status").asInt()==200
                &&"hidden-token-values-before-persistence".equals(text(challenge,"redaction")));
            var uri=java.net.URI.create(text(challenge,"url"));var dest=java.net.URI.create(endpoint);
            require(uri.getScheme().equals(dest.getScheme())&&uri.getAuthority().equals(dest.getAuthority())&&uri.getPath().equals(dest.getPath())
                &&uri.getRawQuery()!=null&&uri.getRawQuery().matches("execution=e[0-9]+s[0-9]+"));
            var received=Instant.parse(text(challenge,"recordedAt"));require(!received.isBefore(at));
            var body=new String(checked(folder,row,"challengeFile","challengeSha256"),StandardCharsets.UTF_8);
            challengeBody=body;
            require(hash(body.getBytes(StandardCharsets.UTF_8)).equals(text(challenge,"bodySha256"))
                &&body.contains("name=\"j_username\"")&&body.contains("name=\"j_password\"")&&!body.contains("SAMLResponse"));
            require(!java.util.regex.Pattern.compile("(?is)<input\\b(?=[^>]*\\bname\\s*=\\s*[\"'](?:j_password|j_username)[\"'])[^>]*\\bvalue\\s*=\\s*[\"'][^\"']+")
                .matcher(body).find());
            for(var input:body.split("(?i)(?=<input\\b)"))if(input.startsWith("<input")&&input.toLowerCase().contains("type=\"hidden\""))
                require(input.substring(0,input.indexOf('>')+1).contains("value=\"[REDACTED]\""));
            var dom=browser.path("dom");require(dom.path("usernameInputs").asInt()==1&&dom.path("passwordInputs").asInt()==1
                &&"en-US".equals(text(dom,"preferredLanguage")));
            last=Instant.parse(text(dom,"observedAt"));require(!last.isBefore(received));
            require(body.contains("<form action=\""+uri.getPath()+"?"+uri.getRawQuery()+"\""));
            refs.add(new EvidenceRef("browser-observation",context.runId()+"/"+text(row,"browserFile")+"#"+text(row,"browserSha256")));
            validateEncoding(body,fixture,dom);
            if(variant.equals("ui-safety-logo-data"))slotControl=tree(checked(folder,row,"slotControlFile","slotControlSha256"));
        }
        readbacks(folder,row,fixtureRaw,first,last);
        var values=tree(checked(folder,row,"nativeValuesFile","nativeValuesSha256"));
        require(context.runId().equals(text(values,"runId"))&&variant.equals(text(values,"variant"))
            &&hash(effective).equals(text(values,"nativeMetadataSha256")));
        return new Observation(variant,fixture,request,browser,values,slotControl,challengeBody,List.copyOf(refs));
    }
    private void configuration(Path folder,JsonNode manifest)throws Exception {
        require(hash(checked(folder,manifest,"nativeClassFile","nativeClassSha256")).equals(CLASS));
        require(hash(checked(folder,manifest,"nativeClassBeforeFile","nativeClassBeforeSha256")).equals(CLASS)
            &&hash(checked(folder,manifest,"nativeClassAfterFile","nativeClassAfterSha256")).equals(CLASS));
        var rows=manifest.path("configurationFiles");require(rows.isArray()&&rows.size()==CONFIG.size());var seen=new HashSet<String>();
        for(var row:rows) {
            String kind=text(row,"kind");require(CONFIG.contains(kind)&&seen.add(kind));
            var original=checked(folder,row,"originalFile","originalSha256");
            require(Arrays.equals(original,checked(folder,row,"finalFile","finalSha256")));
            if(kind.equals("login-template"))require(hash(original).equals(TEMPLATE));
            if(kind.equals("parent-ui-authn-properties")) {
                var props=properties(original);require(props.size()==2&&"Password".equals(props.getProperty("idp.authn.flows"))
                    &&"en,fr,de".equals(props.getProperty("idp.ui.fallbackLanguages")));
            }else if(kind.equals("authn-properties")) {
                var props=properties(original);require(props.getProperty("idp.authn.flows")==null
                    ||"Password".equals(props.getProperty("idp.authn.flows")));
            }else if(kind.equals("global"))require(childrenAny(SecureXml.parse(original).getDocumentElement()).isEmpty());
            else if(kind.equals("relying-party")) {
                var root=SecureXml.parse(original).getDocumentElement();var lists=root.getElementsByTagNameNS(U,"list");
                for(int i=0;i<lists.getLength();i++) {
                    var list=(Element)lists.item(i);if("shibboleth.RelyingPartyOverrides".equals(list.getAttribute("id")))require(childrenAny(list).isEmpty());
                }
                var props=root.getElementsByTagNameNS(B,"property");for(int i=0;i<props.getLength();i++)
                    require(!Set.of("authenticationFlows","defaultAuthenticationMethods").contains(((Element)props.item(i)).getAttribute("name")));
            }else if(kind.equals("password-config")) {
                var root=SecureXml.parse(original).getDocumentElement();var lists=children(root,U,"list");require(lists.size()==1
                    &&"shibboleth.authn.Password.Validators".equals(lists.getFirst().getAttribute("id")));
                var validators=children(lists.getFirst(),B,"bean");require(validators.size()==1
                    &&"shibboleth.HTPasswdValidator".equals(validators.getFirst().getAttribute("parent")));
            }
        }
        require(Arrays.equals(checked(folder,manifest,"providerOriginalFile","providerOriginalSha256"),
            checked(folder,manifest,"providerFinalFile","providerFinalSha256")));
        var original=SecureXml.parse(checked(folder,manifest,"providerOriginalFile","providerOriginalSha256")).getDocumentElement();
        var configured=SecureXml.parse(checked(folder,manifest,"providerConfiguredFile","providerConfiguredSha256")).getDocumentElement();
        String ns="urn:mace:shibboleth:2.0:metadata";var sources=children(configured,ns,"MetadataProvider");var old=children(original,ns,"MetadataProvider");
        require(sources.size()==old.size()+1&&"FilesystemMetadataProvider".equals(sources.getFirst().getAttributeNS("http://www.w3.org/2001/XMLSchema-instance","type")));
        for(int i=0;i<old.size();i++)require(structural(old.get(i)).equals(structural(sources.get(i+1))));
        var selection=SecureXml.parse(checked(folder,manifest,"flowSelectionFile","flowSelectionSha256")).getDocumentElement();
        require(text(manifest,"flowSelectionSha256").equals("6c1de5855d3182944e310201e9102a2d8aed80a2636189e75a22e0e5934b5780"));
        require(children(selection,B,"bean").stream().anyMatch(bean->"PotentialFlowsLookup".equals(bean.getAttribute("id"))
            &&bean.getAttributeNS("http://www.springframework.org/schema/c","expression")
                .contains("id matches 'authn/(' + '%{idp.authn.flows:Password}'.trim() + ')'")));
        var views=new String(checked(folder,manifest,"viewInventoryFile","viewInventorySha256"),StandardCharsets.UTF_8).lines().toList();
        require(new HashSet<>(views).equals(Set.of("/opt/reference-idp/views/admin/hello.vm","/opt/reference-idp/views/client-storage/client-storage-read.vm",
            "/opt/reference-idp/views/client-storage/client-storage-write.vm","/opt/reference-idp/views/error.vm","/opt/reference-idp/views/login.vm",
            "/opt/reference-idp/views/logout-complete.vm","/opt/reference-idp/views/logout-propagate.vm","/opt/reference-idp/views/logout.vm"))&&views.size()==8);
    }
    private static Map<String,List<String>> nativeValues(Path folder,JsonNode manifest)throws Exception {
        require(hash(checked(folder,manifest,"nativeGetterSourceFile","nativeGetterSourceSha256")).equals(GETTER_SOURCE));
        var stdout=new String(checked(folder,manifest,"nativeGetterOutputFile","nativeGetterOutputSha256"),StandardCharsets.UTF_8);
        var rows=new HashMap<String,List<String>>();
        for(var line:stdout.lines().toList()) {
            if(!line.startsWith("SAMLSCOPE_NATIVE_UI\t"))continue;
            var values=line.split("\t",-1);require(values.length==6&&UI_JAR.equals(values[5])
                &&Set.of("null","entity","hostname","display","service","url-control","full-control","other").contains(values[3])
                &&Set.of("null","candidate","other").contains(values[4]));
            require(rows.put(values[1],List.of(values[2],values[3],values[4]))==null);
        }
        require(!rows.isEmpty());return rows;
    }
    private void readbacks(Path folder,JsonNode row,byte[] fixture,Instant first,Instant last)throws Exception {
        var backs=row.path("readBacks");require(backs.isArray()&&backs.size()==2);var seen=new HashSet<String>();
        for(var back:backs) {
            String phase=text(back,"phase");require(seen.add(phase));var at=Instant.parse(text(back,"recordedAt"));
            require(phase.equals("before")?!at.isAfter(first):phase.equals("after")&&!at.isBefore(last));
            require(Arrays.equals(fixture,checked(folder,back,"fixtureFile","fixtureSha256")));
            var values=back.path("configurationFiles");require(values.isArray()&&values.size()==CONFIG.size());var kinds=new HashSet<String>();
            for(var file:values) {String kind=text(file,"kind");require(CONFIG.contains(kind)&&kinds.add(kind));
                require(Arrays.equals(raw(folder,"original-"+kind),checked(folder,file,"file","sha256")));}
            require(Arrays.equals(raw(folder,"configured-providers.xml"),checked(folder,back,"providerFile","providerSha256")));
        }
        require(seen.equals(Set.of("before","after")));
    }
    private static void validateEncoding(String body,Element fixture,JsonNode dom) {
        for(var element:List.of("Logo","InformationURL","PrivacyStatementURL")) {
            var values=fixture.getElementsByTagNameNS(UI,element);if(values.getLength()!=1)continue;String value=values.item(0).getTextContent();
            if(element.equals("Logo")&&dom.path("logos").size()==1) {
                var tags=java.util.regex.Pattern.compile("(?is)<img\\b(?=[^>]*\\bclass=\"service-logo\")[^>]*>").matcher(body);
                require(tags.find());String tag=tags.group();require(!tags.find());
                var attrs=java.util.regex.Pattern.compile("\\bsrc\\s*=\\s*\"([^\"]*)\"").matcher(tag);require(attrs.find());
                String encoded=attrs.group(1);require(!encoded.contains("<")&&!encoded.contains(">"));
                var numeric=java.util.regex.Pattern.compile("&#(?:x([0-9a-fA-F]+)|([0-9]+));").matcher(encoded);
                String decoded=numeric.replaceAll(match->new String(Character.toChars(Integer.parseInt(
                    match.group(1)==null?match.group(2):match.group(1),match.group(1)==null?10:16))));
                decoded=decoded.replace("&quot;","\"").replace("&apos;","'").replace("&lt;","<").replace("&gt;",">").replace("&amp;","&");
                require(value.equals(decoded));
            }
        }
    }
    private EvidenceRef normalControl(CaseContext context,byte[] targetRaw,Element target,Map<String,TranscriptEntry> entries,Observation control)throws Exception {
        require(control!=null);var requestXml=SecureXml.parse(content.readDecodedSaml(control.request())).getDocumentElement();
        var responseEntries=entries.values().stream().filter(e->e.direction()==Direction.INBOUND&&"Response".equals(e.samlSummary().get("type"))
            &&requestXml.getAttribute("ID").equals(e.samlSummary().get("inResponseTo"))).toList();require(responseEntries.size()==1);
        var response=responseEntries.getFirst();var root=SecureXml.parse(content.readDecodedSaml(response)).getDocumentElement();
        require(!response.timestamp().isBefore(control.request().timestamp())&&requestXml.getAttribute("ID").equals(root.getAttribute("InResponseTo"))
            &&target.getAttribute("entityID").equals(one(root,S,"Issuer").getTextContent())
            &&requestXml.getAttribute("AssertionConsumerServiceURL").equals(root.getAttribute("Destination"))
            &&"urn:oasis:names:tc:SAML:2.0:status:Success".equals(one(one(root,P,"Status"),P,"StatusCode").getAttribute("Value"))
            &&(!children(root,S,"Assertion").isEmpty()||!children(root,S,"EncryptedAssertion").isEmpty()));
        var signed=MetadataAlgorithmEvidence.collect(List.of("control"),context,content,targetRaw);
        require(signed.issues().isEmpty()&&signed.exchanges().size()==1
            &&signed.exchanges().getFirst().evidence().stream().anyMatch(ref->ref.reference().equals(response.id())));
        return new EvidenceRef("transcript",response.id());
    }
    private static boolean displaySelected(Observation observation,String candidate) {
        var rows=observation.browser()==null?null:observation.browser().path("dom").path("headings");
        return rows!=null&&rows.isArray()&&rows.size()==1&&candidate.equals(rows.get(0).path("candidate").asText())&&rows.get(0).path("visible").asBoolean(false);
    }
    private static boolean logoAssigned(Observation observation) {
        var rows=observation.browser().path("dom").path("logos");
        return rows.isArray()&&rows.size()==1&&"probe".equals(rows.get(0).path("candidate").asText());
    }
    private static boolean logoAbsent(Observation observation) {
        var rows=observation.browser().path("dom").path("logos");return rows.isArray()&&rows.isEmpty();
    }
    private static boolean logoLoaded(Observation observation) {
        var rows=observation.browser().path("dom").path("logos");
        return logoAssigned(observation)&&rows.get(0).path("complete").asBoolean(false)
            &&rows.get(0).path("width").asInt(-1)>0&&rows.get(0).path("height").asInt(-1)>0;
    }
    private static boolean logoUsed(Observation observation)throws Exception {
        if(!logoAssigned(observation))return false;
        var nodes=observation.fixture().getElementsByTagNameNS(UI,"Logo");require(nodes.getLength()==1);
        String uri=nodes.item(0).getTextContent();if(uri.startsWith("data:"))return logoLoaded(observation);
        if(logoLoaded(observation))return true;
        // An actual native browser image request proves use even when the HTTPS fixture's
        // resource server cannot complete TLS. A DOM assignment alone cannot reach this path.
        var resources=observation.browser().path("resources");require(resources.isArray()&&resources.size()==1);
        var resource=resources.get(0);var sent=observation.browser().path("requests").get(0);
        var at=Instant.parse(text(resource,"requestedAt"));
        require("probe".equals(text(resource,"candidate"))&&"GET".equals(text(resource,"method"))
            &&"image".equals(text(resource,"resourceType"))&&hash(uri.getBytes(StandardCharsets.UTF_8)).equals(text(resource,"urlSha256"))
            &&!at.isBefore(Instant.parse(text(sent,"observedAt")))
            &&!at.isAfter(Instant.parse(text(observation.browser().path("dom"),"observedAt"))));
        if(resource.has("failedAt"))require(!Instant.parse(text(resource,"failedAt")).isBefore(at)
            &&text(resource,"failureCode").matches("net::ERR_[A-Z_]+"));
        else require(resource.path("status").asInt(-1)>0&&resource.path("bytes").asInt(-1)>0
            &&text(resource,"bodySha256").matches("[a-f0-9]{64}")&&!Instant.parse(text(resource,"respondedAt")).isBefore(at));
        return true;
    }
    private static boolean unusedLinks(Observation observation) {
        var rows=observation.browser().path("dom").path("candidateLinks");return rows.isArray()&&rows.isEmpty()
            &&"null".equals(observation.nativeValues().path("logo").asText());
    }
    private static void activeControl(Path folder,Observation logo,byte[] svg)throws Exception {
        var control=logo.browser().path("activeSinkControl");require("isolated-top-level-svg".equals(text(control,"scope")));
        var source=raw(folder,logo.variant()+"/"+text(control,"htmlFile"));require(Arrays.equals(svg,source)&&hash(source).equals(text(control,"htmlSha256")));
        var dialogs=control.path("dialogs");require(dialogs.isArray()&&dialogs.size()==1&&"alert".equals(text(dialogs.get(0),"type"))
            &&dialogs.get(0).path("probeToken").asBoolean(false));
        var slot=logo.slotControl();require(slot!=null&&"samlscope-shibboleth-native-ui-slot-control-v1".equals(text(slot,"schema"))
            &&"captured".equals(text(slot,"status"))&&"isolated-native-logo-slot".equals(text(slot,"scope"))
            &&text(logo.browser(),"runId").equals(text(slot,"runId"))&&logo.variant().equals(text(slot,"variant"))
            &&hash(logo.challenge().getBytes(StandardCharsets.UTF_8)).equals(text(slot,"originalBodySha256"))
            &&hash(svg).equals(text(slot,"svgSha256")));
        var tags=java.util.regex.Pattern.compile("(?is)<img\\b(?=[^>]*\\bclass=\"service-logo\")[^>]*>").matcher(logo.challenge());
        require(tags.find());String tag=tags.group();require(!tags.find());
        var mutated=raw(folder,logo.variant()+"/"+text(slot,"htmlFile"));
        require(Arrays.equals(mutated,logo.challenge().replace(tag,new String(svg,StandardCharsets.UTF_8)).getBytes(StandardCharsets.UTF_8))
            &&hash(mutated).equals(text(slot,"htmlSha256")));
        var slotDialogs=slot.path("dialogs");require(slotDialogs.isArray()&&slotDialogs.size()==1
            &&"alert".equals(text(slotDialogs.get(0),"type"))&&slotDialogs.get(0).path("probeToken").asBoolean(false)
            &&slot.path("dom").path("probeScripts").asInt(-1)==1&&slot.path("dom").path("usernameInputs").asInt(-1)==1
            &&slot.path("dom").path("passwordInputs").asInt(-1)==1);
    }
    private static Observation required(Map<String,Observation> rows,String key){var value=rows.get(key);require(value!=null&&value.browser()!=null);return value;}
    private static List<X509Certificate> signingKeys(Element role)throws Exception {
        var result=new ArrayList<X509Certificate>();for(var key:children(role,MD,"KeyDescriptor")) {
            if(!Set.of("","signing").contains(key.getAttribute("use")))continue;var certs=key.getElementsByTagNameNS(DS,"X509Certificate");
            for(int i=0;i<certs.getLength();i++)result.add((X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(
                new ByteArrayInputStream(Base64.getMimeDecoder().decode(certs.item(i).getTextContent()))));
        }require(!result.isEmpty());return result;
    }
    private static String runtime(Path folder,JsonNode manifest)throws Exception {
        var start=tree(checked(folder,manifest,"runtimeBeforeFile","runtimeBeforeSha256"));var end=tree(checked(folder,manifest,"runtimeAfterFile","runtimeAfterSha256"));
        require("shibboleth".equals(text(start,"product"))&&"shibboleth".equals(text(end,"product"))
            &&start.path("binding").equals(end.path("binding"))&&IMAGE.equals(text(start.path("binding"),"image_id"))
            &&start.path("binding").path("running_at_capture").asBoolean(false)&&start.path("binding").path("host_port_bound").asBoolean(false)
            &&"5.2.3".equals(text(start.path("runtime_version"),"value"))&&"5.2.3".equals(text(end.path("runtime_version"),"value")));
        return IMAGE;
    }
    private static Object structural(Element element) {
        var attrs=new TreeMap<String,String>();for(int i=0;i<element.getAttributes().getLength();i++) {
            var attr=element.getAttributes().item(i);if("http://www.w3.org/2000/xmlns/".equals(attr.getNamespaceURI()))continue;
            attrs.put(Objects.toString(attr.getNamespaceURI(),"")+":"+attr.getLocalName(),attr.getNodeValue());
        }
        var children=new ArrayList<Object>();for(var node=element.getFirstChild();node!=null;node=node.getNextSibling()) {
            if(node instanceof Element child)children.add(structural(child));
            else if(node.getNodeType()==org.w3c.dom.Node.TEXT_NODE&&!node.getTextContent().isBlank())
                children.add(DS.equals(element.getNamespaceURI())?node.getTextContent().replaceAll("\\s+","")
                    :UI.equals(element.getNamespaceURI())&&"Keywords".equals(element.getLocalName())
                        ?node.getTextContent().trim().replaceAll("\\s+"," "):node.getTextContent());
        }return List.of(Objects.toString(element.getNamespaceURI(),""),element.getLocalName(),attrs,children);
    }
    private static TranscriptEntry entry(Map<String,TranscriptEntry> entries,JsonNode row,String key,String type,Direction direction,String variant) {
        var value=entries.get(text(row,key));require(value!=null&&value.direction()==direction&&type.equals(value.samlSummary().get("type"))
            &&variant.equals(value.samlSummary().get("variant")));return value;
    }
    private static Element one(Element parent,String ns,String name){var values=children(parent,ns,name);require(values.size()==1);return values.getFirst();}
    private static List<Element> childrenAny(Element root){var values=new ArrayList<Element>();for(var node=root.getFirstChild();node!=null;node=node.getNextSibling())if(node instanceof Element e)values.add(e);return values;}
    private static Properties properties(byte[] raw)throws Exception{var value=new Properties();value.load(new ByteArrayInputStream(raw));return value;}
    private static JsonNode tree(byte[] raw)throws Exception{return new JsonCodec().mapper().readTree(raw);}
    private static byte[] checked(Path folder,JsonNode row,String file,String digest)throws Exception{var value=raw(folder,text(row,file));require(hash(value).equals(text(row,digest)));return value;}
    private static byte[] raw(Path folder,String name)throws Exception {
        require(name.matches("[A-Za-z0-9][A-Za-z0-9._/-]*")&&!name.contains("..")&&!name.endsWith("/"));
        var path=folder.resolve(name).normalize();require(path.startsWith(folder));
        for(var component:folder.relativize(path)) {folder=folder.resolve(component);require(!Files.isSymbolicLink(folder));}
        require(Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS)&&Files.size(path)>0&&Files.size(path)<=2_097_152);return Files.readAllBytes(path);
    }
    private static String text(JsonNode row,String key){var value=row.path(key);require(value.isTextual()&&!value.asText().isBlank());return value.asText();}
    private static String hash(byte[] value)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));}
    private static void require(boolean condition){if(!condition)throw new IllegalArgumentException("Unproven native Shibboleth UI evidence");}
}
