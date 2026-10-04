package com.samlscope.runner.cases;

import static com.samlscope.runner.cases.MetadataAlgorithmEvidence.children;
import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.crypto.PlanCredentials;
import com.samlscope.saml.normal.*;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.net.URI;
import java.security.MessageDigest;
import java.security.cert.*;
import java.time.Instant;
import java.util.*;
import java.util.function.*;
import java.util.regex.Pattern;
import org.w3c.dom.Element;

/** Two simultaneous native peers, including a valid signature made by the other known peer.
 * Native HTTP errors establish nothing without the product's request-bound signature error.
 * The adapter observes one installed consumer path; it makes no global capability claim. */
public final class SimpleSamlPhpRegisteredSignerEvidence implements RegisteredSignerNativeEvidence {
    public static final String SCHEMA="samlscope-simplesamlphp-registered-signer-v1";
    public static final String ADAPTER="simplesamlphp-native-issuer-key-locator-v1";
    public static final String CAMPAIGN="native-registered-signer";
    public static final String KIND="native-registered-signer-evidence";
    private static final String ORIGINAL="samlscope-simplesamlphp-registered-signer-original-v1";
    private static final String PREPARATION="samlscope-simplesamlphp-registered-signer-preparation-v1";
    private static final String TARGET="http://localhost:18380/idp", BASE="http://localhost:18080";
    private static final String MD="urn:oasis:names:tc:SAML:2.0:metadata", P="urn:oasis:names:tc:SAML:2.0:protocol", DS="http://www.w3.org/2000/09/xmldsig#";
    private static final List<String> FIXTURES=List.of("local-normal","local-invalid-signature","local-other-signer");
    private final Path directory;
    private final TranscriptContentReader content;
    private final Function<String,byte[]> metadata;
    private final BiFunction<String,String,Optional<PlanCredentials>> keys;
    public SimpleSamlPhpRegisteredSignerEvidence(Path directory, TranscriptContentReader content,
            Function<String,byte[]> metadata, BiFunction<String,String,Optional<PlanCredentials>> keys) {
        this.directory=Objects.requireNonNull(directory).toAbsolutePath().normalize();
        this.content=Objects.requireNonNull(content);this.metadata=Objects.requireNonNull(metadata);this.keys=Objects.requireNonNull(keys);
    }
    @Override public String adapter(){return ADAPTER;}
    @Override public String evidenceKind(){return KIND;}
    @Override public boolean exists(String run){return validRun(run)&&Files.exists(directory.resolve(run),LinkOption.NOFOLLOW_LINKS);}
    @Override public boolean hasFinalProof(String run){return validRun(run)&&Files.exists(directory.resolve(run).resolve("manifest.json"),LinkOption.NOFOLLOW_LINKS);}
    private static boolean validRun(String run){return run!=null&&run.matches("run_[0-9A-HJKMNP-TV-Z]{26}");}
    private static void require(boolean condition){if(!condition)throw new IllegalArgumentException("Native signer proof unavailable");}
    static String hash(byte[] bytes)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));}
    private static JsonNode json(byte[] bytes)throws Exception{return new JsonCodec().mapper().readTree(bytes);}
    private static String text(JsonNode node,String field){require(node.path(field).isTextual()&&!node.path(field).asText().isBlank());return node.path(field).asText();}
    private static Instant at(JsonNode node,String field){return Instant.parse(text(node,field));}
    private byte[] raw(Path folder,String name)throws Exception {
        require(!name.isBlank()&&!Path.of(name).isAbsolute());var file=folder.resolve(name).normalize();require(file.startsWith(folder)&&!file.equals(folder));
        for(var p=file;p!=null;p=p.getParent())require(!Files.isSymbolicLink(p));require(Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS));return Files.readAllBytes(file);
    }
    private byte[] file(Path folder,JsonNode m,String name)throws Exception{var bytes=raw(folder,name);require(hash(bytes).equals(text(m.path("files"),name)));return bytes;}
    private JsonNode node(Path folder,JsonNode m,String name)throws Exception{return json(file(folder,m,name));}
    private Map<String,TranscriptEntry> history(CaseContext c,String run){
        require(validRun(run));var result=new LinkedHashMap<String,TranscriptEntry>();
        for(var e:c.transcript().list(run)){require(run.equals(e.runId())&&result.put(e.id(),e)==null);if(e.decodedSamlRef()!=null)require(("transcripts/"+run+"/"+e.id()+".saml.xml").equals(e.decodedSamlRef()));}return result;
    }
    private byte[] decoded(TranscriptEntry e)throws Exception{require(e!=null&&e.decodedSamlRef()!=null);var bytes=content.readDecodedSaml(e);require(bytes!=null&&bytes.length==e.decodedSamlBytes());return bytes;}
    private JsonNode original(CaseContext c,Path folder,JsonNode m,String name,String kind)throws Exception {
        var ref=m.path("originals").path(name);var e=history(c,c.runId()).get(text(ref,"reference"));var bytes=decoded(e);
        require(hash(bytes).equals(text(ref,"sha256"))&&Arrays.equals(bytes,file(folder,m,"native-originals/"+name+".json")));
        require(e.direction()==Direction.INBOUND&&"POST".equals(e.method())&&Objects.equals(e.status(),204)&&"application/json".equals(e.contentType())&&(BASE+"/p/"+text(m,"planId")+"/sp/paos?run="+c.runId()).equals(e.url()));
        var n=json(bytes);require(ORIGINAL.equals(text(n,"schema"))&&c.runId().equals(text(n,"runId"))&&CAMPAIGN.equals(text(n,"campaignId"))&&kind.equals(text(n,"kind"))&&m.path("targetMetadataSha256").equals(n.path("targetMetadataSha256"))&&at(n,"recordedAt").isBefore(e.timestamp())&&!sensitive(n));return n;
    }
    static boolean sensitive(JsonNode n){
        if(n.isObject()){var fields=n.fields();while(fields.hasNext()){var e=fields.next();String k=e.getKey().toLowerCase(Locale.ROOT).replaceAll("[-_.]","");if(Set.of("cookie","setcookie","authorization","proxyauthorization","password","passwd","secret","credentials","token","accesstoken","refreshtoken","registrationaccesstoken","privatekey","metadatasignprivatekey").contains(k)||sensitive(e.getValue()))return true;}}
        else if(n.isArray())for(var item:n)if(sensitive(item))return true;return false;
    }
    private static List<X509Certificate> spKeys(Element root)throws Exception {
        var roles=children(root,MD,"SPSSODescriptor");require(roles.size()==1);var result=new ArrayList<X509Certificate>();
        for(var kd:children(roles.getFirst(),MD,"KeyDescriptor")){if(!kd.getAttribute("use").isBlank()&&!"signing".equals(kd.getAttribute("use")))continue;var certs=kd.getElementsByTagNameNS(DS,"X509Certificate");for(int i=0;i<certs.getLength();i++)result.add(certificate(certs.item(i).getTextContent()));}require(!result.isEmpty());return result;
    }
    private static X509Certificate certificate(String value)throws Exception{return (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(Base64.getMimeDecoder().decode(value)));}
    private static Set<String> certHashes(List<X509Certificate> certificates)throws Exception{var result=new HashSet<String>();for(var c:certificates)result.add(hash(c.getEncoded()));return result;}
    private static Element fixture(byte[] raw,String entity)throws Exception {var root=SecureXml.parse(raw).getDocumentElement();require(MD.equals(root.getNamespaceURI())&&"EntityDescriptor".equals(root.getLocalName())&&entity.equals(root.getAttribute("entityID"))&&KeycloakSubjectConfirmationEvidence.signed(root,spKeys(root)));return root;}
    private static URI destination(Element target){var roles=children(target,MD,"IDPSSODescriptor");require(roles.size()==1);var urls=new HashSet<String>();for(var e:children(roles.getFirst(),MD,"SingleSignOnService"))if("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".equals(e.getAttribute("Binding")))urls.add(e.getAttribute("Location"));require(urls.size()==1);var uri=URI.create(urls.iterator().next());require("http".equals(uri.getScheme())&&"localhost".equals(uri.getHost())&&uri.getPort()==18380&&uri.getRawQuery()==null&&uri.getRawFragment()==null);return uri;}
    @Override public Optional<RegisteredSignerProbeInputs> probeInputs(CaseContext c){
        if(!exists(c.runId()))return Optional.empty();try{
            var folder=directory.resolve(c.runId());var raw=raw(folder,"preparation.json");var m=json(raw);
            require(PREPARATION.equals(text(m,"schema"))&&CAMPAIGN.equals(text(m,"campaignId"))&&c.runId().equals(text(m,"localRunId")));
            var targetRaw=metadata.apply(c.runId());require(Arrays.equals(targetRaw,file(folder,m,"target-metadata.xml"))&&hash(targetRaw).equals(text(m,"targetMetadataSha256")));var target=SecureXml.parse(targetRaw).getDocumentElement();require(TARGET.equals(target.getAttribute("entityID")));
            var peers=m.path("peers");require(peers.isArray()&&peers.size()==2);JsonNode local=null,other=null;var ids=new HashSet<String>();var entities=new HashSet<String>();var labels=new HashSet<String>();var certs=new ArrayList<List<X509Certificate>>();
            for(var peer:peers){String run=text(peer,"runId"),plan=text(peer,"planId"),entity=text(peer,"entity"),label=text(peer,"label");require(validRun(run)&&plan.matches("plan_[0-9A-HJKMNP-TV-Z]{26}")&&entity.equals(BASE+"/p/"+plan)&&ids.add(run)&&entities.add(entity)&&Set.of("primary","secondary").contains(label)&&labels.add(label));var known=node(folder,m,label+"/created.json");require(run.equals(known.at("/run/id").asText())&&plan.equals(known.at("/run/planId").asText()));var sp=fixture(file(folder,m,label+"/fixture.xml"),entity);var key=keys.apply(run,"primary").orElseThrow();require(spKeys(sp).stream().anyMatch(cert->Arrays.equals(cert.getPublicKey().getEncoded(),key.certificate().getPublicKey().getEncoded())));certs.add(spKeys(sp));require(Arrays.equals(metadata.apply(run),targetRaw));if(run.equals(c.runId()))local=peer;else other=peer;}
            require(local!=null&&other!=null&&Collections.disjoint(certHashes(certs.get(0)),certHashes(certs.get(1))));var sp=fixture(file(folder,m,text(local,"label")+"/fixture.xml"),text(local,"entity"));return Optional.of(new RegisteredSignerProbeInputs(c.runId(),text(other,"runId"),text(local,"entity"),destination(target),MetadataSupersessionProbeTestCase.acs(sp,0),hash(raw)));
        }catch(Exception unavailable){return Optional.empty();}
    }
    private static final Map<String,String> SOURCE=Map.of(
        "native-idp.php","ae55fc922431d29ca6e87654ae2071500a4c3d7185ed80a6fcc5b26eed12495d",
        "native-message.php","ab017ee6cf9fb66db1037e40ed50feff0b277b1a5d43fd8ca774a3d27ce355d2",
        "native-configuration.php","53837359cd60433082d3968843605a864bab97f23be482447bcfef37e7f6946e",
        "native-parser.php","8620bb26fd41d2be29d2611883839a4cfde0b6c8458c274e2d40a002678fd93d",
        "native-handler.php","43a0e730d624c5a937f800c4e7e045ff3625eeb0738d81a4ab1dac96f82fe040",
        "native-source.php","48fe4682d980e62416c751b7a39406ebf9664bf539e6a1557e7f54df770398c6",
        "native-signed-helper.php","4928545a8147e4222288def64a992ed8fbf0ba54243079fc3c919470b2cc766c");
    private JsonNode nativeState(CaseContext c,Path folder,JsonNode m,String name,String phase)throws Exception{
        var n=original(c,folder,m,name,"native-registered-peers");require(phase.equals(text(n,"phase"))&&n.path("peers").isArray()&&n.path("peers").size()==2&&n.path("metadataSources").equals(json("[{\"type\":\"flatfile\"}]".getBytes(StandardCharsets.UTF_8))));
        var rawReadback=file(folder,m,"native-readbacks/"+name+".json");require(hash(rawReadback).equals(text(n,"nativeReadbackSha256")));var readback=json(rawReadback);require(readback.isObject()&&!sensitive(readback));for(String field:List.of("peers","configurationSha256","metadataSources","hostedIdp","sourceHashes"))require(n.path(field).equals(readback.path(field)));
        require(at(n,"nativeStartedAt").isBefore(at(n,"nativeFinishedAt"))&&at(n,"nativeFinishedAt").isBefore(at(n,"recordedAt"))&&n.at("/runtime/running").isBoolean()&&n.at("/runtime/running").asBoolean()&&text(n.path("runtime"),"id").matches("[0-9a-f]{64}")&&text(n.path("runtime"),"image").matches("sha256:[0-9a-f]{64}"));
        require(n.path("hostedIdp").path("entityId").asText().equals(TARGET)&&n.path("hostedIdp").path("authproc").isArray()&&n.path("hostedIdp").path("authproc").isEmpty());
        for(var source:SOURCE.entrySet())require(source.getValue().equals(text(n.path("sourceHashes"),source.getKey()))&&source.getValue().equals(hash(file(folder,m,"native-source/"+source.getKey()))));
        String config=phase.equals("initial")||phase.equals("restored")?"original-configuration.php":"configured-configuration.php";require(hash(file(folder,m,config)).equals(text(n,"configurationSha256")));return n;
    }
    private static void nativeKeys(JsonNode keys,List<X509Certificate> expected)throws Exception {
        require(keys.isArray()&&!keys.isEmpty());var found=new HashSet<String>();for(var key:keys){require("X509Certificate".equals(text(key,"type"))&&(!key.has("signing")||key.path("signing").isBoolean()&&key.path("signing").asBoolean()));require(found.add(hash(certificate(text(key,"X509Certificate")).getEncoded())));}require(found.equals(certHashes(expected)));
    }
    /** This parses the actual public product error, not a collector's boolean or label. */
    static boolean nativeSignatureRejection(String page,String entity){
        try{if(page.getBytes(StandardCharsets.UTF_8).length>262144||Pattern.compile("(?i)<\\s*input\\b|SAMLResponse|SAMLRequest|Authorization\\s*:|Cookie\\s*:").matcher(page).find())return false;
            String visible=page.replaceAll("(?is)<(?:script|style)\\b[^>]*>.*?</(?:script|style)\\s*>","").replaceAll("(?s)<[^>]+>","\n");visible=visible.replace("&quot;","\"").replace("&#34;","\"").replace("&#x22;","\"").replace("&amp;","&");
            var matcher=Pattern.compile("SimpleSAML\\\\+Error\\\\+Error:\\s*(\\{[^\\r\\n]*\\})").matcher(visible);int matched=0;while(matcher.find()){var n=json(matcher.group(1).getBytes(StandardCharsets.UTF_8));if("NOTVALIDCERTSIGNATURE".equals(n.path("errorCode").asText())&&Pattern.matches("SAML2\\\\+(?:XML\\\\+samlp\\\\+)?AuthnRequest",n.path("%ELEMENT%").asText())&&entity.equals(n.path("%ISSUER%").asText())&&entity.equals(n.path("%ENTITYID%").asText()))matched++;}return matched==1;
        }catch(Exception unavailable){return false;}
    }
    private record Checked(TranscriptEntry request,TranscriptEntry response,boolean success){}
    private Checked probe(CaseContext c,Path folder,JsonNode m,JsonNode peer,JsonNode otherPeer,Element sp,Element other,Element target,JsonNode row,String name)throws Exception {
        String run=text(peer,"runId"),entity=text(peer,"entity");var entries=history(c,run);var request=entries.get(text(row,"requestReference"));require(request!=null&&request.direction()==Direction.OUTBOUND&&"POST".equals(request.method())&&request.timestamp().isAfter(at(m,"configuredAt")));
        String action=ActionIds.derive(run,RegisteredSignerObservationTestCase.CASE,"await-fixture-"+name,0);require(name.equals(text(row,"fixture"))&&run.equals(text(row,"runId"))&&action.equals(text(row,"actionId"))&&action.equals(request.correlationId()));
        var raw=decoded(request);var q=SecureXml.parse(raw).getDocumentElement();String id=q.getAttribute("ID"),acs=MetadataSupersessionProbeTestCase.acs(sp,0).toString();require(P.equals(q.getNamespaceURI())&&"AuthnRequest".equals(q.getLocalName())&&("_"+action).equals(id)&&entity.equals(KeycloakSubjectConfirmationEvidence.issuer(q))&&destination(target).toString().equals(request.url())&&request.url().equals(q.getAttribute("Destination"))&&acs.equals(q.getAttribute("AssertionConsumerServiceURL"))&&Set.of("","false","0").contains(q.getAttribute("ForceAuthn"))&&Set.of("","false","0").contains(q.getAttribute("IsPassive")));
        var issue=Instant.parse(q.getAttribute("IssueInstant"));require(!issue.isAfter(request.timestamp())&&issue.isAfter(at(m,"configuredAt")));var signer=keys.apply(name.equals("local-other-signer")?text(otherPeer,"runId"):run,"primary").orElseThrow();var expected=new SamlSignedRequestFactory().build(name.equals("local-invalid-signature")?SamlSignedRequestFactory.Fixture.BAD_SIGNATURE_VALUE:SamlSignedRequestFactory.Fixture.VALID,id,URI.create(request.url()),entity,URI.create(acs),issue,signer);require(Arrays.equals(expected,raw));
        boolean own=KeycloakSubjectConfirmationEvidence.signed(q,spKeys(sp)),foreign=KeycloakSubjectConfirmationEvidence.signed(q,spKeys(other));require(name.equals("local-normal")?own&&!foreign:name.equals("local-invalid-signature")?!own&&!foreign:!own&&foreign);
        var responses=entries.values().stream().filter(e->e.direction()==Direction.INBOUND&&id.equals(e.samlSummary().get("inResponseTo"))).toList();var browsers=entries.values().stream().filter(e->e.direction()==Direction.INBOUND&&action.equals(e.correlationId())&&"BrowserResponseObservation".equals(e.samlSummary().get("type"))).toList();require(responses.size()+browsers.size()==1);boolean success=!responses.isEmpty();TranscriptEntry response;
        if(success){response=responses.getFirst();require(!name.equals("local-invalid-signature")&&"POST".equals(response.method())&&acs.equals(response.url()));var r=SecureXml.parse(decoded(response)).getDocumentElement();require(TARGET.equals(KeycloakSubjectConfirmationEvidence.issuer(r)));VerifiedResponseAssertion.read(r,TARGET,MetadataAlgorithmEvidence.signingKeys(target),sp,keys.apply(run,"primary"),id,acs);}
        else{response=browsers.getFirst();require(!name.equals("local-normal")&&"BROWSER".equals(response.method())&&Integer.valueOf(500).equals(response.status())&&request.url().equals(response.url())&&("transcripts/"+run+"/"+response.id()+".body").equals(response.bodyRef())&&response.bodyBytes()>0&&response.bodyBytes()<=262144);var body=raw(directory.getParent(),response.bodyRef());require(body.length==response.bodyBytes()&&nativeSignatureRejection(new String(body,StandardCharsets.UTF_8),entity));var record=original(c,folder,m,text(row,"nativeHttpOriginal"),"native-http-response");var n=record.path("native");require(run.equals(text(record,"observedRunId"))&&request.id().equals(text(record,"requestReference"))&&response.id().equals(text(record,"responseReference"))&&action.equals(text(record,"actionId"))&&"POST".equals(text(n,"method"))&&request.url().equals(text(n,"requestUrl"))&&request.url().equals(text(n,"responseUrl"))&&id.equals(text(n,"requestId"))&&hash(raw).equals(text(n,"requestSha256"))&&n.path("responseStatus").asInt(-1)==500&&n.path("responseBodyBytes").asLong(-1)==body.length&&hash(body).equals(text(n,"responseBodySha256"))&&!at(n,"startedAt").isBefore(request.timestamp())&&!at(n,"finishedAt").isBefore(at(n,"startedAt"))&&!at(n,"finishedAt").isAfter(response.timestamp())&&at(record,"recordedAt").isAfter(response.timestamp()));}
        require(response.timestamp().isAfter(request.timestamp())&&response.timestamp().isBefore(at(m,"completedAt")));return new Checked(request,response,success);
    }
    @Override public Optional<CaseOutcome> evaluate(CaseContext c){
        if(!exists(c.runId()))return Optional.empty();String stage="registered-signer-originals-unproven";try{
            require(c.transcriptComplete());var folder=directory.resolve(c.runId());var manifest=raw(folder,"manifest.json");var m=json(manifest);require(SCHEMA.equals(text(m,"schema"))&&ADAPTER.equals(text(m,"adapter"))&&CAMPAIGN.equals(text(m,"campaignId"))&&c.runId().equals(text(m,"runId"))&&TARGET.equals(text(m,"targetEntityId"))&&probeInputs(c).isPresent());
            var prep=node(folder,m,"preparation.json");require(m.path("peers").equals(prep.path("peers")));var peers=m.path("peers");require(peers.size()==2&&c.runId().equals(text(peers.get(0),"runId"))&&"primary".equals(text(peers.get(0),"label")));var targetRaw=metadata.apply(c.runId());require(Arrays.equals(targetRaw,file(folder,m,"target-metadata.xml"))&&hash(targetRaw).equals(text(m,"targetMetadataSha256")));var target=SecureXml.parse(targetRaw).getDocumentElement();var fixtures=new ArrayList<Element>();for(var p:peers)fixtures.add(fixture(file(folder,m,text(p,"label")+"/fixture.xml"),text(p,"entity")));
            stage="native-signature-configuration-unproven";require(hash(file(folder,m,"native-parser-command.php")).equals("abb80516e0fcc62d0768e142ddcfa7818bb8d8a533cdce0950441ee6d3a2543d")&&hash(file(folder,m,"native-readback-command.php")).equals("dc3006662fb5ecf37ad30574d5ad13778cde5fe66031fae26fd09d537332ff40"));var initial=nativeState(c,folder,m,"initial","initial");var before=nativeState(c,folder,m,"probes-before","configured");var after=nativeState(c,folder,m,"probes-after","configured");require(initial.path("runtime").equals(before.path("runtime"))&&initial.path("hostedIdp").equals(before.path("hostedIdp"))&&before.path("peers").equals(after.path("peers"))&&before.path("runtime").equals(after.path("runtime"))&&before.path("hostedIdp").equals(after.path("hostedIdp"))&&at(before,"recordedAt").equals(at(m,"configuredAt"))&&at(after,"recordedAt").equals(at(m,"completedAt")));
            var overlay=new StringBuilder("\n");for(int i=0;i<2;i++){var peer=peers.get(i);var empty=initial.path("peers").get(i);require(text(peer,"entity").equals(text(empty,"entityId"))&&empty.path("present").isBoolean()&&!empty.path("present").asBoolean());var conversion=original(c,folder,m,text(peer,"label")+"-conversion","native-metadata-conversion");var parserRaw=file(folder,m,text(peer,"label")+"/parser-output.json");require(hash(parserRaw).equals(text(conversion,"parserOutputSha256"))&&json(parserRaw).equals(conversion.path("parserOutput"))&&at(conversion,"nativeStartedAt").isBefore(at(conversion,"nativeFinishedAt"))&&at(conversion,"nativeFinishedAt").isBefore(at(conversion,"recordedAt")));require(text(peer,"entity").equals(text(conversion,"entityId"))&&hash(file(folder,m,text(peer,"label")+"/fixture.xml")).equals(text(conversion,"fixtureSha256"))&&conversion.path("parserOutput").path("validateAuthnRequest").isBoolean()&&conversion.at("/parserOutput/validateAuthnRequest").asBoolean());var parsed=conversion.at("/parserOutput/metadata");require(parsed.isObject()&&text(peer,"entity").equals(text(parsed,"entityid"))&&parsed.path("validate.authnrequest").isBoolean()&&parsed.path("validate.authnrequest").asBoolean());var state=before.path("peers").get(i);require(text(peer,"entity").equals(text(state,"entityId"))&&state.path("present").isBoolean()&&state.path("present").asBoolean());var resolved=state.path("resolvedMetadata").deepCopy();require(resolved.isObject()&&text(peer,"entity").equals(text(resolved,"metadata-index")));((com.fasterxml.jackson.databind.node.ObjectNode)resolved).remove("metadata-index");require(parsed.equals(resolved));nativeKeys(state.path("signingKeys"),spKeys(fixtures.get(i)));overlay.append(text(conversion.path("parserOutput"),"php")).append('\n');require(at(conversion,"recordedAt").isAfter(at(initial,"recordedAt"))&&at(conversion,"recordedAt").isBefore(at(before,"recordedAt")));}
            byte[] originalConfig=file(folder,m,"original-configuration.php"),configured=file(folder,m,"configured-configuration.php");require(Arrays.equals(configured,concat(originalConfig,overlay.toString().getBytes(StandardCharsets.UTF_8))));
            stage="six-outbox-controls-unproven";var rows=m.path("probes");require(rows.isArray()&&rows.size()==6);var checked=new ArrayList<Checked>();var evidence=new ArrayList<EvidenceRef>();for(int i=0;i<2;i++)for(int j=0;j<3;j++){var result=probe(c,folder,m,peers.get(i),peers.get(1-i),fixtures.get(i),fixtures.get(1-i),target,rows.get(i*3+j),FIXTURES.get(j));checked.add(result);evidence.add(new EvidenceRef("transcript",result.request().id()));evidence.add(new EvidenceRef("transcript",result.response().id()));}for(int i=1;i<checked.size();i++)require(checked.get(i-1).response().timestamp().isBefore(checked.get(i).request().timestamp()));
            stage="restoration-unproven";var restoration=nativeState(c,folder,m,"restoration","restored");require(restoration.path("restored").isBoolean()&&restoration.path("restored").asBoolean()&&restoration.path("runtime").equals(initial.path("runtime"))&&restoration.path("hostedIdp").equals(initial.path("hostedIdp"))&&at(restoration,"recordedAt").isAfter(at(after,"recordedAt"))&&Arrays.equals(originalConfig,file(folder,m,"final-configuration.php")));for(int i=0;i<2;i++)require(restoration.path("peers").get(i).equals(initial.path("peers").get(i)));
            var counts=node(folder,m,"operation-counts.json");require(counts.path("restored").isBoolean()&&counts.path("restored").asBoolean()&&counts.path("nativeConfigurationWrites").asInt(-1)==2&&counts.path("restorationWrites").asInt(-1)==1&&counts.path("outboxProtocolSubmissions").asInt(-1)==6&&counts.path("selectedProbeAttempts").asInt(-1)==6&&counts.path("initialBaselineSubmissions").asInt(-1)==2&&counts.path("protocolSubmissions").asInt(-1)==8&&counts.path("credentialPosts").asInt(-1)==1&&counts.path("personOperations").asInt(-1)==0&&counts.path("productRestarts").asInt(-1)==0);
            evidence.add(new EvidenceRef(KIND,c.runId()+"/manifest.json#"+hash(manifest)));for(var ref:m.path("originals"))evidence.add(new EvidenceRef("transcript",text(ref,"reference")));boolean accepted=checked.get(2).success()||checked.get(5).success();String reason=accepted?"signature.signer.issuer-key-mismatch-accepted":"signature.signer.issuer-key-restriction-observed";return Optional.of(new CaseOutcome(accepted?Outcome.VIOLATED:Outcome.SATISFIED,null,reason,reason,evidence.stream().distinct().toList(),Map.of("evidence_adapter",ADAPTER,"native_run_id",c.runId(),"case_id",RegisteredSignerObservationTestCase.CASE,"native_originals_verified",true,"restoration_verified",true,"scope","two-simultaneously-registered-native-saml-peers","native_receipt_owned",true)));
        }catch(Exception unavailable){return Optional.of(pending(c.runId(),stage));}
    }
    private static byte[] concat(byte[] a,byte[] b){var result=Arrays.copyOf(a,a.length+b.length);System.arraycopy(b,0,result,a.length,b.length);return result;}
    @Override public CaseOutcome pending(String run,String stage){return new CaseOutcome(Outcome.NOT_VERIFIED,stage,"signature.signer.native-unproven","signature.signer.native-unproven",List.of(),Map.of("evidence_adapter",ADAPTER,"native_run_id",run,"case_id",RegisteredSignerObservationTestCase.CASE,"native_receipt_owned",true));}
}
