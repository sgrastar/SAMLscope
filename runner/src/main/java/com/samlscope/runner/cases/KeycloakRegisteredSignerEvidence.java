package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import java.util.zip.ZipFile;
import com.samlscope.saml.crypto.SamlXmlDecrypter;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.*;
import java.time.Instant;
import java.util.*;
import java.util.function.Function;
import static com.samlscope.runner.cases.MetadataAlgorithmEvidence.children;
import org.w3c.dom.Element;

/** Native registered secondary-peer signer restriction. Only complete original-backed proof is adopted.
 * The proof is scoped to the observed two native SAML clients; it makes no global trust-store claim. */
final class KeycloakRegisteredSignerEvidence implements RegisteredSignerNativeEvidence {
    static final String SCHEMA="samlscope-keycloak-registered-signer-v1";
    static final String ADAPTER="keycloak-native-issuer-key-locator-v1";
    static final String CAMPAIGN="native-registered-signer";
    static final String KIND="native-registered-signer-evidence";
    private static final String ORIGINAL="samlscope-keycloak-registered-signer-original-v1";
    private static final String MD="urn:oasis:names:tc:SAML:2.0:metadata",S="urn:oasis:names:tc:SAML:2.0:assertion",P="urn:oasis:names:tc:SAML:2.0:protocol",DS="http://www.w3.org/2000/09/xmldsig#";
    private static final String TARGET="http://localhost:18180/realms/samlscope",ADMIN="http://localhost:18180/admin/realms/samlscope",BASE="http://localhost:18080";
    @Override public String adapter(){return ADAPTER;}
    @Override public String evidenceKind(){return KIND;}
    private final Path directory;private final TranscriptContentReader content;private final Function<String,byte[]> metadata;private final java.util.function.BiFunction<String,String,Optional<com.samlscope.saml.crypto.PlanCredentials>> keys;
    KeycloakRegisteredSignerEvidence(Path directory,TranscriptContentReader content,Function<String,byte[]> metadata,java.util.function.BiFunction<String,String,Optional<com.samlscope.saml.crypto.PlanCredentials>> keys){this.directory=Objects.requireNonNull(directory).toAbsolutePath().normalize();this.content=Objects.requireNonNull(content);this.metadata=Objects.requireNonNull(metadata);this.keys=Objects.requireNonNull(keys);}
    @Override public boolean hasFinalProof(String run){return validRun(run)&&Files.exists(directory.resolve(run).resolve("manifest.json"),LinkOption.NOFOLLOW_LINKS);}
    public boolean exists(String run){return validRun(run)&&Files.exists(directory.resolve(run),LinkOption.NOFOLLOW_LINKS);}
    private static boolean validRun(String run){return run!=null&&run.matches("run_[0-9A-HJKMNP-TV-Z]{26}");}
    private static void require(boolean yes){if(!yes)throw new IllegalArgumentException("registered signer originals unproven");}
    static String hash(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
    private static JsonNode json(byte[] raw)throws Exception{return new JsonCodec().mapper().readTree(raw);}
    private static String text(JsonNode n,String name){require(n.path(name).isTextual()&&!n.path(name).asText().isBlank());return n.path(name).asText();}
    private static Instant at(JsonNode n,String field){return Instant.parse(text(n,field));}
    private byte[] raw(Path folder,String name)throws Exception {require(!name.isBlank()&&!Path.of(name).isAbsolute());var file=folder.resolve(name).normalize();require(file.startsWith(folder)&&!file.equals(folder));for(var p=file;p!=null;p=p.getParent())require(!Files.isSymbolicLink(p));require(Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS));return Files.readAllBytes(file);}
    private byte[] file(Path folder,JsonNode manifest,String name)throws Exception {var b=raw(folder,name);require(hash(b).equals(text(manifest.path("files"),name)));return b;}
    private JsonNode node(Path folder,JsonNode m,String name)throws Exception{return json(file(folder,m,name));}
    private Map<String,TranscriptEntry> history(CaseContext c,String run){require(validRun(run));var out=new LinkedHashMap<String,TranscriptEntry>();for(var e:c.transcript().list(run)){require(run.equals(e.runId())&&out.put(e.id(),e)==null);if(e.decodedSamlRef()!=null)require(("transcripts/"+run+"/"+e.id()+".saml.xml").equals(e.decodedSamlRef()));}return out;}
    private byte[] decoded(TranscriptEntry e)throws Exception{require(e!=null&&e.decodedSamlRef()!=null);var b=content.readDecodedSaml(e);require(b!=null&&b.length==e.decodedSamlBytes());return b;}
    private JsonNode original(Path folder,JsonNode m,Map<String,TranscriptEntry> entries,String name,String kind)throws Exception {
        var ref=m.path("originals").path(name);var e=entries.get(text(ref,"reference"));var b=decoded(e);require(hash(b).equals(text(ref,"sha256"))&&Arrays.equals(b,file(folder,m,"native-originals/"+name+".json")));
        require(e.direction()==Direction.INBOUND&&"POST".equals(e.method())&&Objects.equals(e.status(),204)&&"application/json".equals(e.contentType())&&(BASE+"/p/"+text(m,"planId")+"/sp/paos?run="+text(m,"runId")).equals(e.url()));var n=json(b);require(ORIGINAL.equals(text(n,"schema"))&&m.path("runId").equals(n.path("runId"))&&CAMPAIGN.equals(text(n,"campaignId"))&&kind.equals(text(n,"kind"))&&m.path("targetMetadataSha256").equals(n.path("targetMetadataSha256"))&&at(n,"recordedAt").isBefore(e.timestamp()));if(n.path("native").isObject())require(at(n.path("native"),"finishedAt").isBefore(at(n,"recordedAt")));return n;
    }
    private static byte[] response(JsonNode n)throws Exception{require(n.path("response_base64").isTextual());var b=Base64.getDecoder().decode(n.path("response_base64").asText());require(hash(b).equals(text(n,"response_sha256")));return b;}
    private static byte[] request(JsonNode n)throws Exception{var b=Base64.getDecoder().decode(text(n,"request_base64"));require(hash(b).equals(text(n,"request_sha256")));return b;}
    private static void nativeHttp(JsonNode n,String method,String path,int status){require(method.equals(text(n,"method"))&&(ADMIN+path).equals(text(n,"url"))&&n.path("status").isInt()&&status==n.path("status").asInt()&&at(n,"startedAt").isBefore(at(n,"finishedAt")));}
    private static JsonNode publicReply(JsonNode n,String db)throws Exception{
        nativeHttp(n,"GET","/clients/"+db,200);require("native-client-public-readback-v1".equals(text(n,"response_projection"))&&n.path("redactions").isArray());var removed=new HashSet<String>();for(var e:n.path("redactions"))require(e.isTextual()&&Set.of("$.secret","$.registrationAccessToken").contains(e.asText())&&removed.add(e.asText()));
        var value=json(response(n));require(value.isObject()&&!sensitive(value));return value;
    }
    private static boolean sensitive(JsonNode n){if(KeycloakSubjectConfirmationEvidence.sensitive(n))return true;if(n.isObject()){var f=n.fields();while(f.hasNext()){var e=f.next();if(e.getKey().matches("(?i).*(cookie|authorization).*"))return true;if(sensitive(e.getValue()))return true;}}else if(n.isArray()){for(var e:n)if(sensitive(e))return true;}return false;}
    private static List<X509Certificate> spKeys(Element root)throws Exception {
        var roles=children(root,MD,"SPSSODescriptor");require(roles.size()==1);var keys=new ArrayList<X509Certificate>();for(var kd:children(roles.getFirst(),MD,"KeyDescriptor")){if(!kd.getAttribute("use").isBlank()&&!"signing".equals(kd.getAttribute("use")))continue;var certs=kd.getElementsByTagNameNS(DS,"X509Certificate");for(int i=0;i<certs.getLength();i++)keys.add((X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(Base64.getMimeDecoder().decode(certs.item(i).getTextContent()))));}require(!keys.isEmpty());return keys;
    }
    private static Set<String> certHashes(List<X509Certificate> certs)throws Exception{var set=new HashSet<String>();for(var c:certs)set.add(hash(c.getEncoded()));return set;}
    private static Element fixture(byte[] raw,String entity)throws Exception{var root=SecureXml.parse(raw).getDocumentElement();require(MD.equals(root.getNamespaceURI())&&"EntityDescriptor".equals(root.getLocalName())&&entity.equals(root.getAttribute("entityID"))&&KeycloakSubjectConfirmationEvidence.signed(root,spKeys(root)));return root;}
    private static Set<String> acs(Element root){var roles=children(root,MD,"SPSSODescriptor");require(roles.size()==1);var out=new HashSet<String>();for(var e:children(roles.getFirst(),MD,"AssertionConsumerService")){require(!e.getAttribute("Location").isBlank());out.add(e.getAttribute("Location"));}require(!out.isEmpty());return out;}
    private static void savedAttributes(JsonNode converted,JsonNode saved){
        require(converted.isObject()&&saved.isObject());var fields=converted.fields();while(fields.hasNext()){var f=fields.next();require(f.getValue().equals(saved.get(f.getKey())));}
        var defaults=Map.of("saml.force.post.binding","true","realm_client","false","saml_force_name_id_format","false","saml_name_id_format","username","saml.allow.ecp.flow","false","saml_signature_canonicalization_method","http://www.w3.org/2001/10/xml-exc-c14n#");var count=0;var actual=saved.fields();while(actual.hasNext()){var f=actual.next();if(converted.has(f.getKey()))continue;require(f.getValue().isTextual());String name=f.getKey(),value=f.getValue().asText();if(defaults.containsKey(name))require(defaults.get(name).equals(value));else if("client.secret.creation.time".equals(name))require(value.matches("[0-9]{10}"));else if("saml.artifact.binding.identifier".equals(name))require(Base64.getDecoder().decode(value).length==20);else require(false);count++;}require(count==defaults.size()+2);
    }
    private static void incorporated(JsonNode converted,JsonNode saved,String db,String entity){require(db.equals(text(saved,"id"))&&entity.equals(text(saved,"clientId"))&&"saml".equals(text(saved,"protocol"))&&saved.path("enabled").asBoolean(false)&&saved.path("authenticationFlowBindingOverrides").isEmpty());var fields=converted.fields();while(fields.hasNext()){var f=fields.next();if(f.getKey().equals("redirectUris")){var left=new HashSet<String>();var right=new HashSet<String>();for(var e:f.getValue())left.add(e.asText());for(var e:saved.path("redirectUris"))right.add(e.asText());require(left.equals(right)&&left.size()==f.getValue().size()&&right.size()==saved.path("redirectUris").size());continue;}if(f.getKey().equals("attributes")){savedAttributes(f.getValue(),saved.path("attributes"));continue;}if(f.getKey().equals("protocolMappers")&&f.getValue().isEmpty()){require(!saved.has("protocolMappers")||saved.path("protocolMappers").isEmpty());continue;}require(f.getValue().equals(saved.get(f.getKey())));}}
    public Optional<RegisteredSignerProbeInputs> probeInputs(CaseContext context) {
        if(!exists(context.runId()))return Optional.empty();
        try {
            var folder=directory.resolve(context.runId());var raw=raw(folder,"preparation.json");var m=json(raw);
            require("samlscope-registered-signer-preparation-v1".equals(text(m,"schema"))&&CAMPAIGN.equals(text(m,"campaignId"))&&context.runId().equals(text(m,"localRunId")));
            var peers=m.path("peers");require(peers.isArray()&&peers.size()==2);JsonNode local=null,other=null;
            var targetRaw=metadata.apply(context.runId());require(hash(targetRaw).equals(text(m,"targetMetadataSha256"))&&Arrays.equals(targetRaw,file(folder,m,"target-metadata.xml")));
            var target=SecureXml.parse(targetRaw).getDocumentElement();require(TARGET.equals(target.getAttribute("entityID")));
            var ids=new HashSet<String>();var entities=new HashSet<String>();var certs=new ArrayList<List<X509Certificate>>();
            for(var peer:peers) {
                String run=text(peer,"runId"),plan=text(peer,"planId"),entity=text(peer,"entity"),label=text(peer,"label");
                require(validRun(run)&&plan.matches("plan_[0-9A-HJKMNP-TV-Z]{26}")&&entity.equals(BASE+"/p/"+plan)&&ids.add(run)&&entities.add(entity));
                var created=node(folder,m,label+"/created.json");require(run.equals(created.path("run").path("id").asText())&&plan.equals(created.path("run").path("planId").asText()));
                var sp=fixture(file(folder,m,label+"/fixture.xml"),entity);var actual=keys.apply(run,"primary").orElseThrow();
                require(spKeys(sp).stream().anyMatch(c->Arrays.equals(c.getPublicKey().getEncoded(),actual.certificate().getPublicKey().getEncoded())));certs.add(spKeys(sp));
                require(Arrays.equals(metadata.apply(run),targetRaw));if(run.equals(context.runId()))local=peer;else other=peer;
            }
            require(local!=null&&other!=null&&Collections.disjoint(certHashes(certs.get(0)),certHashes(certs.get(1))));
            var sp=fixture(file(folder,m,text(local,"label")+"/fixture.xml"),text(local,"entity"));
            var acs=MetadataSupersessionProbeTestCase.acs(sp,0);require(acs(sp).contains(acs.toString()));
            return Optional.of(new RegisteredSignerProbeInputs(context.runId(),text(other,"runId"),text(local,"entity"),java.net.URI.create(TARGET+"/protocol/saml"),acs,hash(raw)));
        }catch(Exception unavailable){return Optional.empty();}
    }
    static boolean nativeSignatureRejectionPage(byte[] body) {
        var page=new String(body,StandardCharsets.UTF_8);
        return !page.contains("SAMLResponse") && java.util.regex.Pattern.compile("<div\\s+id=\"kc-error-message\">\\s*<p\\s+class=\"instruction\">Invalid requester</p>\\s*</div>").matcher(page).find();
    }
    private record Checked(TranscriptEntry request,TranscriptEntry response,boolean success){}
    private Checked probe(CaseContext context,Path folder,JsonNode m,JsonNode peer,Map<String,TranscriptEntry> entries,Element sp,Element other,Element target,JsonNode row,String name)throws Exception {
        String run=text(peer,"runId");var request=entries.get(text(row,"requestReference"));require(request!=null&&request.direction()==Direction.OUTBOUND&&"POST".equals(request.method())&&request.timestamp().isAfter(Instant.parse(text(m,"configuredAt"))));
        require(text(row,"fixture").equals(name)&&text(row,"runId").equals(run)&&text(row,"actionId").equals(request.correlationId()));
        String expectedAction=com.samlscope.core.caseexec.ActionIds.derive(run,"IIP-SSO01-al-idp-01","await-fixture-"+name,0);require(expectedAction.equals(request.correlationId()));
        var raw=decoded(request);var q=SecureXml.parse(raw).getDocumentElement();String id=q.getAttribute("ID"),entity=text(peer,"entity"),url=q.getAttribute("AssertionConsumerServiceURL");
        require(P.equals(q.getNamespaceURI())&&"AuthnRequest".equals(q.getLocalName())&&("_"+expectedAction).equals(id)&&entity.equals(KeycloakSubjectConfirmationEvidence.issuer(q))&&request.url().equals(q.getAttribute("Destination"))&&(TARGET+"/protocol/saml").equals(request.url())&&acs(sp).contains(url)&&url.equals(MetadataSupersessionProbeTestCase.acs(sp,0).toString()));
        require(Set.of("","false","0").contains(q.getAttribute("ForceAuthn"))&&Set.of("","false","0").contains(q.getAttribute("IsPassive")));
        var issuerKey=keys.apply(run,"primary").orElseThrow();String otherRun=text(m.path("peers").get(run.equals(m.path("peers").get(0).path("runId").asText())?1:0),"runId");
        var signer=name.equals("local-other-signer")?keys.apply(otherRun,"primary").orElseThrow():issuerKey;
        var issue=Instant.parse(q.getAttribute("IssueInstant"));require(!issue.isAfter(request.timestamp())&&issue.isAfter(Instant.parse(text(m,"configuredAt"))));
        var expected=new com.samlscope.saml.normal.SamlSignedRequestFactory().build(name.equals("local-invalid-signature")?com.samlscope.saml.normal.SamlSignedRequestFactory.Fixture.BAD_SIGNATURE_VALUE:com.samlscope.saml.normal.SamlSignedRequestFactory.Fixture.VALID,id,java.net.URI.create(request.url()),entity,java.net.URI.create(url),issue,signer);
        require(Arrays.equals(expected,raw));
        boolean own=KeycloakSubjectConfirmationEvidence.signed(q,spKeys(sp)),foreign=KeycloakSubjectConfirmationEvidence.signed(q,spKeys(other));
        require(name.equals("local-normal")?own&&!foreign:name.equals("local-invalid-signature")?!own&&!foreign:!own&&foreign);
        var responses=entries.values().stream().filter(e->e.direction()==Direction.INBOUND&&id.equals(e.samlSummary().get("inResponseTo"))).toList();
        var browsers=entries.values().stream().filter(e->e.direction()==Direction.INBOUND&&expectedAction.equals(e.correlationId())&&"BrowserResponseObservation".equals(e.samlSummary().get("type"))).toList();
        require(responses.size()+browsers.size()==1);boolean success=!responses.isEmpty();TranscriptEntry response;
        if(success) {
            response=responses.getFirst();require(name.equals("local-normal")||name.equals("local-other-signer"));var r=SecureXml.parse(decoded(response)).getDocumentElement();
            require("POST".equals(response.method())&&url.equals(response.url())&&P.equals(r.getNamespaceURI())&&"Response".equals(r.getLocalName())&&id.equals(r.getAttribute("InResponseTo"))&&url.equals(r.getAttribute("Destination"))&&TARGET.equals(KeycloakSubjectConfirmationEvidence.issuer(r))&&KeycloakSubjectConfirmationEvidence.signed(r,MetadataAlgorithmEvidence.signingKeys(target)));
            var status=children(r,P,"Status");require(status.size()==1&&children(status.getFirst(),P,"StatusCode").size()==1&&"urn:oasis:names:tc:SAML:2.0:status:Success".equals(children(status.getFirst(),P,"StatusCode").getFirst().getAttribute("Value")));
            var encrypted=children(r,S,"EncryptedAssertion");require(encrypted.size()==1&&children(r,S,"Assertion").isEmpty());var assertion=new SamlXmlDecrypter().decrypt(encrypted.getFirst(),keys.apply(run,"primary").orElseThrow().privateKey());
            require(KeycloakSubjectConfirmationEvidence.signed(assertion,MetadataAlgorithmEvidence.signingKeys(target))&&TARGET.equals(KeycloakSubjectConfirmationEvidence.issuer(assertion))&&assertion.getElementsByTagNameNS(S,"Audience").getLength()==1&&entity.equals(assertion.getElementsByTagNameNS(S,"Audience").item(0).getTextContent()));
            var sc=assertion.getElementsByTagNameNS(S,"SubjectConfirmationData");require(sc.getLength()==1&&id.equals(((Element)sc.item(0)).getAttribute("InResponseTo"))&&url.equals(((Element)sc.item(0)).getAttribute("Recipient"))&&children(assertion,S,"AuthnStatement").size()==1);
        }else {
            response=browsers.getFirst();require(!name.equals("local-normal")&&"BROWSER".equals(response.method())&&Integer.valueOf(400).equals(response.status())&&request.url().equals(response.url()));
            require(response.bodyRef()!=null&&response.bodyRef().equals("transcripts/"+run+"/"+response.id()+".body")&&response.bodyBytes()>0&&response.bodyBytes()<=262144);
            var body=raw(directory.getParent(),response.bodyRef());require(body.length==response.bodyBytes());require(nativeSignatureRejectionPage(body));
            var original=original(folder,m,history(context,text(m,"runId")),text(row,"nativeHttpOriginal"),"native-http-response");var n=original.path("native");
            require(run.equals(text(original,"observedRunId"))&&request.id().equals(text(original,"requestReference"))&&response.id().equals(text(original,"responseReference"))&&expectedAction.equals(text(original,"actionId"))&&"POST".equals(text(n,"method"))&&request.url().equals(text(n,"requestUrl"))&&request.url().equals(text(n,"responseUrl"))&&id.equals(text(n,"requestId"))&&hash(raw).equals(text(n,"requestSha256"))&&n.path("responseStatus").asInt(-1)==400&&n.path("responseBodyBytes").asInt(-1)==body.length&&hash(body).equals(text(n,"responseBodySha256")));
            require(!at(n,"startedAt").isBefore(request.timestamp())&&!at(n,"finishedAt").isBefore(at(n,"startedAt"))&&!at(n,"finishedAt").isAfter(response.timestamp())&&at(original,"recordedAt").isAfter(response.timestamp()));
        }
        require(response.timestamp().isAfter(request.timestamp())&&response.timestamp().isBefore(Instant.parse(text(m,"completedAt"))));return new Checked(request,response,success);
    }
    private Map<String,JsonNode> state(CaseContext context,Path folder,JsonNode m,Map<String,TranscriptEntry> entries,String name)throws Exception {
        var record=original(folder,m,entries,name,"registered-signer-native-clients");var peers=m.path("peers");require(record.path("peers").size()==2);var clients=new LinkedHashMap<String,JsonNode>();
        for(int i=0;i<2;i++){var peer=peers.get(i);var row=record.path("peers").get(i);for(String key:List.of("label","planId","runId"))require(peer.path(key).equals(row.path(key)));require(text(peer,"entity").equals(text(row,"entityId"))&&text(peer,"clientId").equals(text(row,"clientDatabaseId")));var n=row.path("native");var value=publicReply(n,text(peer,"clientId"));require(at(n,"finishedAt").isBefore(at(record,"recordedAt")));clients.put(text(peer,"label"),value);}return clients;
    }
    private static final Map<String,String> SOURCE=Map.of(
        "org/keycloak/protocol/saml/SamlService.class","9595db004ef39dfa3e560ae4817d30646c15d117dbff08737283d14f0fbc7f45",
        "org/keycloak/protocol/saml/SamlService$BindingProtocol.class","1567d07d08492c6a80587e50e1db84ce5a4aab8a32ead70f043a7b8648ce172d",
        "org/keycloak/protocol/saml/SamlService$PostBindingProtocol.class","04d7a04ab56a3ffd515e3b77623b7f7dc7812d43fe8d07a4f193bec8159960db",
        "org/keycloak/protocol/saml/SamlProtocolUtils.class","c739a9e125462591a0d697fc38d5b7754b36b11d86dbe9f85ef0e397ef65be35",
        "org/keycloak/protocol/saml/SamlClient.class","b06ad9303baf1ca1a8702604b3424cf6a82497d6eb72fb29d60ce33baa3b3fa6");
    private void source(Path folder,JsonNode m)throws Exception {
        var path=folder.resolve("native-runtime/org.keycloak.keycloak-services-26.7.2.jar");require(hash(file(folder,m,"native-runtime/"+path.getFileName())).equals(KeycloakSelfContainedTrustEvidenceFile.SERVICES_HASH));
        try(var zip=new ZipFile(path.toFile())){for(var p:SOURCE.entrySet()){var e=zip.getEntry(p.getKey());require(e!=null);try(var in=zip.getInputStream(e)){require(p.getValue().equals(hash(in.readAllBytes())));}}}
    }
    public Optional<CaseOutcome> evaluate(CaseContext context) {
        if(!exists(context.runId()))return Optional.empty();String stage="registered-signer-originals-unproven";
        try {
            require(context.transcriptComplete());var folder=directory.resolve(context.runId());var raw=raw(folder,"manifest.json");var m=json(raw);
            require(SCHEMA.equals(text(m,"schema"))&&ADAPTER.equals(text(m,"adapter"))&&CAMPAIGN.equals(text(m,"campaignId"))&&context.runId().equals(text(m,"runId"))&&TARGET.equals(text(m,"targetEntityId")));
            byte[] targetRaw=metadata.apply(context.runId());require(Arrays.equals(targetRaw,file(folder,m,"target-metadata.xml"))&&hash(targetRaw).equals(text(m,"targetMetadataSha256")));var target=SecureXml.parse(targetRaw).getDocumentElement();require(TARGET.equals(target.getAttribute("entityID")));
            require(probeInputs(context).isPresent());var peers=m.path("peers");require(peers.isArray()&&peers.size()==2&&context.runId().equals(text(peers.get(0),"runId")));var primary=history(context,context.runId());var fixtures=new ArrayList<Element>();var converted=new ArrayList<JsonNode>();var refs=new ArrayList<EvidenceRef>();
            stage="native-signature-configuration-unproven";
            for(var peer:peers) {
                String label=text(peer,"label"),entity=text(peer,"entity"),db=text(peer,"clientId"),lookup="/clients?clientId="+java.net.URLEncoder.encode(entity,StandardCharsets.UTF_8)+"&briefRepresentation=true";require(lookup.equals(text(peer,"lookup"))&&db.matches("[0-9a-f-]{36}"));var spRaw=file(folder,m,label+"/fixture.xml");var sp=fixture(spRaw,entity);fixtures.add(sp);
                var initial=original(folder,m,primary,label+"-initial","initial-native-inventory");nativeHttp(initial.path("native"),"GET",lookup,200);require(json(response(initial.path("native"))).isArray()&&json(response(initial.path("native"))).isEmpty());
                var conversion=original(folder,m,primary,label+"-conversion","native-metadata-conversion");nativeHttp(conversion.path("native"),"POST","/client-description-converter",200);require(Arrays.equals(spRaw,request(conversion.path("native")))&&hash(spRaw).equals(text(conversion,"fixtureSha256")));var value=json(response(conversion.path("native")));require(entity.equals(text(value,"clientId"))&&"saml".equals(text(value,"protocol"))&&!value.has("id")&&!sensitive(value));converted.add(value);
                var creation=original(folder,m,primary,label+"-creation","native-simultaneous-create");nativeHttp(creation.path("native"),"POST","/clients",201);require(db.equals(text(creation,"clientDatabaseId"))&&Arrays.equals(response(conversion.path("native")),request(creation.path("native")))&&at(initial.path("native"),"finishedAt").isBefore(at(conversion.path("native"),"startedAt"))&&at(conversion.path("native"),"finishedAt").isBefore(at(creation.path("native"),"startedAt")));
            }
            require(Collections.disjoint(certHashes(spKeys(fixtures.get(0))),certHashes(spKeys(fixtures.get(1)))));
            var before=state(context,folder,m,primary,"probes-before");var after=state(context,folder,m,primary,"probes-after");require(before.equals(after));var a=original(folder,m,primary,"probes-before","registered-signer-native-clients");var b=original(folder,m,primary,"probes-after","registered-signer-native-clients");
            require(a.path("runtime").equals(b.path("runtime"))&&a.path("runtime").path("running").asBoolean(false)&&a.path("policies").equals(b.path("policies"))&&KeycloakSelfContainedTrustEvidenceFile.SERVICES_HASH.equals(text(a,"nativeServicesSha256"))&&a.path("nativeServicesSha256").equals(b.path("nativeServicesSha256"))&&a.at("/policies/policies/policies").isEmpty()&&a.at("/policies/profiles/profiles").isEmpty());
            require(at(a,"recordedAt").equals(Instant.parse(text(m,"configuredAt")))&&at(b,"recordedAt").equals(Instant.parse(text(m,"completedAt"))));
            for(int i=0;i<2;i++){var peer=peers.get(i);var client=before.get(text(peer,"label"));incorporated(converted.get(i),client,text(peer,"clientId"),text(peer,"entity"));var attrs=client.path("attributes");require("true".equals(text(attrs,"saml.client.signature"))&&"true".equals(text(attrs,"saml.encrypt"))&&"true".equals(text(attrs,"saml.server.signature"))&&!attrs.has("saml.metadataDescriptorUrl")&&!attrs.has("saml.useMetadataDescriptorUrl"));
                var cert=(X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(Base64.getMimeDecoder().decode(text(attrs,"saml.signing.certificate"))));require(certHashes(spKeys(fixtures.get(i))).contains(hash(cert.getEncoded())));}
            stage="native-issuer-key-locator-unproven";source(folder,m);
            stage="six-outbox-controls-unproven";var results=new ArrayList<Checked>();var rows=m.path("probes");require(rows.isArray()&&rows.size()==6);
            for(int i=0;i<2;i++)for(int j=0;j<3;j++){String name=List.of("local-normal","local-invalid-signature","local-other-signer").get(j);var row=rows.get(i*3+j);var entries=history(context,text(peers.get(i),"runId"));var checked=probe(context,folder,m,peers.get(i),entries,fixtures.get(i),fixtures.get(1-i),target,row,name);results.add(checked);for(var e:List.of(checked.request(),checked.response()))refs.add(new EvidenceRef("transcript",e.id()));}
            for(int i=1;i<results.size();i++)require(results.get(i-1).response().timestamp().isBefore(results.get(i).request().timestamp()));
            stage="restoration-unproven";var restoration=original(folder,m,primary,"restoration","native-restoration");require(restoration.path("restored").asBoolean(false)&&restoration.path("runtime").equals(a.path("runtime"))&&restoration.path("policies").equals(a.path("policies"))&&at(b,"recordedAt").isBefore(at(restoration,"recordedAt"))&&restoration.path("peers").size()==2);
            for(int i=0;i<2;i++){var p=peers.get(i);var row=restoration.path("peers").get(i);nativeHttp(row.path("deletion"),"DELETE","/clients/"+text(p,"clientId"),204);nativeHttp(row.path("inventory"),"GET",text(p,"lookup"),200);require(json(response(row.path("inventory"))).isEmpty()&&at(row.path("deletion"),"finishedAt").isBefore(at(row.path("inventory"),"startedAt"))&&at(b,"recordedAt").isBefore(at(row.path("deletion"),"startedAt")));}
            var costs=node(folder,m,"operation-counts.json");require(costs.path("restored").asBoolean(false)&&costs.path("nativeConfigurationWrites").asInt(-1)==4&&costs.path("protocolSubmissions").asInt(-1)>=6&&costs.path("credentialPosts").asInt(-1)==1&&costs.path("personOperations").asInt(-1)==0&&costs.path("productRestarts").asInt(-1)==0);
            refs.add(new EvidenceRef(KIND,context.runId()+"/manifest.json#"+hash(raw)));for(var ref:m.path("originals"))refs.add(new EvidenceRef("transcript",text(ref,"reference")));
            boolean mismatchAccepted=results.get(2).success()||results.get(5).success();String reason=mismatchAccepted?"signature.signer.issuer-key-mismatch-accepted":"signature.signer.issuer-key-restriction-observed";
            return Optional.of(new CaseOutcome(mismatchAccepted?Outcome.VIOLATED:Outcome.SATISFIED,null,reason,reason,refs.stream().distinct().toList(),Map.of("evidence_adapter",ADAPTER,"native_run_id",context.runId(),"case_id","IIP-SSO01-al-idp-01","native_originals_verified",true,"restoration_verified",true,"scope","two-simultaneously-registered-native-saml-clients","native_receipt_owned",true)));
        }catch(Exception unavailable){return Optional.of(pending(context.runId(),stage));}
    }
    public CaseOutcome pending(String run,String stage){return new CaseOutcome(Outcome.NOT_VERIFIED,stage,"signature.signer.native-unproven","signature.signer.native-unproven",List.of(),Map.of("evidence_adapter",ADAPTER,"native_run_id",run,"case_id","IIP-SSO01-al-idp-01","native_receipt_owned",true));}
}
