package com.samlscope.runner.cases;

import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.*;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.binding.RedirectSignatureVerifier;
import com.samlscope.saml.crypto.SamlXmlDecrypter;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.cert.*;
import java.time.Instant;
import java.util.*;
import java.util.function.Function;
import org.w3c.dom.Element;
import static com.samlscope.runner.cases.MetadataAlgorithmEvidence.children;

/** Public originals only. Source precedence is not evidence of identity conflict detection. */
final class SimpleSamlPhpMetadataEntityIdentityEvidence {
    static final String ADAPTER = "simplesamlphp-native-metadata-entity-identity-v1";
    static final String SCHEMA = "samlscope-ssp-metadata-entity-identity-v1";
    static final String ORIGINAL = "samlscope-ssp-metadata-entity-identity-original-v1";
    static final String CAMPAIGN = "native-metadata-entity-identity";
    static final String KIND = "ssp-metadata-entity-identity-evidence";
    static final String TARGET = "http://localhost:18380/idp", BASE = "http://localhost:18080";
    static final Map<String,String> CASES = Map.of(
        "IIP-MD05-a1-idp-01", "sha256:308f52da818fe17f173314127627e15084ab297b72ea504d27077f86df4af72d",
        "IIP-MD05-a2-idp-01", "sha256:f175ab21c50fdf5861980473955f0d5f4ba17d7e4b064ad06beeca0cf4b3d4ca");
    private static final String MD="urn:oasis:names:tc:SAML:2.0:metadata", S="urn:oasis:names:tc:SAML:2.0:assertion",
        P="urn:oasis:names:tc:SAML:2.0:protocol", DS="http://www.w3.org/2000/09/xmldsig#";
    private static final ObjectMapper JSON = new JsonCodec().mapper().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION.mappedFeature());
    private final Path directory;
    private final TranscriptContentReader content;
    private final Function<String,byte[]> metadata;
    private final SamlDecryptionKeyProvider keys;
    SimpleSamlPhpMetadataEntityIdentityEvidence(Path directory, TranscriptContentReader content,
            Function<String,byte[]> metadata, SamlDecryptionKeyProvider keys) {
        this.directory=directory.toAbsolutePath().normalize(); this.content=Objects.requireNonNull(content);
        this.metadata=Objects.requireNonNull(metadata); this.keys=Objects.requireNonNull(keys);
    }
    static boolean validRun(String run) { return run!=null && run.matches("run_[0-9A-HJKMNP-TV-Z]{26}"); }
    boolean exists(String run) { return validRun(run) && Files.exists(directory.resolve(run), LinkOption.NOFOLLOW_LINKS); }
    static void require(boolean value) { if(!value) throw new IllegalArgumentException("Native identity evidence unproven"); }
    static String text(JsonNode n,String field) { require(n.path(field).isTextual()&&!n.path(field).asText().isBlank()); return n.path(field).asText(); }
    static String hash(byte[] bytes) throws Exception { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
    static JsonNode json(byte[] bytes) throws Exception { return JSON.readTree(bytes); }
    private byte[] raw(Path folder,String name) throws Exception {
        require(!name.isBlank()&&!name.contains("\\")&&!Path.of(name).isAbsolute());
        var path=folder.resolve(name).normalize(); require(path.startsWith(folder)&&!path.equals(folder)&&folder.relativize(path).toString().equals(name));
        for(var p=path;p!=null;p=p.getParent()) require(!Files.isSymbolicLink(p));
        require(Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS)&&Files.size(path)<=20*1024*1024);
        return Files.readAllBytes(path);
    }
    private byte[] file(Path folder,JsonNode m,String name) throws Exception {
        var bytes=raw(folder,name); require(hash(bytes).equals(text(m.path("files"),name))); return bytes;
    }
    private Map<String,TranscriptEntry> history(CaseContext c,String run) throws Exception {
        require(validRun(run)); var result=new LinkedHashMap<String,TranscriptEntry>();
        for(var e:c.transcript().list(run)) {
            require(run.equals(e.runId())&&e.id().matches("tx_[0-9A-HJKMNP-TV-Z]{26}")&&result.put(e.id(),e)==null);
            for(var header:e.headers().keySet()) require(!Set.of("authorization","cookie","set-cookie").contains(header.toLowerCase(Locale.ROOT)));
            if(e.decodedSamlRef()!=null) { require(("transcripts/"+run+"/"+e.id()+".saml.xml").equals(e.decodedSamlRef())); decoded(e); }
        }
        require(!result.isEmpty()); return result;
    }
    private byte[] decoded(TranscriptEntry e) throws Exception {
        require(e!=null&&e.decodedSamlRef()!=null); var b=content.readDecodedSaml(e);
        require(b!=null&&b.length==e.decodedSamlBytes()); return b;
    }
    private JsonNode original(Path folder,JsonNode m,Map<String,TranscriptEntry> history,String name) throws Exception {
        var ref=m.path("originals").path(name); var e=history.get(text(ref,"reference")); var b=decoded(e);
        require(Arrays.equals(b,file(folder,m,"native-originals/"+name+".json"))&&hash(b).equals(text(ref,"sha256")));
        require(e.direction()==Direction.INBOUND&&"POST".equals(e.method())&&Objects.equals(e.status(),204)
            &&"application/json".equals(e.contentType())&&(BASE+"/p/"+text(m,"planId")+"/sp/paos?run="+text(m,"runId")).equals(e.url()));
        var n=json(b); require(ORIGINAL.equals(text(n,"schema"))&&CAMPAIGN.equals(text(n,"campaignId"))
            &&m.path("runId").equals(n.path("runId"))&&m.path("targetMetadataSha256").equals(n.path("targetMetadataSha256"))
            &&Instant.parse(text(n,"recordedAt")).isBefore(e.timestamp())&&name.equals(text(n,"kind")));
        if(!name.equals("restoration")) require(!Instant.parse(text(n,"observedStartedAt")).isAfter(Instant.parse(text(n,"observedFinishedAt")))
            &&!Instant.parse(text(n,"observedFinishedAt")).isAfter(Instant.parse(text(n,"recordedAt"))));
        require(!sensitive(n)); return n;
    }
    private static boolean sensitive(JsonNode n) {
        if(n.isObject()) { var f=n.fields(); while(f.hasNext()) { var e=f.next();
            if(e.getKey().matches("(?i).*(password|secret|credential|token|cookie|authorization|privatekey).*")) return true;
            if(sensitive(e.getValue())) return true;
        }} else if(n.isArray()) for(var v:n) if(sensitive(v)) return true;
        return false;
    }
    private static List<X509Certificate> certs(Element root) throws Exception {
        var roles=children(root,MD,"SPSSODescriptor"); require(roles.size()==1); var result=new ArrayList<X509Certificate>();
        for(var kd:children(roles.getFirst(),MD,"KeyDescriptor")) if(Set.of("","signing").contains(kd.getAttribute("use"))) {
            var list=kd.getElementsByTagNameNS(DS,"X509Certificate");
            for(int i=0;i<list.getLength();i++) result.add((X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(
                new java.io.ByteArrayInputStream(Base64.getMimeDecoder().decode(list.item(i).getTextContent()))));
        }
        require(!result.isEmpty()); return result;
    }
    static Set<String> strings(JsonNode node) {
        require(node.isArray()); var result=new TreeSet<String>(); for(var v:node) require(v.isTextual()&&!v.asText().isBlank()&&result.add(v.asText())); return result;
    }
    private static JsonNode projection(Element root) throws Exception {
        var n=JSON.createObjectNode().put("entityId",root.getAttribute("entityID")); var k=new TreeSet<String>();
        for(var c:certs(root)) k.add(hash(c.getEncoded())); var a=new TreeSet<String>();
        for(var e:children(children(root,MD,"SPSSODescriptor").getFirst(),MD,"AssertionConsumerService")) a.add(e.getAttribute("Location"));
        require(!a.isEmpty()&&!a.contains("")); n.set("keys",JSON.valueToTree(k)); n.set("endpoints",JSON.valueToTree(a)); return n;
    }
    /** Controls exercise distinct entities and an actual merged identity, not just a boolean receipt. */
    static Outcome classify(JsonNode a,JsonNode b,JsonNode effective,String operation) {
        require("simultaneous-sources".equals(operation));
        require(text(a,"entityId").equals(text(b,"entityId"))&&text(a,"entityId").equals(text(effective,"entityId")));
        var ak=strings(a.path("keys")); var bk=strings(b.path("keys")); var aa=strings(a.path("endpoints")); var ba=strings(b.path("endpoints"));
        require(!ak.isEmpty()&&!bk.isEmpty()&&!aa.isEmpty()&&!ba.isEmpty()&&!ak.equals(bk)&&!aa.equals(ba));
        var ek=strings(effective.path("keys")); var ea=strings(effective.path("endpoints"));
        var unionK=new TreeSet<>(ak); unionK.addAll(bk); var unionA=new TreeSet<>(aa); unionA.addAll(ba);
        if(ek.equals(unionK)&&ea.equals(unionA)&&!effective.equals(a)&&!effective.equals(b)) return Outcome.VIOLATED;
        // A first-source/last-source winner, an overwrite, and an unqualified exception cannot
        // establish the approved conflict variant. No stock 2.5.0 conflict diagnostic is assumed.
        return Outcome.NOT_VERIFIED;
    }
    private void normal(CaseContext c,JsonNode peer,Map<String,TranscriptEntry> entries,Element sp,Element target,
            Instant begin,Instant end,List<EvidenceRef> refs) throws Exception {
        var rq=entries.get(text(peer.path("normal"),"requestReference")); var rs=entries.get(text(peer.path("normal"),"responseReference"));
        require(rq!=null&&rs!=null&&rq.direction()==Direction.OUTBOUND&&rs.direction()==Direction.INBOUND
            &&begin.isBefore(rq.timestamp())&&rq.timestamp().isBefore(rs.timestamp())&&rs.timestamp().isBefore(end));
        var requestRaw=decoded(rq); var q=SecureXml.parse(requestRaw).getDocumentElement(); var r=SecureXml.parse(decoded(rs)).getDocumentElement();
        String id=q.getAttribute("ID"), acs=q.getAttribute("AssertionConsumerServiceURL"), entity=text(peer,"entity");
        require(P.equals(q.getNamespaceURI())&&"AuthnRequest".equals(q.getLocalName())&&!id.isBlank()
            &&entity.equals(KeycloakSubjectConfirmationEvidence.issuer(q))&&strings(projection(sp).path("endpoints")).contains(acs));
        require(Set.of("","false","0").contains(q.getAttribute("ForceAuthn"))&&Set.of("","false","0").contains(q.getAttribute("IsPassive")));
        var endpoints=target.getElementsByTagNameNS(MD,"SingleSignOnService"); boolean destination=false;
        for(int i=0;i<endpoints.getLength();i++) if(q.getAttribute("Destination").equals(((Element)endpoints.item(i)).getAttribute("Location"))) destination=true;
        require(destination&&rq.url().split("\\?",2)[0].equals(q.getAttribute("Destination")));
        var signing=certs(sp); require("GET".equals(rq.method())&&rq.rawQuery()!=null
            &&signing.stream().anyMatch(cert->new RedirectSignatureVerifier().isValidForMessage(rq.rawQuery(),cert,requestRaw))
            ||"POST".equals(rq.method())&&KeycloakSubjectConfirmationEvidence.signed(q,signing));
        require(P.equals(r.getNamespaceURI())&&"Response".equals(r.getLocalName())&&id.equals(r.getAttribute("InResponseTo"))
            &&acs.equals(r.getAttribute("Destination"))&&acs.equals(rs.url())&&TARGET.equals(KeycloakSubjectConfirmationEvidence.issuer(r)));
        var statuses=children(r,P,"Status"); require(statuses.size()==1&&children(statuses.getFirst(),P,"StatusCode").size()==1
            &&"urn:oasis:names:tc:SAML:2.0:status:Success".equals(children(statuses.getFirst(),P,"StatusCode").getFirst().getAttribute("Value")));
        require(entries.values().stream().filter(e->e.direction()==Direction.INBOUND&&id.equals(e.samlSummary().get("inResponseTo"))).count()==1);
        var assertions=children(r,S,"Assertion"); var encrypted=children(r,S,"EncryptedAssertion"); Element assertion;
        if(encrypted.size()==1&&assertions.isEmpty()) assertion=new SamlXmlDecrypter().decrypt(encrypted.getFirst(),keys.keyFor(text(peer,"runId")).orElseThrow());
        else { require(assertions.size()==1&&encrypted.isEmpty()); assertion=assertions.getFirst(); }
        require(KeycloakSubjectConfirmationEvidence.signed(assertion,MetadataAlgorithmEvidence.signingKeys(target))
            &&TARGET.equals(KeycloakSubjectConfirmationEvidence.issuer(assertion)));
        var audience=assertion.getElementsByTagNameNS(S,"Audience"); var sc=assertion.getElementsByTagNameNS(S,"SubjectConfirmationData");
        require(audience.getLength()==1&&entity.equals(audience.item(0).getTextContent())&&sc.getLength()==1
            &&id.equals(((Element)sc.item(0)).getAttribute("InResponseTo"))&&acs.equals(((Element)sc.item(0)).getAttribute("Recipient")));
        refs.add(new EvidenceRef("transcript",rq.id())); refs.add(new EvidenceRef("transcript",rs.id()));
    }
    Optional<CaseOutcome> evaluate(CaseContext c,String caseId) {
        if(!CASES.containsKey(caseId)||!exists(c.runId())) return Optional.empty(); String stage="originals-unproven";
        try {
            require(c.targetRole()==TargetRole.IDP&&c.transcriptComplete()); var folder=directory.resolve(c.runId()); var manifestRaw=raw(folder,"manifest.json"); var m=json(manifestRaw);
            require(!m.path("files").has("manifest.json"));
            require(SCHEMA.equals(text(m,"schema"))&&ADAPTER.equals(text(m,"adapter"))&&CAMPAIGN.equals(text(m,"campaignId"))
                &&c.runId().equals(text(m,"runId"))&&TARGET.equals(text(m,"targetEntityId"))&&"metadata_idp".equals(text(m,"profile"))
                &&JSON.valueToTree(CASES).equals(m.path("caseDigests")));
            require(m.path("files").isObject()&&!m.path("files").isEmpty()); for(var it=m.path("files").fieldNames();it.hasNext();) file(folder,m,it.next());
            var targetRaw=metadata.apply(c.runId()); require(Arrays.equals(targetRaw,file(folder,m,"target-metadata.xml"))&&hash(targetRaw).equals(text(m,"targetMetadataSha256")));
            var target=SecureXml.parse(targetRaw).getDocumentElement(); require(TARGET.equals(target.getAttribute("entityID")));
            var entries=history(c,c.runId()); var peers=m.path("peers"); require(peers.isArray()&&peers.size()==2);
            var originals=m.path("originals"); var labels=new HashSet<String>(); originals.fieldNames().forEachRemaining(labels::add);
            require(labels.equals(Set.of("before","after","restoration")));
            var before=original(folder,m,entries,"before"); var after=original(folder,m,entries,"after"); var restoration=original(folder,m,entries,"restoration");
            require(Instant.parse(text(after,"recordedAt")).isBefore(Instant.parse(text(restoration,"recordedAt"))));
            require(before.path("native").equals(after.path("native"))&&before.path("runtime").equals(after.path("runtime"))
                &&before.path("runtime").equals(restoration.path("runtime"))&&before.at("/runtime/running").asBoolean(false));
            require(text(before.path("runtime"),"image").matches("sha256:[0-9a-f]{64}"));
            require(text(before.path("native"),"configurationSha256").matches("[0-9a-f]{64}")
                &&text(before,"originalSha256").matches("[0-9a-f]{64}")&&!before.path("originalSha256").equals(before.at("/native/configurationSha256")));
            require("2.5.0".equals(text(before.path("native"),"version"))&&"simultaneous-sources".equals(text(m,"operation")));
            stage="native-sources-and-distinct-controls-unproven";
            var expected=new ArrayList<JsonNode>(); var refs=new ArrayList<EvidenceRef>(); var runs=new HashSet<String>(); var entities=new HashSet<String>(); var plans=new HashSet<String>();
            for(int i=0;i<2;i++) {
                var peer=peers.get(i); String label=i==0?"primary":"secondary", run=text(peer,"runId"), plan=text(peer,"planId"), entity=text(peer,"entity");
                require(label.equals(text(peer,"label"))&&validRun(run)&&runs.add(run)&&plan.matches("plan_[0-9A-HJKMNP-TV-Z]{26}")&&plans.add(plan)
                    &&entity.equals(BASE+"/p/"+plan)&&entities.add(entity)&&Arrays.equals(targetRaw,metadata.apply(run)));
                if(i==0) require(c.runId().equals(run)&&text(m,"planId").equals(plan));
                var saved=json(file(folder,m,label+"/plan.json")).at("/plan/plan"); var created=json(file(folder,m,label+"/created.json")).path("run");
                require(plan.equals(saved.path("id").asText())&&"metadata_idp".equals(saved.path("profile").asText())&&run.equals(created.path("id").asText())&&plan.equals(created.path("planId").asText()));
                var included=json(file(folder,m,label+"/case-inventory.json")); require(JSON.valueToTree(CASES).equals(included));
                var sp=SecureXml.parse(file(folder,m,label+"/fixture.xml")).getDocumentElement(); require(entity.equals(sp.getAttribute("entityID"))&&KeycloakSubjectConfirmationEvidence.signed(sp,certs(sp)));
                var value=projection(sp); expected.add(value);
                require(value.equals(before.at("/native/sourceA/"+i)));
                if(i==1) require(value.equals(before.at("/native/effective/"+i)));
                normal(c,peer,i==0?entries:history(c,run),sp,target,Instant.parse(text(before,"recordedAt")),Instant.parse(text(after,"observedStartedAt")),refs);
            }
            require(!strings(expected.get(0).path("keys")).equals(strings(expected.get(1).path("keys"))));
            var duplicate=SecureXml.parse(file(folder,m,"duplicate-fixture.xml")).getDocumentElement(); var dup=projection(duplicate);
            require(text(peers.get(0),"entity").equals(duplicate.getAttribute("entityID"))&&KeycloakSubjectConfirmationEvidence.signed(duplicate,certs(duplicate))
                &&dup.equals(before.at("/native/sourceB/0"))&&before.at("/native/sourceA").size()==2&&before.at("/native/sourceB").size()==1&&before.at("/native/effective").size()==2);
            var prepared=entries.values().stream().filter(e->"MetadataPrepared".equals(e.samlSummary().get("type"))&&"multiple-signing-keys".equals(e.samlSummary().get("variant"))).toList();
            require(prepared.size()==1&&Arrays.equals(decoded(prepared.getFirst()),file(folder,m,"duplicate-fixture.xml"))
                &&hash(file(folder,m,"duplicate-fixture.xml")).equals(prepared.getFirst().samlSummary().get("metadataSha256"))
                &&prepared.getFirst().timestamp().isBefore(Instant.parse(text(before,"observedStartedAt"))));
            var fetch=entries.get(String.valueOf(prepared.getFirst().samlSummary().get("fetchTranscriptId")));
            require(fetch!=null&&fetch.direction()==Direction.INBOUND&&Objects.equals(fetch.status(),200)&&"MetadataFetch".equals(fetch.samlSummary().get("type"))&&fetch.timestamp().isBefore(prepared.getFirst().timestamp()));
            require(before.at("/native/sources").equals(m.path("sources"))&&m.path("sources").size()==3
                &&before.at("/native/sourceHashes").equals(m.path("sourceHashes")));
            var nativeNames=new HashSet<String>();m.path("sourceHashes").fieldNames().forEachRemaining(nativeNames::add);
            require(nativeNames.equals(Set.of("handler.php","source.php","flatfile.php","parser.php","configuration.php")));
            for(var it=m.path("sourceHashes").fields();it.hasNext();) {var e=it.next();require(hash(file(folder,m,"native-runtime/"+e.getKey())).equals(e.getValue().asText()));}
            stage="restoration-unproven";
            require(restoration.path("restored").asBoolean(false)&&restoration.path("originalSha256").equals(restoration.path("finalSha256"))
                &&restoration.path("originalSha256").equals(before.path("originalSha256"))&&restoration.path("temporarySourcesRemoved").asBoolean(false)
                &&restoration.path("sources").equals(JSON.readTree("[{\"type\":\"flatfile\"}]"))&&restoration.path("ownedPeersAbsent").asBoolean(false));
            var counts=json(file(folder,m,"operation-counts.json")); require(counts.path("configurationApplyWrites").asInt(-1)==1&&counts.path("restorationWrites").asInt(-1)==1
                &&counts.path("configurationWriteAttempts").asInt(-1)==2&&counts.path("successfulHostWrites").asInt(-1)==2&&counts.path("nativeApplications").asInt(-1)==1
                &&counts.path("fixtureFileWrites").asInt(-1)==2&&counts.path("fixtureRemovalOperations").asInt(-1)==1&&counts.path("normalFlowsAttempted").asInt(-1)==2
                &&counts.path("protocolSubmissions").asInt(-1)==2&&counts.path("nativeParserInvocations").asInt(-1)==3&&counts.path("humanOperations").asInt(-1)==0&&counts.path("productRestarts").asInt(-1)==0&&counts.path("restored").asBoolean(false));
            var commands=json(file(folder,m,"native-commands.json"));require(commands.isArray()&&!commands.isEmpty()
                &&counts.path("nativeCommandAttempts").asInt(-1)==commands.size());
            for(var command:commands) require(command.path("exitCode").asInt(-1)==0&&command.path("arguments").isArray()
                &&!Instant.parse(text(command,"startedAt")).isAfter(Instant.parse(text(command,"finishedAt"))));
            stage="duplicate-conflict-unqualified";
            // Native merging is distinguishable from single-source resolution. A source
            // winner remains diagnostic because no native conflict diagnostic is qualified.
            var outcome=classify(expected.getFirst(),dup,before.at("/native/effective/0"),text(m,"operation"));
            refs.add(new EvidenceRef("transcript",prepared.getFirst().id())); for(var ref:originals) refs.add(new EvidenceRef("transcript",text(ref,"reference")));
            refs.add(new EvidenceRef(KIND,c.runId()+"/manifest.json#"+hash(manifestRaw)));
            String reason=outcome==Outcome.VIOLATED?"metadata.entity-identity.ssp-ambiguous-native-merge":"metadata.entity-identity.ssp-unproven";
            return Optional.of(new CaseOutcome(outcome,outcome==Outcome.NOT_VERIFIED?stage:null,reason,reason,refs,
                Map.of("evidence_adapter",ADAPTER,"native_run_id",c.runId(),"case_id",caseId,"native_receipt_owned",true,"configuration_restored",true)));
        } catch(Exception unproven) { return Optional.of(unproven(c.runId(),caseId,stage)); }
    }
    static CaseOutcome unproven(String run,String id,String stage) {
        return new CaseOutcome(Outcome.NOT_VERIFIED,stage,"metadata.entity-identity.ssp-unproven","metadata.entity-identity.ssp-unproven",List.of(),
            Map.of("evidence_adapter",ADAPTER,"native_run_id",run,"case_id",id,"native_receipt_owned",true));
    }
}
