package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.binding.RedirectSignatureVerifier;
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

/** Native simultaneous registration, two signed normal controls, and an idless duplicate
 * create. Metadata admission and identity conflict are the measured obligations: this does
 * not infer complete metadata-key or endpoint incorporation from converter output. The
 * secondary Run is explicitly bound to its Suite plan, original SP role and encrypted flow.
 */
final class KeycloakMetadataEntityIdentityEvidence {
    static final String SCHEMA="samlscope-keycloak-metadata-entity-identity-v1";
    static final String ADAPTER="keycloak-native-simultaneous-entity-registration-v1";
    static final String CAMPAIGN="native-metadata-entity-identity";
    static final String KIND="native-metadata-entity-identity-evidence";
    private static final String ORIGINAL="samlscope-keycloak-metadata-entity-identity-original-v1";
    private static final String MD="urn:oasis:names:tc:SAML:2.0:metadata",S="urn:oasis:names:tc:SAML:2.0:assertion",P="urn:oasis:names:tc:SAML:2.0:protocol",DS="http://www.w3.org/2000/09/xmldsig#";
    private static final String TARGET="http://localhost:18180/realms/samlscope",ADMIN="http://localhost:18180/admin/realms/samlscope",BASE="http://localhost:18080";
    private final Path directory;private final TranscriptContentReader content;private final Function<String,byte[]> metadata;private final SamlDecryptionKeyProvider keys;
    KeycloakMetadataEntityIdentityEvidence(Path directory,TranscriptContentReader content,Function<String,byte[]> metadata,SamlDecryptionKeyProvider keys){this.directory=Objects.requireNonNull(directory).toAbsolutePath().normalize();this.content=Objects.requireNonNull(content);this.metadata=Objects.requireNonNull(metadata);this.keys=Objects.requireNonNull(keys);}
    boolean exists(String run){return validRun(run)&&Files.exists(directory.resolve(run),LinkOption.NOFOLLOW_LINKS);}
    private static boolean validRun(String run){return run!=null&&run.matches("run_[0-9A-HJKMNP-TV-Z]{26}");}
    private static void require(boolean yes){if(!yes)throw new IllegalArgumentException("native entity identity originals unproven");}
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
    private record Pair(TranscriptEntry request,TranscriptEntry response){}
    private Pair normal(CaseContext context,JsonNode peer,Map<String,TranscriptEntry> entries,Element sp,Element target)throws Exception{
        String run=text(peer,"runId"),entity=text(peer,"entity");var request=entries.get(text(peer.path("normal"),"requestReference"));var response=entries.get(text(peer.path("normal"),"responseReference"));
        require(request!=null&&response!=null&&request.direction()==Direction.OUTBOUND&&response.direction()==Direction.INBOUND&&request.timestamp().isBefore(response.timestamp())&&"GET".equals(request.method())&&request.rawQuery()!=null);
        var rq=decoded(request);var rs=decoded(response);var q=SecureXml.parse(rq).getDocumentElement();var doc=SecureXml.parse(rs);var r=doc.getDocumentElement();String id=q.getAttribute("ID"),url=q.getAttribute("AssertionConsumerServiceURL");
        require(P.equals(q.getNamespaceURI())&&"AuthnRequest".equals(q.getLocalName())&&!id.isBlank()&&entity.equals(KeycloakSubjectConfirmationEvidence.issuer(q))&&TARGET.concat("/protocol/saml").equals(q.getAttribute("Destination"))&&url.equals(response.url())&&acs(sp).contains(url));
        require(Set.of("","false","0").contains(q.getAttribute("ForceAuthn"))&&Set.of("","false","0").contains(q.getAttribute("IsPassive"))&&spKeys(sp).stream().anyMatch(c->new RedirectSignatureVerifier().isValidForMessage(request.rawQuery(),c,rq)));
        require(P.equals(r.getNamespaceURI())&&"Response".equals(r.getLocalName())&&id.equals(r.getAttribute("InResponseTo"))&&url.equals(r.getAttribute("Destination"))&&TARGET.equals(KeycloakSubjectConfirmationEvidence.issuer(r))&&KeycloakSubjectConfirmationEvidence.signed(r,MetadataAlgorithmEvidence.signingKeys(target)));
        var status=children(r,P,"Status");require(status.size()==1&&children(status.getFirst(),P,"StatusCode").size()==1&&"urn:oasis:names:tc:SAML:2.0:status:Success".equals(children(status.getFirst(),P,"StatusCode").getFirst().getAttribute("Value")));
        require(entries.values().stream().filter(e->e.direction()==Direction.INBOUND&&id.equals(e.samlSummary().get("inResponseTo"))).count()==1);
        var encrypted=children(r,S,"EncryptedAssertion");require(encrypted.size()==1&&children(r,S,"Assertion").isEmpty());var privateKey=keys.keyFor(run).orElseThrow();var assertion=new SamlXmlDecrypter().decrypt(encrypted.getFirst(),privateKey);
        require(KeycloakSubjectConfirmationEvidence.signed(assertion,MetadataAlgorithmEvidence.signingKeys(target))&&TARGET.equals(KeycloakSubjectConfirmationEvidence.issuer(assertion))&&assertion.getElementsByTagNameNS(S,"Audience").getLength()==1&&entity.equals(assertion.getElementsByTagNameNS(S,"Audience").item(0).getTextContent()));
        var sc=assertion.getElementsByTagNameNS(S,"SubjectConfirmationData");require(sc.getLength()==1&&id.equals(((Element)sc.item(0)).getAttribute("InResponseTo"))&&url.equals(((Element)sc.item(0)).getAttribute("Recipient")));
        require(children(assertion,S,"Subject").size()==1&&children(children(assertion,S,"Subject").getFirst(),S,"NameID").size()==1&&children(assertion,S,"AuthnStatement").size()==1);
        return new Pair(request,response);
    }
    private Map<String,JsonNode> epoch(Path folder,JsonNode m,Map<String,TranscriptEntry> entries,String name,JsonNode peers)throws Exception{
        var record=original(folder,m,entries,name,"simultaneous-native-entities");require(record.path("peers").isArray()&&record.path("peers").size()==2);var clients=new LinkedHashMap<String,JsonNode>();
        for(int i=0;i<2;i++){var peer=peers.get(i);var row=record.path("peers").get(i);for(String key:List.of("label","planId","runId"))require(peer.path(key).equals(row.path(key)));require(text(peer,"entity").equals(text(row,"entityId"))&&text(peer,"clientId").equals(text(row,"clientDatabaseId")));var n=row.path("native");var value=publicReply(n,text(peer,"clientId"));require(at(n,"finishedAt").isBefore(at(record,"recordedAt")));clients.put(text(peer,"label"),value);}return clients;
    }
    private static void scope(JsonNode a,JsonNode b){require(a.path("runtime").isObject()&&a.path("runtime").equals(b.path("runtime"))&&a.path("runtime").path("running").asBoolean(false)&&a.path("policies").equals(b.path("policies"))&&a.at("/policies/policies/policies").isEmpty()&&a.at("/policies/profiles/profiles").isEmpty());}
    Optional<CaseOutcome> evaluate(CaseContext context,String caseId){
        if(!Set.of("IIP-MD05-a1-idp-01","IIP-MD05-a2-idp-01").contains(caseId)||!exists(context.runId()))return Optional.empty();String stage="native-originals-unproven";
        try{
            require(context.transcriptComplete());var folder=directory.resolve(context.runId());var m=json(raw(folder,"manifest.json"));require(SCHEMA.equals(text(m,"schema"))&&ADAPTER.equals(text(m,"adapter"))&&CAMPAIGN.equals(text(m,"campaignId"))&&context.runId().equals(text(m,"runId"))&&TARGET.equals(text(m,"targetEntityId")));
            byte[] targetRaw=metadata.apply(context.runId());require(Arrays.equals(targetRaw,file(folder,m,"target-metadata.xml"))&&hash(targetRaw).equals(text(m,"targetMetadataSha256")));var target=SecureXml.parse(targetRaw).getDocumentElement();require(TARGET.equals(target.getAttribute("entityID")));
            var peers=m.path("peers");require(peers.isArray()&&peers.size()==2&&"primary".equals(text(peers.get(0),"label"))&&"secondary".equals(text(peers.get(1),"label"))&&context.runId().equals(text(peers.get(0),"runId"))&&text(m,"planId").equals(text(peers.get(0),"planId")));
            var primary=history(context,context.runId());var all=new ArrayList<EvidenceRef>();var fixtures=new ArrayList<Element>();var pairs=new ArrayList<Pair>();var conversions=new ArrayList<JsonNode>();
            stage="two-native-entities-and-normal-controls-unproven";
            for(int i=0;i<2;i++){
                var peer=peers.get(i);String label=text(peer,"label"),run=text(peer,"runId"),plan=text(peer,"planId"),entity=text(peer,"entity"),db=text(peer,"clientId");require(validRun(run)&&plan.matches("plan_[0-9A-HJKMNP-TV-Z]{26}")&&entity.equals(BASE+"/p/"+plan)&&db.matches("[0-9a-f-]{36}"));
                require(text(peer,"lookup").equals("/clients?clientId="+java.net.URLEncoder.encode(entity,StandardCharsets.UTF_8).replace("+","%20")+"&briefRepresentation=true"));
                if(i==1)require(!run.equals(context.runId())&&!plan.equals(text(peers.get(0),"planId"))&&!entity.equals(text(peers.get(0),"entity"))&&!db.equals(text(peers.get(0),"clientId")));
                var created=node(folder,m,label+"/created.json");var storedPlan=node(folder,m,label+"/plan.json");require(run.equals(created.at("/run/id").asText())&&plan.equals(created.at("/run/planId").asText())&&plan.equals(storedPlan.at("/plan/plan/id").asText())&&"metadata_idp".equals(storedPlan.at("/plan/plan/profile").asText()));
                require(Arrays.equals(metadata.apply(run),targetRaw)&&Arrays.equals(file(folder,m,label+"/target-metadata.xml"),targetRaw));var spRaw=file(folder,m,label+"/fixture.xml");var sp=fixture(spRaw,entity);fixtures.add(sp);
                var initial=original(folder,m,primary,label+"-initial","initial-native-inventory");nativeHttp(initial.path("native"),"GET",text(peer,"lookup"),200);require(json(response(initial.path("native"))).isArray()&&json(response(initial.path("native"))).isEmpty()&&entity.equals(text(initial,"entityId")));
                var conversion=original(folder,m,primary,label+"-conversion","native-metadata-conversion");nativeHttp(conversion.path("native"),"POST","/client-description-converter",200);require(entity.equals(text(conversion,"entityId"))&&label.equals(text(conversion,"label"))&&Arrays.equals(spRaw,request(conversion.path("native")))&&hash(spRaw).equals(text(conversion,"fixtureSha256"))&&Arrays.equals(spRaw,Base64.getDecoder().decode(text(conversion,"fixtureBase64"))));
                var converted=json(response(conversion.path("native")));require(entity.equals(text(converted,"clientId"))&&"saml".equals(text(converted,"protocol"))&&!converted.has("id")&&!sensitive(converted));conversions.add(converted);
                var creation=original(folder,m,primary,label+"-creation","native-simultaneous-create");nativeHttp(creation.path("native"),"POST","/clients",201);require(db.equals(text(creation,"clientDatabaseId"))&&entity.equals(text(creation,"entityId"))&&Arrays.equals(response(conversion.path("native")),request(creation.path("native")))&&response(creation.path("native")).length==0&&at(initial.path("native"),"finishedAt").isBefore(at(conversion.path("native"),"startedAt"))&&at(conversion.path("native"),"finishedAt").isBefore(at(creation.path("native"),"startedAt")));
                var pair=normal(context,peer,i==0?primary:history(context,run),sp,target);pairs.add(pair);for(var e:List.of(pair.request(),pair.response()))all.add(new EvidenceRef("transcript",e.id()));
            }
            require(Collections.disjoint(certHashes(spKeys(fixtures.get(0))),certHashes(spKeys(fixtures.get(1)))));
            var before=epoch(folder,m,primary,"normal-before",peers);var after=epoch(folder,m,primary,"normal-after",peers);var duplicateBefore=epoch(folder,m,primary,"duplicate-before",peers);var duplicateAfter=epoch(folder,m,primary,"duplicate-after",peers);require(before.equals(after)&&before.equals(duplicateBefore));
            for(int i=0;i<2;i++)incorporated(conversions.get(i),before.get(text(peers.get(i),"label")),text(peers.get(i),"clientId"),text(peers.get(i),"entity"));
            var nb=original(folder,m,primary,"normal-before","simultaneous-native-entities");var na=original(folder,m,primary,"normal-after","simultaneous-native-entities");var db=original(folder,m,primary,"duplicate-before","simultaneous-native-entities");var da=original(folder,m,primary,"duplicate-after","simultaneous-native-entities");
            scope(nb,na);scope(nb,db);scope(nb,da);for(int i=0;i<2;i++){var creation=original(folder,m,primary,text(peers.get(i),"label")+"-creation","native-simultaneous-create");require(at(creation,"recordedAt").isBefore(at(nb.path("peers").get(i).path("native"),"startedAt")));}
            for(var pair:pairs)require(at(nb,"recordedAt").isBefore(pair.request().timestamp())&&pair.response().timestamp().isBefore(at(na.path("peers").get(0).path("native"),"startedAt")));
            require(pairs.get(0).response().timestamp().isBefore(pairs.get(1).request().timestamp())&&at(na,"recordedAt").isBefore(at(db.path("peers").get(0).path("native"),"startedAt")));
            stage="simultaneous-duplicate-native-conflict-unproven";
            var duplicateRaw=file(folder,m,"duplicate-fixture.xml");var duplicate=fixture(duplicateRaw,text(peers.get(0),"entity"));require(!acs(duplicate).equals(acs(fixtures.get(0)))&&!certHashes(spKeys(duplicate)).equals(certHashes(spKeys(fixtures.get(0)))));
            var prepared=primary.values().stream().filter(e->"MetadataPrepared".equals(e.samlSummary().get("type"))&&"multiple-signing-keys".equals(e.samlSummary().get("variant"))).toList();require(prepared.size()==1);var prep=prepared.getFirst();require(Arrays.equals(duplicateRaw,decoded(prep))&&hash(duplicateRaw).equals(prep.samlSummary().get("metadataSha256")));var fetch=primary.get(String.valueOf(prep.samlSummary().get("fetchTranscriptId")));require(fetch!=null&&fetch.direction()==Direction.INBOUND&&Objects.equals(fetch.status(),200)&&fetch.timestamp().isBefore(prep.timestamp())&&"MetadataFetch".equals(fetch.samlSummary().get("type")));
            var dc=original(folder,m,primary,"duplicate-conversion","native-metadata-conversion");nativeHttp(dc.path("native"),"POST","/client-description-converter",200);require(Arrays.equals(request(dc.path("native")),duplicateRaw)&&hash(duplicateRaw).equals(text(dc,"fixtureSha256"))&&at(na,"recordedAt").isBefore(at(dc.path("native"),"startedAt"))&&prep.timestamp().isBefore(at(dc.path("native"),"startedAt")));
            var value=json(response(dc.path("native")));require(text(peers.get(0),"entity").equals(text(value,"clientId"))&&"saml".equals(text(value,"protocol"))&&!value.has("id")&&!sensitive(value));
            var create=original(folder,m,primary,"duplicate-create","native-simultaneous-duplicate-create");var n=create.path("native");require("POST".equals(text(n,"method"))&&(ADMIN+"/clients").equals(text(n,"url"))&&Arrays.equals(response(dc.path("native")),request(n))&&at(db,"recordedAt").isBefore(at(n,"startedAt"))&&at(dc.path("native"),"finishedAt").isBefore(at(n,"startedAt"))&&at(n,"finishedAt").isBefore(at(da.path("peers").get(0).path("native"),"startedAt")));
            boolean conflict=n.path("status").asInt(-1)==409&&("Client "+text(peers.get(0),"entity")+" already exists").equals(json(response(n)).path("errorMessage").asText())&&before.equals(duplicateAfter);
            boolean ambiguous=n.path("status").asInt(-1)==201&&response(n).length==0&&!before.get("primary").equals(duplicateAfter.get("primary"))&&before.get("secondary").equals(duplicateAfter.get("secondary"));
            if(ambiguous)incorporated(value,duplicateAfter.get("primary"),text(peers.get(0),"clientId"),text(peers.get(0),"entity"));require(conflict||ambiguous);
            stage="restoration-and-costs-unproven";
            var restored=original(folder,m,primary,"restoration","native-restoration");require(restored.path("restored").asBoolean(false)&&restored.path("runtimeBefore").equals(nb.path("runtime"))&&restored.path("runtimeAfter").equals(nb.path("runtime"))&&restored.path("policiesBefore").equals(nb.path("policies"))&&restored.path("policiesAfter").equals(nb.path("policies"))&&restored.path("cleanup").isArray()&&restored.path("cleanup").size()==4);
            for(int i=0;i<2;i++){var peer=peers.get(1-i);var deletion=restored.path("cleanup").get(i*2);var lookup=restored.path("cleanup").get(i*2+1);require(text(peer,"clientId").equals(text(deletion,"clientDatabaseId"))&&text(peer,"entity").equals(text(deletion,"entityId"))&&text(peer,"entity").equals(text(lookup,"entityId")));nativeHttp(deletion.path("native"),"DELETE","/clients/"+text(peer,"clientId"),204);nativeHttp(lookup.path("native"),"GET",text(peer,"lookup"),200);require(response(deletion.path("native")).length==0&&json(response(lookup.path("native"))).isEmpty()&&at(deletion.path("native"),"startedAt").isAfter(at(da,"recordedAt"))&&at(deletion.path("native"),"finishedAt").isBefore(at(lookup.path("native"),"startedAt")));}
            var counts=node(folder,m,"operation-counts.json");require(counts.path("restored").asBoolean(false)&&counts.path("protocolSubmissions").asInt(-1)==2&&counts.path("credentialPosts").asInt(-1)==1&&counts.path("normalFlowsAttempted").asInt(-1)==2&&counts.path("nativeConfigurationWriteAttempts").asInt(-1)==5&&counts.path("nativeConfigurationWrites").asInt(-1)==(ambiguous?5:4)&&counts.path("restorationWrites").asInt(-1)==2&&counts.path("personOperations").asInt(-1)==0&&counts.path("productRestarts").asInt(-1)==0);
            all.add(new EvidenceRef("transcript",prep.id()));for(var ref:m.path("originals"))all.add(new EvidenceRef("transcript",text(ref,"reference")));all.add(new EvidenceRef(KIND,context.runId()+"/manifest.json#"+hash(raw(folder,"manifest.json"))));
            String reason=ambiguous?"metadata.entity-identity.ambiguous-registration-observed":caseId.equals("IIP-MD05-a1-idp-01")?"metadata.entity-identity.uniqueness-observed":"metadata.entity-identity.unambiguous-registration-observed";
            return Optional.of(new CaseOutcome(ambiguous?Outcome.VIOLATED:Outcome.SATISFIED,null,reason,reason,all,Map.of("evidence_adapter",ADAPTER,"native_run_id",context.runId(),"case_id",caseId,"configuration_restored",true,"native_registration_operation","simultaneous-idless-POST","distinct_entity_controls",2,"automated_credential_submissions",1,"test_user_operations",0,"administrator_preparation_writes",2,"administrator_restoration_writes",2)));
        }catch(Exception missing){return Optional.of(new CaseOutcome(Outcome.NOT_VERIFIED,stage,"metadata.entity-identity.native-unproven","metadata.entity-identity.native-unproven",List.of(),Map.of("evidence_adapter",ADAPTER,"native_run_id",context.runId(),"case_id",caseId,"native_receipt_owned",true)));}
    }
}
