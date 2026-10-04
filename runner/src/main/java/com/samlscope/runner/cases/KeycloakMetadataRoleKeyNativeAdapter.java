package com.samlscope.runner.cases;

import static com.samlscope.runner.cases.MetadataRoleKeyEvidence.*;
import static com.samlscope.runner.cases.MetadataAlgorithmEvidence.children;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.transcript.*;
import java.nio.file.Path;
import java.time.Instant;
import java.util.*;
import org.w3c.dom.Element;

/** Native full-XML client importer plus same-client effective SP-role consumer epochs. */
public final class KeycloakMetadataRoleKeyNativeAdapter implements MetadataRoleKeyNativeAdapter {
    public static final String ADAPTER="keycloak-native-role-key-consumption-v1";
    static final String ORIGINAL="samlscope-keycloak-role-key-original-v1",CAMPAIGN="native-role-key-consumption";
    private static final String BASE="http://localhost:18080",ADMIN="http://localhost:18180/admin/realms/samlscope",MD="urn:oasis:names:tc:SAML:2.0:metadata";
    private final TranscriptContentReader content;
    public KeycloakMetadataRoleKeyNativeAdapter(TranscriptContentReader content){this.content=Objects.requireNonNull(content);}
    @Override public String adapter(){return ADAPTER;}
    private static Instant at(JsonNode n,String f){return Instant.parse(text(n,f));}
    static byte[] request(JsonNode n)throws Exception{var b=Base64.getDecoder().decode(text(n,"request_base64"));require(hash(b).equals(text(n,"request_sha256")));return b;}
    static byte[] response(JsonNode n)throws Exception{var b=Base64.getDecoder().decode(text(n,"response_base64"));require(hash(b).equals(text(n,"response_sha256")));return b;}
    static void nativeHttp(JsonNode n,String method,String path,int status){require(method.equals(text(n,"method"))&&(ADMIN+path).equals(text(n,"url"))&&n.path("status").asInt(-1)==status&&at(n,"startedAt").isBefore(at(n,"finishedAt")));}
    static void validateCertificates(JsonNode attributes,Element peer)throws Exception {
        var sp=single(peer,MD,"SPSSODescriptor");var signing=SimpleSamlPhpMetadataRoleKeyNativeAdapter.certificateKeys(sp,"signing");var encryption=SimpleSamlPhpMetadataRoleKeyNativeAdapter.certificateKeys(sp,"encryption");
        require(signing.size()==1&&encryption.size()==1&&signing.contains(SimpleSamlPhpMetadataRoleKeyNativeAdapter.certHash(text(attributes,"saml.signing.certificate")))&&encryption.contains(SimpleSamlPhpMetadataRoleKeyNativeAdapter.certHash(text(attributes,"saml.encryption.certificate"))));
    }
    static JsonNode publicReply(JsonNode n,String db)throws Exception {
        nativeHttp(n,"GET","/clients/"+db,200);require("native-client-public-readback-v1".equals(text(n,"response_projection"))&&n.path("redactions").isArray());var redactions=new HashSet<String>();for(var r:n.path("redactions"))require(r.isTextual()&&Set.of("$.secret","$.registrationAccessToken").contains(r.asText())&&redactions.add(r.asText()));var saved=json(response(n));require(saved.isObject()&&!KeycloakSubjectConfirmationEvidence.sensitive(saved));return saved;
    }
    @Override public Session open(CaseContext context,Path folder,JsonNode manifest,String entity)throws Exception{return new Proof(context,folder,manifest,entity);}
    private final class Proof implements Session {
        private final CaseContext c;private final Path folder;private final JsonNode m,initial,restored;private final String entity,db;private final Map<String,TranscriptEntry> entries=new HashMap<>();
        Proof(CaseContext context,Path f,JsonNode manifest,String e)throws Exception {
            c=context;folder=f;m=manifest;entity=e;require(ADAPTER.equals(text(m,"adapter"))&&CAMPAIGN.equals(text(m,"campaignId")));db=text(m,"clientDatabaseId");require(db.matches("[0-9a-f-]{36}"));var created=json(original(f,"created.json"));require(c.runId().equals(created.at("/run/id").asText())&&text(m,"planId").equals(created.at("/run/planId").asText())&&entity.equals(BASE+"/p/"+text(m,"planId")));
            for(var tx:c.transcript().list(c.runId()))require(c.runId().equals(tx.runId())&&entries.put(tx.id(),tx)==null);
            initial=nativeOriginal("initial","native-role-key-inventory");restored=nativeOriginal("restoration","native-role-key-inventory");var lookup="/clients?clientId="+java.net.URLEncoder.encode(entity,java.nio.charset.StandardCharsets.UTF_8)+"&briefRepresentation=true";
            for(var n:List.of(initial,restored)){nativeHttp(n.path("native"),"GET",lookup,200);require(json(response(n.path("native"))).isArray()&&json(response(n.path("native"))).isEmpty());validateScope(n);}
            require(initial.path("runtime").equals(restored.path("runtime"))&&initial.path("policies").equals(restored.path("policies"))&&at(restored,"recordedAt").isAfter(at(initial,"recordedAt")));
            var creation=nativeOriginal("creation","native-role-key-create");nativeHttp(creation.path("native"),"POST","/clients",201);require(db.equals(text(creation,"clientDatabaseId")));var baselineConversion=nativeOriginal("baseline-conversion","native-role-key-conversion");nativeHttp(baselineConversion.path("native"),"POST","/client-description-converter",200);require(Arrays.equals(response(baselineConversion.path("native")),request(creation.path("native"))));
            var deletion=nativeOriginal("deletion","native-role-key-delete");nativeHttp(deletion.path("native"),"DELETE","/clients/"+db,204);require(at(deletion,"recordedAt").isBefore(at(restored,"recordedAt")));
            var restore=json(original(f,"restoration.json"));var costs=json(original(f,"operation-counts.json"));require(restore.path("restored").asBoolean(false)&&costs.path("restored").asBoolean(false)&&db.equals(text(restore,"clientDatabaseId"))&&costs.path("credentialPosts").asInt(-1)==1&&costs.path("initialBaselineSubmissions").asInt(-1)==1&&costs.path("selectedProbeAttempts").asInt(-1)==11&&costs.path("protocolSubmissions").asInt(-1)==12&&costs.path("nativeConfigurationWrites").asInt(-1)==6&&costs.path("restorationWrites").asInt(-1)==1&&costs.path("personOperations").asInt(-1)==0&&costs.path("productRestarts").asInt(-1)==0);
        }
        private void validateScope(JsonNode n)throws Exception {
            require(n.at("/runtime/running").asBoolean(false)&&text(n.path("runtime"),"id").matches("[a-f0-9]{64}")&&KeycloakSelfContainedTrustEvidenceFile.SERVICES_HASH.equals(text(n,"nativeServicesSha256"))&&n.at("/policies/policies/policies").isArray()&&n.at("/policies/policies/policies").isEmpty()&&n.at("/policies/profiles/profiles").isArray()&&n.at("/policies/profiles/profiles").isEmpty());
        }
        private JsonNode nativeOriginal(String label,String kind)throws Exception {
            var ref=m.path("nativeOriginals").path(label);var tx=entries.get(text(ref,"reference"));require(tx!=null&&tx.decodedSamlRef()!=null&&("transcripts/"+c.runId()+"/"+tx.id()+".saml.xml").equals(tx.decodedSamlRef()));var b=content.readDecodedSaml(tx);require(b.length==tx.decodedSamlBytes()&&hash(b).equals(text(ref,"sha256"))&&Arrays.equals(b,original(folder,text(ref,"file"))));
            require(tx.direction()==Direction.INBOUND&&"POST".equals(tx.method())&&Objects.equals(tx.status(),204)&&"application/json".equals(tx.contentType())&&(BASE+"/p/"+text(m,"planId")+"/sp/paos?run="+c.runId()).equals(tx.url()));var n=json(b);require(ORIGINAL.equals(text(n,"schema"))&&c.runId().equals(text(n,"runId"))&&CAMPAIGN.equals(text(n,"campaignId"))&&kind.equals(text(n,"kind"))&&m.path("targetMetadataSha256").equals(n.path("targetMetadataSha256"))&&at(n,"recordedAt").isBefore(tx.timestamp())&&!KeycloakSubjectConfirmationEvidence.sensitive(n));return n;
        }
        private JsonNode state(String label,String v)throws Exception {
            var n=nativeOriginal(label,"native-role-key-state");require(v.equals(text(n,"variant"))&&entity.equals(text(n,"entityId"))&&db.equals(text(n,"clientDatabaseId")));validateScope(n);require(n.path("runtime").equals(initial.path("runtime"))&&n.path("policies").equals(initial.path("policies")));return n;
        }
        @Override public Instant validateEpoch(JsonNode row,byte[] fixture,Element peer,Instant start,Instant end)throws Exception {
            String v=text(row,"variant");var conversion=nativeOriginal(v+"-conversion","native-role-key-conversion");var api=conversion.path("native");nativeHttp(api,"POST","/client-description-converter",200);require(Arrays.equals(fixture,request(api))&&hash(fixture).equals(text(conversion,"fixtureSha256"))&&entity.equals(text(conversion,"entityId")));var parsed=json(response(api));require(entity.equals(text(parsed,"clientId"))&&"saml".equals(text(parsed,"protocol"))&&!parsed.has("id"));validateCertificates(parsed.path("attributes"),peer);
            var update=nativeOriginal(v+"-apply","native-role-key-apply");nativeHttp(update.path("native"),"PUT","/clients/"+db,204);var applied=json(request(update.path("native")));var configured=parsed.deepCopy();require(configured.isObject());((ObjectNode)configured.path("attributes")).put("saml.client.signature","true").put("saml.encrypt","true");require(configured.equals(applied)&&!update.at("/nativePolicy/keysModified").asBoolean(true));
            var before=state(v+"-before",v);var after=state(v+"-after",v);require(at(conversion,"recordedAt").isBefore(at(update,"recordedAt"))&&at(update,"recordedAt").isBefore(at(before,"recordedAt"))&&!at(before,"recordedAt").isBefore(start)&&!at(after,"recordedAt").isAfter(end)&&at(after,"recordedAt").isAfter(at(before,"recordedAt"))&&at(restored,"recordedAt").isAfter(at(after,"recordedAt")));
            for(var n:List.of(before,after)){var saved=publicReply(n.path("native"),db);require(db.equals(text(saved,"id"))&&entity.equals(text(saved,"clientId"))&&"saml".equals(text(saved,"protocol"))&&saved.path("enabled").asBoolean(false)&&saved.path("authenticationFlowBindingOverrides").isEmpty());validateCertificates(saved.path("attributes"),peer);var fields=applied.fields();while(fields.hasNext()){var f=fields.next();if(f.getKey().equals("attributes")){var attrs=f.getValue().fields();while(attrs.hasNext()){var a=attrs.next();require(a.getValue().equals(saved.path("attributes").get(a.getKey())));}}else if(f.getKey().equals("redirectUris")){var left=new HashSet<String>();var right=new HashSet<String>();f.getValue().forEach(x->left.add(x.asText()));saved.path("redirectUris").forEach(x->right.add(x.asText()));require(left.equals(right));}else if(f.getKey().equals("protocolMappers")&&f.getValue().isEmpty())require(saved.path("protocolMappers").isMissingNode()||saved.path("protocolMappers").isEmpty());else require(f.getValue().equals(saved.get(f.getKey())));}}
            return at(before,"recordedAt");
        }
        @Override public void validateExchange(JsonNode row,JsonNode exchange,Element request,byte[] raw,JsonNode http,Instant preparedAt,Instant start,Instant end,Disposition disposition)throws Exception {
            String f=text(exchange,"fixtureId");var n=nativeOriginal(f+"-http","native-role-key-http");require(f.equals(text(n,"fixtureId"))&&exchange.path("requestReference").equals(n.path("requestReference"))&&exchange.path("responseReference").equals(n.path("responseReference"))&&request.getAttribute("ID").equals("_"+text(n,"actionId"))&&http.equals(n.path("native"))&&at(n,"recordedAt").isBefore(at(nativeOriginal(text(row,"variant")+"-after","native-role-key-state"),"recordedAt")));
            var tx=entries.get(text(exchange,"responseReference"));require(tx!=null&&tx.direction()==Direction.INBOUND&&tx.timestamp().isAfter(entries.get(text(exchange,"requestReference")).timestamp())&&tx.timestamp().isBefore(at(n,"recordedAt"))&&at(http,"startedAt").isAfter(preparedAt)&&at(http,"completedAt").isBefore(at(n,"recordedAt")));
            if(disposition==Disposition.SIGNATURE_REJECTED){require("BROWSER".equals(tx.method())&&"BrowserResponseObservation".equals(tx.samlSummary().get("type"))&&text(n,"actionId").equals(tx.correlationId())&&tx.bodyRef().equals("transcripts/"+c.runId()+"/"+tx.id()+".body")&&Objects.equals(tx.status(),http.path("responseStatus").asInt())&&request.getAttribute("Destination").equals(tx.url()));var body=original(folder,"browser-"+tx.id()+".body");require(body.length==tx.bodyBytes()&&body.length==http.path("responseBodyBytes").asLong(-1)&&hash(body).equals(text(http,"responseBodySha256"))&&request.getAttribute("Destination").equals(text(http,"responseUrl"))&&KeycloakRegisteredSignerEvidence.nativeSignatureRejectionPage(body));}
            else require(!"BROWSER".equals(tx.method())&&http.path("samlResponseFormPresent").asBoolean(false)&&hash(content.readDecodedSaml(tx)).equals(text(http,"responseSamlSha256")));
        }
    }
}
