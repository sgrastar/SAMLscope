package com.samlscope.runner.cases;

import static com.samlscope.runner.cases.MetadataRoleKeyEvidence.*;
import static com.samlscope.runner.cases.MetadataAlgorithmEvidence.children;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.transcript.*;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.security.cert.*;
import org.w3c.dom.Element;

/** Installed native SP-role parser and effective consumer closure; all crypto belongs to the common reader. */
public final class SimpleSamlPhpMetadataRoleKeyNativeAdapter implements MetadataRoleKeyNativeAdapter {
    public static final String ADAPTER="simplesamlphp-native-role-key-consumption-v1";
    static final String ORIGINAL="samlscope-simplesamlphp-role-key-original-v1",CAMPAIGN="native-role-key-consumption";
    private static final String MD="urn:oasis:names:tc:SAML:2.0:metadata",DS="http://www.w3.org/2000/09/xmldsig#",BASE="http://localhost:18080",TARGET="http://localhost:18380/idp";
    private final TranscriptContentReader content;
    public SimpleSamlPhpMetadataRoleKeyNativeAdapter(TranscriptContentReader content){this.content=Objects.requireNonNull(content);}
    @Override public String adapter(){return ADAPTER;}
    static final Map<String,String> SOURCE=Map.of(
        "native-idp.php","ae55fc922431d29ca6e87654ae2071500a4c3d7185ed80a6fcc5b26eed12495d",
        "native-message.php","ab017ee6cf9fb66db1037e40ed50feff0b277b1a5d43fd8ca774a3d27ce355d2",
        "native-configuration.php","53837359cd60433082d3968843605a864bab97f23be482447bcfef37e7f6946e",
        "native-parser.php","8620bb26fd41d2be29d2611883839a4cfde0b6c8458c274e2d40a002678fd93d",
        "native-handler.php","43a0e730d624c5a937f800c4e7e045ff3625eeb0738d81a4ab1dac96f82fe040",
        "native-source.php","48fe4682d980e62416c751b7a39406ebf9664bf539e6a1557e7f54df770398c6",
        "native-signed-helper.php","4928545a8147e4222288def64a992ed8fbf0ba54243079fc3c919470b2cc766c",
        "native-utils.php","5845e28158c7641d5ce1e6b9205e8005b6d9c090e1888ea46416abb8fdf0018d",
        "native-xml-security-key.php","6c89ac116aca2c05791712749450be474218fd97cd9a66b7aad9d2ba4e6cba17",
        "native-xml-security-dsig.php","79597160c501fbdbe19bdca12b6797c06c38c4eae7cad6d0d1dca89301a5734f");
    private static Instant at(JsonNode n,String f){return Instant.parse(text(n,f));}
    static Set<String> certificateKeys(Element role,String purpose)throws Exception {
        var values=new LinkedHashSet<String>();
        for(var kd:children(role,MD,"KeyDescriptor"))if(purpose==null||kd.getAttribute("use").isEmpty()||purpose.equals(kd.getAttribute("use"))){var list=kd.getElementsByTagNameNS(DS,"X509Certificate");require(list.getLength()==1);values.add(certHash(list.item(0).getTextContent()));}
        return values;
    }
    static String certHash(String cert)throws Exception{var c=(X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(Base64.getMimeDecoder().decode(cert)));return hash(c.getEncoded());}
    static Set<String> nativeKeys(JsonNode keys,String purpose)throws Exception {
        require(keys.isArray());var values=new LinkedHashSet<String>();
        for(var k:keys){require(k.isObject()&&"X509Certificate".equals(text(k,"type"))&&k.path("signing").isBoolean()&&k.path("encryption").isBoolean());if(purpose==null||k.path(purpose).asBoolean())values.add(certHash(text(k,"X509Certificate")));}
        return values;
    }
    static void validateParsedRole(JsonNode nativeRole,Element role)throws Exception {
        require(nativeRole.isObject());var keys=nativeRole.path("keys");require(keys.size()==children(role,MD,"KeyDescriptor").size());
        require(nativeKeys(keys,null).equals(certificateKeys(role,null))&&nativeKeys(keys,"signing").equals(certificateKeys(role,"signing"))&&nativeKeys(keys,"encryption").equals(certificateKeys(role,"encryption")));
    }
    @Override public Session open(CaseContext context,Path folder,JsonNode manifest,String entity)throws Exception{return new Proof(context,folder,manifest,entity);}
    private final class Proof implements Session {
        private final CaseContext context;private final Path folder;private final JsonNode m;private final String entity;private final Map<String,TranscriptEntry> entries=new HashMap<>();private final JsonNode initial,restored;
        Proof(CaseContext c,Path f,JsonNode manifest,String e)throws Exception {
            context=c;folder=f;m=manifest;entity=e;require(ADAPTER.equals(text(m,"adapter"))&&CAMPAIGN.equals(text(m,"campaignId")));
            var created=json(original(f,"created.json"));require(c.runId().equals(created.at("/run/id").asText())&&text(m,"planId").equals(created.at("/run/planId").asText())&&e.equals(BASE+"/p/"+text(m,"planId")));
            for(var tx:c.transcript().list(c.runId()))require(c.runId().equals(tx.runId())&&entries.put(tx.id(),tx)==null);
            for(var source:SOURCE.entrySet())require(source.getValue().equals(hash(original(f,source.getKey()))));
            initial=state("initial","initial",null);restored=state("restoration","restored",null);
            require(initial.path("runtime").equals(restored.path("runtime"))&&at(restored,"recordedAt").isAfter(at(initial,"recordedAt")));
            require(Arrays.equals(original(f,"original-configuration.php"),original(f,"final-configuration.php"))&&text(initial,"configurationSha256").equals(hash(original(f,"original-configuration.php")))&&text(restored,"configurationSha256").equals(hash(original(f,"final-configuration.php"))));
            var restore=json(original(f,"restoration.json"));var costs=json(original(f,"operation-counts.json"));
            require(restore.path("restored").asBoolean(false)&&hash(original(f,"original-configuration.php")).equals(text(restore,"original_sha256"))&&text(restore,"original_sha256").equals(text(restore,"final_sha256"))&&costs.path("restored").asBoolean(false));
            require(costs.path("credentialPosts").asInt(-1)==1&&costs.path("credentialPostAttempts").asInt(-1)==1&&costs.path("initialBaselineSubmissions").asInt(-1)==1&&costs.path("selectedProbeAttempts").asInt(-1)==11&&costs.path("outboxProtocolSubmissions").asInt(-1)==11&&costs.path("protocolSubmissions").asInt(-1)==12&&costs.path("personOperations").asInt(-1)==0&&costs.path("productRestarts").asInt(-1)==0&&costs.path("restorationWrites").asInt(-1)==1&&costs.path("nativeConfigurationWrites").asInt(-1)==6);
            require(costs.path("nativeConfigurationWrites").asInt()==restore.path("configuration_write_attempts").asInt()&&costs.path("restorationWrites").asInt()==restore.path("restoration_write_attempts").asInt());
        }
        private JsonNode nativeOriginal(String label,String kind)throws Exception {
            var ref=m.path("nativeOriginals").path(label);var tx=entries.get(text(ref,"reference"));require(tx!=null&&tx.decodedSamlRef()!=null&&("transcripts/"+context.runId()+"/"+tx.id()+".saml.xml").equals(tx.decodedSamlRef()));var bytes=content.readDecodedSaml(tx);
            require(bytes.length==tx.decodedSamlBytes()&&hash(bytes).equals(text(ref,"sha256"))&&Arrays.equals(bytes,original(folder,text(ref,"file"))));
            require(tx.direction()==Direction.INBOUND&&"POST".equals(tx.method())&&Objects.equals(tx.status(),204)&&"application/json".equals(tx.contentType())&&(BASE+"/p/"+text(m,"planId")+"/sp/paos?run="+context.runId()).equals(tx.url()));
            var n=json(bytes);require(ORIGINAL.equals(text(n,"schema"))&&context.runId().equals(text(n,"runId"))&&CAMPAIGN.equals(text(n,"campaignId"))&&kind.equals(text(n,"kind"))&&m.path("targetMetadataSha256").equals(n.path("targetMetadataSha256"))&&at(n,"recordedAt").isBefore(tx.timestamp())&&!SimpleSamlPhpMetadataCertificateRuntimeEvidence.sensitive(n));return n;
        }
        private JsonNode state(String label,String phase,String variant)throws Exception {
            var n=nativeOriginal(label,"native-role-key-state");require(phase.equals(text(n,"phase"))&&(variant==null?n.path("variant").isNull():variant.equals(text(n,"variant"))));var raw=original(folder,text(n,"nativeReadbackFile"));require(hash(raw).equals(text(n,"nativeReadbackSha256")));var read=json(raw);
            for(var field:List.of("peers","configurationSha256","metadataSources","hostedIdp","sourceHashes"))require(n.path(field).equals(read.path(field)));
            require(n.path("metadataSources").equals(json("[{\"type\":\"flatfile\"}]".getBytes(StandardCharsets.UTF_8)))&&TARGET.equals(n.at("/hostedIdp/entityId").asText())&&"example-userpass".equals(n.at("/hostedIdp/authSource").asText())&&n.at("/hostedIdp/authproc").isArray()&&n.at("/hostedIdp/authproc").isEmpty());
            require(n.at("/runtime/running").asBoolean(false)&&text(n.path("runtime"),"id").matches("[a-f0-9]{64}")&&text(n.path("runtime"),"image").startsWith("sha256:")&&at(n,"nativeStartedAt").isBefore(at(n,"nativeFinishedAt"))&&at(n,"nativeFinishedAt").isBefore(at(n,"recordedAt")));
            for(var source:SOURCE.entrySet())require(source.getValue().equals(text(n.path("sourceHashes"),source.getKey())));
            var rows=n.path("peers");require(rows.isArray()&&rows.size()==1&&entity.equals(text(rows.get(0),"entityId")));if(variant==null)require(!rows.get(0).path("present").asBoolean(true)&&rows.get(0).path("resolvedMetadata").isNull()&&rows.get(0).path("signingKeys").isEmpty()&&rows.get(0).path("encryptionKeys").isEmpty());return n;
        }
        @Override public Instant validateEpoch(JsonNode row,byte[] fixture,Element peer,Instant start,Instant end)throws Exception {
            var v=text(row,"variant");var conversion=nativeOriginal(v+"-conversion","native-role-key-conversion");require(v.equals(text(conversion,"variant"))&&entity.equals(text(conversion,"entityId"))&&hash(fixture).equals(text(conversion,"fixtureSha256")));var output=json(original(folder,v+"-parser-output.json"));require(output.equals(conversion.path("parserOutput"))&&hash(original(folder,v+"-parser-output.json")).equals(text(conversion,"parserOutputSha256"))&&entity.equals(text(output,"entityId"))&&output.path("validateAuthnRequest").asBoolean(false));
            validateParsedRole(output.path("nativeSpMetadata"),single(peer,MD,"SPSSODescriptor"));validateParsedRole(output.path("nativePeerIdpMetadata"),single(peer,MD,"IDPSSODescriptor"));
            var configured=output.path("metadata").deepCopy();require(configured.isObject());((ObjectNode)configured).remove("assertion.encryption");require(configured.equals(output.path("nativeSpMetadata"))&&output.at("/metadata/assertion.encryption").asBoolean(false)&&output.at("/nativePolicy/assertionEncryption").asBoolean(false)&&!output.at("/nativePolicy/keysModified").asBoolean(true));
            byte[] expected=(new String(original(folder,"original-configuration.php"),StandardCharsets.UTF_8)+"\n"+text(output,"php")+"\n").getBytes(StandardCharsets.UTF_8);require(Arrays.equals(expected,original(folder,v+"-configuration.php")));
            var before=state(v+"-before","configured",v);var after=state(v+"-after","configured",v);require(before.path("runtime").equals(initial.path("runtime"))&&after.path("runtime").equals(initial.path("runtime"))&&text(before,"configurationSha256").equals(hash(expected))&&text(after,"configurationSha256").equals(hash(expected))&&at(conversion,"recordedAt").isBefore(at(before,"nativeStartedAt"))&&!at(before,"nativeStartedAt").isBefore(start)&&!at(after,"recordedAt").isAfter(end)&&at(after,"nativeStartedAt").isAfter(at(before,"recordedAt"))&&at(restored,"nativeStartedAt").isAfter(at(after,"recordedAt")));
            for(var n:List.of(before,after)){var p=n.path("peers").get(0);require(p.path("present").asBoolean(false));var effective=p.path("resolvedMetadata").deepCopy();require(effective.isObject());((ObjectNode)effective).remove("metadata-index");require(effective.equals(output.path("metadata"))&&nativeKeys(p.path("signingKeys"),null).equals(certificateKeys(single(peer,MD,"SPSSODescriptor"),"signing"))&&nativeKeys(p.path("encryptionKeys"),null).equals(certificateKeys(single(peer,MD,"SPSSODescriptor"),"encryption")));}
            return at(before,"recordedAt");
        }
        @Override public void validateExchange(JsonNode row,JsonNode exchange,Element request,byte[] raw,JsonNode http,Instant preparedAt,Instant start,Instant end,Disposition disposition)throws Exception {
            var v=text(row,"variant");var f=text(exchange,"fixtureId");var n=nativeOriginal(f+"-http","native-role-key-http");require(f.equals(text(n,"fixtureId"))&&exchange.path("requestReference").equals(n.path("requestReference"))&&exchange.path("responseReference").equals(n.path("responseReference"))&&request.getAttribute("ID").equals("_"+text(n,"actionId"))&&http.equals(n.path("native"))&&at(n,"recordedAt").isBefore(at(nativeOriginal(v+"-after","native-role-key-state"),"nativeStartedAt")));
            var response=entries.get(text(exchange,"responseReference"));require(response!=null&&response.direction()==Direction.INBOUND&&response.timestamp().isAfter(entries.get(text(exchange,"requestReference")).timestamp())&&response.timestamp().isBefore(at(n,"recordedAt"))&&at(http,"startedAt").isAfter(preparedAt)&&at(http,"completedAt").isBefore(at(n,"recordedAt")));
            if(disposition==Disposition.SIGNATURE_REJECTED){require("BROWSER".equals(response.method())&&"BrowserResponseObservation".equals(response.samlSummary().get("type"))&&text(n,"actionId").equals(response.correlationId())&&response.bodyRef().equals("transcripts/"+context.runId()+"/"+response.id()+".body")&&Objects.equals(response.status(),http.path("responseStatus").asInt())&&request.getAttribute("Destination").equals(response.url()));var body=original(folder,"browser-"+response.id()+".body");require(body.length==response.bodyBytes()&&body.length==http.path("responseBodyBytes").asLong(-1)&&hash(body).equals(text(http,"responseBodySha256"))&&request.getAttribute("Destination").equals(text(http,"responseUrl"))&&SimpleSamlPhpRegisteredSignerEvidence.nativeSignatureRejection(new String(body,StandardCharsets.UTF_8),entity));}
            else {require(!"BROWSER".equals(response.method())&&http.path("samlResponseFormPresent").asBoolean(false)&&hash(content.readDecodedSaml(response)).equals(text(http,"responseSamlSha256")));}
        }
    }
}
