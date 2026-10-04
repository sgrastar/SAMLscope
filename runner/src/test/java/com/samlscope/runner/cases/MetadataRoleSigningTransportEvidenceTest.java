package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.*;
import java.util.*;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.store.JsonCodec;
import org.junit.jupiter.api.Test;

class MetadataRoleSigningTransportEvidenceTest {
    private static final String RUN="run_00000000000000000000000000", MD="urn:oasis:names:tc:SAML:2.0:metadata";
    private final JsonCodec json=new JsonCodec();
    private final Map<String,byte[]> originals=new HashMap<>();
    private final List<TranscriptEntry> entries=new ArrayList<>();
    private final byte[] target=("<EntityDescriptor xmlns='"+MD+"' entityID='http://idp.example'>"
            +"<IDPSSODescriptor><SingleSignOnService Location='http://idp.example/sso'/></IDPSSODescriptor></EntityDescriptor>").getBytes(StandardCharsets.UTF_8);
    private DefaultCaseContext context() {
        return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(),Reachability.CONFIRMED,new TranscriptRecorder(){
            public List<TranscriptEntry> list(String run){return List.copyOf(entries);}
            public TranscriptEntry record(TranscriptInput input){throw new AssertionError();}
            public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary){throw new AssertionError();}
        },true);
    }
    private void entry(String id,byte[] raw,Direction direction,Integer status,String url) {
        originals.put(id,raw);entries.add(new TranscriptEntry(id,RUN,direction,Instant.now(),null,"POST",url,status,
                Map.of(),null,0,id,raw.length,"application/json",null,Map.of()));
    }
    private String hash(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
    private ObjectNode fixture()throws Exception {
        var receipt=json.mapper().createObjectNode().put("evidenceAdapter","keycloak-native-event");
        var nativeConfig=json.mapper().createObjectNode().put("schema",MetadataRoleSigningTransportEvidence.SCHEMA)
                .put("runId",RUN).put("targetEntityId","http://idp.example").put("targetMetadataSha256",hash(target));
        var runtime=nativeConfig.putObject("runtime").put("image","sha256:"+"a".repeat(64));
        runtime.putArray("command").add("start-dev");runtime.putObject("portBindings").putArray("8080/tcp");
        var config=nativeConfig.putObject("nativeConfiguration").put("source","kc.sh show-config");
        config.putArray("selectedConfiguration").add("kc.http-enabled = true (ENV)").add("kc.hostname = http://localhost:18180 (ENV)");
        config.putArray("tlsConfiguration");
        var full="Current Mode: development\nCurrent Configuration:\n\tkc.http-enabled = true (ENV)\n\tkc.hostname = http://localhost:18180 (ENV)\n\tkc.version = 26.7.2 (SysPropConfigSource)\n\tkc.db = dev-file (Persisted)\n\tkc.run-in-container = true (SysPropConfigSource)\n";
        config.put("originalText",full).put("originalTextSha256",hash(full.getBytes(StandardCharsets.UTF_8)));
        var raw=json.mapper().writeValueAsBytes(nativeConfig);entry("native",raw,Direction.INBOUND,204,"http://suite.example/paos");
        receipt.putObject("roleSigningTransport").put("reference","native").put("sha256",hash(raw)).put("configurationTextSha256",hash(full.getBytes(StandardCharsets.UTF_8)));
        var conditions=receipt.putArray("conditions");
        for(var variant:MetadataKeySelectionComparison.required(MetadataKeySelectionComparison.PUBLIC_KEY)) {
            var row=conditions.addObject().put("variant",variant).put("metadataReference","fixture-"+variant);
            var xml=("<EntityDescriptor xmlns='"+MD+"'><SPSSODescriptor><AssertionConsumerService Location='http://suite.example/acs'/>"
                    +"<SingleLogoutService Location='http://suite.example/slo'/></SPSSODescriptor></EntityDescriptor>").getBytes(StandardCharsets.UTF_8);
            entry("fixture-"+variant,xml,Direction.OUTBOUND,200,"http://suite.example/metadata");
            for(var slot:List.of("positive","negative")) {
                row.putObject(slot).put("requestReference",variant+slot);
                entry(variant+slot,new byte[0],Direction.OUTBOUND,null,"http://idp.example/sso");
            }
        }
        return receipt;
    }
    @Test void nativeReadBackAndEveryUsedPathProveTlsUnused()throws Exception {
        var receipt=fixture();
        assertEquals("native",MetadataRoleSigningTransportEvidence.verify(context(),target,e->originals.get(e.id()),receipt).reference());
    }
    @Test void configuredTlsMissingOriginalOtherRunAndWrongTargetRemainUnverified()throws Exception {
        for(var mutation:List.of("missing","hash","run","target","tls","disabled","extraPort","hiddenTls")) {
            entries.clear();originals.clear();var receipt=fixture();
            var nativeConfig=(ObjectNode)json.mapper().readTree(originals.get("native"));
            switch(mutation) {
                case "missing" -> receipt.path("roleSigningTransport").deepCopy();
                case "hash" -> ((ObjectNode)receipt.path("roleSigningTransport")).put("sha256","0".repeat(64));
                case "run" -> nativeConfig.put("runId","other");
                case "target" -> nativeConfig.put("targetEntityId","other");
                case "tls" -> ((com.fasterxml.jackson.databind.node.ArrayNode)nativeConfig.at("/nativeConfiguration/tlsConfiguration")).add("kc.https-certificate-file = cert.pem (ENV)");
                case "disabled" -> ((ObjectNode)nativeConfig.path("nativeConfiguration")).putArray("selectedConfiguration").add("kc.http-enabled = false (ENV)");
                case "extraPort" -> ((ObjectNode)nativeConfig.at("/runtime/portBindings")).putArray("8443/tcp");
                case "hiddenTls" -> {
                    var cfg=(ObjectNode)nativeConfig.path("nativeConfiguration");
                    var text=cfg.path("originalText").asText()+"\tkc.https-certificate-file = cert.pem (ENV)\n";
                    cfg.put("originalText",text).put("originalTextSha256",hash(text.getBytes(StandardCharsets.UTF_8)));
                    ((ObjectNode)receipt.path("roleSigningTransport")).put("configurationTextSha256",hash(text.getBytes(StandardCharsets.UTF_8)));
                }
            }
            if(mutation.equals("missing"))((ObjectNode)receipt.path("roleSigningTransport")).put("reference","missing");
            if(!mutation.equals("hash")) {
                var raw=json.mapper().writeValueAsBytes(nativeConfig);originals.put("native",raw);
                ((ObjectNode)receipt.path("roleSigningTransport")).put("sha256",hash(raw));
            }
            assertThrows(IllegalArgumentException.class,()->MetadataRoleSigningTransportEvidence.verify(context(),target,e->originals.get(e.id()),receipt),mutation);
        }
    }
    @Test void httpsInActualFixtureCannotBeCalledUnused()throws Exception {
        var receipt=fixture();var id="fixture-entity-root";
        originals.put(id,new String(originals.get(id),StandardCharsets.UTF_8).replace("http://suite.example/acs","https://suite.example/acs").getBytes(StandardCharsets.UTF_8));
        assertThrows(IllegalArgumentException.class,()->MetadataRoleSigningTransportEvidence.verify(context(),target,e->originals.get(e.id()),receipt));
    }
}
