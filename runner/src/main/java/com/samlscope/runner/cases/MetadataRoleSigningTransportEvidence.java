package com.samlscope.runner.cases;

import static com.samlscope.runner.cases.MetadataAlgorithmEvidence.children;
import java.net.URI;
import java.security.MessageDigest;
import java.util.*;
import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;

/** Proves the approved TLS-unused variant for the actual HTTP reference campaign. */
final class MetadataRoleSigningTransportEvidence {
    static final String ID="IIP-MD06-a3-idp-01";
    static final String SCHEMA="samlscope-keycloak-role-signing-transport-v1";
    private static final String MD="urn:oasis:names:tc:SAML:2.0:metadata";

    static EvidenceRef verify(CaseContext context, byte[] targetRaw, TranscriptContentReader content,
            JsonNode receipt) throws Exception {
        require("keycloak-native-event".equals(receipt.path("evidenceAdapter").asText()));
        var proof=receipt.path("roleSigningTransport");
        var entry=context.transcript().list(context.runId()).stream()
                .filter(e->e.id().equals(proof.path("reference").asText())).toList();
        require(entry.size()==1);
        var original=entry.getFirst();
        require(context.runId().equals(original.runId())&&original.direction()==Direction.INBOUND
                &&"POST".equals(original.method())&&Integer.valueOf(204).equals(original.status()));
        var raw=content.readDecodedSaml(original);
        require(hash(raw).equals(proof.path("sha256").asText()));
        var readback=new JsonCodec().mapper().readTree(raw);
        var target=SecureXml.parse(targetRaw).getDocumentElement();
        require(SCHEMA.equals(readback.path("schema").asText())
                &&context.runId().equals(readback.path("runId").asText())
                &&hash(targetRaw).equals(readback.path("targetMetadataSha256").asText())
                &&target.getAttribute("entityID").equals(readback.path("targetEntityId").asText()));
        var runtime=readback.path("runtime");
        require(runtime.path("image").asText().matches("sha256:[0-9a-f]{64}")
                &&runtime.path("command").isArray()
                &&runtime.path("command").toString().contains("\"start-dev\"")
                &&runtime.path("portBindings").isObject()
                &&runtime.path("portBindings").size()==1
                &&runtime.path("portBindings").has("8080/tcp"));
        var config=readback.path("nativeConfiguration");
        require("kc.sh show-config".equals(config.path("source").asText())
                &&config.path("tlsConfiguration").isArray()&&config.path("tlsConfiguration").isEmpty());
        var fullText=config.path("originalText").asText();
        require(fullText.startsWith("Current Mode: development\nCurrent Configuration:\n")
                &&hash(fullText.getBytes(java.nio.charset.StandardCharsets.UTF_8)).equals(config.path("originalTextSha256").asText())
                &&config.path("originalTextSha256").asText().equals(proof.path("configurationTextSha256").asText()));
        int enabled=0,hostname=0;
        var selectedFromText=new ArrayList<String>();
        var names=new HashSet<String>();
        for(var line:fullText.split("\n")) {
            var value=line.trim();
            if(value.startsWith("kc.")) {
                var separator=value.indexOf(" =");require(separator>3);
                var name=value.substring(0,separator);require(names.add(name));
                require(!Set.of("kc.https-certificate-file","kc.https-certificate-key-file",
                        "kc.https-key-store-file","kc.https-client-auth","kc.https-trust-store-file").contains(name));
            }
            if(value.startsWith("kc.hostname =")||value.startsWith("kc.http-enabled ="))selectedFromText.add(value);
            if(value.matches("kc\\.http-enabled\\s*=\\s*true\\s+\\(ENV\\)"))enabled++;
            if(value.matches("kc\\.hostname\\s*=\\s*http://localhost:18180\\s+\\(ENV\\)"))hostname++;
        }
        var selectedClaims=new ArrayList<String>();for(var value:config.path("selectedConfiguration"))selectedClaims.add(value.asText());
        require(selectedFromText.equals(selectedClaims));
        require(enabled==1&&hostname==1&&names.containsAll(Set.of("kc.version","kc.db","kc.run-in-container")));
        boolean sso=false;
        for(var role:children(target,MD,"IDPSSODescriptor"))
            for(var endpoint:children(role,MD,"SingleSignOnService")) {
                require(http(endpoint.getAttribute("Location")));sso=true;
            }
        require(sso);
        var required=MetadataKeySelectionComparison.required(MetadataKeySelectionComparison.PUBLIC_KEY);
        var entries=new HashMap<String,TranscriptEntry>();
        for(var e:context.transcript().list(context.runId()))require(entries.put(e.id(),e)==null);
        for(var row:receipt.path("conditions"))if(required.contains(row.path("variant").asText())) {
            var prepared=entries.get(row.path("metadataReference").asText());require(prepared!=null);
            var fixture=SecureXml.parse(content.readDecodedSaml(prepared)).getDocumentElement();
            for(var role:children(fixture,MD,"SPSSODescriptor"))
                for(var local:List.of("AssertionConsumerService","SingleLogoutService"))
                    for(var endpoint:children(role,MD,local))require(http(endpoint.getAttribute("Location")));
            for(var slot:List.of("positive","negative")) {
                var request=entries.get(row.path(slot).path("requestReference").asText());
                require(request!=null&&http(request.url()));
                if(row.path(slot).has("responseReference")) {
                    var response=entries.get(row.path(slot).path("responseReference").asText());
                    require(response!=null&&http(response.url()));
                }
            }
        }
        return new EvidenceRef("transcript",original.id());
    }
    private static boolean http(String url) {try{return "http".equals(URI.create(url).getScheme());}catch(Exception invalid){return false;}}
    private static String hash(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
    private static void require(boolean condition){if(!condition)throw new IllegalArgumentException("Role signing transport original unproven");}
}
