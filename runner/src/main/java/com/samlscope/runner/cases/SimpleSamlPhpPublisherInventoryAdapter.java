package com.samlscope.runner.cases;

import static com.samlscope.runner.cases.MetadataPublisherKeyInventoryEvidence.*;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.*;

/** Stock hosted-metadata producer and native credential loader. Configured new_
 * keys and per-peer overrides are not automatically called current role keys.
 * Their operative purpose must be separately established before a finding. */
public final class SimpleSamlPhpPublisherInventoryAdapter implements NativeMetadataPublisherInventoryAdapter {
    public static final String ID = "simplesamlphp-stock-publisher-inventory-v1";
    static final String TARGET = "http://localhost:18380/idp";
    static final Map<String, String> SOURCES = Map.of(
            "native-idp.php", "ae55fc922431d29ca6e87654ae2071500a4c3d7185ed80a6fcc5b26eed12495d",
            "native-builder.php", "b6c295c053a6b8c178899d3e35c1cf8c9752cd0442e4a45861559c7aa2107591",
            "native-configuration.php", "53837359cd60433082d3968843605a864bab97f23be482447bcfef37e7f6946e",
            "native-crypto.php", "eedf4f4d133e117235d6829c4e386570c5168ad01afe060b3a31f38d0a1db0f3",
            "native-handler.php", "43a0e730d624c5a937f800c4e7e045ff3625eeb0738d81a4ab1dac96f82fe040",
            "native-message.php", "ab017ee6cf9fb66db1037e40ed50feff0b277b1a5d43fd8ca774a3d27ce355d2",
            "native-controller.php", "e048fb572f43168187c178e0927f9e6c885031197b8a9c8682539963dde8ec56");
    // These are fixed with the public dev programs before actual capture. An unknown
    // projection/producer source fails closed rather than accepting receipt labels.
    static final String PUBLIC_READBACK_SOURCE = "d372d37aa319cca4115ef6a6c3e685ea44755ccc4400c502d623d8601121f110";
    static final String CONTROL_SOURCE = "504a170d2df9b62cfdc3a498cac3cfaf984cf9430d7b6f8a84b94926f6b38f62";
    @Override public String id() { return ID; }
    @Override public Inventory validate(Frame f, JsonNode epoch) throws Exception {
        JsonNode before = state(f, text(epoch, "beforeOriginal"), text(epoch, "id"));
        JsonNode after = state(f, text(epoch, "afterOriginal"), text(epoch, "id"));
        require(before.path("runtime").equals(after.path("runtime")));
        JsonNode b = f.node(text(before, "readbackFile")), a = f.node(text(after, "readbackFile"));
        for (String field : List.of("entityId", "publicRequestContext", "publicNativeMetadata", "currentCredentials", "remotePeers", "loadedClasses", "metadataSources", "configurationHashes", "roleFeatureFlags", "nativeProducedMetadataXmlBase64", "nativeProducedMetadataSha256"))
            require(b.path(field).equals(a.path(field)));
        require(at(before, "nativeFinishedAt").isBefore(at(epoch, "startedAt"))
                && at(after, "nativeStartedAt").isAfter(at(epoch, "finishedAt")));
        validateSources(f, b);
        validatePublicRequestContext(b);validatePublicRequestContext(a);
        var publication=f.original(text(epoch,"publicationOriginal"),"native-publication");
        require("http://localhost:18380/simplesaml/module.php/saml/idp/metadata".equals(text(publication,"url")));
        byte[] nativeProduced = Base64.getDecoder().decode(text(b,"nativeProducedMetadataXmlBase64"));
        require(hash(nativeProduced).equals(text(b,"nativeProducedMetadataSha256"))
                && Arrays.equals(nativeProduced,f.file(text(epoch,"publicationFile"))));
        return inventory(b);
    }
    static JsonNode state(Frame f, String name, String epoch) throws Exception {
        JsonNode n = f.original(name, "native-role-inventory");
        require(epoch.equals(text(n, "epochId")) && ID.equals(text(n, "adapter")));
        var raw = f.file(text(n, "readbackFile")); require(hash(raw).equals(text(n, "readbackSha256")));
        JsonNode readback = json(raw); require(!sensitive(readback)
                && "samlscope-ssp-public-publisher-state-v1".equals(text(readback, "schema")));
        require(at(n, "nativeStartedAt").isBefore(at(n, "nativeFinishedAt"))
                && !at(n, "nativeFinishedAt").isAfter(at(n, "recordedAt")));
        var runtime = n.path("runtime"); require(runtime.isObject() && runtime.path("running").isBoolean()
                && runtime.path("running").asBoolean() && text(runtime, "id").matches("[a-f0-9]{64}")
                && text(runtime, "image").matches("sha256:[a-f0-9]{64}") && runtime.path("mounts").isArray());
        at(runtime, "startedAt");
        var invocation = n.path("invocation");
        require(invocation.path("exitCode").isIntegralNumber() && invocation.path("exitCode").asInt(-1) == 0
                && PUBLIC_READBACK_SOURCE.equals(text(invocation, "inputSha256"))
                && PUBLIC_READBACK_SOURCE.equals(hash(f.file("native-public-readback.php")))
                && text(n, "readbackSha256").equals(text(invocation, "outputSha256"))
                && "docker-exec-php-stdin-public-projection".equals(text(invocation, "operation")));
        require(invocation.path("command").equals(json("[\"docker\",\"exec\",\"-i\",\"samlscope-reference-ssp\",\"php\",\"-d\",\"display_errors=0\",\"-d\",\"log_errors=0\"]".getBytes(java.nio.charset.StandardCharsets.UTF_8))));
        return n;
    }
    static void validateSources(Frame f, JsonNode n) throws Exception {
        require(TARGET.equals(text(n, "entityId")) && TARGET.equals(text(f.manifest, "entityId")));
        var classes = n.path("loadedClasses"); require(classes.isArray() && classes.size() == SOURCES.size());
        var found = new HashSet<String>();
        for (var row : classes) {
            String name = text(row, "logicalFile"); require(found.add(name) && SOURCES.containsKey(name)
                    && SOURCES.get(name).equals(text(row, "sha256")) && SOURCES.get(name).equals(hash(f.file("native-source/" + name))));
            require(text(row, "file").startsWith("/var/simplesamlphp/") && !text(row, "class").isBlank());
        }
        var metadataSources = n.path("metadataSources"); require(metadataSources.isArray() && metadataSources.size() == 1
                && "flatfile".equals(text(metadataSources.get(0), "type"))
                && text(metadataSources.get(0), "configurationHash").matches("[a-f0-9]{64}"));
        var hashes = n.path("configurationHashes"); require(hashes.isArray() && hashes.size() == 3);
        var expected = Set.of("/var/simplesamlphp/config/config.php", "/var/simplesamlphp/metadata/saml20-idp-hosted.php", "/var/simplesamlphp/metadata/saml20-sp-remote.php");
        var paths = new HashSet<String>(); for (var row : hashes) require(expected.contains(text(row, "file"))
                && paths.add(text(row, "file")) && text(row, "sha256").matches("[a-f0-9]{64}"));
    }
    static void validatePublicRequestContext(JsonNode readback) throws Exception {
        require(readback.path("publicRequestContext").equals(json("{\"method\":\"GET\",\"scheme\":\"http\",\"host\":\"localhost\",\"port\":18380,\"path\":\"/simplesaml/module.php/saml/idp/metadata\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8))));
    }
    static Inventory inventory(JsonNode n) throws Exception {
        require("samlscope-ssp-public-publisher-state-v1".equals(text(n, "schema")) && TARGET.equals(text(n, "entityId")));
        var metadata = n.path("publicNativeMetadata"); require(metadata.isObject()
                && TARGET.equals(text(metadata, "entityid")) && "saml20-idp-hosted".equals(text(metadata, "metadata-set")));
        var keys = new ArrayList<RoleKey>(); var gaps = new ArrayList<String>();
        var rows = n.path("currentCredentials"); require(rows.isArray() && rows.size() == 3);
        var prefixes = new HashSet<String>();
        for (var row : rows) {
            require(row.path("prefix").isTextual()); String prefix = row.path("prefix").asText();
            require(Set.of("", "new_", "https.").contains(prefix) && prefixes.add(prefix)
                    && row.path("publicCertificatePresent").isBoolean() && row.path("privateCredentialPresent").isBoolean());
            boolean present = row.path("publicCertificatePresent").asBoolean();
            if (!present) { require(!row.path("privateCredentialPresent").asBoolean()); continue; }
            String spki = certificateSpki(text(row, "certificateDerBase64"));
            require(spki.equals(publicPemSpki(text(row, "certificatePublicSpkiPem"))));
            if (row.path("privateCredentialPresent").asBoolean()) require(spki.equals(publicPemSpki(text(row, "nativePrivateCredentialPublicSpkiPem"))));
            if (prefix.isEmpty()) {
                require(row.path("privateCredentialPresent").asBoolean());
                keys.add(new RoleKey(spki, "signing", "native-hosted-current-credential"));
                keys.add(new RoleKey(spki, "encryption", "native-hosted-current-credential"));
            } else if (prefix.equals("new_")) {
                // new_ is published during rollover, but public certificates alone do
                // not establish when a purpose became current in the selected role.
                gaps.add("new-credential-current-role-purpose-unproven");
            } else gaps.add("configured-https-credential-operative-role-use-unproven");
        }
        require(!keys.isEmpty());
        var peers = n.path("remotePeers"); require(peers.isArray()); var entities = new HashSet<String>();
        for (var peer : peers) {
            require(entities.add(text(peer, "entityId")) && peer.path("signatureOverridePresent").isBoolean()
                    && peer.path("sharedEncryptionOverridePresent").isBoolean());
            if (peer.path("signatureOverridePresent").asBoolean()) gaps.add("per-peer-current-signer-use-unproven:" + text(peer, "entityId"));
            if (peer.path("sharedEncryptionOverridePresent").asBoolean()) gaps.add("per-peer-symmetric-encryption-inventory-unproven:" + text(peer, "entityId"));
        }
        var endpoints = new ArrayList<Endpoint>();
        for (String kind : List.of("SingleSignOnService", "SingleLogoutService", "ArtifactResolutionService")) {
            var values = metadata.path(kind); if (values.isMissingNode()) continue;
            require(values.isArray()); for (var row : values) {
                String location = text(row, "Location"); var uri = java.net.URI.create(location);
                require(uri.getUserInfo() == null && uri.getFragment() == null && Set.of("http", "https").contains(uri.getScheme()));
                if (!uri.getScheme().equals("http")) gaps.add("role-endpoint-transport-authentication-unproven");
                endpoints.add(new Endpoint(kind, text(row, "Binding"), location, row.path("ResponseLocation").asText("")));
            }
        }
        require(endpoints.stream().anyMatch(e -> e.kind().equals("SingleSignOnService")));
        JsonNode flags = n.path("roleFeatureFlags");
        for (String flag : List.of("saml20.ecp", "saml20.hok.assertion", "saml20.sendartifact", "metadata.sign.enable")) require(flags.path(flag).isBoolean());
        // Do not infer absent TLS/message authentication from publication URLs alone.
        // A narrower stock Browser role has no configured hosted transport key; ECP,
        // artifact and HoK paths require their own operative transport closure.
        if (flags.path("saml20.ecp").asBoolean() || flags.path("saml20.hok.assertion").asBoolean() || flags.path("saml20.sendartifact").asBoolean())
            gaps.add("additional-role-protocol-transport-scope-unproven");
        if (flags.path("metadata.sign.enable").asBoolean()) gaps.add("separate-document-signing-producer-scope-unproven");
        for (var endpoint:endpoints) if (!Set.of("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST").contains(endpoint.binding()))
            gaps.add("additional-endpoint-binding-transport-scope-unproven");
        Boolean signed = null;
        if (metadata.has("sign.authnrequest")) { require(metadata.path("sign.authnrequest").isBoolean()); signed = metadata.path("sign.authnrequest").asBoolean(); }
        else if (metadata.has("redirect.sign")) { require(metadata.path("redirect.sign").isBoolean()); signed = metadata.path("redirect.sign").asBoolean(); }
        return new Inventory(keys, endpoints, Set.of(P), signed, gaps);
    }
    static void validateProducerControl(Frame f, JsonNode controls, byte[] inputRaw, byte[] positiveRaw, byte[] negativeRaw) throws Exception {
        JsonNode input = json(inputRaw), p = json(positiveRaw), n = json(negativeRaw);
        require(!sensitive(input) && !sensitive(p) && !sensitive(n)
                && "samlscope-native-publisher-detector-input-v1".equals(text(input, "schema"))
                && "oracle-calibration-only".equals(text(input, "purpose")) && TARGET.equals(text(input, "entityId")));
        require(CONTROL_SOURCE.equals(hash(f.file("native-publisher-control.php"))));
        validateControlOutput(p, inputRaw, "stock-native-builder");
        validateControlOutput(n, inputRaw, "developer-omitted-transport-key");
        var rows = input.path("roleKeys"); require(rows.isArray() && rows.size() >= 3);
        var expected = new ArrayList<RoleKey>(); var ids = new HashSet<String>(); String transport = null;
        for (var row : rows) {
            String purpose = text(row, "purpose"); require(Set.of("signing", "encryption", "transport-authentication").contains(purpose));
            String spki = certificateSpki(text(row, "certificateDerBase64")); require(ids.add(purpose+":"+spki));
            expected.add(new RoleKey(spki, purpose, "diagnostic-public-input"));
            if (purpose.equals("transport-authentication")) { require(transport == null); transport = spki; }
        }
        require(transport != null && expected.stream().anyMatch(k -> k.purpose().equals("signing"))
                && expected.stream().anyMatch(k -> k.purpose().equals("encryption"))
                && expected.stream().filter(k -> k.purpose().equals("signing")).map(RoleKey::spkiSha256).distinct().count() >= 2);
        Inventory inventory = new Inventory(expected, List.of(), Set.of(P), null, List.of());
        ElementOutput stock = controlMetadata(p), omitted = controlMetadata(n);
        require(compare(stock.role(), inventory, C3).isEmpty()
                && compare(omitted.role(), inventory, C3).equals(List.of("key:transport-authentication:" + transport)));
        // Full output differences may contain only the transport KeyDescriptor.
        var pk = roleKeys(stock.role()); var nk = roleKeys(omitted.role());
        var signing = new HashSet<>(pk.get("signing")); signing.remove(transport);
        require(signing.equals(nk.get("signing")) && pk.get("encryption").equals(nk.get("encryption")));
        var invocations = f.node(text(controls, "invocationsFile")); require(invocations.isArray() && invocations.size() == 2);
        var modes = new HashSet<String>(); for (var row : invocations) {
            String mode = text(row, "mode"); require(modes.add(mode) && Set.of("stock-native-builder", "developer-omitted-transport-key").contains(mode)
                    && row.path("exitCode").asInt(-1) == 0 && CONTROL_SOURCE.equals(text(row, "sourceSha256"))
                    && hash(inputRaw).equals(text(row, "inputSha256"))
                    && hash(mode.equals("stock-native-builder") ? positiveRaw : negativeRaw).equals(text(row, "outputSha256")));
            require(at(row, "startedAt").isBefore(at(row, "finishedAt")));
            var initial=f.original("initial","native-role-inventory");
            require(row.path("runtimeBefore").equals(initial.path("runtime"))
                    && row.path("runtimeAfter").equals(initial.path("runtime")));
            var controlOriginal=f.original(text(controls,"original"),"native-publisher-detector-control");
            require(!at(row,"finishedAt").isAfter(at(controlOriginal,"recordedAt")));
            var command = row.path("command"); require(command.isArray() && command.size() == 11
                    && "docker".equals(command.get(0).asText()) && "exec".equals(command.get(1).asText())
                    && "-i".equals(command.get(2).asText()) && "samlscope-reference-ssp".equals(command.get(3).asText())
                    && "php".equals(command.get(4).asText()) && "-d".equals(command.get(5).asText())
                    && "display_errors=0".equals(command.get(6).asText()) && "-r".equals(command.get(7).asText())
                    && new String(f.file("native-publisher-control.php"), java.nio.charset.StandardCharsets.UTF_8)
                    .replaceFirst("^<\\?php\\s*", "").equals(command.get(8).asText())
                    && mode.equals(command.get(9).asText()) && CONTROL_SOURCE.equals(command.get(10).asText()));
        }
    }
    static List<String> controlOmissions(Frame f, JsonNode controls, String caseId) throws Exception {
        JsonNode input=f.node(text(controls,"inputFile")),negative=f.node(text(controls,"negativeOutputFile"));
        var keys=new ArrayList<RoleKey>();
        for(var row:input.path("roleKeys"))keys.add(new RoleKey(certificateSpki(text(row,"certificateDerBase64")),text(row,"purpose"),"diagnostic-public-native-producer"));
        return compare(controlMetadata(negative).role(),new Inventory(keys,List.of(),Set.of(P),null,List.of()),caseId);
    }
    private record ElementOutput(org.w3c.dom.Element role) {}
    private static ElementOutput controlMetadata(JsonNode output) throws Exception {
        byte[] raw = Base64.getDecoder().decode(text(output, "metadataXmlBase64"));
        require(hash(raw).equals(text(output, "metadataSha256"))); return new ElementOutput(role(raw, TARGET));
    }
    private static void validateControlOutput(JsonNode n, byte[] input, String mode) throws Exception {
        require("samlscope-ssp-native-publisher-detector-output-v1".equals(text(n, "schema"))
                && mode.equals(text(n, "selectedProducer")) && hash(input).equals(text(n, "inputSha256"))
                && CONTROL_SOURCE.equals(text(n, "producerSourceSha256"))
                && "oracle-calibration-only".equals(text(n, "purpose")));
        var classes = n.path("loadedClasses"); require(classes.isArray() && classes.size() == 2);
        var seen = new HashSet<String>(); for (var row : classes) require(seen.add(text(row, "logicalFile"))
                && Set.of("native-builder.php", "native-configuration.php").contains(text(row, "logicalFile"))
                && SOURCES.get(text(row, "logicalFile")).equals(text(row, "sha256")));
        for (String cost : List.of("productSettings", "samlSubmissions", "credentialPosts", "personOperations"))
            require(n.path(cost).isIntegralNumber() && n.path(cost).asInt(-1) == 0);
    }
}
