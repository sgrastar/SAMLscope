package com.samlscope.runner.cases;

import java.nio.file.*;
import java.net.URI;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.crypto.VerifiedSignatureAlgorithms;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import org.w3c.dom.Element;

/** MD06.a3's XML path plus a complete native HTTP-only transport inventory for this campaign. */
final class ShibbolethRoleSigningTransportEvidenceFile {
    private static final String SCHEMA = "samlscope-shibboleth-role-signing-transport-v1";
    private static final String ADAPTER = "shibboleth-native-http-refresh-v1";
    private static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String NS = "urn:mace:shibboleth:2.0:metadata";
    private static final String XSI = "http://www.w3.org/2001/XMLSchema-instance";
    private final Path directory;
    private final TranscriptContentReader content;

    ShibbolethRoleSigningTransportEvidenceFile(Path directory, TranscriptContentReader content) {
        this.directory = Objects.requireNonNull(directory).toAbsolutePath().normalize();
        this.content = Objects.requireNonNull(content);
    }

    Optional<CaseOutcome> evaluate(CaseContext context, byte[] targetRaw) {
        if (!context.runId().matches("run_[0-9A-HJKMNP-TV-Z]{26}")) return Optional.empty();
        var folder = directory.resolve(context.runId() + ".refresh").normalize();
        if (!Files.isRegularFile(folder.resolve("http-scope.json"), LinkOption.NOFOLLOW_LINKS)) return Optional.empty();
        String stage = "http-scope-unproven";
        try {
            require(folder.getParent().equals(directory) && Files.isDirectory(folder, LinkOption.NOFOLLOW_LINKS));
            var json = new JsonCodec().mapper();
            var manifestRaw = raw(folder, "manifest.json");
            var manifest = json.readTree(manifestRaw);
            if (!ADAPTER.equals(manifest.path("adapter").asText())) return Optional.empty();
            var scopeRaw = raw(folder, "http-scope.json");
            var scope = json.readTree(scopeRaw);
            require(SCHEMA.equals(text(scope, "schema")) && context.runId().equals(text(scope, "runId"))
                    && hash(targetRaw).equals(text(scope, "targetMetadataSha256")));
            var target = SecureXml.parse(targetRaw).getDocumentElement();
            require(MD.equals(target.getNamespaceURI()) && "EntityDescriptor".equals(target.getLocalName())
                    && "http://localhost:18280/idp/shibboleth".equals(target.getAttribute("entityID"))
                    && target.getAttribute("entityID").equals(text(scope, "targetEntityId")));
            metadataHttp(target);
            var before = scope.path("before");
            var after = scope.path("after");
            require("/usr/local/tomcat/conf/server.xml".equals(text(before, "serverPath"))
                    && text(before, "serverPath").equals(text(after, "serverPath"))
                    && "/opt/reference-idp/conf/metadata-providers.xml".equals(text(before, "providersPath"))
                    && text(before, "providersPath").equals(text(after, "providersPath")));
            var server = checked(folder, before, "serverFile", "serverSha256");
            require(Arrays.equals(server, checked(folder, after, "serverFile", "serverSha256")));
            serverHttp(server);
            var originalProviders = checked(folder, before, "providersFile", "providersSha256");
            var finalProviders = checked(folder, after, "providersFile", "providersSha256");
            require(Arrays.equals(originalProviders, finalProviders)
                    && Arrays.equals(originalProviders, raw(folder, "original-providers.xml"))
                    && Arrays.equals(finalProviders, raw(folder, "final-providers.xml")));
            var configured = SecureXml.parse(raw(folder, "configured-providers.xml")).getDocumentElement();
            var configuredSources = sources(configured, true);
            var nativeSources = sources(SecureXml.parse(originalProviders).getDocumentElement(), false);
            require(configuredSources.equals(nativeSources));
            var beforeFiles = sourceFiles(folder, before, nativeSources);
            var afterFiles = sourceFiles(folder, after, nativeSources);
            require(beforeFiles.keySet().equals(afterFiles.keySet()));
            for (var path : beforeFiles.keySet()) require(Arrays.equals(beforeFiles.get(path), afterFiles.get(path)));
            var entries = context.transcript().list(context.runId());
            require(!entries.isEmpty() && entries.stream().allMatch(entry -> context.runId().equals(entry.runId()) && http(entry.url())));
            var earliest = entries.stream().map(TranscriptEntry::timestamp).min(Instant::compareTo).orElseThrow();
            var latest = entries.stream().map(TranscriptEntry::timestamp).max(Instant::compareTo).orElseThrow();
            require(!Instant.parse(text(before, "recordedAt")).isAfter(earliest)
                    && !Instant.parse(text(after, "recordedAt")).isBefore(latest));
            stage = "role-key-signature-unproven";
            var proof = new ShibbolethMetadataRefreshEvidenceFile(content, directory).evaluate(context);
            require(proof.outcome() == Outcome.SATISFIED);
            var targetKeys = MetadataAlgorithmEvidence.signingKeys(target);
            require(!targetKeys.isEmpty());
            var byId = new HashMap<String, TranscriptEntry>();
            for (var entry : entries) require(byId.put(entry.id(), entry) == null);
            for (var phase : List.of(manifest.path("phaseA"), manifest.path("phaseB"))) {
                var response = byId.get(text(phase, "responseReference"));
                require(response != null && response.direction() == Direction.INBOUND);
                var responseXml = SecureXml.parse(content.readDecodedSaml(response)).getDocumentElement();
                require(new VerifiedSignatureAlgorithms().read(responseXml, target.getAttribute("entityID"), targetKeys)
                        .stream().anyMatch(signature -> "Response".equals(signature.element())));
            }
            require(Arrays.equals(manifestRaw, raw(folder, "manifest.json"))
                    && Arrays.equals(scopeRaw, raw(folder, "http-scope.json")));
            var details = new LinkedHashMap<String, Object>(proof.details());
            details.put("xml_signature_path_verified", true);
            details.put("tls_server_authentication", "not_used");
            details.put("mutual_tls_authentication", "not_used");
            details.put("native_http_listener_verified", true);
            details.put("native_metadata_source_count", nativeSources.size());
            details.put("http_scope_sha256", hash(scopeRaw));
            var refs = new ArrayList<>(proof.evidence());
            refs.add(new EvidenceRef("native-http-transport-scope", context.runId() + ".refresh/http-scope.json"));
            return Optional.of(new CaseOutcome(Outcome.SATISFIED_WITH_NOTE, null,
                    "metadata.role-signing.http-transport-observed", "metadata.role-signing.http-transport-observed",
                    List.copyOf(refs), Map.copyOf(details)));
        } catch (Exception unproven) {
            return Optional.of(new CaseOutcome(Outcome.NOT_VERIFIED, "native_role_signing_transport_unproven",
                    "metadata.role-signing.native-http-unproven", "metadata.role-signing.native-http-unproven",
                    List.of(), Map.of("adapter", ADAPTER, "stage", stage)));
        }
    }

    private Set<String> sources(Element root, boolean refresh) {
        require(NS.equals(root.getNamespaceURI()) && "MetadataProvider".equals(root.getLocalName()));
        var paths = new HashSet<String>();
        int remote = 0;
        for (var child = root.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (!(child instanceof Element provider)) continue;
            require(NS.equals(provider.getNamespaceURI()) && "MetadataProvider".equals(provider.getLocalName()));
            var type = provider.getAttributeNS(XSI, "type");
            if ("FilesystemMetadataProvider".equals(type)) {
                var path = provider.getAttribute("metadataFile").replace("%{idp.home}", "/opt/reference-idp");
                require(path.startsWith("/opt/reference-idp/metadata/") && !path.contains("..") && paths.add(path));
            } else {
                require(refresh && "FileBackedHTTPMetadataProvider".equals(type)
                        && provider.getAttribute("id").startsWith("Refreshrun_") && http(provider.getAttribute("metadataURL")));
                remote++;
            }
        }
        require(!paths.isEmpty() && remote == (refresh ? 1 : 0));
        return paths;
    }

    private Map<String, byte[]> sourceFiles(Path folder, JsonNode snapshot, Set<String> paths) throws Exception {
        var rows = snapshot.path("files");
        require(rows.isArray() && rows.size() == paths.size());
        var result = new HashMap<String, byte[]>();
        for (var row : rows) {
            var path = text(row, "nativePath");
            require(paths.contains(path));
            var bytes = checked(folder, row, "file", "sha256");
            metadataHttp(SecureXml.parse(bytes).getDocumentElement());
            require(result.put(path, bytes) == null);
        }
        return result;
    }

    private void metadataHttp(Element root) {
        require(MD.equals(root.getNamespaceURI()) && List.of("EntityDescriptor", "EntitiesDescriptor").contains(root.getLocalName()));
        for (var node = root.getFirstChild(); node != null; node = node.getNextSibling()) {
            if (node instanceof Element child) metadataLocations(child);
        }
    }

    private void metadataLocations(Element element) {
        if (element.hasAttribute("Location")) require(http(element.getAttribute("Location")));
        if (element.hasAttribute("ResponseLocation")) require(http(element.getAttribute("ResponseLocation")));
        if (MD.equals(element.getNamespaceURI()) && "AdditionalMetadataLocation".equals(element.getLocalName()))
            require(http(element.getTextContent().strip()));
        for (var child = element.getFirstChild(); child != null; child = child.getNextSibling())
            if (child instanceof Element nested) metadataLocations(nested);
    }

    private void serverHttp(byte[] raw) throws Exception {
        var document = SecureXml.parse(raw);
        var connectors = document.getElementsByTagName("Connector");
        require(connectors.getLength() == 1);
        var connector = (Element) connectors.item(0);
        require("8080".equals(connector.getAttribute("port")) && "HTTP/1.1".equals(connector.getAttribute("protocol"))
                && !"true".equalsIgnoreCase(connector.getAttribute("SSLEnabled"))
                && !"https".equalsIgnoreCase(connector.getAttribute("scheme"))
                && !"true".equalsIgnoreCase(connector.getAttribute("secure"))
                && connector.getElementsByTagName("SSLHostConfig").getLength() == 0);
    }

    private boolean http(String value) {
        try { var uri = URI.create(value); return "http".equals(uri.getScheme()) && uri.getHost() != null && uri.getUserInfo() == null; }
        catch (RuntimeException invalid) { return false; }
    }

    private byte[] checked(Path folder, JsonNode row, String file, String digest) throws Exception {
        var value = raw(folder, text(row, file));
        require(hash(value).equals(text(row, digest)));
        return value;
    }

    private byte[] raw(Path folder, String name) throws Exception {
        require(name.matches("[A-Za-z0-9][A-Za-z0-9._-]*"));
        var path = folder.resolve(name).normalize();
        require(path.getParent().equals(folder) && Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
                && Files.size(path) > 0 && Files.size(path) <= 2_097_152);
        return Files.readAllBytes(path);
    }

    private String text(JsonNode node, String field) {
        require(node.path(field).isTextual() && !node.path(field).asText().isBlank());
        return node.path(field).asText();
    }

    private String hash(byte[] raw) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));
    }

    private void require(boolean value) { if (!value) throw new IllegalArgumentException("Native role signing transport unproven"); }
}
