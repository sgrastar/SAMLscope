package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.crypto.VerifiedSignatureAlgorithms;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import com.samlscope.saml.normal.*;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.cert.*;
import java.io.ByteArrayInputStream;
import java.time.Instant;
import java.util.*;
import java.util.function.Function;
import javax.xml.namespace.QName;
import org.w3c.dom.Element;

/** Completes one missing native parser observation; every other matrix member remains required. */
final class ExtensionAttributeParserEvidence {
    static final String ID = "IIP-EXT01-c-idp-01", VARIANT = "foreign-attribute-affiliation";
    static final String SUFFIX = ".extension-attribute-parser.json";
    private static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata", A = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String P = "urn:oasis:names:tc:SAML:2.0:protocol", DS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String FOREIGN = "urn:samlscope:fixture:foreign-attribute";
    private static final String ACTIVE_FOREIGN = "urn:samlscope:probe:unknown-attribute";
    private static final ObjectMapper JSON = new ObjectMapper()
            .enable(com.fasterxml.jackson.core.JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    private final Path directory;
    private final TranscriptContentReader content;
    private final Function<String,String> profiles;
    ExtensionAttributeParserEvidence(Path directory, TranscriptContentReader content) {
        this(directory, content, new SuiteRunProfileLookup(directory.toAbsolutePath().normalize().getParent())::profile);
    }
    ExtensionAttributeParserEvidence(Path directory, TranscriptContentReader content, Function<String,String> profiles) {
        this.directory = directory.toAbsolutePath().normalize(); this.content = Objects.requireNonNull(content);
        this.profiles = Objects.requireNonNull(profiles);
    }
    boolean exists(String run) {
        return run != null && run.matches("run_[0-9A-HJKMNP-TV-Z]{26}")
                && Files.exists(directory.resolve(run + SUFFIX), LinkOption.NOFOLLOW_LINKS);
    }
    private static void require(boolean condition) {
        if (!condition) throw new IllegalArgumentException("extension_attribute_parser_original_unproven");
    }
    static String sha(byte[] raw) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));
    }
    private byte[] file(String run, String name, JsonNode hashes) throws Exception {
        require(name.matches("[A-Za-z0-9_.-]+"));
        var path = directory.resolve(run + ".extension-attribute-parser").resolve(name).normalize();
        require(path.startsWith(directory) && Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS));
        for (var at = path; at != null; at = at.getParent()) require(!Files.isSymbolicLink(at));
        require(Files.size(path) <= 32 * 1024 * 1024);
        var bytes = Files.readAllBytes(path); require(sha(bytes).equals(hashes.path(name).asText())); return bytes;
    }
    private record Original(TranscriptEntry entry, JsonNode json) {}
    private Original original(JsonNode reference, String run, String targetHash,
            Map<String,TranscriptEntry> entries, List<EvidenceRef> evidence) throws Exception {
        var entry = entries.get(reference.path("reference").asText());
        require(entry != null && entry.direction() == Direction.INBOUND);
        var bytes = content.readDecodedSaml(entry);
        require(bytes.length == entry.decodedSamlBytes() && sha(bytes).equals(reference.path("sha256").asText()));
        var json = JSON.readTree(bytes);
        require(run.equals(json.path("runId").asText()) && targetHash.equals(json.path("targetMetadataSha256").asText()));
        evidence.add(new EvidenceRef("transcript", entry.id())); return new Original(entry, json);
    }
    private static List<String> metadataVariants() {
        return Arrays.stream(com.samlscope.saml.metadata.MetadataService.Variant.values())
                .map(com.samlscope.saml.metadata.MetadataService.Variant::id)
                .filter(value -> value.startsWith("foreign-attribute-")).sorted().toList();
    }
    private static List<Element> children(Element parent, String ns, String name) {
        return MetadataAlgorithmEvidence.children(parent, ns, name);
    }
    private static QName metadataPlacement(String variant, Element xml) {
        var names = Map.ofEntries(Map.entry("entity", "EntityDescriptor"), Map.entry("organization", "Organization"),
                Map.entry("contact", "ContactPerson"), Map.entry("role", "RoleDescriptor"),
                Map.entry("single-logout", "SingleLogoutService"), Map.entry("single-sign-on", "SingleSignOnService"),
                Map.entry("manage-nameid", "ManageNameIDService"), Map.entry("nameid-mapping", "NameIDMappingService"),
                Map.entry("assertion-id", "AssertionIDRequestService"), Map.entry("authn-query", "AuthnQueryService"),
                Map.entry("authz", "AuthzService"), Map.entry("attribute-service", "AttributeService"));
        var marked = new ArrayList<Element>();
        if (xml.hasAttributeNS(FOREIGN, "undefined")) marked.add(xml);
        var descendants = xml.getElementsByTagNameNS("*", "*");
        for (int i = 0; i < descendants.getLength(); i++) {
            var element = (Element) descendants.item(i);
            if (element.hasAttributeNS(FOREIGN, "undefined")) marked.add(element);
        }
        if (variant.equals("control")) { require(marked.isEmpty()); return null; }
        require(marked.size() == 1 && MD.equals(marked.getFirst().getNamespaceURI())
                && names.get(variant.substring("foreign-attribute-".length())).equals(marked.getFirst().getLocalName())
                && "ignored-content".equals(marked.getFirst().getAttributeNS(FOREIGN, "undefined"))
                && SamlSchemaValidation.validationFailure(xml, SamlSchemaValidation.SchemaKind.METADATA).isEmpty());
        return new QName(marked.getFirst().getNamespaceURI(), marked.getFirst().getLocalName());
    }
    private List<EvidenceRef> active(CaseContext context, Map<String,TranscriptEntry> entries, byte[] targetMetadata) throws Exception {
        var target = SecureXml.parse(targetMetadata).getDocumentElement();
        var certificates = MetadataAlgorithmEvidence.signingKeys(target);
        var fixtures = List.of("baseline-success", "unknown-any-attribute", "unknown-attribute-any-attribute");
        var result = new ArrayList<EvidenceRef>(); var seen = new HashSet<String>();
        for (var request : entries.values()) {
            if (request.direction() != Direction.OUTBOUND || !ID.equals(request.samlSummary().get("scenario_case_id"))) continue;
            var fixture = String.valueOf(request.samlSummary().get("fixture_id"));
            require(fixtures.contains(fixture) && seen.add(fixture));
            var action = String.valueOf(request.samlSummary().get("action_id"));
            require(action.matches("action_[0-9a-f]{32}") && action.equals(request.correlationId()));
            var xml = SecureXml.parse(content.readDecodedSaml(request)).getDocumentElement();
            require(P.equals(xml.getNamespaceURI()) && "AuthnRequest".equals(xml.getLocalName())
                    && ("_" + action).equals(xml.getAttribute("ID"))
                    && SamlSchemaValidation.validationFailure(xml, SamlSchemaValidation.SchemaKind.PROTOCOL).isEmpty());
            var marked = new ArrayList<Element>(); var all = xml.getElementsByTagNameNS("*", "*");
            for (int i = 0; i < all.getLength(); i++) if (((Element) all.item(i)).hasAttributeNS(ACTIVE_FOREIGN, "fixture")) marked.add((Element) all.item(i));
            if (fixture.equals("baseline-success")) require(marked.isEmpty());
            else require(marked.size() == 1 && A.equals(marked.getFirst().getNamespaceURI())
                    && (fixture.equals("unknown-any-attribute") ? "SubjectConfirmationData" : "Attribute").equals(marked.getFirst().getLocalName())
                    && action.equals(marked.getFirst().getAttributeNS(ACTIVE_FOREIGN, "fixture")));
            var responses = entries.values().stream().filter(entry -> entry.direction() == Direction.INBOUND
                    && ("_" + action).equals(entry.samlSummary().get("inResponseTo"))).toList();
            require(responses.size() == 1); var response = responses.getFirst();
            require(!response.timestamp().isBefore(request.timestamp()) && Boolean.TRUE.equals(response.samlSummary().get("activeProbeAccepted")));
            var received = SecureXml.parse(content.readDecodedSaml(response)).getDocumentElement();
            require(P.equals(received.getNamespaceURI()) && "Response".equals(received.getLocalName())
                    && xml.getAttribute("ID").equals(received.getAttribute("InResponseTo"))
                    && xml.getAttribute("AssertionConsumerServiceURL").equals(received.getAttribute("Destination"))
                    && response.url().equals(received.getAttribute("Destination")));
            var statuses = children(received, P, "Status");
            require(statuses.size() == 1 && children(statuses.getFirst(), P, "StatusCode").size() == 1
                    && "urn:oasis:names:tc:SAML:2.0:status:Success".equals(children(statuses.getFirst(), P, "StatusCode").getFirst().getAttribute("Value")));
            require(!children(received, A, "Assertion").isEmpty() || !children(received, A, "EncryptedAssertion").isEmpty());
            var signatures = new VerifiedSignatureAlgorithms().read(received, target.getAttribute("entityID"), certificates);
            require(signatures.stream().anyMatch(value -> value.element().equals("Response"))
                    && signatures.size() == children(received, DS, "Signature").size()
                        + children(received, A, "Assertion").stream().mapToInt(value -> children(value, DS, "Signature").size()).sum());
            result.add(new EvidenceRef("transcript", request.id())); result.add(new EvidenceRef("transcript", response.id()));
        }
        require(seen.equals(new HashSet<>(fixtures))); return result;
    }

    CaseOutcome evaluate(CaseContext context, byte[] targetMetadata) {
        var evidence = new ArrayList<EvidenceRef>();
        var stage = "receipt_and_profile";
        try {
            require(context.transcriptComplete() && context.targetRole() == com.samlscope.core.plan.TargetRole.IDP && exists(context.runId()));
            var receiptPath = directory.resolve(context.runId() + SUFFIX);
            require(Files.isRegularFile(receiptPath, LinkOption.NOFOLLOW_LINKS) && Files.size(receiptPath) < 1024 * 1024);
            for (var at = receiptPath; at != null; at = at.getParent()) require(!Files.isSymbolicLink(at));
            var receiptBytes = Files.readAllBytes(receiptPath); var receipt = JSON.readTree(receiptBytes);
            var target = SecureXml.parse(targetMetadata).getDocumentElement(); var targetHash = sha(targetMetadata);
            require("samlscope-extension-attribute-parser-v1".equals(receipt.path("schema").asText())
                    && "keycloak-native-affiliation-parser-v1".equals(receipt.path("adapter").asText())
                    && ID.equals(receipt.path("caseId").asText()) && context.runId().equals(receipt.path("runId").asText())
                    && context.runId().equals(receipt.path("sourceRunId").asText())
                    && targetHash.equals(receipt.path("targetMetadataSha256").asText())
                    && target.getAttribute("entityID").equals(receipt.path("targetEntityId").asText())
                    && Set.of("browser_sso_idp", "metadata_idp", "ecp_idp", "single_logout_idp").contains(receipt.path("profile").asText())
                    && receipt.path("profile").asText().equals(profiles.apply(context.runId())));
            var entries = new HashMap<String,TranscriptEntry>();
            for (var entry : context.transcript().list(context.runId())) require(context.runId().equals(entry.runId()) && entries.put(entry.id(), entry) == null);
            stage = "active_protocol_matrix";
            evidence.addAll(active(context, entries, targetMetadata));
            var coveredPoints = new HashSet<>(List.of(new QName(A, "SubjectConfirmationData"), new QName(A, "Attribute")));
            stage = "metadata_protocol_matrix";
            var required = new ArrayList<>(metadataVariants()); require(required.size() == 13 && required.remove(VARIANT)); required.add("control");
            var collected = MetadataAlgorithmEvidence.collect(required, context, content, targetMetadata);
            require(collected.issues().isEmpty());
            for (var variant : required) {
                var exchanges = collected.exchanges().stream().filter(exchange -> variant.equals(exchange.variant())).toList();
                require(exchanges.size() == 1); var point = metadataPlacement(variant, exchanges.getFirst().metadata());
                if (point != null) require(coveredPoints.add(point));
                evidence.addAll(exchanges.getFirst().evidence());
            }
            var peer = collected.exchanges().getFirst().metadata().getAttribute("entityID");
            stage = "affiliation_prepared_original";
            var prepared = entries.get(receipt.path("preparedReference").asText());
            require(prepared != null && prepared.direction() == Direction.OUTBOUND && Integer.valueOf(200).equals(prepared.status())
                    && "MetadataPrepared".equals(prepared.samlSummary().get("type")) && VARIANT.equals(prepared.samlSummary().get("variant")));
            require("PREPARED".equals(prepared.samlSummary().get("delivery")));
            var fetch = entries.get(prepared.samlSummary().get("fetchTranscriptId"));
            require(fetch != null && fetch.direction() == Direction.INBOUND && Integer.valueOf(200).equals(fetch.status())
                    && "MetadataFetch".equals(fetch.samlSummary().get("type")) && VARIANT.equals(fetch.samlSummary().get("variant"))
                    && prepared.correlationId().equals(fetch.id()) && prepared.url().equals(fetch.url()) && !prepared.timestamp().isBefore(fetch.timestamp()));
            var original = content.readDecodedSaml(prepared);
            require(original.length == prepared.decodedSamlBytes()
                    && sha(original).equals(prepared.samlSummary().get("metadataSha256")) && sha(original).equals(receipt.path("inputSha256").asText())
                    && Arrays.equals(original, file(context.runId(), "input.xml", receipt.path("files"))));
            var xml = SecureXml.parse(original).getDocumentElement();
            require(MD.equals(xml.getNamespaceURI()) && "EntitiesDescriptor".equals(xml.getLocalName())
                    && SamlSchemaValidation.validationFailure(xml, SamlSchemaValidation.SchemaKind.METADATA).isEmpty());
            var entities = children(xml, MD, "EntityDescriptor"); require(entities.size() == 2 && peer.equals(entities.getFirst().getAttribute("entityID")));
            var signatures = children(xml, DS, "Signature"); require(signatures.size() == 1);
            var certs = signatures.getFirst().getElementsByTagNameNS(DS, "X509Certificate"); require(certs.getLength() == 1);
            var cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                    new ByteArrayInputStream(Base64.getMimeDecoder().decode(certs.item(0).getTextContent())));
            require(new XmlSignatureVerifier().hasValidEnvelopedSignature(xml, cert));
            var affiliations = children(entities.get(1), MD, "AffiliationDescriptor"); require(affiliations.size() == 1);
            var affiliation = affiliations.getFirst();
            require("ignored-content".equals(affiliation.getAttributeNS(FOREIGN, "undefined"))
                    && children(affiliation, MD, "AffiliateMember").size() == 1
                    && peer.equals(children(affiliation, MD, "AffiliateMember").getFirst().getTextContent()));
            require(coveredPoints.add(new QName(MD, "AffiliationDescriptor"))
                    && coveredPoints.equals(SamlExtensionAttributePoints.inventory().stream()
                        .map(SamlExtensionAttributePoints.Point::element).collect(java.util.stream.Collectors.toSet())));
            var control = file(context.runId(), "control.xml", receipt.path("files"));
            stage = "exact_parser_control";
            // This narrow parser control changes exactly one attribute. It does not claim signature validation.
            var literal = " foreign:undefined=\"ignored-content\"";
            var text = new String(original, StandardCharsets.UTF_8);
            require(text.indexOf(literal) >= 0 && text.indexOf(literal) == text.lastIndexOf(literal)
                    && Arrays.equals(control, text.replace(literal, "").getBytes(StandardCharsets.UTF_8))
                    && SamlSchemaValidation.validationFailure(SecureXml.parse(control).getDocumentElement(), SamlSchemaValidation.SchemaKind.METADATA).isEmpty());
            var invocation = original(receipt.path("invocation"), context.runId(), targetHash, entries, evidence);
            stage = "native_invocation_original";
            require("samlscope-native-affiliation-parser-invocation-v1".equals(invocation.json().path("schema").asText())
                    && receipt.path("profile").equals(invocation.json().path("profile"))
                    && sha(original).equals(invocation.json().path("inputSha256").asText())
                    && sha(control).equals(invocation.json().path("controlSha256").asText())
                    && "org.keycloak.saml.processing.core.parsers.saml.SAMLParser#parse(XMLEventReader)".equals(invocation.json().path("nativeMethod").asText())
                    && invocation.json().path("exitCode").isInt() && invocation.json().path("exitCode").asInt() == 0
                    && !invocation.entry().timestamp().isBefore(prepared.timestamp())
                    && !Instant.parse(invocation.json().path("startedAt").asText()).isBefore(prepared.timestamp())
                    && !Instant.parse(invocation.json().path("finishedAt").asText()).isBefore(Instant.parse(invocation.json().path("startedAt").asText()))
                    && !invocation.entry().timestamp().isBefore(Instant.parse(invocation.json().path("finishedAt").asText()))
                    && Instant.parse(xml.getAttribute("validUntil")).isAfter(Instant.parse(invocation.json().path("finishedAt").asText())));
            var processOutput = JSON.readTree(file(context.runId(), "native-output.json", receipt.path("files")));
            for (var name : List.of("nativeMethod", "inputSha256", "controlSha256", "inputTreeBase64", "controlTreeBase64",
                    "inputRootType", "controlRootType", "inputEntityIds", "controlEntityIds",
                    "inputAffiliationDescriptorPresent", "controlAffiliationDescriptorPresent",
                    "nativeJars", "startedAt", "finishedAt", "exitCode"))
                require(processOutput.path(name).equals(invocation.json().path(name)));
            stage = "native_runtime_identity";
            var urls = new ArrayList<java.net.URL>();
            for (var jar : KeycloakNativeSchemaAdmissionEvidence.NATIVE_JARS.entrySet()) {
                var raw = file(context.runId(), jar.getKey(), receipt.path("files")); require(sha(raw).equals(jar.getValue()));
                if (!jar.getKey().contains("services")) urls.add(directory.resolve(context.runId() + ".extension-attribute-parser").resolve(jar.getKey()).toUri().toURL());
            }
            require(invocation.json().path("nativeJars").equals(JSON.valueToTree(KeycloakNativeSchemaAdmissionEvidence.NATIVE_JARS))
                    && invocation.json().path("runtimeBefore").equals(invocation.json().path("runtimeAfter"))
                    && "sha256:9d1f1b2b7261ff53c66cb1092dfcdc34a5fb77e81f9e6a6e75b8b6a795de8067".equals(invocation.json().path("runtimeBefore").path("image").asText())
                    && invocation.json().path("runtimeBefore").path("running").asBoolean()
                    && invocation.json().path("runtimeBefore").path("containerId").asText().matches("[0-9a-f]{64}"));
            try (var loader = new URLClassLoader(urls.toArray(java.net.URL[]::new), ClassLoader.getPlatformClassLoader())) {
                stage = "full_native_parser_replay";
                var actual = NativeMetadataParserProjection.observe(loader, original);
                var baseline = NativeMetadataParserProjection.observe(loader, control);
                require(actual.equals(baseline)
                        && actual.entityIds().equals(entities.stream().map(entity -> entity.getAttribute("entityID")).toList())
                        && actual.affiliationDescriptorPresent().equals(List.of(false, false))
                        && JSON.valueToTree(actual.entityIds()).equals(invocation.json().path("inputEntityIds"))
                        && JSON.valueToTree(baseline.entityIds()).equals(invocation.json().path("controlEntityIds"))
                        && actual.rootType().equals(invocation.json().path("inputRootType").asText())
                        && baseline.rootType().equals(invocation.json().path("controlRootType").asText())
                        && JSON.valueToTree(actual.affiliationDescriptorPresent()).equals(invocation.json().path("inputAffiliationDescriptorPresent"))
                        && JSON.valueToTree(baseline.affiliationDescriptorPresent()).equals(invocation.json().path("controlAffiliationDescriptorPresent"))
                        && actual.tree().equals(new String(Base64.getDecoder().decode(invocation.json().path("inputTreeBase64").asText()), StandardCharsets.UTF_8))
                        && baseline.tree().equals(new String(Base64.getDecoder().decode(invocation.json().path("controlTreeBase64").asText()), StandardCharsets.UTF_8)));
            }
            evidence.add(new EvidenceRef("transcript", fetch.id())); evidence.add(new EvidenceRef("transcript", prepared.id()));
            evidence.add(new EvidenceRef("native-extension-attribute-parser-evidence", context.runId() + SUFFIX + "#" + sha(receiptBytes)));
            return new CaseOutcome(Outcome.SATISFIED, null, "browser_fixture_satisfied", "case.idp.browser-fixture.satisfied",
                    evidence.stream().distinct().toList(), Map.of("native_affiliation_parser_verified", true,
                            "metadata_attribute_matrix_complete", true, "source_run_id", context.runId(),
                            "parser_scope", "foreign-attribute-affiliation", "native_parser_replayed", true,
                            "affiliation_descriptor_absent_in_both_native_trees", true, "aggregate_import_client_acceptance_claimed", false));
        } catch (Exception unavailable) {
            return new CaseOutcome(Outcome.NOT_VERIFIED, "extension_attribute_parser_original_unproven", "browser_fixture_partial",
                    "browser_fixture_partial", List.of(), Map.of("unproven_stage", stage));
        }
    }
}
