package com.samlscope.runner.cases;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.jar.JarInputStream;
import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import org.w3c.dom.Element;

/**
 * Reads local, Run-bound proof for both approved MD05.ah variants.
 *
 * <p>The target metadata is independently verified as a real RSA-SHA1 signature. The receipt must
 * also carry the product configuration before, during and after the probe, the exact native
 * verifier and product sources, and the original inputs/results for positive, tampered-content,
 * wrong-key and unsigned controls. A mere algorithm URI in metadata never proves this case.</p>
 */
final class MetadataRsaSha1CapabilityEvidenceFile {
    static final String CASE_ID = "IIP-MD05-ah-idp-01";
    private static final String SCHEMA = "samlscope-native-metadata-rsa-sha1-capability-v1";
    private static final String SSP_OBSERVATION_SCHEMA = "samlscope-simplesamlphp-rsa-sha1-verification-v1";
    private static final String SSP_ADAPTER = "simplesamlphp-native";
    private static final String SSP_CONTAINER = "samlscope-reference-ssp";
    private static final String SIGNER_PATH = "/var/simplesamlphp/src/SimpleSAML/Metadata/Signer.php";
    private static final String PARSER_PATH = "/var/simplesamlphp/src/SimpleSAML/Metadata/SAMLParser.php";
    private static final String VERSION_PATH = "/var/simplesamlphp/src/SimpleSAML/Configuration.php";
    private static final String VERIFIER_PATH = "/tmp/samlscope-rsa-sha1-capability/verifier.php";
    private static final ReferenceIdentity SSP_REFERENCE = new ReferenceIdentity(
            "sha256:9ae050473c68ce13c5451839cb64257eaa17be3a4d2c9a3f87996bbe0cebb0aa",
            "2.5.0",
            "b58d46886406d2fc58f4e05cf3eddc9f39d3d5545ae7aaeffd84b29a36bab4c4",
            "8620bb26fd41d2be29d2611883839a4cfde0b6c8458c274e2d40a002678fd93d",
            "53837359cd60433082d3968843605a864bab97f23be482447bcfef37e7f6946e",
            "5f6a92c2d3af39391dbb7e7e063ae16ea7240ff4045d81562397159690803d20");
    private static final String KEYCLOAK_ADAPTER = "keycloak-native-jvm";
    private static final String KEYCLOAK_OBSERVATION_SCHEMA = "samlscope-keycloak-rsa-sha1-verification-v1";
    private static final String KEYCLOAK_CONTAINER = "samlscope-reference-keycloak";
    private static final String KEYCLOAK_CORE_PATH =
            "/opt/keycloak/lib/lib/main/org.keycloak.keycloak-saml-core-26.7.2.jar";
    private static final String KEYCLOAK_PUBLIC_PATH =
            "/opt/keycloak/lib/lib/main/org.keycloak.keycloak-saml-core-public-26.7.2.jar";
    private static final String KEYCLOAK_VERIFIER_PATH =
            "/tmp/samlscope-keycloak-rsa-sha1-capability/KeycloakRsaSha1MetadataCapability.java";
    private static final byte[] KEYCLOAK_CAPABILITY_POLICY =
            "jdk.xml.dsig.secureValidationPolicy=\n".getBytes(StandardCharsets.UTF_8);
    private static final KeycloakReferenceIdentity KEYCLOAK_REFERENCE = new KeycloakReferenceIdentity(
            "sha256:9d1f1b2b7261ff53c66cb1092dfcdc34a5fb77e81f9e6a6e75b8b6a795de8067",
            "26.7.2",
            "191794d8be9289121c628f5e69380771b67f72ea869207248c2bbda253979e84",
            "e1262687b87e92edb759b02d568fed8518d5e00b32a70749bee61a787178bbb2",
            "2589889c0bf09c720600bcda09a2856dd6cf02bf0fe05b0e882c17de05f22a1e");
    private static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String DS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String RSA_SHA1 = DS + "rsa-sha1";
    private static final String DIGEST_SHA1 = DS + "sha1";
    private static final byte[] OVERLAY = ("\n// samlscope-rsa-sha1-capability-probe\n"
            + "$config['metadata.sign.enable'] = true;\n"
            + "$config['metadata.sign.privatekey'] = 'server.pem';\n"
            + "$config['metadata.sign.certificate'] = 'server.crt';\n"
            + "$config['metadata.sign.algorithm'] = '" + RSA_SHA1 + "';\n").getBytes(StandardCharsets.UTF_8);
    private static final int RECEIPT_LIMIT = 2_097_152;
    private final Path directory;
    private final ReferenceIdentity reference;
    private final KeycloakReferenceIdentity keycloakReference;

    MetadataRsaSha1CapabilityEvidenceFile(Path directory) {
        this(directory, SSP_REFERENCE, KEYCLOAK_REFERENCE);
    }

    MetadataRsaSha1CapabilityEvidenceFile(Path directory, ReferenceIdentity reference) {
        this(directory, reference, KEYCLOAK_REFERENCE);
    }

    MetadataRsaSha1CapabilityEvidenceFile(Path directory, ReferenceIdentity reference,
            KeycloakReferenceIdentity keycloakReference) {
        this.directory = directory == null ? null : directory.toAbsolutePath().normalize();
        this.reference = java.util.Objects.requireNonNull(reference, "reference");
        this.keycloakReference = java.util.Objects.requireNonNull(keycloakReference, "keycloakReference");
    }

    Optional<Proof> read(CaseContext context, byte[] targetMetadata) {
        if (directory == null || targetMetadata == null || targetMetadata.length == 0) return Optional.empty();
        try {
            require(context.runId().matches("run_[0-9A-HJKMNP-TV-Z]{26}"));
            var file = directory.resolve(context.runId() + ".json");
            if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)) return Optional.empty();
            require(Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS));
            require(Files.size(file) > 0 && Files.size(file) <= RECEIPT_LIMIT);
            var before = Files.readAllBytes(file);
            var receipt = new JsonCodec().mapper().readTree(before);
            var adapter = receipt.path("evidenceAdapter").asText();
            if (SSP_ADAPTER.equals(adapter)) {
                requireFields(receipt, Set.of("schema", "runId", "caseId", "targetEntityId",
                        "targetMetadataSha256", "evidenceAdapter", "configuration", "runtime",
                        "nativeObservation", "wrongCertificate", "nativeVerifierExitCode",
                        "nativeVerifierStderr", "operationCounts"));
            } else if (KEYCLOAK_ADAPTER.equals(adapter)) {
                requireFields(receipt, Set.of("schema", "runId", "caseId", "targetEntityId",
                        "targetMetadataSha256", "evidenceAdapter", "configuration", "runtime",
                        "defaultPolicyObservation", "defaultPolicyVerifierExitCode",
                        "defaultPolicyVerifierStderr", "nativeObservation", "wrongCertificate",
                        "nativeVerifierExitCode", "nativeVerifierStderr", "operationCounts"));
            } else if (ShibbolethRsaSha1CapabilityProof.ADAPTER.equals(adapter)) {
                requireFields(receipt, Set.of("schema", "runId", "caseId", "targetEntityId",
                        "targetMetadataSha256", "evidenceAdapter", "configuration", "runtime",
                        "originalUnsignedMetadata", "signerObservation", "signerExitCode", "signerStderr",
                        "nativeObservation", "wrongCertificate", "nativeVerifierExitCode",
                        "nativeVerifierStderr", "operationCounts"));
            } else {
                return Optional.empty();
            }
            require(SCHEMA.equals(receipt.path("schema").asText()));
            require(context.runId().equals(receipt.path("runId").asText()));
            require(CASE_ID.equals(receipt.path("caseId").asText()));
            require(hash(targetMetadata).equals(receipt.path("targetMetadataSha256").asText()));

            var signed = signedMetadata(targetMetadata, receipt.path("targetEntityId").asText());
            if (SSP_ADAPTER.equals(adapter)) {
                verifyConfiguration(receipt.path("configuration"));
                verifyRuntime(receipt.path("runtime"));
                verifyNativeObservation(receipt, targetMetadata, signed);
            } else if (KEYCLOAK_ADAPTER.equals(adapter)) {
                verifyKeycloakConfiguration(receipt.path("configuration"));
                verifyKeycloakRuntime(receipt.path("runtime"));
                verifyKeycloakObservations(receipt, targetMetadata, signed);
            } else {
                ShibbolethRsaSha1CapabilityProof.verify(receipt, targetMetadata);
            }
            verifyOperationCounts(receipt.path("operationCounts"), adapter);

            var after = Files.readAllBytes(file);
            require(Arrays.equals(before, after));
            return Optional.of(new Proof(hash(before), signed.certificateSha256(),
                    receipt.path("runtime").path("productVersion").asText()));
        } catch (Exception unproven) {
            return Optional.empty();
        }
    }

    private SignedMetadata signedMetadata(byte[] raw, String targetEntityId) throws Exception {
        require(!targetEntityId.isBlank());
        var document = SecureXml.parse(raw);
        var root = document.getDocumentElement();
        require(MD.equals(root.getNamespaceURI()) && "EntityDescriptor".equals(root.getLocalName()));
        require(targetEntityId.equals(root.getAttribute("entityID")));
        require(document.getElementsByTagNameNS(DS, "Signature").getLength() == 1);
        var signatures = children(root, DS, "Signature");
        require(signatures.size() == 1);
        var signedInfo = children(signatures.getFirst(), DS, "SignedInfo");
        require(signedInfo.size() == 1);
        var methods = children(signedInfo.getFirst(), DS, "SignatureMethod");
        require(methods.size() == 1 && RSA_SHA1.equals(methods.getFirst().getAttribute("Algorithm")));
        var keyInfos = children(signatures.getFirst(), DS, "KeyInfo");
        require(keyInfos.size() == 1);
        var x509Data = children(keyInfos.getFirst(), DS, "X509Data");
        require(x509Data.size() == 1);
        var values = children(x509Data.getFirst(), DS, "X509Certificate");
        require(values.size() == 1);
        var der = Base64.getMimeDecoder().decode(values.getFirst().getTextContent());
        var certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(der));
        require("RSA".equals(certificate.getPublicKey().getAlgorithm()));
        var verifier = new XmlSignatureVerifier();
        require(verifier.hasValidEnvelopedReferenceDigests(root));
        require(verifier.hasValidEnvelopedSignature(root, certificate));
        return new SignedMetadata(root.getAttribute("entityID"), certificate, hash(der));
    }

    private void verifyConfiguration(JsonNode configuration) throws Exception {
        requireFields(configuration, Set.of("original", "configuredReadBack", "restoredReadBack", "restored"));
        var original = blob(configuration.path("original"), 524_288, false, null);
        var configured = blob(configuration.path("configuredReadBack"), 524_288, false, null);
        var restored = blob(configuration.path("restoredReadBack"), 524_288, false, null);
        require(configuration.path("restored").isBoolean() && configuration.path("restored").asBoolean());
        require(Arrays.equals(original, restored));
        var expected = Arrays.copyOf(original, original.length + OVERLAY.length);
        System.arraycopy(OVERLAY, 0, expected, original.length, OVERLAY.length);
        require(Arrays.equals(expected, configured));
        require(!new String(original, StandardCharsets.UTF_8).contains("samlscope-rsa-sha1-capability-probe"));
    }

    private void verifyRuntime(JsonNode runtime) throws Exception {
        requireFields(runtime, Set.of("containerName", "containerId", "imageId", "startedAt",
                "runningAtCapture", "productVersion", "signerSource", "parserSource",
                "verifierSource", "versionSource"));
        require(SSP_CONTAINER.equals(runtime.path("containerName").asText()));
        require(runtime.path("containerId").asText().matches("[0-9a-f]{64}"));
        require(reference.productImage().equals(runtime.path("imageId").asText()));
        Instant.parse(runtime.path("startedAt").asText());
        require(runtime.path("runningAtCapture").isBoolean() && runtime.path("runningAtCapture").asBoolean());
        require(reference.productVersion().equals(runtime.path("productVersion").asText()));
        var signer = blob(runtime.path("signerSource"), 262_144, true, SIGNER_PATH);
        var parser = blob(runtime.path("parserSource"), 262_144, true, PARSER_PATH);
        var verifier = blob(runtime.path("verifierSource"), 32_768, true, VERIFIER_PATH);
        var version = blob(runtime.path("versionSource"), 262_144, true, VERSION_PATH);
        require(reference.signerSha256().equals(hash(signer)) && reference.parserSha256().equals(hash(parser))
                && reference.verifierSha256().equals(hash(verifier))
                && reference.versionSha256().equals(hash(version)));
        var signerText = new String(signer, StandardCharsets.UTF_8);
        var parserText = new String(parser, StandardCharsets.UTF_8);
        var verifierText = new String(verifier, StandardCharsets.UTF_8);
        var versionText = new String(version, StandardCharsets.UTF_8);
        require(signerText.contains("metadata.sign.algorithm") && signerText.contains("XMLSecurityKey::RSA_SHA1"));
        require(parserText.contains("function validateSignature(array $certificates): bool")
                && parserText.contains("$validator->validate($key)"));
        require(verifierText.contains("tamperedAccepted") && verifierText.contains("wrongKeyAccepted")
                && verifierText.contains("unsignedAccepted"));
        require(versionText.contains("public const string VERSION = '" + reference.productVersion() + "';"));
    }

    private void verifyNativeObservation(JsonNode receipt, byte[] targetMetadata, SignedMetadata signed)
            throws Exception {
        require(receipt.path("nativeVerifierExitCode").isIntegralNumber()
                && receipt.path("nativeVerifierExitCode").asInt(-1) == 0);
        require(blob(receipt.path("nativeVerifierStderr"), 4096, false, null).length == 0);
        var wrongPem = blob(receipt.path("wrongCertificate"), 32_768, false, null);
        var wrong = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(wrongPem));
        require("RSA".equals(wrong.getPublicKey().getAlgorithm()));
        var wrongSha = hash(wrong.getEncoded());
        require(!wrongSha.equals(signed.certificateSha256()));

        var raw = blob(receipt.path("nativeObservation"), 65_536, false, null);
        var observation = new JsonCodec().mapper().readTree(raw);
        requireFields(observation, Set.of("schema", "inputSha256", "targetEntityId",
                "signatureAlgorithm", "trustedCertificateSha256", "wrongCertificateSha256",
                "tamperedInputBase64", "tamperedInputSha256", "unsignedInputBase64",
                "unsignedInputSha256", "positiveAccepted", "tamperedAccepted",
                "wrongKeyAccepted", "unsignedAccepted"));
        require(SSP_OBSERVATION_SCHEMA.equals(observation.path("schema").asText()));
        require(hash(targetMetadata).equals(observation.path("inputSha256").asText()));
        require(signed.entityId().equals(observation.path("targetEntityId").asText()));
        require(RSA_SHA1.equals(observation.path("signatureAlgorithm").asText()));
        require(signed.certificateSha256().equals(observation.path("trustedCertificateSha256").asText()));
        require(wrongSha.equals(observation.path("wrongCertificateSha256").asText()));
        require(observation.path("positiveAccepted").isBoolean() && observation.path("positiveAccepted").asBoolean());
        requireFalse(observation, "tamperedAccepted");
        requireFalse(observation, "wrongKeyAccepted");
        requireFalse(observation, "unsignedAccepted");

        var tampered = controlInput(observation, "tamperedInputBase64", "tamperedInputSha256");
        var tamperedRoot = SecureXml.parse(tampered).getDocumentElement();
        require((signed.entityId() + "#tampered").equals(tamperedRoot.getAttribute("entityID")));
        require(tamperedRoot.getElementsByTagNameNS(DS, "Signature").getLength() == 1);
        require(!new XmlSignatureVerifier().hasValidEnvelopedSignature(tamperedRoot, signed.certificate()));

        var unsigned = controlInput(observation, "unsignedInputBase64", "unsignedInputSha256");
        var unsignedRoot = SecureXml.parse(unsigned).getDocumentElement();
        require(signed.entityId().equals(unsignedRoot.getAttribute("entityID")));
        require(unsignedRoot.getElementsByTagNameNS(DS, "Signature").getLength() == 0);
    }

    private byte[] controlInput(JsonNode observation, String base64Field, String hashField) throws Exception {
        var raw = Base64.getDecoder().decode(observation.path(base64Field).asText());
        require(raw.length > 0 && raw.length <= 65_536);
        require(hash(raw).equals(observation.path(hashField).asText()));
        return raw;
    }

    private void verifyKeycloakConfiguration(JsonNode configuration) throws Exception {
        requireFields(configuration, Set.of("defaultSecurityPolicy", "capabilitySecurityPolicy",
                "serverConfigurationUnchanged"));
        var defaultPolicy = new String(blob(configuration.path("defaultSecurityPolicy"),
                131_072, false, null), StandardCharsets.UTF_8);
        require(defaultPolicy.contains("jdk.xml.dsig.secureValidationPolicy="));
        require(defaultPolicy.contains("disallowAlg " + RSA_SHA1));
        require(defaultPolicy.contains("disallowAlg " + DIGEST_SHA1));
        require(Arrays.equals(KEYCLOAK_CAPABILITY_POLICY,
                blob(configuration.path("capabilitySecurityPolicy"), 1024, false, null)));
        require(configuration.path("serverConfigurationUnchanged").isBoolean()
                && configuration.path("serverConfigurationUnchanged").asBoolean());
    }

    private void verifyKeycloakRuntime(JsonNode runtime) throws Exception {
        requireFields(runtime, Set.of("containerName", "containerId", "imageId", "startedAt",
                "runningAtCapture", "productVersion", "coreLibrary", "publicLibrary",
                "verifierSource"));
        require(KEYCLOAK_CONTAINER.equals(runtime.path("containerName").asText()));
        require(runtime.path("containerId").asText().matches("[0-9a-f]{64}"));
        require(keycloakReference.productImage().equals(runtime.path("imageId").asText()));
        Instant.parse(runtime.path("startedAt").asText());
        require(runtime.path("runningAtCapture").isBoolean()
                && runtime.path("runningAtCapture").asBoolean());
        require(keycloakReference.productVersion().equals(runtime.path("productVersion").asText()));
        var core = blob(runtime.path("coreLibrary"), 700_000, true, KEYCLOAK_CORE_PATH);
        var publicApi = blob(runtime.path("publicLibrary"), 350_000, true, KEYCLOAK_PUBLIC_PATH);
        var verifier = blob(runtime.path("verifierSource"), 65_536, true, KEYCLOAK_VERIFIER_PATH);
        require(keycloakReference.coreLibrarySha256().equals(hash(core))
                && keycloakReference.publicLibrarySha256().equals(hash(publicApi))
                && keycloakReference.verifierSha256().equals(hash(verifier)));
        var entries = new HashSet<String>();
        try (var jar = new JarInputStream(new ByteArrayInputStream(core))) {
            for (var entry = jar.getNextJarEntry(); entry != null; entry = jar.getNextJarEntry()) {
                entries.add(entry.getName());
            }
        }
        require(entries.containsAll(Set.of(
                "org/keycloak/saml/SignatureAlgorithm.class",
                "org/keycloak/rotation/KeyLocator.class",
                "org/keycloak/saml/processing/api/saml/v2/sig/SAML2Signature.class",
                "org/keycloak/saml/processing/core/saml/v2/util/DocumentUtil.class")));
        var source = new String(verifier, StandardCharsets.UTF_8);
        require(source.contains("SignatureAlgorithm.RSA_SHA1")
                && source.contains("new SAML2Signature().validate")
                && source.contains("tamperedAccepted")
                && source.contains("wrongKeyAccepted")
                && source.contains("unsignedAccepted"));
    }

    private void verifyKeycloakObservations(JsonNode receipt, byte[] targetMetadata,
            SignedMetadata signed) throws Exception {
        require(receipt.path("defaultPolicyVerifierExitCode").isIntegralNumber()
                && receipt.path("defaultPolicyVerifierExitCode").asInt(-1) == 0);
        require(receipt.path("nativeVerifierExitCode").isIntegralNumber()
                && receipt.path("nativeVerifierExitCode").asInt(-1) == 0);
        blob(receipt.path("defaultPolicyVerifierStderr"), 16_384, false, null);
        blob(receipt.path("nativeVerifierStderr"), 16_384, false, null);
        var wrongDer = blob(receipt.path("wrongCertificate"), 32_768, false, null);
        var wrong = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(wrongDer));
        require("RSA".equals(wrong.getPublicKey().getAlgorithm()));
        var wrongSha = hash(wrong.getEncoded());
        require(!wrongSha.equals(signed.certificateSha256()));

        var defaultObservation = keycloakObservation(receipt.path("defaultPolicyObservation"),
                "default", false, targetMetadata, signed, wrongSha);
        require(defaultObservation.error().contains("It is forbidden to use algorithm " + RSA_SHA1)
                && defaultObservation.error().contains("secure validation is enabled"));
        var capabilityObservation = keycloakObservation(receipt.path("nativeObservation"),
                "capability", true, targetMetadata, signed, wrongSha);
        require(capabilityObservation.error().isEmpty());
        require(Arrays.equals(defaultObservation.tampered(), capabilityObservation.tampered()));
        require(Arrays.equals(defaultObservation.unsigned(), capabilityObservation.unsigned()));

        var tamperedRoot = SecureXml.parse(capabilityObservation.tampered()).getDocumentElement();
        require((signed.entityId() + "#tampered").equals(tamperedRoot.getAttribute("entityID")));
        require(tamperedRoot.getElementsByTagNameNS(DS, "Signature").getLength() == 1);
        require(!new XmlSignatureVerifier().hasValidEnvelopedSignature(tamperedRoot, signed.certificate()));
        var unsignedRoot = SecureXml.parse(capabilityObservation.unsigned()).getDocumentElement();
        require(signed.entityId().equals(unsignedRoot.getAttribute("entityID")));
        require(unsignedRoot.getElementsByTagNameNS(DS, "Signature").getLength() == 0);
    }

    private KeycloakObservation keycloakObservation(JsonNode blob, String policyMode,
            boolean positiveAccepted, byte[] targetMetadata, SignedMetadata signed, String wrongSha)
            throws Exception {
        var observation = new JsonCodec().mapper().readTree(blob(blob, 131_072, false, null));
        requireFields(observation, Set.of("schema", "policyMode", "inputSha256", "targetEntityId",
                "signatureAlgorithm", "trustedCertificateSha256", "wrongCertificateSha256",
                "tamperedInputBase64", "tamperedInputSha256", "unsignedInputBase64",
                "unsignedInputSha256", "positiveAccepted", "positiveError", "tamperedAccepted",
                "wrongKeyAccepted", "unsignedAccepted"));
        require(KEYCLOAK_OBSERVATION_SCHEMA.equals(observation.path("schema").asText()));
        require(policyMode.equals(observation.path("policyMode").asText()));
        require(hash(targetMetadata).equals(observation.path("inputSha256").asText()));
        require(signed.entityId().equals(observation.path("targetEntityId").asText()));
        require(RSA_SHA1.equals(observation.path("signatureAlgorithm").asText()));
        require(signed.certificateSha256().equals(observation.path("trustedCertificateSha256").asText()));
        require(wrongSha.equals(observation.path("wrongCertificateSha256").asText()));
        require(observation.path("positiveAccepted").isBoolean()
                && observation.path("positiveAccepted").asBoolean() == positiveAccepted);
        require(observation.path("positiveError").isTextual());
        requireFalse(observation, "tamperedAccepted");
        requireFalse(observation, "wrongKeyAccepted");
        requireFalse(observation, "unsignedAccepted");
        return new KeycloakObservation(
                controlInput(observation, "tamperedInputBase64", "tamperedInputSha256"),
                controlInput(observation, "unsignedInputBase64", "unsignedInputSha256"),
                observation.path("positiveError").asText());
    }

    private void verifyOperationCounts(JsonNode counts, String adapter) {
        requireFields(counts, Set.of("productConfigurationWrites", "productRestarts",
                "humanOperations", "nativeVerificationExecutions"));
        var expectedWrites = SSP_ADAPTER.equals(adapter) ? 2 : 0;
        var expectedExecutions = SSP_ADAPTER.equals(adapter) ? 1 : 2;
        require(counts.path("productConfigurationWrites").isIntegralNumber()
                && counts.path("productConfigurationWrites").asInt(-1) == expectedWrites);
        require(counts.path("productRestarts").isIntegralNumber() && counts.path("productRestarts").asInt(-1) == 0);
        require(counts.path("humanOperations").isIntegralNumber() && counts.path("humanOperations").asInt(-1) == 0);
        require(counts.path("nativeVerificationExecutions").isIntegralNumber()
                && counts.path("nativeVerificationExecutions").asInt(-1) == expectedExecutions);
    }

    private byte[] blob(JsonNode node, int limit, boolean hasPath, String expectedPath) throws Exception {
        requireFields(node, hasPath ? Set.of("base64", "sha256", "path") : Set.of("base64", "sha256"));
        if (hasPath) require(expectedPath.equals(node.path("path").asText()));
        var raw = Base64.getDecoder().decode(node.path("base64").asText());
        require(raw.length <= limit && hash(raw).equals(node.path("sha256").asText()));
        return raw;
    }

    private static List<Element> children(Element parent, String namespace, String localName) {
        var result = new ArrayList<Element>();
        for (var child = parent.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (child instanceof Element element && namespace.equals(element.getNamespaceURI())
                    && localName.equals(element.getLocalName())) result.add(element);
        }
        return result;
    }

    private static void requireFields(JsonNode node, Set<String> expected) {
        require(node.isObject());
        var actual = new HashSet<String>();
        node.fieldNames().forEachRemaining(actual::add);
        require(actual.equals(expected));
    }

    private static void requireFalse(JsonNode node, String field) {
        require(node.path(field).isBoolean() && !node.path(field).asBoolean(true));
    }

    private static String hash(byte[] value) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
    }

    private static void require(boolean value) {
        if (!value) throw new IllegalArgumentException("RSA-SHA1 capability evidence unproven");
    }

    record Proof(String receiptSha256, String signingCertificateSha256, String productVersion) {}
    record ReferenceIdentity(String productImage, String productVersion, String signerSha256,
            String parserSha256, String versionSha256, String verifierSha256) {}
    record KeycloakReferenceIdentity(String productImage, String productVersion,
            String coreLibrarySha256, String publicLibrarySha256, String verifierSha256) {}
    private record KeycloakObservation(byte[] tampered, byte[] unsigned, String error) {}
    private record SignedMetadata(String entityId, X509Certificate certificate, String certificateSha256) {}
}
