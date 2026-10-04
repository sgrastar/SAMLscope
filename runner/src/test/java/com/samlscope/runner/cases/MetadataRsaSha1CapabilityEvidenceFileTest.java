package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseStep;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.TranscriptEntry;
import com.samlscope.core.transcript.TranscriptInput;
import com.samlscope.core.transcript.TranscriptRecorder;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Element;

class MetadataRsaSha1CapabilityEvidenceFileTest {
    private static final String RUN = "run_0123456789ABCDEFGHJKMNPQRS";
    private static final String ENTITY = "http://localhost:18380/idp";
    private static final String DS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String RSA_SHA1 = DS + "rsa-sha1";
    private static final String RESOURCE = "/com/samlscope/runner/cases/rsa-sha1/";
    private static final String TEST_IMAGE = "sha256:" + "1".repeat(64);
    private static final byte[] SIGNER_SOURCE = ("<?php\n"
            + "$algorithm = $config->getOptionalString('metadata.sign.algorithm', XMLSecurityKey::RSA_SHA256);\n"
            + "$supported = [XMLSecurityKey::RSA_SHA1, XMLSecurityKey::RSA_SHA256];\n").getBytes(StandardCharsets.UTF_8);
    private static final byte[] PARSER_SOURCE = ("<?php\n"
            + "public function validateSignature(array $certificates): bool {\n"
            + "  foreach ($certificates as $certificate) { if ($validator->validate($key)) return true; }\n"
            + "  return false;\n}\n").getBytes(StandardCharsets.UTF_8);
    private static final byte[] VERSION_SOURCE =
            "<?php public const string VERSION = '2.5.0';\n".getBytes(StandardCharsets.UTF_8);
    private static final byte[] VERIFIER_SOURCE =
            "<?php $tamperedAccepted = false; $wrongKeyAccepted = false; $unsignedAccepted = false;\n"
                    .getBytes(StandardCharsets.UTF_8);
    private static final byte[] KEYCLOAK_VERIFIER_SOURCE = ("class Probe {\n"
            + "  Object algorithm = SignatureAlgorithm.RSA_SHA1;\n"
            + "  Object verifier = new SAML2Signature().validate(input, key);\n"
            + "  boolean tamperedAccepted, wrongKeyAccepted, unsignedAccepted;\n"
            + "}\n").getBytes(StandardCharsets.UTF_8);
    private static final byte[] OVERLAY = ("\n// samlscope-rsa-sha1-capability-probe\n"
            + "$config['metadata.sign.enable'] = true;\n"
            + "$config['metadata.sign.privatekey'] = 'server.pem';\n"
            + "$config['metadata.sign.certificate'] = 'server.crt';\n"
            + "$config['metadata.sign.algorithm'] = '" + RSA_SHA1 + "';\n").getBytes(StandardCharsets.UTF_8);
    private final JsonCodec json = new JsonCodec();

    @TempDir Path temp;

    @Test
    void algorithmTextAloneCannotProveBothApprovedVariants() throws Exception {
        var target = resource("target-metadata.xml");
        var result = evaluate(new MetadataSignatureTestCase(
                MetadataRsaSha1CapabilityEvidenceFile.CASE_ID, ignored -> target));
        assertEquals(Outcome.NOT_VERIFIED, result.outcome());
        assertEquals("rsa_sha1_verification_unproven", result.notVerifiedReason());
        assertEquals("metadata.rsa-sha1.verification-unproven", result.reasonCode());
    }

    @Test
    void exactRunBoundOriginalsAndAllControlsProveBothVariants() throws Exception {
        writeReceipt(validReceipt());
        var result = evaluate(test(resource("target-metadata.xml")));
        assertEquals(Outcome.SATISFIED, result.outcome());
        assertEquals("metadata.rsa-sha1.observed", result.reasonCode());
        assertEquals(true, result.details().get("producer_variant_proven"));
        assertEquals(true, result.details().get("verifier_variant_proven"));
        assertEquals("2.5.0", result.details().get("product_version"));
        assertTrue(String.valueOf(result.details().get("native_receipt_sha256")).matches("[0-9a-f]{64}"));
    }

    @Test
    void scopeIsLimitedToTheApprovedIdpCase() throws Exception {
        var target = resource("target-metadata.xml");
        assertEquals(Outcome.SATISFIED,
                evaluate(new MetadataSignatureTestCase("IIP-MD05-ah-sp-01", ignored -> target)).outcome());
        assertEquals(Outcome.SATISFIED,
                evaluate(new MetadataSignatureTestCase("IIP-MD05-ag-idp-01", ignored -> target)).outcome());
    }

    @Test
    void receiptAndOriginalTamperingFailClosed() throws Exception {
        var mutations = List.<Consumer<ObjectNode>>of(
                value -> value.put("runId", "run_00000000000000000000000000"),
                value -> value.put("targetMetadataSha256", "0".repeat(64)),
                value -> value.put("evidenceAdapter", "suite-native"),
                value -> value.put("unexpected", true),
                value -> value.withObject("/configuration").put("restored", false),
                value -> replaceBlob(value.withObject("/configuration").withObject("/restoredReadBack"), "changed".getBytes()),
                value -> replaceBlob(value.withObject("/runtime").withObject("/signerSource"), "<?php forged".getBytes()),
                value -> replaceBlob(value.withObject("/runtime").withObject("/verifierSource"), "<?php forged".getBytes()),
                value -> value.withObject("/runtime").put("imageId", "sha256:" + "0".repeat(64)),
                value -> mutateObservation(value, observation -> observation.put("positiveAccepted", false)),
                value -> mutateObservation(value, observation -> observation.put("tamperedAccepted", true)),
                value -> mutateObservation(value, observation -> observation.put("wrongKeyAccepted", true)),
                value -> mutateObservation(value, observation -> observation.put("unsignedAccepted", true)),
                value -> mutateObservation(value, observation -> observation.put("tamperedInputSha256", "0".repeat(64))),
                value -> replaceBlob(value.withObject("/wrongCertificate"), resourceUnchecked("target-metadata.xml")),
                value -> value.withObject("/operationCounts").put("humanOperations", 1),
                value -> value.put("nativeVerifierExitCode", 1));
        for (var index = 0; index < mutations.size(); index++) {
            var receipt = validReceipt();
            mutations.get(index).accept(receipt);
            writeReceipt(receipt);
            var result = evaluate(test(resource("target-metadata.xml")));
            assertEquals(Outcome.NOT_VERIFIED, result.outcome(), "mutation " + index);
            assertEquals("rsa_sha1_verification_unproven", result.notVerifiedReason(), "mutation " + index);
        }
    }

    @Test
    void independentlyInvalidSignatureIsRejectedEvenWhenAllReceiptHashesAreRewritten() throws Exception {
        var metadata = resource("target-metadata.xml");
        var altered = new String(metadata, StandardCharsets.UTF_8)
                .replaceFirst("<ds:SignatureValue>.", "<ds:SignatureValue>A")
                .getBytes(StandardCharsets.UTF_8);
        var receipt = validReceipt();
        receipt.put("targetMetadataSha256", hash(altered));
        mutateObservation(receipt, observation -> observation.put("inputSha256", hashUnchecked(altered)));
        writeReceipt(receipt);
        var result = evaluate(test(altered));
        assertEquals(Outcome.NOT_VERIFIED, result.outcome());
        assertEquals("rsa_sha1_verification_unproven", result.notVerifiedReason());
    }

    @Test
    void keycloakNativeSignerAndVerifierWithPolicyControlProveBothVariants() throws Exception {
        writeReceipt(validKeycloakReceipt());
        var result = evaluate(keycloakTest(resource("target-metadata.xml")));
        assertEquals(Outcome.SATISFIED, result.outcome());
        assertEquals("metadata.rsa-sha1.observed", result.reasonCode());
        assertEquals(true, result.details().get("producer_variant_proven"));
        assertEquals(true, result.details().get("verifier_variant_proven"));
        assertEquals("26.7.2", result.details().get("product_version"));
    }

    @Test
    void keycloakReceiptTamperingAndMissingControlsFailClosed() throws Exception {
        var mutations = List.<Consumer<ObjectNode>>of(
                value -> value.withObject("/configuration").put("serverConfigurationUnchanged", false),
                value -> replaceBlob(value.withObject("/configuration").withObject("/defaultSecurityPolicy"),
                        "jdk.xml.dsig.secureValidationPolicy=disallowAlg rsa-sha1\n".getBytes()),
                value -> replaceBlob(value.withObject("/configuration").withObject("/capabilitySecurityPolicy"),
                        "jdk.xml.dsig.secureValidationPolicy=disallowAlg rsa-sha1\n".getBytes()),
                value -> replaceBlob(value.withObject("/runtime").withObject("/coreLibrary"), jar("forged.class")),
                value -> replaceBlob(value.withObject("/runtime").withObject("/verifierSource"),
                        "class Forged {}".getBytes()),
                value -> mutateObservation(value, "defaultPolicyObservation",
                        observation -> observation.put("positiveAccepted", true)),
                value -> mutateObservation(value, "defaultPolicyObservation",
                        observation -> observation.put("positiveError", "")),
                value -> mutateObservation(value, "nativeObservation",
                        observation -> observation.put("positiveAccepted", false)),
                value -> mutateObservation(value, "nativeObservation",
                        observation -> observation.put("tamperedAccepted", true)),
                value -> mutateObservation(value, "nativeObservation",
                        observation -> observation.put("wrongKeyAccepted", true)),
                value -> mutateObservation(value, "nativeObservation",
                        observation -> observation.put("unsignedAccepted", true)),
                value -> mutateObservation(value, "nativeObservation",
                        observation -> observation.put("policyMode", "default")),
                value -> value.withObject("/operationCounts").put("nativeVerificationExecutions", 1),
                value -> value.put("defaultPolicyVerifierExitCode", 2));
        for (var index = 0; index < mutations.size(); index++) {
            var receipt = validKeycloakReceipt();
            mutations.get(index).accept(receipt);
            writeReceipt(receipt);
            var result = evaluate(keycloakTest(resource("target-metadata.xml")));
            assertEquals(Outcome.NOT_VERIFIED, result.outcome(), "Keycloak mutation " + index);
            assertEquals("rsa_sha1_verification_unproven", result.notVerifiedReason(),
                    "Keycloak mutation " + index);
        }
    }

    private MetadataSignatureTestCase test(byte[] target) {
        var identity = new MetadataRsaSha1CapabilityEvidenceFile.ReferenceIdentity(
                TEST_IMAGE, "2.5.0", hashUnchecked(SIGNER_SOURCE), hashUnchecked(PARSER_SOURCE),
                hashUnchecked(VERSION_SOURCE), hashUnchecked(VERIFIER_SOURCE));
        var evidence = new MetadataRsaSha1CapabilityEvidenceFile(
                temp.resolve("metadata-rsa-sha1-evidence"), identity);
        return new MetadataSignatureTestCase(
                MetadataRsaSha1CapabilityEvidenceFile.CASE_ID, ignored -> target, evidence);
    }

    private MetadataSignatureTestCase keycloakTest(byte[] target) {
        var sspIdentity = new MetadataRsaSha1CapabilityEvidenceFile.ReferenceIdentity(
                TEST_IMAGE, "2.5.0", hashUnchecked(SIGNER_SOURCE), hashUnchecked(PARSER_SOURCE),
                hashUnchecked(VERSION_SOURCE), hashUnchecked(VERIFIER_SOURCE));
        var core = keycloakCoreJar();
        var publicApi = jar("org/keycloak/saml/Public.class");
        var keycloakIdentity = new MetadataRsaSha1CapabilityEvidenceFile.KeycloakReferenceIdentity(
                TEST_IMAGE, "26.7.2", hashUnchecked(core), hashUnchecked(publicApi),
                hashUnchecked(KEYCLOAK_VERIFIER_SOURCE));
        var evidence = new MetadataRsaSha1CapabilityEvidenceFile(
                temp.resolve("metadata-rsa-sha1-evidence"), sspIdentity, keycloakIdentity);
        return new MetadataSignatureTestCase(
                MetadataRsaSha1CapabilityEvidenceFile.CASE_ID, ignored -> target, evidence);
    }

    private CaseOutcome evaluate(MetadataSignatureTestCase test) {
        var step = test.start(context());
        return ((CaseStep.Finish) step).outcome();
    }

    private ObjectNode validReceipt() throws Exception {
        var target = resource("target-metadata.xml");
        var signer = SIGNER_SOURCE;
        var parser = PARSER_SOURCE;
        var verifier = VERIFIER_SOURCE;
        var version = VERSION_SOURCE;
        var wrongPem = resource("wrong-certificate.pem");
        var original = "<?php\n$config = [];\n".getBytes(StandardCharsets.UTF_8);
        var configured = new byte[original.length + OVERLAY.length];
        System.arraycopy(original, 0, configured, 0, original.length);
        System.arraycopy(OVERLAY, 0, configured, original.length, OVERLAY.length);
        var targetDocument = SecureXml.parse(target);
        var root = targetDocument.getDocumentElement();
        var certText = ((Element) root.getElementsByTagNameNS(DS, "X509Certificate").item(0)).getTextContent();
        var certDer = Base64.getMimeDecoder().decode(certText);
        var wrong = CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(wrongPem));

        var tamperedDocument = SecureXml.parse(target);
        tamperedDocument.getDocumentElement().setAttribute("entityID", ENTITY + "#tampered");
        var tampered = serialize(tamperedDocument);
        var unsignedDocument = SecureXml.parse(target);
        var signature = unsignedDocument.getDocumentElement().getElementsByTagNameNS(DS, "Signature").item(0);
        signature.getParentNode().removeChild(signature);
        var unsigned = serialize(unsignedDocument);

        var observation = json.mapper().createObjectNode();
        observation.put("schema", "samlscope-simplesamlphp-rsa-sha1-verification-v1");
        observation.put("inputSha256", hash(target));
        observation.put("targetEntityId", ENTITY);
        observation.put("signatureAlgorithm", RSA_SHA1);
        observation.put("trustedCertificateSha256", hash(certDer));
        observation.put("wrongCertificateSha256", hash(wrong.getEncoded()));
        observation.put("tamperedInputBase64", Base64.getEncoder().encodeToString(tampered));
        observation.put("tamperedInputSha256", hash(tampered));
        observation.put("unsignedInputBase64", Base64.getEncoder().encodeToString(unsigned));
        observation.put("unsignedInputSha256", hash(unsigned));
        observation.put("positiveAccepted", true);
        observation.put("tamperedAccepted", false);
        observation.put("wrongKeyAccepted", false);
        observation.put("unsignedAccepted", false);

        var receipt = json.mapper().createObjectNode();
        receipt.put("schema", "samlscope-native-metadata-rsa-sha1-capability-v1");
        receipt.put("runId", RUN);
        receipt.put("caseId", MetadataRsaSha1CapabilityEvidenceFile.CASE_ID);
        receipt.put("targetEntityId", ENTITY);
        receipt.put("targetMetadataSha256", hash(target));
        receipt.put("evidenceAdapter", "simplesamlphp-native");
        var configuration = receipt.putObject("configuration");
        configuration.set("original", blob(original, null));
        configuration.set("configuredReadBack", blob(configured, null));
        configuration.set("restoredReadBack", blob(original, null));
        configuration.put("restored", true);
        var runtime = receipt.putObject("runtime");
        runtime.put("containerName", "samlscope-reference-ssp");
        runtime.put("containerId", "a".repeat(64));
        runtime.put("imageId", TEST_IMAGE);
        runtime.put("startedAt", "2026-09-28T00:50:56.977126300Z");
        runtime.put("runningAtCapture", true);
        runtime.put("productVersion", "2.5.0");
        runtime.set("signerSource", blob(signer, "/var/simplesamlphp/src/SimpleSAML/Metadata/Signer.php"));
        runtime.set("parserSource", blob(parser, "/var/simplesamlphp/src/SimpleSAML/Metadata/SAMLParser.php"));
        runtime.set("verifierSource", blob(verifier, "/tmp/samlscope-rsa-sha1-capability/verifier.php"));
        runtime.set("versionSource", blob(version, "/var/simplesamlphp/src/SimpleSAML/Configuration.php"));
        receipt.set("nativeObservation", blob(json.mapper().writerWithDefaultPrettyPrinter()
                .writeValueAsBytes(observation), null));
        receipt.set("wrongCertificate", blob(wrongPem, null));
        receipt.put("nativeVerifierExitCode", 0);
        receipt.set("nativeVerifierStderr", blob(new byte[0], null));
        var counts = receipt.putObject("operationCounts");
        counts.put("productConfigurationWrites", 2);
        counts.put("productRestarts", 0);
        counts.put("humanOperations", 0);
        counts.put("nativeVerificationExecutions", 1);
        return receipt;
    }

    private ObjectNode validKeycloakReceipt() throws Exception {
        var target = resource("target-metadata.xml");
        var wrongDer = CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(resource("wrong-certificate.pem")))
                .getEncoded();
        var targetDocument = SecureXml.parse(target);
        var root = targetDocument.getDocumentElement();
        var certText = ((Element) root.getElementsByTagNameNS(DS, "X509Certificate").item(0))
                .getTextContent();
        var certDer = Base64.getMimeDecoder().decode(certText);

        var tamperedDocument = SecureXml.parse(target);
        tamperedDocument.getDocumentElement().setAttribute("entityID", ENTITY + "#tampered");
        var tampered = serialize(tamperedDocument);
        var unsignedDocument = SecureXml.parse(target);
        var signature = unsignedDocument.getDocumentElement()
                .getElementsByTagNameNS(DS, "Signature").item(0);
        signature.getParentNode().removeChild(signature);
        var unsigned = serialize(unsignedDocument);

        var defaultObservation = keycloakObservation(target, certDer, wrongDer, tampered, unsigned,
                "default", false,
                "javax.xml.crypto.MarshalException: It is forbidden to use algorithm " + RSA_SHA1
                        + " when secure validation is enabled");
        var capabilityObservation = keycloakObservation(target, certDer, wrongDer, tampered, unsigned,
                "capability", true, "");

        var defaultPolicy = ("jdk.xml.dsig.secureValidationPolicy=disallowAlg " + RSA_SHA1
                + ",disallowAlg " + DS + "sha1\n").getBytes(StandardCharsets.UTF_8);
        var capabilityPolicy = "jdk.xml.dsig.secureValidationPolicy=\n".getBytes(StandardCharsets.UTF_8);
        var core = keycloakCoreJar();
        var publicApi = jar("org/keycloak/saml/Public.class");

        var receipt = json.mapper().createObjectNode();
        receipt.put("schema", "samlscope-native-metadata-rsa-sha1-capability-v1");
        receipt.put("runId", RUN);
        receipt.put("caseId", MetadataRsaSha1CapabilityEvidenceFile.CASE_ID);
        receipt.put("targetEntityId", ENTITY);
        receipt.put("targetMetadataSha256", hash(target));
        receipt.put("evidenceAdapter", "keycloak-native-jvm");
        var configuration = receipt.putObject("configuration");
        configuration.set("defaultSecurityPolicy", blob(defaultPolicy, null));
        configuration.set("capabilitySecurityPolicy", blob(capabilityPolicy, null));
        configuration.put("serverConfigurationUnchanged", true);
        var runtime = receipt.putObject("runtime");
        runtime.put("containerName", "samlscope-reference-keycloak");
        runtime.put("containerId", "b".repeat(64));
        runtime.put("imageId", TEST_IMAGE);
        runtime.put("startedAt", "2026-09-30T00:50:56.977126300Z");
        runtime.put("runningAtCapture", true);
        runtime.put("productVersion", "26.7.2");
        runtime.set("coreLibrary", blob(core,
                "/opt/keycloak/lib/lib/main/org.keycloak.keycloak-saml-core-26.7.2.jar"));
        runtime.set("publicLibrary", blob(publicApi,
                "/opt/keycloak/lib/lib/main/org.keycloak.keycloak-saml-core-public-26.7.2.jar"));
        runtime.set("verifierSource", blob(KEYCLOAK_VERIFIER_SOURCE,
                "/tmp/samlscope-keycloak-rsa-sha1-capability/KeycloakRsaSha1MetadataCapability.java"));
        receipt.set("defaultPolicyObservation", blob(json.mapper().writerWithDefaultPrettyPrinter()
                .writeValueAsBytes(defaultObservation), null));
        receipt.put("defaultPolicyVerifierExitCode", 0);
        receipt.set("defaultPolicyVerifierStderr", blob("default policy diagnostic".getBytes(), null));
        receipt.set("nativeObservation", blob(json.mapper().writerWithDefaultPrettyPrinter()
                .writeValueAsBytes(capabilityObservation), null));
        receipt.set("wrongCertificate", blob(wrongDer, null));
        receipt.put("nativeVerifierExitCode", 0);
        receipt.set("nativeVerifierStderr", blob(new byte[0], null));
        var counts = receipt.putObject("operationCounts");
        counts.put("productConfigurationWrites", 0);
        counts.put("productRestarts", 0);
        counts.put("humanOperations", 0);
        counts.put("nativeVerificationExecutions", 2);
        return receipt;
    }

    private ObjectNode keycloakObservation(byte[] target, byte[] trustedDer, byte[] wrongDer,
            byte[] tampered, byte[] unsigned, String policyMode, boolean positiveAccepted,
            String positiveError) throws Exception {
        var observation = json.mapper().createObjectNode();
        observation.put("schema", "samlscope-keycloak-rsa-sha1-verification-v1");
        observation.put("policyMode", policyMode);
        observation.put("inputSha256", hash(target));
        observation.put("targetEntityId", ENTITY);
        observation.put("signatureAlgorithm", RSA_SHA1);
        observation.put("trustedCertificateSha256", hash(trustedDer));
        observation.put("wrongCertificateSha256", hash(wrongDer));
        observation.put("tamperedInputBase64", Base64.getEncoder().encodeToString(tampered));
        observation.put("tamperedInputSha256", hash(tampered));
        observation.put("unsignedInputBase64", Base64.getEncoder().encodeToString(unsigned));
        observation.put("unsignedInputSha256", hash(unsigned));
        observation.put("positiveAccepted", positiveAccepted);
        observation.put("positiveError", positiveError);
        observation.put("tamperedAccepted", false);
        observation.put("wrongKeyAccepted", false);
        observation.put("unsignedAccepted", false);
        return observation;
    }

    private static byte[] keycloakCoreJar() {
        return jar(
                "org/keycloak/saml/SignatureAlgorithm.class",
                "org/keycloak/rotation/KeyLocator.class",
                "org/keycloak/saml/processing/api/saml/v2/sig/SAML2Signature.class",
                "org/keycloak/saml/processing/core/saml/v2/util/DocumentUtil.class");
    }

    private static byte[] jar(String... entries) {
        try {
            var output = new ByteArrayOutputStream();
            try (var jar = new JarOutputStream(output)) {
                for (var name : entries) {
                    jar.putNextEntry(new JarEntry(name));
                    jar.write(name.getBytes(StandardCharsets.UTF_8));
                    jar.closeEntry();
                }
            }
            return output.toByteArray();
        } catch (Exception failure) {
            throw new AssertionError(failure);
        }
    }

    private ObjectNode blob(byte[] value, String path) throws Exception {
        var result = json.mapper().createObjectNode();
        result.put("base64", Base64.getEncoder().encodeToString(value));
        result.put("sha256", hash(value));
        if (path != null) result.put("path", path);
        return result;
    }

    private static void replaceBlob(ObjectNode blob, byte[] value) {
        blob.put("base64", Base64.getEncoder().encodeToString(value));
        blob.put("sha256", hashUnchecked(value));
    }

    private void mutateObservation(ObjectNode receipt, Consumer<ObjectNode> change) {
        mutateObservation(receipt, "nativeObservation", change);
    }

    private void mutateObservation(ObjectNode receipt, String field, Consumer<ObjectNode> change) {
        try {
            var raw = Base64.getDecoder().decode(receipt.path(field).path("base64").asText());
            var observation = (ObjectNode) json.mapper().readTree(raw);
            change.accept(observation);
            replaceBlob(receipt.withObject("/" + field),
                    json.mapper().writerWithDefaultPrettyPrinter().writeValueAsBytes(observation));
        } catch (Exception failure) {
            throw new AssertionError(failure);
        }
    }

    private void writeReceipt(ObjectNode receipt) throws Exception {
        var directory = temp.resolve("metadata-rsa-sha1-evidence");
        Files.createDirectories(directory);
        Files.write(directory.resolve(RUN + ".json"), json.mapper().writerWithDefaultPrettyPrinter()
                .writeValueAsBytes(receipt));
    }

    private byte[] resource(String name) throws Exception {
        try (var input = getClass().getResourceAsStream(RESOURCE + name)) {
            if (input == null) throw new IllegalArgumentException("Missing test resource " + name);
            return input.readAllBytes();
        }
    }

    private byte[] resourceUnchecked(String name) {
        try { return resource(name); }
        catch (Exception failure) { throw new AssertionError(failure); }
    }

    private byte[] serialize(org.w3c.dom.Document document) throws Exception {
        var transformer = TransformerFactory.newInstance().newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
        transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
        var output = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(output));
        return output.toByteArray();
    }

    private String hash(byte[] value) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
    }

    private static String hashUnchecked(byte[] value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value)); }
        catch (Exception impossible) { throw new IllegalStateException(impossible); }
    }

    private DefaultCaseContext context() {
        return new DefaultCaseContext(RUN, TargetRole.IDP,
                Clock.fixed(Instant.parse("2026-09-30T00:00:00Z"), ZoneOffset.UTC),
                TestPlan.Parameters.defaults(), TestPlan.Interaction.defaults(), Reachability.CONFIRMED,
                new TranscriptRecorder() {
                    @Override public TranscriptEntry record(TranscriptInput input) { throw new AssertionError(); }
                    @Override public TranscriptEntry updateSamlAnalysis(
                            String id, String correlationId, Map<String, Object> samlSummary) {
                        throw new AssertionError();
                    }
                    @Override public List<TranscriptEntry> list(String runId) { return List.of(); }
                }, true);
    }
}
