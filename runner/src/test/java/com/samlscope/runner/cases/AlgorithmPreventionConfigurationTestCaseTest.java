package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseState;
import com.samlscope.core.caseexec.CaseStep;
import com.samlscope.core.caseexec.TestCase;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.Direction;
import com.samlscope.core.transcript.TranscriptEntry;
import com.samlscope.core.transcript.TranscriptInput;
import com.samlscope.core.transcript.TranscriptRecorder;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.saml.crypto.FilePlanKeyStore;
import com.samlscope.saml.crypto.PlanCredentials;
import com.samlscope.saml.crypto.SamlEncryptionFixtureFactory;
import com.samlscope.saml.crypto.XmlSigner;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Element;

class AlgorithmPreventionConfigurationTestCaseTest {
    private static final String RUN = "run_0123456789ABCDEFGHJKMNPQRS";
    private static final String OTHER_RUN = "run_00000000000000000000000000";
    private static final String PLAN = "plan_0123456789ABCDEFGHJKMNPQRS";
    private static final String PROFILE = "browser_sso_idp";
    private static final String TARGET = "https://idp.example";
    private static final String SUITE = "https://suite.example/sp";
    private static final String ACS = "https://suite.example/acs";
    private static final String P = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
    private static final String S = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String IMAGE = "sha256:" + "1".repeat(64);
    private static final Instant NOW = Instant.parse("2026-09-30T01:00:00Z");
    private static final byte[] ORIGINAL_GLOBAL = ("<?xml version='1.0'?><beans xmlns='http://www.springframework.org/schema/beans' "
            + "xmlns:util='http://www.springframework.org/schema/util' xmlns:p='http://www.springframework.org/schema/p'>\n</beans>\n")
            .getBytes(StandardCharsets.UTF_8);
    private static final byte[] ORIGINAL_RELYING = ("<?xml version='1.0'?><beans xmlns='http://www.springframework.org/schema/beans' "
            + "xmlns:util='http://www.springframework.org/schema/util' xmlns:p='http://www.springframework.org/schema/p'>\n"
            + "<bean id=\"shibboleth.DefaultRelyingParty\" parent=\"RelyingParty\"></bean>\n</beans>\n")
            .getBytes(StandardCharsets.UTF_8);
    private static final byte[] ORIGINAL_PROVIDERS = ("<?xml version='1.0'?><MetadataProvider xmlns='urn:mace:shibboleth:2.0:metadata' "
            + "xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' id='root'>\n"
            + "<MetadataProvider id='nested'></MetadataProvider>\n</MetadataProvider>\n").getBytes(StandardCharsets.UTF_8);

    @TempDir Path temp;
    private final JsonCodec json = new JsonCodec();
    private final List<TranscriptEntry> entries = new ArrayList<>();
    private final Map<String, byte[]> bodies = new HashMap<>();
    private PlanCredentials suite;
    private PlanCredentials target;
    private byte[] targetMetadata;
    private byte[] suiteMetadata;

    @BeforeEach
    void setUp() throws Exception {
        var keyStore = new FilePlanKeyStore(temp, Clock.fixed(NOW, ZoneOffset.UTC));
        suite = keyStore.getOrCreate(PLAN, "suite");
        target = keyStore.getOrCreate(PLAN, "target");
        targetMetadata = metadata(TARGET, "IDPSSODescriptor", "signing", target);
        suiteMetadata = metadata(SUITE, "SPSSODescriptor", "encryption", suite);
        addExchange(0, SamlEncryptionFixtureFactory.Transport.RSA_1_5);
        addExchange(1, SamlEncryptionFixtureFactory.Transport.RSA_OAEP);
        addExchange(2, SamlEncryptionFixtureFactory.Transport.RSA_1_5);
    }

    @Test
    void exactRunBoundAbaEvidenceProvesBothApprovedCases() throws Exception {
        write(validReceipt());
        for (var id : List.of(AlgorithmPreventionEvidenceFile.CASE_A, AlgorithmPreventionEvidenceFile.CASE_B)) {
            var outcome = testCase(id, run -> Optional.of(suite.privateKey())).observe(context(RUN));
            assertEquals(Outcome.SATISFIED, outcome.outcome());
            assertEquals(List.of(AlgorithmPreventionEvidenceFile.RSA15, AlgorithmPreventionEvidenceFile.OAEP,
                    AlgorithmPreventionEvidenceFile.RSA15), outcome.details().get("observed_key_transport_algorithms"));
            assertEquals(6, outcome.evidence().size());
        }
    }

    @Test
    void ecpProfileRequiresIndependentSoapOutboxExchanges() throws Exception {
        for (var index = 3; index < 7; index++)
            addExchange(index, SamlEncryptionFixtureFactory.Transport.RSA_1_5);
        for (var index = 0; index < 7; index++) {
            var requestId = "request-" + index;
            var responseId = "response-" + index;
            bodies.put(requestId, soap(bodies.get(requestId)));
            bodies.put(responseId, soap(bodies.get(responseId)));
            var request = entries.get(index * 2);
            var response = entries.get(index * 2 + 1);
            var endpoint = "https://idp.example/idp/profile/SAML2/SOAP/ECP";
            var correlation = "action-alg08-" + index;
            entries.set(index * 2, replaced(request, endpoint, correlation, "EcpSoapRequest", bodies.get(requestId)));
            entries.set(index * 2 + 1, replaced(response, endpoint, correlation, "EcpSoapResponse", bodies.get(responseId)));
        }
        var receipt = validReceipt();
        receipt.put("profile", "ecp_idp");
        receipt.withObject("/operationCounts").put("protocolOperations", 7);
        write(receipt);
        var reader = new AlgorithmPreventionEvidenceFile(temp.resolve("evidence"),
                entry -> bodies.get(entry.decodedSamlRef()), run -> targetMetadata,
                run -> Optional.of(suite.privateKey()), run -> "ecp_idp",
                new AlgorithmPreventionEvidenceFile.ReferenceIdentity(IMAGE, "5.2.3", "test-shibboleth"));
        var outcome = new AlgorithmPreventionConfigurationTestCase(
                new Fallback(AlgorithmPreventionEvidenceFile.CASE_A), reader).observe(context(RUN));
        assertEquals(Outcome.SATISFIED, outcome.outcome());

        receipt.withObject("/operationCounts").put("protocolOperations", 3);
        write(receipt);
        assertEquals(Outcome.NOT_VERIFIED,
                new AlgorithmPreventionConfigurationTestCase(
                        new Fallback(AlgorithmPreventionEvidenceFile.CASE_A), reader).observe(context(RUN)).outcome());
        receipt.withObject("/operationCounts").put("protocolOperations", 7);
        write(receipt);

        var response = entries.get(1);
        entries.set(1, replaced(response, ACS, response.correlationId(), "Response", bodies.get("response-0")));
        assertEquals(Outcome.NOT_VERIFIED,
                new AlgorithmPreventionConfigurationTestCase(
                        new Fallback(AlgorithmPreventionEvidenceFile.CASE_A), reader).observe(context(RUN)).outcome());
    }

    @Test
    void preventionThatDoesNotChangeSelectionIsAProductViolation() throws Exception {
        entries.clear(); bodies.clear();
        for (var index = 0; index < 3; index++)
            addExchange(index, SamlEncryptionFixtureFactory.Transport.RSA_1_5);
        write(validReceipt());
        assertEquals(Outcome.VIOLATED,
                testCase(AlgorithmPreventionEvidenceFile.CASE_A, run -> Optional.of(suite.privateKey()))
                        .observe(context(RUN)).outcome());
    }

    @Test
    void nativeClientPolicyPreventsConfigurationAndSupportsSetChanges() throws Exception {
        write(validKeycloakReceipt(false));
        for (var id : List.of(AlgorithmPreventionEvidenceFile.CASE_A, AlgorithmPreventionEvidenceFile.CASE_B)) {
            var result = testCase(id, run -> Optional.of(suite.privateKey())).observe(context(RUN));
            assertEquals(Outcome.SATISFIED, result.outcome());
            assertTrue(result.evidence().size() > 14);
        }
    }

    @Test
    void nativePolicyThatStillAllowsThePreventedAlgorithmsIsViolated() throws Exception {
        write(validKeycloakReceipt(true));
        assertEquals(Outcome.VIOLATED, testCase(AlgorithmPreventionEvidenceFile.CASE_A,
                run -> Optional.of(suite.privateKey())).observe(context(RUN)).outcome());
    }

    @Test
    void genericHttpFailureCannotProveNativeAlgorithmPrevention() throws Exception {
        var receipt = validKeycloakReceipt(false);
        var descriptor = receipt.at("/phases/1/clientUpdateOriginal");
        var id = descriptor.path("reference").asText();
        var nativeValue = (ObjectNode) json.mapper().readTree(bodies.get(id));
        nativeValue.withObject("/response").put("error_description", "Unrelated request failure");
        var raw = json.mapper().writeValueAsBytes(nativeValue);
        bodies.put(id, raw);
        ((ObjectNode) descriptor).put("sha256", hash(raw));
        write(receipt);
        assertEquals(Outcome.NOT_VERIFIED, testCase(AlgorithmPreventionEvidenceFile.CASE_A,
                run -> Optional.of(suite.privateKey())).observe(context(RUN)).outcome());
    }

    @Test
    void nativeExplicitConfigurationRejectionCannotHideSuccessfulSamlUse() throws Exception {
        var receipt = validKeycloakReceipt(false);
        addExchange(1, SamlEncryptionFixtureFactory.Transport.RSA_1_5);
        entries.remove(entries.size() - 2); // Keep only the contradictory response.
        write(receipt);
        assertEquals(Outcome.NOT_VERIFIED, testCase(AlgorithmPreventionEvidenceFile.CASE_A,
                run -> Optional.of(suite.privateKey())).observe(context(RUN)).outcome());
    }

    @Test
    void changedNativePolicyWithRecomputedHashStillFailsSemanticValidation() throws Exception {
        var receipt = validKeycloakReceipt(false);
        var descriptor = receipt.at("/phases/1/policiesOriginal");
        var id = descriptor.path("reference").asText();
        var nativeValue = (ObjectNode) json.mapper().readTree(bodies.get(id));
        nativeValue.withArray("/response/policies").removeAll();
        var raw = json.mapper().writeValueAsBytes(nativeValue);
        bodies.put(id, raw);
        ((ObjectNode) descriptor).put("sha256", hash(raw));
        write(receipt);
        assertEquals(Outcome.NOT_VERIFIED, testCase(AlgorithmPreventionEvidenceFile.CASE_B,
                run -> Optional.of(suite.privateKey())).observe(context(RUN)).outcome());
    }

    @Test
    void nativeEcpPolicyRequiresIndependentSoapControlsAndOriginalNativeRejection() throws Exception {
        var receipt = validKeycloakEcpReceipt();
        write(receipt);
        assertEquals(Outcome.SATISFIED, keycloakEcpCase().observe(context(RUN)).outcome());
        // A native policy read-back plus an HTTP/SOAP fault does not replace the
        // explicit configuration rejection required from the product itself.
        ((ObjectNode) receipt.withArray("phases").get(1))
                .set("clientUpdateOriginal", receipt.at("/phases/0/clientUpdateOriginal"));
        write(receipt);
        assertEquals(Outcome.NOT_VERIFIED, keycloakEcpCase().observe(context(RUN)).outcome());
    }

    @Test
    void nativeEcpResponseWithWrongOutboxCorrelationOrMissingOriginalFailsClosed() throws Exception {
        write(validKeycloakEcpReceipt());
        var response = entries.stream().filter(value -> value.id().equals("response-2")).findFirst().orElseThrow();
        var at = entries.indexOf(response);
        entries.set(at, replaced(response, response.url(), "another-outbox-action", "EcpSoapResponse", bodies.get(response.id())));
        assertEquals(Outcome.NOT_VERIFIED, keycloakEcpCase().observe(context(RUN)).outcome());
        entries.set(at, response);
        var raw = bodies.remove("response-1");
        assertEquals(Outcome.NOT_VERIFIED, keycloakEcpCase().observe(context(RUN)).outcome());
        bodies.put("response-1", raw);
        assertEquals(Outcome.SATISFIED, keycloakEcpCase().observe(context(RUN)).outcome());
        assertEquals(Outcome.NOT_VERIFIED, testCase(AlgorithmPreventionEvidenceFile.CASE_A,
                run -> Optional.of(suite.privateKey())).observe(context(RUN)).outcome());
    }

    private AlgorithmPreventionConfigurationTestCase keycloakEcpCase() {
        var reader = new AlgorithmPreventionEvidenceFile(temp.resolve("evidence"), entry -> bodies.get(entry.decodedSamlRef()),
                run -> targetMetadata, run -> Optional.of(suite.privateKey()), run -> "ecp_idp",
                new AlgorithmPreventionEvidenceFile.ReferenceIdentity(IMAGE, "5.2.3", "test-shibboleth"));
        return new AlgorithmPreventionConfigurationTestCase(new Fallback(AlgorithmPreventionEvidenceFile.CASE_A), reader);
    }

    @Test
    void tamperingAmbiguityAndMissingCryptographicEvidenceFailClosed() throws Exception {
        var mutations = List.<Consumer<ObjectNode>>of(
                value -> value.put("runId", OTHER_RUN),
                value -> value.put("profile", "ecp_idp"),
                value -> value.put("targetMetadataSha256", "0".repeat(64)),
                value -> value.withObject("/configuration").put("restored", false),
                value -> value.withObject("/configuration").set("restoredGlobal", blob("changed".getBytes(StandardCharsets.UTF_8))),
                value -> value.withArray("phases").remove(2),
                value -> value.withArray("phases").get(1).withObject("/runtime").set("inspect", runtimeInspect(1)),
                value -> value.withObject("/operationCounts").put("humanOperations", 1),
                value -> ((ObjectNode) value.withArray("phases").get(1)).put("responseReference", "request-1"),
                value -> value.put("unexpected", true));
        for (var index = 0; index < mutations.size(); index++) {
            var receipt = validReceipt();
            mutations.get(index).accept(receipt);
            write(receipt);
            assertEquals(Outcome.NOT_VERIFIED,
                    testCase(AlgorithmPreventionEvidenceFile.CASE_B, run -> Optional.of(suite.privateKey()))
                            .observe(context(RUN)).outcome(), "mutation " + index);
        }
        write(validReceipt());
        var wrong = new FilePlanKeyStore(temp, Clock.fixed(NOW, ZoneOffset.UTC)).getOrCreate(PLAN, "wrong");
        assertEquals(Outcome.NOT_VERIFIED,
                testCase(AlgorithmPreventionEvidenceFile.CASE_A, run -> Optional.of(wrong.privateKey()))
                        .observe(context(RUN)).outcome());
        assertEquals(Outcome.NOT_VERIFIED,
                testCase(AlgorithmPreventionEvidenceFile.CASE_A, run -> Optional.of(suite.privateKey()))
                        .observe(context(OTHER_RUN)).outcome());
    }

    @Test
    void terminalOrSummaryOnlyCannotReplaceOriginalRequestAndResponse() throws Exception {
        write(validReceipt());
        var saved = bodies.remove("response-1");
        assertEquals(Outcome.NOT_VERIFIED,
                testCase(AlgorithmPreventionEvidenceFile.CASE_A, run -> Optional.of(suite.privateKey()))
                        .observe(context(RUN)).outcome());
        bodies.put("response-1", saved);
        var original = entries.get(3);
        entries.set(3, new TranscriptEntry(original.id(), original.runId(), original.direction(), original.timestamp(),
                original.correlationId(), original.method(), original.url(), original.status(), original.headers(),
                original.bodyRef(), original.bodyBytes(), null, 0, original.contentType(), original.rawQuery(),
                original.samlSummary()));
        assertEquals(Outcome.NOT_VERIFIED,
                testCase(AlgorithmPreventionEvidenceFile.CASE_A, run -> Optional.of(suite.privateKey()))
                        .observe(context(RUN)).outcome());
    }

    @Test
    void receiptIsRunScopedAndSymlinksAreRejected() throws Exception {
        write(validReceipt());
        assertTrue(reader(run -> Optional.of(suite.privateKey())).exists(RUN));
        var receipt = temp.resolve("evidence").resolve(RUN + ".json");
        var moved = temp.resolve("actual.json");
        Files.move(receipt, moved);
        Files.createSymbolicLink(receipt, moved);
        assertFalse(reader(run -> Optional.of(suite.privateKey())).read(context(RUN)).isPresent());
    }

    private AlgorithmPreventionConfigurationTestCase testCase(String id, SamlDecryptionKeyProvider keys) {
        return new AlgorithmPreventionConfigurationTestCase(new Fallback(id), reader(keys));
    }

    private AlgorithmPreventionEvidenceFile reader(SamlDecryptionKeyProvider keys) {
        return new AlgorithmPreventionEvidenceFile(temp.resolve("evidence"), entry -> bodies.get(entry.decodedSamlRef()),
                run -> targetMetadata, keys, run -> PROFILE,
                new AlgorithmPreventionEvidenceFile.ReferenceIdentity(IMAGE, "5.2.3", "test-shibboleth"));
    }

    private ObjectNode validReceipt() throws Exception {
        var value = json.mapper().createObjectNode();
        value.put("schema", "samlscope-shibboleth-algorithm-prevention-v2");
        value.put("runId", RUN);
        value.put("profile", PROFILE);
        value.put("targetEntityId", TARGET);
        value.put("targetMetadataSha256", hash(targetMetadata));
        value.set("suiteMetadata", blob(suiteMetadata));
        var config = value.putObject("configuration");
        config.set("originalGlobal", blob(ORIGINAL_GLOBAL));
        config.set("originalRelyingParty", blob(ORIGINAL_RELYING));
        config.set("originalProviders", blob(ORIGINAL_PROVIDERS));
        config.set("providerConfiguredReadBack", blob(AlgorithmPreventionEvidenceFile.providerConfiguration(ORIGINAL_PROVIDERS, RUN)));
        config.set("fixtureReadBack", blob(suiteMetadata));
        config.set("restoredGlobal", blob(ORIGINAL_GLOBAL));
        config.set("restoredRelyingParty", blob(ORIGINAL_RELYING));
        config.set("restoredProviders", blob(ORIGINAL_PROVIDERS));
        config.put("temporaryMetadataRemoved", true);
        config.put("restored", true);
        var runtime = value.putObject("runtime");
        runtime.set("initial", runtime(0));
        runtime.set("restored", runtime(4));
        var phases = value.putArray("phases");
        for (var index = 0; index < 3; index++) {
            var phase = phases.addObject();
            phase.put("name", List.of("allowed-before", "blocked", "allowed-after").get(index));
            phase.set("globalReadBack", blob(AlgorithmPreventionEvidenceFile.configuredGlobal(ORIGINAL_GLOBAL, index == 1)));
            phase.set("relyingPartyReadBack", blob(AlgorithmPreventionEvidenceFile.configuredRelyingParty(ORIGINAL_RELYING)));
            phase.set("runtime", runtime(index + 1));
            phase.put("requestReference", "request-" + index);
            phase.put("responseReference", "response-" + index);
        }
        var counts = value.putObject("operationCounts");
        counts.put("productConfigurationWrites", 9);
        counts.put("productRestarts", 4);
        counts.put("metadataReloads", 0);
        counts.put("protocolOperations", 3);
        counts.put("humanOperations", 0);
        return value;
    }

    private ObjectNode validKeycloakReceipt(boolean ineffective) throws Exception {
        entries.clear(); bodies.clear();
        var names = List.of("rsa15-before", "rsa15-prevented", "oaep-allowed-during-rsa15-prevention",
                "rsa15-after-remove", "rsa15-allowed-during-oaep-prevention", "oaep-prevented", "oaep-after-remove");
        var rsa15 = AlgorithmPreventionEvidenceFile.RSA15;
        var oaep = AlgorithmPreventionEvidenceFile.OAEP;
        var selected = List.of(rsa15, rsa15, oaep, rsa15, rsa15, oaep, oaep);
        var prevented = List.of("", rsa15, rsa15, "", oaep, oaep, "");
        var clientId = "00000000-0000-0000-0000-000000000001";
        var profile = "samlscope-algorithm-prevention-profile-" + RUN;
        var policy = "samlscope-algorithm-prevention-" + RUN;
        var originalProfiles = json.mapper().createObjectNode(); originalProfiles.putArray("profiles");
        var originalPolicies = json.mapper().createObjectNode(); originalPolicies.putArray("policies");
        var value = json.mapper().createObjectNode();
        value.put("schema", KeycloakAlgorithmPreventionEvidenceFile.SCHEMA).put("runId", RUN)
                .put("profile", PROFILE).put("targetEntityId", TARGET).put("targetMetadataSha256", hash(targetMetadata))
                .put("clientDatabaseId", clientId).put("profileName", profile).put("policyName", policy);
        value.set("suiteMetadata", blob(suiteMetadata));
        var config = value.putObject("configuration");
        config.set("originalProfiles", nativeOriginal("profiles-before", 0, "GET", "/client-policies/profiles", 200, originalProfiles, null));
        config.set("originalPolicies", nativeOriginal("policies-before", 0, "GET", "/client-policies/policies", 200, originalPolicies, null));
        var phases = value.putArray("phases");
        for (int index = 0; index < names.size(); index++) {
            addExchange(index, selected.get(index).equals(rsa15)
                    ? SamlEncryptionFixtureFactory.Transport.RSA_1_5 : SamlEncryptionFixtureFactory.Transport.RSA_OAEP);
            boolean blocked = index == 1 || index == 5;
            if (blocked && !ineffective) entries.remove(entries.size() - 1);
            var phase = phases.addObject();
            phase.put("phase", names.get(index)).put("requestedAlgorithm", selected.get(index));
            var refs = phase.putArray("addedTranscriptIds").add("request-" + index);
            if (!blocked || ineffective) refs.add("response-" + index);
            var client = json.mapper().createObjectNode();
            client.put("id", clientId).put("clientId", SUITE).put("protocol", "saml");
            client.putObject("attributes").put("samlscope-algorithm-policy-campaign", RUN)
                    .put("saml.encryption.keyAlgorithm", selected.get(index))
                    .put("saml.encryption.algorithm", AlgorithmPreventionEvidenceFile.AES128);
            var nativeProfiles = originalProfiles.deepCopy();
            if (index > 0) {
                var row = nativeProfiles.withArray("profiles").addObject();
                row.put("name", profile).put("description", "Temporary native algorithm prevention evidence");
                row.withArray("executors").addObject().put("executor", "reject-request").putObject("configuration");
            }
            var nativePolicies = originalPolicies.deepCopy();
            if (!prevented.get(index).isBlank()) {
                var row = nativePolicies.withArray("policies").addObject();
                row.put("name", policy).put("enabled", true).put("description", "Temporary native algorithm prevention evidence");
                row.withArray("profiles").add(profile);
                var condition = row.withArray("conditions").addObject().put("condition", "client-attributes").putObject("configuration");
                var pairs = json.mapper().createArrayNode();
                pairs.addObject().put("key", "samlscope-algorithm-policy-campaign").put("value", RUN);
                pairs.addObject().put("key", "saml.encryption.keyAlgorithm").put("value", prevented.get(index));
                condition.put("attributes", json.mapper().writeValueAsString(pairs)).put("is-negative-logic", false);
            }
            var rejection = json.mapper().createObjectNode().put("error", "invalid_request").put("error_description", "Request not allowed");
            long at = index * 20L + 1;
            phase.set("clientConfigurationOriginal", nativeOriginal("client-config-" + index, at, "GET", "/clients/" + clientId, 200, client, null));
            phase.set("profilesOriginal", nativeOriginal("profiles-" + index, at, "GET", "/client-policies/profiles", 200, nativeProfiles, null));
            phase.set("policiesOriginal", nativeOriginal("policies-" + index, at, "GET", "/client-policies/policies", 200, nativePolicies, null));
            phase.set("clientReadOriginal", nativeOriginal("client-read-" + index, at, "GET", "/clients/" + clientId,
                    blocked && !ineffective ? 400 : 200, blocked && !ineffective ? rejection : client, null));
            phase.set("clientUpdateOriginal", nativeOriginal("client-put-" + index, at, "PUT", "/clients/" + clientId,
                    blocked && !ineffective ? 400 : 204, blocked && !ineffective ? rejection : null, client));
        }
        config.set("restoredProfiles", nativeOriginal("profiles-after", 160, "GET", "/client-policies/profiles", 200, originalProfiles, null));
        config.set("restoredPolicies", nativeOriginal("policies-after", 160, "GET", "/client-policies/policies", 200, originalPolicies, null));
        config.set("deletedClient", nativeOriginal("client-deleted", 160, "GET", "/clients?clientId="
                + java.net.URLEncoder.encode(SUITE, StandardCharsets.UTF_8), 200, json.mapper().createArrayNode(), null));
        value.putObject("operationCounts").put("productConfigurationWrites", 23).put("protocolOperations", 7)
                .put("productRestarts", 0).put("humanOperations", 0);
        return value;
    }

    private ObjectNode nativeOriginal(String id, long time, String method, String path, int status,
            com.fasterxml.jackson.databind.JsonNode response, com.fasterxml.jackson.databind.JsonNode request) throws Exception {
        var nativeValue = json.mapper().createObjectNode();
        nativeValue.put("schema", "samlscope-keycloak-native-admin-original-v1").put("runId", RUN)
                .put("campaignId", "keycloak-algorithm-prevention").put("method", method).put("path", path).put("httpStatus", status);
        nativeValue.set("response", response == null ? json.mapper().nullNode() : response);
        nativeValue.set("request", request == null ? json.mapper().nullNode() : request);
        var raw = json.mapper().writeValueAsBytes(nativeValue);
        bodies.put(id, raw);
        entries.add(new TranscriptEntry(id, RUN, Direction.INBOUND, NOW.plusSeconds(time), null, "POST",
                "https://suite.example/p/" + PLAN + "/sp/paos?run=" + RUN, 204, Map.of(), null, 0,
                id, raw.length, "application/json", null, Map.of()));
        return json.mapper().createObjectNode().put("reference", id).put("sha256", hash(raw));
    }

    private ObjectNode validKeycloakEcpReceipt() throws Exception {
        var value = validKeycloakReceipt(false);
        value.put("profile", "ecp_idp");
        var endpoint = "https://idp.example/soap";
        var paos = SUITE + "/sp/paos?run=" + RUN;
        var descriptor = SecureXml.parse(targetMetadata);
        var role = descriptor.getDocumentElement().getElementsByTagNameNS(MD, "IDPSSODescriptor").item(0);
        var sso = descriptor.createElementNS(MD, "md:SingleSignOnService");
        sso.setAttribute("Binding", "urn:oasis:names:tc:SAML:2.0:bindings:SOAP");
        sso.setAttribute("Location", endpoint);
        role.appendChild(sso);
        targetMetadata = SecureXml.serialize(descriptor);
        value.put("targetMetadataSha256", hash(targetMetadata));
        entries.removeIf(entry -> entry.id().matches("(?:request|response)-[0-6]"));
        for (int index = 0; index < 7; index++) {
            var phase = (ObjectNode) value.withArray("phases").get(index);
            var transport = AlgorithmPreventionEvidenceFile.RSA15.equals(phase.path("requestedAlgorithm").asText())
                    ? SamlEncryptionFixtureFactory.Transport.RSA_1_5 : SamlEncryptionFixtureFactory.Transport.RSA_OAEP;
            addExchange(index, transport, paos);
            var request = entries.get(entries.size() - 2);
            var response = entries.getLast();
            var authn = SecureXml.parse(bodies.get(request.id()));
            authn.getDocumentElement().setAttribute("Destination", endpoint);
            authn.getDocumentElement().setAttribute("AssertionConsumerServiceURL", paos);
            bodies.put(request.id(), soap(SecureXml.serialize(authn)));
            if (index == 1 || index == 5) {
                bodies.put(response.id(), ("<soap:Envelope xmlns:soap='http://schemas.xmlsoap.org/soap/envelope/'>"
                        + "<soap:Body><soap:Fault><faultcode>error</faultcode>"
                        + "<faultstring>Authentication request cannot be processed.</faultstring>"
                        + "</soap:Fault></soap:Body></soap:Envelope>").getBytes(StandardCharsets.UTF_8));
                response = new TranscriptEntry(response.id(), response.runId(), response.direction(), response.timestamp(),
                        response.correlationId(), response.method(), response.url(), 500, response.headers(), response.bodyRef(),
                        response.bodyBytes(), response.decodedSamlRef(), response.decodedSamlBytes(), response.contentType(),
                        response.rawQuery(), response.samlSummary());
                phase.withArray("addedTranscriptIds").add(response.id());
            } else {
                var envelope = SecureXml.parse(soap(bodies.get(response.id())));
                var header = envelope.createElementNS("http://schemas.xmlsoap.org/soap/envelope/", "soap:Header");
                var consumer = envelope.createElementNS("urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp", "ecp:Response");
                consumer.setAttribute("AssertionConsumerServiceURL", paos); header.appendChild(consumer);
                envelope.getDocumentElement().insertBefore(header, envelope.getDocumentElement().getFirstChild());
                bodies.put(response.id(), SecureXml.serialize(envelope));
            }
            entries.set(entries.size() - 2, replaced(request, endpoint, "action-" + index,
                    "EcpSoapRequest", bodies.get(request.id())));
            entries.set(entries.size() - 1, replaced(response, endpoint, "action-" + index,
                    "EcpSoapResponse", bodies.get(response.id())));
            for (var field : List.of("clientConfigurationOriginal", "clientReadOriginal", "clientUpdateOriginal")) {
                var ref = (ObjectNode) phase.path(field);
                var originalId = ref.path("reference").asText();
                var nativeValue = (ObjectNode) json.mapper().readTree(bodies.get(originalId));
                for (var part : List.of("response", "request")) if (nativeValue.path(part).path("attributes").isObject())
                    nativeValue.withObject("/" + part + "/attributes").put("saml.allow.ecp.flow", "true")
                            .put("saml_assertion_consumer_url_paos", paos);
                var raw = json.mapper().writeValueAsBytes(nativeValue);
                bodies.put(originalId, raw); ref.put("sha256", hash(raw));
            }
        }
        return value;
    }

    private ObjectNode runtime(int generation) {
        var value = json.mapper().createObjectNode();
        value.set("inspect", runtimeInspect(generation));
        value.set("version", blob("5.2.3\n".getBytes(StandardCharsets.UTF_8)));
        return value;
    }

    private ObjectNode runtimeInspect(int generation) {
        var started = NOW.plusSeconds(generation * 10L);
        var raw = ("[{\"Name\":\"/test-shibboleth\",\"Id\":\"" + "a".repeat(64)
                + "\",\"Image\":\"" + IMAGE + "\",\"State\":{\"Running\":true,\"StartedAt\":\""
                + started + "\"}}]").getBytes(StandardCharsets.UTF_8);
        return blob(raw);
    }

    private void addExchange(int index, SamlEncryptionFixtureFactory.Transport transport) throws Exception {
        addExchange(index, transport, ACS);
    }

    private void addExchange(int index, SamlEncryptionFixtureFactory.Transport transport, String consumer) throws Exception {
        var requestId = "_request_" + index;
        var request = ("<p:AuthnRequest xmlns:p='" + P + "' xmlns:s='" + S + "' ID='" + requestId
                + "'><s:Issuer>" + SUITE + "</s:Issuer></p:AuthnRequest>").getBytes(StandardCharsets.UTF_8);
        var assertion = SecureXml.parse(("<s:Assertion xmlns:s='" + S + "' ID='_assertion_" + index
                + "' Version='2.0' IssueInstant='" + NOW + "'><s:Issuer>" + TARGET
                + "</s:Issuer></s:Assertion>").getBytes(StandardCharsets.UTF_8)).getDocumentElement();
        var algorithms = new SamlEncryptionFixtureFactory.Algorithms(
                SamlEncryptionFixtureFactory.Content.AES128_GCM, transport,
                SamlEncryptionFixtureFactory.Digest.DEFAULT, SamlEncryptionFixtureFactory.Mgf.DEFAULT);
        var encrypted = new SamlEncryptionFixtureFactory().encrypt(
                SamlEncryptionFixtureFactory.Wrapper.EncryptedAssertion, assertion,
                suite.certificate().getPublicKey(), algorithms);
        var responseDocument = SecureXml.parse(("<p:Response xmlns:p='" + P + "' xmlns:s='" + S
                + "' ID='_response_" + index + "' Version='2.0' IssueInstant='" + NOW
                + "' InResponseTo='" + requestId + "' Destination='" + consumer + "'><s:Issuer>" + TARGET
                + "</s:Issuer><p:Status><p:StatusCode Value='" + SUCCESS
                + "'/></p:Status></p:Response>").getBytes(StandardCharsets.UTF_8));
        var response = responseDocument.getDocumentElement();
        response.appendChild(responseDocument.importNode(encrypted, true));
        var status = (Element) response.getElementsByTagNameNS(P, "Status").item(0);
        new XmlSigner().sign(response, target, status);
        var responseBytes = SecureXml.serialize(responseDocument);
        bodies.put("request-" + index, request);
        bodies.put("response-" + index, responseBytes);
        entries.add(entry("request-" + index, Direction.OUTBOUND, NOW.plusSeconds(index * 20L + 11),
                "https://idp.example/sso", request, Map.of("type", "AuthnRequest")));
        entries.add(entry("response-" + index, Direction.INBOUND, NOW.plusSeconds(index * 20L + 12),
                ACS, responseBytes, Map.of("type", "Response", "normalFlowAccepted", true)));
    }

    private TranscriptEntry entry(String id, Direction direction, Instant at, String url, byte[] bytes,
            Map<String, Object> summary) {
        return new TranscriptEntry(id, RUN, direction, at, "correlation", "POST", url, 200, Map.of(),
                null, 0, id, bytes.length, "application/xml", null, summary);
    }

    private TranscriptEntry replaced(TranscriptEntry entry, String url, String correlation, String type, byte[] bytes) {
        var summary = "EcpSoapResponse".equals(type)
                ? Map.<String, Object>of("type", type,
                        "request_transcript", "request-" + entry.id().substring("response-".length()))
                : Map.<String, Object>of("type", type);
        return new TranscriptEntry(entry.id(), entry.runId(), entry.direction(), entry.timestamp(), correlation,
                entry.method(), url, entry.status(), entry.headers(), entry.bodyRef(), entry.bodyBytes(), entry.id(),
                bytes.length, entry.contentType(), entry.rawQuery(), summary);
    }

    private byte[] soap(byte[] payload) {
        var document = SecureXml.parse(("<soap:Envelope xmlns:soap='http://schemas.xmlsoap.org/soap/envelope/'><soap:Body/>"
                + "</soap:Envelope>").getBytes(StandardCharsets.UTF_8));
        var body = (Element) document.getDocumentElement().getElementsByTagNameNS(
                "http://schemas.xmlsoap.org/soap/envelope/", "Body").item(0);
        body.appendChild(document.importNode(SecureXml.parse(payload).getDocumentElement(), true));
        return SecureXml.serialize(document);
    }

    private CaseContext context(String runId) {
        var recorder = new TranscriptRecorder() {
            @Override public TranscriptEntry record(TranscriptInput input) { throw new UnsupportedOperationException(); }
            @Override public TranscriptEntry updateSamlAnalysis(String id, String correlation, Map<String, Object> summary) {
                throw new UnsupportedOperationException();
            }
            @Override public List<TranscriptEntry> list(String ignored) { return entries; }
        };
        return new DefaultCaseContext(runId, TargetRole.IDP, Clock.fixed(NOW, ZoneOffset.UTC),
                TestPlan.Parameters.defaults(), TestPlan.Interaction.defaults(), Reachability.CONFIRMED, recorder, true);
    }

    private byte[] metadata(String entity, String role, String use, PlanCredentials credentials) throws Exception {
        var endpoint = role.startsWith("IDP")
                ? "<md:SingleSignOnService Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect' Location='https://idp.example/sso'/>"
                : "<md:AssertionConsumerService Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST' Location='" + ACS + "' index='0'/>";
        return ("<md:EntityDescriptor xmlns:md='" + MD + "' xmlns:ds='http://www.w3.org/2000/09/xmldsig#' entityID='"
                + entity + "'><md:" + role + " protocolSupportEnumeration='" + P + "'><md:KeyDescriptor use='" + use
                + "'><ds:KeyInfo><ds:X509Data><ds:X509Certificate>"
                + Base64.getEncoder().encodeToString(credentials.certificate().getEncoded())
                + "</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>" + endpoint
                + "</md:" + role + "></md:EntityDescriptor>").getBytes(StandardCharsets.UTF_8);
    }

    private ObjectNode blob(byte[] bytes) {
        var value = json.mapper().createObjectNode();
        value.put("base64", Base64.getEncoder().encodeToString(bytes));
        value.put("sha256", hashUnchecked(bytes));
        return value;
    }

    private void write(ObjectNode receipt) throws Exception {
        Files.createDirectories(temp.resolve("evidence"));
        Files.write(temp.resolve("evidence").resolve(RUN + ".json"), json.mapper().writeValueAsBytes(receipt));
    }

    private static String hash(byte[] value) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
    }

    private static String hashUnchecked(byte[] value) {
        try { return hash(value); } catch (Exception impossible) { throw new IllegalStateException(impossible); }
    }

    private static final class Fallback implements TestCase, ConfigurationPrompt, AttestationPrompt {
        private final String id;
        private Fallback(String id) { this.id = id; }
        @Override public String id() { return id; }
        @Override public TargetRole role() { return TargetRole.IDP; }
        @Override public String instructionEn() { return "configure"; }
        @Override public String promptEn() { return "observe"; }
        @Override public List<AttestationOption> options() {
            return List.of(AttestationOption.notVerified("unknown", "unknown", "unknown"));
        }
        @Override public CaseStep start(CaseContext context) {
            return new CaseStep.Finish(CaseOutcome.notVerified("fallback", "fallback"));
        }
        @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
            return new CaseStep.Finish(CaseOutcome.notVerified("fallback", "fallback"));
        }
    }
}
