package com.samlscope.runner.cases;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.transcript.Direction;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.core.transcript.TranscriptEntry;
import com.samlscope.saml.crypto.SamlXmlDecrypter;
import com.samlscope.saml.crypto.VerifiedSignatureAlgorithms;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import org.w3c.dom.Element;

/** Native administration originals prove prevention; a missing SAML response never does. */
final class KeycloakAlgorithmPreventionEvidenceFile {
    static final String SCHEMA = "samlscope-keycloak-algorithm-prevention-v1";
    private static final String ORIGINAL_SCHEMA = "samlscope-keycloak-native-admin-original-v1";
    private static final String CAMPAIGN = "keycloak-algorithm-prevention";
    private static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String P = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String S = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String X = "http://www.w3.org/2001/04/xmlenc#";
    private static final String SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
    private static final String SOAP = "http://schemas.xmlsoap.org/soap/envelope/";
    private static final String ECP = "urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp";
    private static final String PROFILES = "/client-policies/profiles";
    private static final String POLICIES = "/client-policies/policies";
    private static final List<String> NAMES = List.of("rsa15-before", "rsa15-prevented",
            "oaep-allowed-during-rsa15-prevention", "rsa15-after-remove",
            "rsa15-allowed-during-oaep-prevention", "oaep-prevented", "oaep-after-remove");
    private static final List<String> SELECTED = List.of(AlgorithmPreventionEvidenceFile.RSA15,
            AlgorithmPreventionEvidenceFile.RSA15, AlgorithmPreventionEvidenceFile.OAEP,
            AlgorithmPreventionEvidenceFile.RSA15, AlgorithmPreventionEvidenceFile.RSA15,
            AlgorithmPreventionEvidenceFile.OAEP, AlgorithmPreventionEvidenceFile.OAEP);
    private static final List<String> PREVENTED = List.of("", AlgorithmPreventionEvidenceFile.RSA15,
            AlgorithmPreventionEvidenceFile.RSA15, "", AlgorithmPreventionEvidenceFile.OAEP,
            AlgorithmPreventionEvidenceFile.OAEP, "");
    private final TranscriptContentReader content;
    private final Function<String, byte[]> metadata;
    private final SamlDecryptionKeyProvider keys;
    private final Function<String, String> profiles;
    private final JsonCodec json = new JsonCodec();

    KeycloakAlgorithmPreventionEvidenceFile(TranscriptContentReader content, Function<String, byte[]> metadata,
            SamlDecryptionKeyProvider keys, Function<String, String> profiles) {
        this.content = content;
        this.metadata = metadata;
        this.keys = keys;
        this.profiles = profiles;
    }

    Optional<AlgorithmPreventionEvidenceFile.Proof> read(CaseContext context, JsonNode receipt,
            String receiptSha256) {
        try {
            require(context.transcriptComplete());
            fields(receipt, Set.of("schema", "runId", "profile", "targetEntityId", "targetMetadataSha256",
                    "suiteMetadata", "clientDatabaseId", "profileName", "policyName", "configuration",
                    "phases", "operationCounts"));
            require(SCHEMA.equals(text(receipt, "schema")) && context.runId().equals(text(receipt, "runId")));
            var profile = text(receipt, "profile");
            require(Set.of("browser_sso_idp", "ecp_idp").contains(profile)
                    && profile.equals(profiles.apply(context.runId())));
            boolean ecp = "ecp_idp".equals(profile);
            var targetRaw = metadata.apply(context.runId());
            require(targetRaw != null && hash(targetRaw).equals(text(receipt, "targetMetadataSha256")));
            var target = SecureXml.parse(targetRaw).getDocumentElement();
            require(MD.equals(target.getNamespaceURI()) && "EntityDescriptor".equals(target.getLocalName()));
            var targetEntity = text(receipt, "targetEntityId");
            require(targetEntity.equals(target.getAttribute("entityID")));
            var signingKeys = MetadataAlgorithmEvidence.signingKeys(target);
            require(!signingKeys.isEmpty());
            var suite = SecureXml.parse(blob(receipt.path("suiteMetadata"))).getDocumentElement();
            require(MD.equals(suite.getNamespaceURI()) && "EntityDescriptor".equals(suite.getLocalName()));
            var suiteEntity = suite.getAttribute("entityID");
            require(!suiteEntity.isBlank() && suite.getElementsByTagNameNS(MD, "SPSSODescriptor").getLength() == 1);
            var clientId = text(receipt, "clientDatabaseId");
            require(clientId.matches("[0-9a-f-]{36}"));
            var profileName = "samlscope-algorithm-prevention-profile-" + context.runId();
            var policyName = "samlscope-algorithm-prevention-" + context.runId();
            require(profileName.equals(text(receipt, "profileName")) && policyName.equals(text(receipt, "policyName")));
            var entries = new HashMap<String, TranscriptEntry>();
            for (var entry : context.transcript().list(context.runId())) {
                require(context.runId().equals(entry.runId()) && entries.putIfAbsent(entry.id(), entry) == null);
            }
            var evidence = new ArrayList<EvidenceRef>();
            var configuration = receipt.path("configuration");
            fields(configuration, Set.of("originalProfiles", "originalPolicies", "restoredProfiles",
                    "restoredPolicies", "deletedClient"));
            var originalProfiles = original(context, entries, configuration.path("originalProfiles"),
                    "GET", PROFILES, evidence);
            var originalPolicies = original(context, entries, configuration.path("originalPolicies"),
                    "GET", POLICIES, evidence);
            require(success(originalProfiles) && success(originalPolicies));
            require(originalProfiles.body().path("profiles").isArray() && originalPolicies.body().path("policies").isArray());
            require(originalProfiles.body().path("profiles").findValuesAsText("name").stream()
                    .noneMatch(profileName::equals));
            require(originalPolicies.body().path("policies").findValuesAsText("name").stream()
                    .noneMatch(policyName::equals));

            var phases = receipt.path("phases");
            require(phases.isArray() && phases.size() == NAMES.size());
            var protocolReferences = new HashSet<String>();
            var algorithms = new ArrayList<String>();
            Instant previous = originalProfiles.time().isAfter(originalPolicies.time())
                    ? originalProfiles.time() : originalPolicies.time();
            boolean ineffective = false;
            for (int index = 0; index < NAMES.size(); index++) {
                var phase = phases.get(index);
                require(NAMES.get(index).equals(text(phase, "phase"))
                        && SELECTED.get(index).equals(text(phase, "requestedAlgorithm")));
                var nativeClient = original(context, entries, phase.path("clientConfigurationOriginal"),
                        "GET", "/clients/" + clientId, evidence);
                require(success(nativeClient));
                var client = nativeClient.body();
                require(clientId.equals(client.path("id").asText()) && suiteEntity.equals(client.path("clientId").asText())
                        && "saml".equals(client.path("protocol").asText())
                        && context.runId().equals(client.path("attributes").path("samlscope-algorithm-policy-campaign").asText())
                        && SELECTED.get(index).equals(client.path("attributes").path("saml.encryption.keyAlgorithm").asText())
                        && AlgorithmPreventionEvidenceFile.AES128.equals(client.path("attributes").path("saml.encryption.algorithm").asText()));
                if (ecp) require("true".equals(client.path("attributes").path("saml.allow.ecp.flow").asText())
                        && (suiteEntity + "/sp/paos?run=" + context.runId())
                            .equals(client.path("attributes").path("saml_assertion_consumer_url_paos").asText()));
                var nativeProfiles = original(context, entries, phase.path("profilesOriginal"), "GET", PROFILES, evidence);
                var nativePolicies = original(context, entries, phase.path("policiesOriginal"), "GET", POLICIES, evidence);
                require(success(nativeProfiles) && success(nativePolicies));
                require(expectedProfiles(originalProfiles.body(), profileName, index != 0).equals(nativeProfiles.body()));
                require(expectedPolicies(originalPolicies.body(), policyName, profileName, context.runId(), PREVENTED.get(index))
                        .equals(nativePolicies.body()));
                var nativeRead = original(context, entries, phase.path("clientReadOriginal"), "GET", "/clients/" + clientId, evidence);
                var nativeUpdate = original(context, entries, phase.path("clientUpdateOriginal"), "PUT", "/clients/" + clientId, evidence);
                require(client.equals(nativeUpdate.value().path("request")));
                boolean blocked = index == 1 || index == 5;
                boolean explicitPrevention = prevented(nativeRead) && prevented(nativeUpdate);
                boolean acceptedConfiguration = success(nativeRead) && nativeRead.body().equals(client)
                        && nativeUpdate.status() == 204 && nativeUpdate.body().isNull();
                require(blocked ? explicitPrevention || acceptedConfiguration : acceptedConfiguration);
                var refs = phase.path("addedTranscriptIds");
                require(refs.isArray() && refs.size() >= 1 && refs.size() <= 2);
                var request = entry(entries, refs.get(0).asText(), Direction.OUTBOUND);
                require(protocolReferences.add(request.id()) && request.timestamp().isAfter(previous));
                for (var record : List.of(nativeClient, nativeProfiles, nativePolicies, nativeRead, nativeUpdate))
                    require(!record.time().isAfter(request.timestamp()));
                var requestRoot = SecureXml.parse(bytes(request)).getDocumentElement();
                var authn = ecp ? soapBody(requestRoot, P, "AuthnRequest") : requestRoot;
                require(P.equals(authn.getNamespaceURI()) && "AuthnRequest".equals(authn.getLocalName())
                        && (ecp ? "EcpSoapRequest" : "AuthnRequest").equals(request.samlSummary().get("type"))
                        && !authn.getAttribute("ID").isBlank()
                        && suiteEntity.equals(singleText(authn, S, "Issuer")));
                if (ecp) require(request.url().equals(authn.getAttribute("Destination"))
                        && target.getElementsByTagNameNS(MD, "SingleSignOnService").getLength() > 0
                        && metadataSoapEndpoint(target, request.url())
                        && (suiteEntity + "/sp/paos?run=" + context.runId())
                            .equals(authn.getAttribute("AssertionConsumerServiceURL")));
                evidence.add(new EvidenceRef("transcript", request.id()));
                if (explicitPrevention) {
                    require(refs.size() == (ecp ? 2 : 1));
                    if (ecp) {
                        var response = entry(entries, refs.get(1).asText(), Direction.INBOUND);
                        require(protocolReferences.add(response.id()) && !response.timestamp().isBefore(request.timestamp()));
                        ecpCorrelation(request, response);
                        require(Integer.valueOf(500).equals(response.status()));
                        var fault = soapBody(SecureXml.parse(bytes(response)).getDocumentElement(), SOAP, "Fault");
                        require("error".equals(singleText(fault, null, "faultcode"))
                                && "Authentication request cannot be processed.".equals(singleText(fault, null, "faultstring")));
                        // A SOAP fault only records delivery. Prevention is proved by the
                        // independently matched native GET/PUT policy-rejection originals.
                        evidence.add(new EvidenceRef("transcript", response.id()));
                        previous = response.timestamp();
                    }
                    // Parse every recorded SAML response; a missing/forged summary cannot hide a contradiction.
                    for (var candidate : entries.values()) if (candidate.direction() == Direction.INBOUND
                            && ("Response".equals(candidate.samlSummary().get("type"))
                                || "EcpSoapResponse".equals(candidate.samlSummary().get("type")))) {
                        var parsed = SecureXml.parse(bytes(candidate)).getDocumentElement();
                        if (SOAP.equals(parsed.getNamespaceURI())) {
                            var responses = parsed.getElementsByTagNameNS(P, "Response");
                            if (responses.getLength() == 0) continue;
                            require(responses.getLength() == 1);
                            parsed = (Element) responses.item(0);
                        }
                        require(!authn.getAttribute("ID").equals(parsed.getAttribute("InResponseTo")));
                    }
                    algorithms.add("prevented:" + SELECTED.get(index));
                    if (!ecp) previous = request.timestamp();
                } else {
                    require(refs.size() == 2);
                    var response = entry(entries, refs.get(1).asText(), Direction.INBOUND);
                    require(protocolReferences.add(response.id()) && !response.timestamp().isBefore(request.timestamp()));
                    var responseRoot = SecureXml.parse(bytes(response)).getDocumentElement();
                    var saml = ecp ? soapBody(responseRoot, P, "Response") : responseRoot;
                    require(P.equals(saml.getNamespaceURI()) && "Response".equals(saml.getLocalName())
                            && (ecp ? "EcpSoapResponse" : "Response").equals(response.samlSummary().get("type"))
                            && (ecp || Boolean.TRUE.equals(response.samlSummary().get("normalFlowAccepted")))
                            && authn.getAttribute("ID").equals(saml.getAttribute("InResponseTo"))
                            && SUCCESS.equals(singleAttribute(saml, P, "StatusCode", "Value")));
                    if (ecp) {
                        ecpCorrelation(request, response);
                        require(Integer.valueOf(200).equals(response.status())
                                && authn.getAttribute("AssertionConsumerServiceURL").equals(saml.getAttribute("Destination"))
                                && authn.getAttribute("AssertionConsumerServiceURL")
                                    .equals(singleAttribute(responseRoot, ECP, "Response", "AssertionConsumerServiceURL")));
                    } else require(response.url().equals(saml.getAttribute("Destination")));
                    require(new VerifiedSignatureAlgorithms().read(saml, targetEntity, signingKeys).stream()
                            .anyMatch(value -> "Response".equals(value.element())));
                    var encrypted = saml.getElementsByTagNameNS(S, "EncryptedAssertion");
                    require(encrypted.getLength() == 1);
                    var wrapper = (Element) encrypted.item(0);
                    var keyMethods = wrapper.getElementsByTagNameNS(X, "EncryptionMethod");
                    require(keyMethods.getLength() == 2);
                    var methods = new HashSet<String>();
                    for (int n = 0; n < keyMethods.getLength(); n++) methods.add(((Element) keyMethods.item(n)).getAttribute("Algorithm"));
                    require(methods.equals(Set.of(AlgorithmPreventionEvidenceFile.AES128, SELECTED.get(index))));
                    var plaintext = new SamlXmlDecrypter().decrypt(wrapper, keys.keyFor(context.runId()).orElseThrow());
                    require(S.equals(plaintext.getNamespaceURI()) && "Assertion".equals(plaintext.getLocalName()));
                    algorithms.add(SELECTED.get(index));
                    evidence.add(new EvidenceRef("transcript", response.id()));
                    previous = response.timestamp();
                    if (blocked) ineffective = true;
                }
            }
            var restoredProfiles = original(context, entries, configuration.path("restoredProfiles"), "GET", PROFILES, evidence);
            var restoredPolicies = original(context, entries, configuration.path("restoredPolicies"), "GET", POLICIES, evidence);
            var deleted = original(context, entries, configuration.path("deletedClient"), "GET",
                    "/clients?clientId=" + java.net.URLEncoder.encode(suiteEntity, StandardCharsets.UTF_8).replace("+", "%20"), evidence);
            require(success(restoredProfiles) && success(restoredPolicies) && success(deleted)
                    && originalProfiles.body().equals(restoredProfiles.body())
                    && originalPolicies.body().equals(restoredPolicies.body()) && deleted.body().isArray() && deleted.body().isEmpty());
            for (var record : List.of(restoredProfiles, restoredPolicies, deleted)) require(record.time().isAfter(previous));
            if (ecp) {
                var requests = entries.values().stream().filter(value -> value.direction() == Direction.OUTBOUND
                        && "EcpSoapRequest".equals(value.samlSummary().get("type"))).toList();
                require(requests.size() == 7 && requests.stream().map(TranscriptEntry::correlationId)
                        .filter(java.util.Objects::nonNull).distinct().count() == 7);
                require(requests.stream().allMatch(value -> protocolReferences.contains(value.id())));
            }
            var counts = receipt.path("operationCounts");
            fields(counts, Set.of("productConfigurationWrites", "protocolOperations", "productRestarts", "humanOperations"));
            require(counts.path("productConfigurationWrites").asInt(-1) > 0
                    && counts.path("protocolOperations").asInt(-1) == 7 && counts.path("productRestarts").asInt(-1) == 0
                    && counts.path("humanOperations").asInt(-1) == 0);
            return Optional.of(new AlgorithmPreventionEvidenceFile.Proof(ineffective
                    ? AlgorithmPreventionEvidenceFile.Result.VIOLATED : AlgorithmPreventionEvidenceFile.Result.SATISFIED,
                    evidence.stream().distinct().toList(), List.copyOf(algorithms), receiptSha256));
        } catch (Exception invalid) {
            return Optional.empty();
        }
    }

    private Original original(CaseContext context, Map<String, TranscriptEntry> entries, JsonNode descriptor,
            String method, String path, List<EvidenceRef> evidence) throws Exception {
        fields(descriptor, Set.of("reference", "sha256"));
        var entry = entry(entries, text(descriptor, "reference"), Direction.INBOUND);
        require("POST".equals(entry.method()) && Integer.valueOf(204).equals(entry.status())
                && entry.url() != null && entry.url().contains("/sp/paos?run=" + context.runId()));
        var raw = bytes(entry);
        require(hash(raw).equals(text(descriptor, "sha256")));
        var value = json.mapper().readTree(raw);
        fields(value, Set.of("schema", "runId", "campaignId", "method", "path", "httpStatus", "response", "request"));
        require(ORIGINAL_SCHEMA.equals(text(value, "schema")) && CAMPAIGN.equals(text(value, "campaignId"))
                && context.runId().equals(text(value, "runId")) && method.equals(text(value, "method"))
                && path.equals(text(value, "path")) && value.path("httpStatus").isIntegralNumber());
        noCredentials(value);
        evidence.add(new EvidenceRef("transcript", entry.id()));
        return new Original(value, entry.timestamp());
    }

    private JsonNode expectedProfiles(JsonNode baseline, String name, boolean enabled) {
        ObjectNode expected = baseline.deepCopy();
        if (enabled) {
            var profile = expected.withArray("profiles").addObject();
            profile.put("name", name).put("description", "Temporary native algorithm prevention evidence");
            profile.withArray("executors").addObject().put("executor", "reject-request").putObject("configuration");
        }
        return expected;
    }

    private JsonNode expectedPolicies(JsonNode baseline, String name, String profile, String run, String prevented) throws Exception {
        ObjectNode expected = baseline.deepCopy();
        if (!prevented.isBlank()) {
            var policy = expected.withArray("policies").addObject();
            policy.put("name", name).put("enabled", true).put("description", "Temporary native algorithm prevention evidence");
            var config = policy.withArray("conditions").addObject().put("condition", "client-attributes").putObject("configuration");
            var pairs = json.mapper().createArrayNode();
            pairs.addObject().put("key", "samlscope-algorithm-policy-campaign").put("value", run);
            pairs.addObject().put("key", "saml.encryption.keyAlgorithm").put("value", prevented);
            config.put("attributes", json.mapper().writeValueAsString(pairs)).put("is-negative-logic", false);
            policy.withArray("profiles").add(profile);
        }
        return expected;
    }

    private static boolean success(Original record) { return record.status() == 200; }
    private static void ecpCorrelation(TranscriptEntry request, TranscriptEntry response) {
        require("POST".equals(request.method()) && "POST".equals(response.method())
                && "EcpSoapResponse".equals(response.samlSummary().get("type"))
                && request.id().equals(response.samlSummary().get("request_transcript"))
                && request.correlationId() != null && request.correlationId().equals(response.correlationId())
                && request.url().equals(response.url()));
    }
    private static Element soapBody(Element root, String namespace, String name) {
        require(SOAP.equals(root.getNamespaceURI()) && "Envelope".equals(root.getLocalName()));
        var bodies = root.getElementsByTagNameNS(SOAP, "Body");
        require(bodies.getLength() == 1 && bodies.item(0).getParentNode() == root);
        var nodes = ((Element) bodies.item(0)).getElementsByTagNameNS(namespace, name);
        require(nodes.getLength() == 1 && nodes.item(0).getParentNode() == bodies.item(0));
        return (Element) nodes.item(0);
    }
    private static boolean metadataSoapEndpoint(Element target, String url) {
        var nodes = target.getElementsByTagNameNS(MD, "SingleSignOnService");
        int matches = 0;
        for (int index = 0; index < nodes.getLength(); index++) {
            var endpoint = (Element) nodes.item(index);
            if ("urn:oasis:names:tc:SAML:2.0:bindings:SOAP".equals(endpoint.getAttribute("Binding"))
                    && url.equals(endpoint.getAttribute("Location"))) matches++;
        }
        return matches == 1;
    }
    private static boolean prevented(Original record) {
        return record.status() == 400 && record.body().isObject() && record.body().size() == 2
                && "invalid_request".equals(record.body().path("error").asText())
                && "Request not allowed".equals(record.body().path("error_description").asText());
    }
    private byte[] bytes(TranscriptEntry entry) throws Exception {
        require(entry.decodedSamlRef() != null);
        var raw = content.readDecodedSaml(entry);
        require(raw != null && raw.length > 0 && raw.length <= 2_097_152);
        return raw;
    }
    private static TranscriptEntry entry(Map<String, TranscriptEntry> entries, String id, Direction direction) {
        var value = entries.get(id);
        require(value != null && value.direction() == direction);
        return value;
    }
    private static void noCredentials(JsonNode value) {
        if (value.isObject()) value.fields().forEachRemaining(field -> {
            require(!Set.of("secret", "password", "authorization", "cookie", "registrationaccesstoken")
                    .contains(field.getKey().toLowerCase(java.util.Locale.ROOT)));
            noCredentials(field.getValue());
        });
        else if (value.isArray()) value.forEach(KeycloakAlgorithmPreventionEvidenceFile::noCredentials);
    }
    private static String singleText(Element element, String namespace, String name) {
        var nodes = element.getElementsByTagNameNS(namespace, name);
        require(nodes.getLength() == 1);
        return nodes.item(0).getTextContent();
    }
    private static String singleAttribute(Element element, String namespace, String name, String attribute) {
        var nodes = element.getElementsByTagNameNS(namespace, name);
        require(nodes.getLength() == 1);
        return ((Element) nodes.item(0)).getAttribute(attribute);
    }
    private static byte[] blob(JsonNode value) throws Exception {
        fields(value, Set.of("base64", "sha256"));
        var raw = Base64.getDecoder().decode(text(value, "base64"));
        require(raw.length > 0 && raw.length <= 524_288 && hash(raw).equals(text(value, "sha256")));
        return raw;
    }
    private static String text(JsonNode value, String key) {
        require(value.path(key).isTextual() && !value.path(key).asText().isBlank());
        return value.path(key).asText();
    }
    private static void fields(JsonNode value, Set<String> expected) {
        require(value.isObject());
        var names = new HashSet<String>();
        value.fieldNames().forEachRemaining(names::add);
        require(names.equals(expected));
    }
    private static String hash(byte[] value) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
    }
    private static void require(boolean condition) {
        if (!condition) throw new IllegalArgumentException("Native algorithm prevention unproven");
    }
    private record Original(JsonNode value, Instant time) {
        JsonNode body() { return value.path("response"); }
        int status() { return value.path("httpStatus").asInt(-1); }
    }
}
