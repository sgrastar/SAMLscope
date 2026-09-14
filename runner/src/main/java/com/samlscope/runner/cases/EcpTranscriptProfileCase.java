package com.samlscope.runner.cases;

import java.security.cert.X509Certificate;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.LinkedHashSet;
import java.util.Set;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.transcript.Direction;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.core.transcript.TranscriptEntry;
import com.samlscope.core.transcript.TranscriptRecorder;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import com.samlscope.saml.crypto.SamlElementDecrypter;
import com.samlscope.saml.crypto.SamlXmlDecrypter;
import com.samlscope.saml.normal.SecureXml;
import org.w3c.dom.Element;

/** Passive evidence rules for ECP and the separately versioned SAML-EC extension. */
public final class EcpTranscriptProfileCase {
    public enum Rule {
        BASIC_EXCHANGE, RESPONSE_OR_FAULT, RESPONSE_HEADER, REQUEST_AUTHENTICATED,
        HEADER_ATTRIBUTES, RESPONSE_INTEGRITY, RELAY_STATE_CHOICE, DELEGATION_CHOICE,
        INTERMEDIATE_EXCHANGES, BEARER_CONFIRMATION, CHANNEL_BINDINGS, HTTP_BASIC,
        GENERATED_KEY
    }

    private static final String SOAP = "http://schemas.xmlsoap.org/soap/envelope/";
    private static final String PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String ECP = "urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp";
    private static final String PAOS = "urn:liberty:paos:2003-08";
    private static final String CB = "urn:oasis:names:tc:SAML:protocol:ext:channel-binding";
    private static final String SAML_EC = "urn:ietf:params:xml:ns:samlec";
    private static final String BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
    private static final String NEXT = "http://schemas.xmlsoap.org/soap/actor/next";
    private final Rule rule;
    private final List<X509Certificate> verificationKeys;
    private final PrivateKey decryptionKey;
    private final SamlElementDecrypter decrypter;
    private final XmlSignatureVerifier verifier = new XmlSignatureVerifier();

    public EcpTranscriptProfileCase(Rule rule, List<X509Certificate> verificationKeys) {
        this(rule, verificationKeys, null, new SamlXmlDecrypter());
    }

    public EcpTranscriptProfileCase(
            Rule rule, List<X509Certificate> verificationKeys, PrivateKey decryptionKey) {
        this(rule, verificationKeys, decryptionKey, new SamlXmlDecrypter());
    }

    EcpTranscriptProfileCase(Rule rule, List<X509Certificate> verificationKeys,
                             PrivateKey decryptionKey, SamlElementDecrypter decrypter) {
        this.rule = java.util.Objects.requireNonNull(rule, "rule");
        this.verificationKeys = List.copyOf(verificationKeys == null ? List.of() : verificationKeys);
        this.decryptionKey = decryptionKey;
        this.decrypter = java.util.Objects.requireNonNull(decrypter, "decrypter");
    }

    public CaseOutcome evaluate(String runId, TranscriptRecorder recorder, TranscriptContentReader content) {
        var exchanges = envelopes(runId, recorder, content);
        var requests = exchanges.stream().filter(value -> value.entry().direction() == Direction.OUTBOUND).toList();
        var responses = exchanges.stream().filter(value -> value.entry().direction() == Direction.INBOUND).toList();
        return switch (rule) {
            case BASIC_EXCHANGE, RESPONSE_OR_FAULT -> exchangeCompletion(requests, responses);
            case RESPONSE_HEADER -> responseHeader(requests, responses);
            case REQUEST_AUTHENTICATED -> requestAuthenticated(requests, responses);
            case HEADER_ATTRIBUTES -> headerAttributes(responses);
            case RESPONSE_INTEGRITY -> integrity(responses);
            case RELAY_STATE_CHOICE -> informational(responses, "ecp.relay-state.choice");
            case DELEGATION_CHOICE -> informational(responses, "ecp.delegation.choice");
            case INTERMEDIATE_EXCHANGES -> informational(exchanges, "ecp.intermediate-exchange.choice");
            case BEARER_CONFIRMATION -> bearer(requests, responses);
            case CHANNEL_BINDINGS -> channelBindings(requests, responses);
            case HTTP_BASIC -> httpBasic(requests, responses);
            case GENERATED_KEY -> generatedKey(requests, responses);
        };
    }

    private CaseOutcome exchangeCompletion(List<Envelope> requests, List<Envelope> responses) {
        if (requests.isEmpty() || responses.isEmpty()) return notVerified("ecp_exchange_not_observed");
        var invalid = responses.stream().filter(value -> !has(value.document(), PROTOCOL, "Response")
                && !has(value.document(), SOAP, "Fault")).map(Envelope::reference).toList();
        return outcome(responses, invalid, "ecp.exchange");
    }

    private CaseOutcome responseHeader(List<Envelope> requests, List<Envelope> responses) {
        if (responses.isEmpty()) return notVerified("ecp_response_not_observed");
        var expected = responseConsumer(requests);
        var scoped = responses.stream().filter(value -> has(value.document(), PROTOCOL, "Response")).toList();
        if (scoped.isEmpty()) return optional("ecp.soap-fault-observed");
        var invalid = new ArrayList<String>();
        for (var response : scoped) {
            var header = first(response.document(), ECP, "Response");
            if (header == null || header.getAttribute("AssertionConsumerServiceURL").isBlank()
                    || (expected != null && !expected.equals(header.getAttribute("AssertionConsumerServiceURL")))) {
                invalid.add(response.reference());
            }
        }
        return outcome(scoped, invalid, "ecp.response-header");
    }

    private CaseOutcome requestAuthenticated(List<Envelope> requests, List<Envelope> responses) {
        var signed = requests.stream().anyMatch(value -> has(value.document(),
                "http://www.w3.org/2000/09/xmldsig#", "Signature"));
        if (!signed) return optional("ecp.signed-request.not-observed");
        var scoped = responses.stream().filter(value -> has(value.document(), PROTOCOL, "Response")).toList();
        if (scoped.isEmpty()) return notVerified("ecp_response_not_observed");
        var invalid = scoped.stream().filter(value -> !has(value.document(), ECP, "RequestAuthenticated"))
                .map(Envelope::reference).toList();
        return outcome(scoped, invalid, "ecp.request-authenticated");
    }

    private CaseOutcome headerAttributes(List<Envelope> responses) {
        if (responses.isEmpty()) return notVerified("ecp_response_not_observed");
        var invalid = new ArrayList<String>();
        var observed = 0;
        for (var response : responses) {
            for (var name : List.of("Response", "RequestAuthenticated", "RelayState")) {
                var namespace = "RelayState".equals(name) ? ECP : ECP;
                var headers = response.document().getElementsByTagNameNS(namespace, name);
                for (var index = 0; index < headers.getLength(); index++) {
                    observed++;
                    var header = (Element) headers.item(index);
                    if (!NEXT.equals(header.getAttributeNS(SOAP, "actor"))) invalid.add(response.reference() + "#" + name);
                    if (("Response".equals(name) || "RelayState".equals(name))
                            && !"1".equals(header.getAttributeNS(SOAP, "mustUnderstand"))) {
                        invalid.add(response.reference() + "#" + name + "-mustUnderstand");
                    }
                }
            }
            var bindings = response.document().getElementsByTagNameNS(CB, "ChannelBindings");
            for (var index = 0; index < bindings.getLength(); index++) {
                var binding = (Element) bindings.item(index);
                if (ancestor(binding, SOAP, "Header")) {
                    observed++;
                    if (!NEXT.equals(binding.getAttributeNS(SOAP, "actor"))
                            || !"1".equals(binding.getAttributeNS(SOAP, "mustUnderstand"))) {
                        invalid.add(response.reference() + "#ChannelBindings");
                    }
                }
            }
        }
        if (observed == 0) return notVerified("ecp_headers_not_observed");
        return outcome(responses, invalid, "ecp.header-attributes");
    }

    private CaseOutcome integrity(List<Envelope> responses) {
        var scoped = responses.stream().filter(value -> has(value.document(), PROTOCOL, "Response")).toList();
        if (scoped.isEmpty()) return notVerified("ecp_response_not_observed");
        if (verificationKeys.isEmpty()) return notVerified("target_signing_key_unavailable");
        var invalid = new ArrayList<String>();
        for (var response : scoped) {
            var assertions = response.document().getElementsByTagNameNS(ASSERTION, "Assertion");
            for (var index = 0; index < assertions.getLength(); index++) {
                var assertion = (Element) assertions.item(index);
                var protocolResponse = ancestorElement(assertion, PROTOCOL, "Response");
                var assertionValid = valid(assertion);
                var responseValid = protocolResponse != null && valid(protocolResponse);
                if (!assertionValid && !responseValid) invalid.add(response.reference() + "#Assertion[" + index + "]");
            }
            if (assertions.getLength() == 0) invalid.add(response.reference() + "#no-assertion");
        }
        return outcome(scoped, invalid, "ecp.response-integrity");
    }

    private CaseOutcome bearer(List<Envelope> requests, List<Envelope> responses) {
        var expected = responseConsumer(requests);
        var confirmations = new ArrayList<Element>();
        responses.forEach(value -> {
            var nodes = value.document().getElementsByTagNameNS(ASSERTION, "SubjectConfirmation");
            for (var index = 0; index < nodes.getLength(); index++) confirmations.add((Element) nodes.item(index));
        });
        if (confirmations.isEmpty()) return notVerified("ecp_subject_confirmation_not_observed");
        var valid = confirmations.stream().anyMatch(value -> {
            if (!BEARER.equals(value.getAttribute("Method"))) return false;
            var data = direct(value, ASSERTION, "SubjectConfirmationData");
            return data != null && !data.getAttribute("Recipient").isBlank()
                    && (expected == null || expected.equals(data.getAttribute("Recipient")));
        });
        return outcome(responses, valid ? List.of() : List.of("bearer-confirmation-missing"), "ecp.bearer");
    }

    private CaseOutcome channelBindings(List<Envelope> requests, List<Envelope> responses) {
        var channelRequests = requests.stream().filter(value ->
                !bindings(value.document(), BindingLocation.REQUEST_EXTENSION).isEmpty()
                        || !bindings(value.document(), BindingLocation.SOAP_HEADER).isEmpty()).toList();
        if (channelRequests.isEmpty()) return notVerified("ecp_channel_binding_probe_not_observed");
        var observedScenarios = new LinkedHashSet<ChannelScenario>();
        var invalid = new ArrayList<String>();
        for (var request : channelRequests) {
            var extensions = bindings(request.document(), BindingLocation.REQUEST_EXTENSION);
            var headers = bindings(request.document(), BindingLocation.SOAP_HEADER);
            var signed = has(request.document(), "http://www.w3.org/2000/09/xmldsig#", "Signature");
            var match = extensions.stream().anyMatch(headers::contains);
            var scenario = scenario(extensions, headers, signed, match);
            observedScenarios.add(scenario);
            var response = responses.stream()
                    .filter(value -> request.entry().correlationId().equals(value.entry().correlationId()))
                    .findFirst().orElse(null);
            if (response == null || !has(response.document(), PROTOCOL, "Response")) {
                invalid.add(request.reference() + "#missing-error-or-success-response");
                continue;
            }
            if (scenario == ChannelScenario.MATCHED_SIGNED) {
                var responseHeaders = bindings(response.document(), BindingLocation.SOAP_HEADER);
                var responseAdvice = bindings(response.document(), BindingLocation.ASSERTION_ADVICE);
                if (!success(response.document())
                        || responseHeaders.stream().noneMatch(extensions::contains)
                        || responseAdvice.stream().noneMatch(extensions::contains)) {
                    invalid.add(response.reference() + "#matched-binding-not-returned-in-both-locations");
                }
            } else if (success(response.document())) {
                invalid.add(response.reference() + "#channel-binding-error-required");
            }
        }
        var required = Set.of(
                ChannelScenario.MATCHED_SIGNED,
                ChannelScenario.MATCHED_UNSIGNED,
                ChannelScenario.MISMATCHED,
                ChannelScenario.REQUEST_ONLY,
                ChannelScenario.HEADER_ONLY);
        var evidence = new ArrayList<Envelope>(channelRequests);
        responses.stream().filter(value -> channelRequests.stream().anyMatch(request ->
                request.entry().correlationId().equals(value.entry().correlationId()))).forEach(evidence::add);
        if (!invalid.isEmpty()) return outcome(evidence, invalid, "ecp.channel-bindings");
        if (!observedScenarios.containsAll(required)) {
            return new CaseOutcome(Outcome.NOT_VERIFIED, "ecp_channel_binding_variants_incomplete",
                    "ecp.channel-bindings.incomplete", "ecp.channel-bindings.incomplete", evidence(evidence),
                    Map.of("observed_scenarios", observedScenarios.stream().map(Enum::name).sorted().toList(),
                            "missing_scenarios", required.stream().filter(value -> !observedScenarios.contains(value))
                                    .map(Enum::name).sorted().toList()));
        }
        return outcome(evidence, List.of(), "ecp.channel-bindings");
    }

    private CaseOutcome httpBasic(List<Envelope> requests, List<Envelope> responses) {
        var basic = requests.stream().anyMatch(value -> value.entry().headers().entrySet().stream()
                .anyMatch(header -> "authorization".equalsIgnoreCase(header.getKey())
                        && header.getValue().stream().anyMatch(item -> item.toLowerCase().contains("basic"))));
        if (!basic) return notVerified("ecp_http_basic_probe_not_observed");
        return exchangeCompletion(requests, responses);
    }

    private CaseOutcome generatedKey(List<Envelope> requests, List<Envelope> responses) {
        var samlEcRequests = requests.stream()
                .filter(value -> has(value.document(), SAML_EC, "SessionKey")).toList();
        if (samlEcRequests.isEmpty()) return notVerified("saml_ec_session_key_probe_not_observed");
        var invalid = new ArrayList<String>();
        var missingResponses = new ArrayList<Envelope>();
        var undecryptable = new ArrayList<EvidenceRef>();
        var scopedResponses = new ArrayList<Envelope>();
        for (var request : samlEcRequests) {
            var response = responses.stream()
                    .filter(value -> request.entry().correlationId().equals(value.entry().correlationId()))
                    .findFirst().orElse(null);
            if (response == null) {
                missingResponses.add(request);
                continue;
            }
            scopedResponses.add(response);
            var keys = response.document().getElementsByTagNameNS(SAML_EC, "GeneratedKey");
            var headerValues = new ArrayList<String>();
            var visibleAdviceValues = new ArrayList<String>();
            for (var index = 0; index < keys.getLength(); index++) {
                var key = (Element) keys.item(index);
                if (ancestor(key, SOAP, "Header")) headerValues.add(key.getTextContent().strip());
                if (ancestor(key, ASSERTION, "Advice")) visibleAdviceValues.add(key.getTextContent().strip());
            }
            if (headerValues.isEmpty() && visibleAdviceValues.isEmpty()) {
                invalid.add(response.reference() + "#GeneratedKey-missing");
                continue;
            }
            for (var value : headerValues) {
                try {
                    if (Base64.getDecoder().decode(value).length < 16) {
                        invalid.add(response.reference() + "#GeneratedKey-too-short");
                    }
                } catch (IllegalArgumentException malformed) {
                    invalid.add(response.reference() + "#GeneratedKey-not-base64");
                }
            }
            var encrypted = response.document().getElementsByTagNameNS(ASSERTION, "EncryptedAssertion");
            if (headerValues.isEmpty() || encrypted.getLength() == 0) {
                invalid.add(response.reference() + "#GeneratedKey-header-or-encryption-missing");
                continue;
            }
            if (decryptionKey == null) {
                undecryptable.add(new EvidenceRef("transcript", response.reference() + "#EncryptedAssertion"));
                continue;
            }
            var adviceValues = new ArrayList<String>();
            var decrypted = false;
            for (var index = 0; index < encrypted.getLength(); index++) {
                try {
                    var assertion = decrypter.decrypt((Element) encrypted.item(index), decryptionKey);
                    decrypted = true;
                    var generated = assertion.getElementsByTagNameNS(SAML_EC, "GeneratedKey");
                    for (var keyIndex = 0; keyIndex < generated.getLength(); keyIndex++) {
                        var key = (Element) generated.item(keyIndex);
                        if (ancestor(key, ASSERTION, "Advice")) adviceValues.add(key.getTextContent().strip());
                    }
                } catch (RuntimeException unavailable) {
                    undecryptable.add(new EvidenceRef(
                            "transcript", response.reference() + "#EncryptedAssertion[" + index + "]"));
                }
            }
            if (decrypted && headerValues.stream().noneMatch(adviceValues::contains)) {
                invalid.add(response.reference() + "#GeneratedKey-advice-copy-missing-or-different");
            }
        }
        if (invalid.isEmpty() && !missingResponses.isEmpty()) {
            return new CaseOutcome(Outcome.NOT_VERIFIED, "saml_ec_response_unavailable",
                    "saml-ec.generated-key.response-unavailable", "saml-ec.generated-key.response-unavailable",
                    evidence(missingResponses), Map.of("missing_responses", missingResponses.size()));
        }
        if (invalid.isEmpty() && !undecryptable.isEmpty()) {
            return new CaseOutcome(Outcome.NOT_VERIFIED, "encrypted_content_not_decryptable",
                    "saml-ec.generated-key.not-decrypted", "saml-ec.generated-key.not-decrypted",
                    List.copyOf(undecryptable), Map.of("undecrypted_assertions", undecryptable.size()));
        }
        var evidence = new ArrayList<Envelope>(samlEcRequests);
        evidence.addAll(scopedResponses);
        return outcome(evidence, invalid, "saml-ec.generated-key");
    }

    private CaseOutcome informational(List<Envelope> messages, String code) {
        return new CaseOutcome(
                Outcome.SATISFIED_WITH_NOTE, null, code, code, evidence(messages),
                Map.of("observed_envelopes", messages.size()));
    }
    private CaseOutcome optional(String code) {
        return new CaseOutcome(Outcome.SATISFIED_WITH_NOTE, null, code, code, List.of(), Map.of());
    }
    private CaseOutcome notVerified(String reason) {
        return CaseOutcome.notVerified(reason, "ecp." + reason.replace('_', '-'));
    }
    private CaseOutcome outcome(List<Envelope> messages, List<String> violations, String code) {
        return new CaseOutcome(
                violations.isEmpty() ? Outcome.SATISFIED : Outcome.VIOLATED, null,
                violations.isEmpty() ? code + ".satisfied" : code + ".violated",
                violations.isEmpty() ? code + ".satisfied" : code + ".violated",
                evidence(messages), Map.of("observed", messages.size(), "violations", List.copyOf(violations)));
    }
    private List<EvidenceRef> evidence(List<Envelope> messages) {
        return messages.stream().map(value -> new EvidenceRef("transcript", value.reference())).distinct().toList();
    }
    private boolean valid(Element element) {
        return verificationKeys.stream().anyMatch(certificate -> verifier.hasValidEnvelopedSignature(element, certificate));
    }

    private ChannelScenario scenario(List<BindingValue> extensions, List<BindingValue> headers,
                                     boolean signed, boolean match) {
        if (extensions.isEmpty()) return ChannelScenario.HEADER_ONLY;
        if (headers.isEmpty()) return ChannelScenario.REQUEST_ONLY;
        if (!match) return ChannelScenario.MISMATCHED;
        return signed ? ChannelScenario.MATCHED_SIGNED : ChannelScenario.MATCHED_UNSIGNED;
    }

    private List<BindingValue> bindings(org.w3c.dom.Document document, BindingLocation location) {
        var result = new ArrayList<BindingValue>();
        var nodes = document.getElementsByTagNameNS(CB, "ChannelBindings");
        for (var index = 0; index < nodes.getLength(); index++) {
            var element = (Element) nodes.item(index);
            var included = switch (location) {
                case SOAP_HEADER -> ancestor(element, SOAP, "Header");
                case REQUEST_EXTENSION -> ancestor(element, PROTOCOL, "Extensions");
                case ASSERTION_ADVICE -> ancestor(element, ASSERTION, "Advice");
            };
            if (included) result.add(new BindingValue(element.getAttribute("Type"), element.getTextContent().strip()));
        }
        return List.copyOf(result);
    }

    private boolean success(org.w3c.dom.Document document) {
        var response = first(document, PROTOCOL, "Response");
        var status = direct(response, PROTOCOL, "Status");
        var code = direct(status, PROTOCOL, "StatusCode");
        return code != null && "urn:oasis:names:tc:SAML:2.0:status:Success".equals(code.getAttribute("Value"));
    }
    private String responseConsumer(List<Envelope> requests) {
        var paosValue = requests.stream().map(value -> first(value.document(), PAOS, "Request"))
                .filter(java.util.Objects::nonNull).map(value -> value.getAttribute("responseConsumerURL"))
                .filter(value -> !value.isBlank()).findFirst();
        if (paosValue.isPresent()) return paosValue.orElseThrow();
        return requests.stream().map(value -> first(value.document(), PROTOCOL, "AuthnRequest"))
                .filter(java.util.Objects::nonNull)
                .map(value -> value.getAttribute("AssertionConsumerServiceURL"))
                .filter(value -> !value.isBlank()).findFirst().orElse(null);
    }
    private List<String> values(org.w3c.dom.Document document, String namespace, String name, boolean headerOnly) {
        var result = new ArrayList<String>();
        var nodes = document.getElementsByTagNameNS(namespace, name);
        for (var index = 0; index < nodes.getLength(); index++) {
            var element = (Element) nodes.item(index);
            if (headerOnly == ancestor(element, SOAP, "Header")) result.add(element.getTextContent().strip());
        }
        return result;
    }

    private List<Envelope> envelopes(String runId, TranscriptRecorder recorder, TranscriptContentReader content) {
        var result = new ArrayList<Envelope>();
        for (var entry : recorder.list(runId)) {
            if (entry.decodedSamlRef() == null || entry.decodedSamlBytes() == 0) continue;
            try {
                var document = SecureXml.parse(content.readDecodedSaml(entry));
                if (SOAP.equals(document.getDocumentElement().getNamespaceURI())
                        && "Envelope".equals(document.getDocumentElement().getLocalName())) {
                    result.add(new Envelope(entry, document, "transcript:" + entry.id()));
                }
            } catch (RuntimeException ignored) {
                // Non-ECP or malformed XML belongs to another case.
            }
        }
        return List.copyOf(result);
    }

    private boolean has(org.w3c.dom.Document document, String namespace, String name) {
        return document.getElementsByTagNameNS(namespace, name).getLength() > 0;
    }
    private Element first(org.w3c.dom.Document document, String namespace, String name) {
        var nodes = document.getElementsByTagNameNS(namespace, name);
        return nodes.getLength() == 0 ? null : (Element) nodes.item(0);
    }
    private Element direct(Element parent, String namespace, String name) {
        if (parent == null) return null;
        for (var child = parent.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (child instanceof Element element && namespace.equals(element.getNamespaceURI())
                    && name.equals(element.getLocalName())) return element;
        }
        return null;
    }
    private boolean ancestor(Element element, String namespace, String name) {
        return ancestorElement(element, namespace, name) != null;
    }
    private Element ancestorElement(Element element, String namespace, String name) {
        for (var node = element.getParentNode(); node != null; node = node.getParentNode()) {
            if (node instanceof Element parent && namespace.equals(parent.getNamespaceURI())
                    && name.equals(parent.getLocalName())) return parent;
        }
        return null;
    }
    private record Envelope(TranscriptEntry entry, org.w3c.dom.Document document, String reference) {}
    private record BindingValue(String type, String value) {}
    private enum BindingLocation { SOAP_HEADER, REQUEST_EXTENSION, ASSERTION_ADVICE }
    private enum ChannelScenario { MATCHED_SIGNED, MATCHED_UNSIGNED, MISMATCHED, REQUEST_ONLY, HEADER_ONLY }
}
