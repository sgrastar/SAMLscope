package com.samlscope.runner.cases;

import java.net.URI;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.security.cert.X509Certificate;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.saml.normal.SamlException;
import com.samlscope.saml.normal.SecureXml;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/** Product-neutral oracles that need only an ordinary AuthnRequest/Response transcript. */
final class NormalFlowBrowserObservation {
    static final String ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";
    static final String PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
    static final String SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
    static final String BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
    static final String PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
    static final String TRANSIENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
    static final String ENTITY = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";
    static final String DS = "http://www.w3.org/2000/09/xmldsig#";
    private static final java.util.Set<String> OBTAINED_CONSENT = java.util.Set.of(
            "urn:oasis:names:tc:SAML:2.0:consent:prior",
            "urn:oasis:names:tc:SAML:2.0:consent:current-implicit",
            "urn:oasis:names:tc:SAML:2.0:consent:current-explicit");

    private NormalFlowBrowserObservation() {}

    static Optional<CaseOutcome> evaluate(String caseId, List<Message> messages) {
        return evaluate(caseId, messages, null);
    }

    static Optional<CaseOutcome> evaluate(
            String caseId, List<Message> messages, String expectedTargetEntityId) {
        return evaluate(caseId, messages, expectedTargetEntityId, List.of());
    }

    static Optional<CaseOutcome> evaluate(
            String caseId,
            List<Message> messages,
            String expectedTargetEntityId,
            List<X509Certificate> targetSigningCertificates) {
        var parsed = parse(messages);
        // Malformed inbound messages still make an observation inconclusive: they could have
        // contained evidence. Malformed outbound requests cannot, and adversarial probes such
        // as DOCTYPE-bearing AuthnRequests must not disable unrelated normal-flow oracles.
        var inbound = messages == null ? 0 : messages.stream().filter(Message::inbound).count();
        var parsedInbound = parsed.stream().filter(value -> value.message().inbound()).count();
        if (parsed.isEmpty() || parsedInbound != inbound) {
            return Optional.empty();
        }
        return switch (caseId) {
            case "IIP-SSO01-a-idp-01" -> completedSpInitiatedSso(parsed);
            case "IIP-SSO01-d-idp-01" -> subjectErrorContainsNoAssertion(parsed);
            case "IIP-SSO01-i1-idp-01" -> sameAssertionIssuer(parsed);
            case "IIP-SSO01-j-idp-01" -> everyAssertionHasBearerConfirmation(parsed);
            case "IIP-SSO01-k-idp-01" -> bearerRecipientAndExpiry(parsed);
            case "IIP-SSO01-k1-idp-01" -> noBearerNotBefore(parsed);
            case "IIP-SSO01-k2-idp-01" -> correlatedResponses(parsed, true);
            case "IIP-SSO01-m-idp-01" -> everyBearerAssertionHasAudience(parsed);
            case "IIP-SSO01-x-idp-01" -> noRedirectResponse(parsed);
            case "IIP-SSO01-ap-idp-01" -> correlatedResponses(parsed, false);
            case "IIP-SSO01-ad-idp-01" -> exchangesUseTls(parsed);
            case "IIP-SSO01-en-idp-01" -> responseVersionNotHigher(parsed);
            case "IIP-SSO01-eo-idp-01" -> responseVersionNotLower(parsed);
            case "IIP-SSO01-ep-idp-01" -> versionMismatchErrors(parsed);
            case "IIP-SSO01-g-idp-01" -> successfulResponsesContainAssertions(parsed);
            case "IIP-SSO01-h-idp-01" -> responseIssuer(parsed, expectedTargetEntityId);
            case "IIP-SSO01-h1-idp-01" -> requiredResponseIssuerPresent(parsed);
            case "IIP-SSO01-i-idp-01" -> assertionIssuers(parsed, expectedTargetEntityId);
            case "IIP-SSO01-l-idp-01" -> authenticationStatements(parsed);
            case "IIP-SSO01-v-idp-01" -> postAssertionsAreSigned(parsed, targetSigningCertificates);
            case "IIP-SSO01-au-idp-01" -> consentResponsesAreSigned(parsed, targetSigningCertificates);
            case "IIP-SSO01-es-idp-01" -> browserAssertionsAreProtected(parsed, targetSigningCertificates);
            case "IIP-SSO01-et-idp-01" -> browserResponsesAreSigned(parsed, targetSigningCertificates);
            case "IIP-SSO01-y-idp-01" -> unsolicitedResponsesAreUncorrelated(parsed);
            case "IIP-SSO01-z-idp-01" -> unsolicitedSsoObserved(parsed);
            case "IIP-SSO02-a-idp-01" -> bothAuthnRequestBindingsObserved(parsed);
            case "IIP-SSO03-a-idp-01" -> successfulPostResponse(parsed);
            case "IIP-SSO03-b-idp-01" -> errorResponsesUsePost(parsed);
            case "IIP-SSO05-a-idp-01" -> requestedNameIdFormat(parsed, PERSISTENT, "persistent");
            case "IIP-SSO05-a2-idp-01" -> nameIdLength(parsed, PERSISTENT, "persistent");
            case "IIP-SSO05-b-idp-01" -> requestedNameIdFormat(parsed, TRANSIENT, "transient");
            case "IIP-SSO05-b1-idp-01" -> nameIdLength(parsed, TRANSIENT, "transient");
            case "IIP-SSO05-b2-idp-01" -> transientIdentifierProperties(parsed);
            case "IIP-IDP09-b-idp-01" -> encryptionChoice(parsed);
            default -> Optional.empty();
        };
    }

    static boolean supports(String caseId) {
        return switch (caseId) {
            case "IIP-SSO01-a-idp-01", "IIP-SSO01-d-idp-01",
                    "IIP-SSO01-i1-idp-01", "IIP-SSO01-j-idp-01", "IIP-SSO01-k-idp-01",
                    "IIP-SSO01-k1-idp-01", "IIP-SSO01-k2-idp-01", "IIP-SSO01-m-idp-01",
                    "IIP-SSO01-x-idp-01",
                    "IIP-SSO01-ad-idp-01", "IIP-SSO01-ap-idp-01", "IIP-SSO01-en-idp-01",
                    "IIP-SSO01-eo-idp-01", "IIP-SSO01-ep-idp-01",
                    "IIP-SSO01-g-idp-01", "IIP-SSO01-h-idp-01",
                    "IIP-SSO01-h1-idp-01", "IIP-SSO01-i-idp-01", "IIP-SSO01-l-idp-01",
                    "IIP-SSO01-v-idp-01", "IIP-SSO01-au-idp-01", "IIP-SSO01-es-idp-01",
                    "IIP-SSO01-et-idp-01", "IIP-SSO01-y-idp-01", "IIP-SSO01-z-idp-01",
                    "IIP-SSO02-a-idp-01",
                    "IIP-SSO03-a-idp-01", "IIP-SSO03-b-idp-01",
                    "IIP-SSO05-a-idp-01", "IIP-SSO05-a2-idp-01",
                    "IIP-SSO05-b-idp-01", "IIP-SSO05-b1-idp-01", "IIP-SSO05-b2-idp-01",
                    "IIP-IDP09-b-idp-01" -> true;
            default -> false;
        };
    }

    static boolean acceptsActiveScenarioEvidence(String caseId) {
        return switch (caseId) {
            case "IIP-SSO01-a-idp-01", "IIP-SSO01-d-idp-01",
                    "IIP-SSO01-g-idp-01", "IIP-SSO01-h-idp-01", "IIP-SSO01-j-idp-01",
                    "IIP-SSO01-h1-idp-01", "IIP-SSO01-i-idp-01", "IIP-SSO01-l-idp-01",
                    "IIP-SSO01-v-idp-01",
                    "IIP-SSO01-k-idp-01",
                    "IIP-SSO01-k1-idp-01", "IIP-SSO01-k2-idp-01", "IIP-SSO01-ad-idp-01",
                    "IIP-SSO01-x-idp-01",
                    "IIP-SSO01-ap-idp-01", "IIP-SSO01-en-idp-01",
                    "IIP-SSO01-eo-idp-01", "IIP-SSO01-ep-idp-01", "IIP-SSO03-a-idp-01",
                    "IIP-SSO02-a-idp-01",
                    "IIP-SSO03-b-idp-01",
                    "IIP-SSO05-a-idp-01", "IIP-SSO05-a2-idp-01",
                    "IIP-SSO05-b-idp-01", "IIP-SSO05-b1-idp-01", "IIP-SSO05-b2-idp-01" -> true;
            default -> false;
        };
    }

    private static Optional<CaseOutcome> completedSpInitiatedSso(List<Parsed> messages) {
        var requests = requestsById(messages);
        var evidence = new ArrayList<EvidenceRef>();
        var completed = 0;
        for (var response : successfulResponses(messages)) {
            var requestId = response.document().getDocumentElement().getAttribute("InResponseTo");
            var request = requests.get(requestId);
            if (request == null) continue;
            var assertions = elements(response.document(), ASSERTION, "Assertion").size()
                    + elements(response.document(), ASSERTION, "EncryptedAssertion").size();
            if (assertions == 0) continue;
            completed++;
            evidence.add(request.evidence());
            evidence.add(response.evidence());
        }
        return completed == 0 ? Optional.empty() : Optional.of(outcome(
                Outcome.SATISFIED, "browser.normal-flow.sp-initiated-sso-completed",
                evidence.stream().distinct().toList(), Map.of("completed_flows", completed)));
    }

    private static Optional<CaseOutcome> subjectErrorContainsNoAssertion(List<Parsed> messages) {
        var requests = requestsById(messages);
        var successfulControl = successfulResponses(messages).stream().anyMatch(response ->
                requests.containsKey(response.document().getDocumentElement().getAttribute("InResponseTo")));
        var evidence = new ArrayList<EvidenceRef>();
        var applicable = 0;
        for (var response : responses(messages)) {
            var root = response.document().getDocumentElement();
            if (SUCCESS.equals(firstAttribute(response.document(), PROTOCOL, "StatusCode", "Value"))) continue;
            var request = requests.get(root.getAttribute("InResponseTo"));
            if (request == null || elements(request.document(), ASSERTION, "Subject").isEmpty()) continue;
            applicable++;
            evidence.add(request.evidence());
            evidence.add(response.evidence());
            var assertions = elements(response.document(), ASSERTION, "Assertion").size()
                    + elements(response.document(), ASSERTION, "EncryptedAssertion").size();
            if (assertions > 0) {
                return Optional.of(outcome(
                        Outcome.VIOLATED, "browser.normal-flow.error-response-contains-assertion",
                        evidence, Map.of("applicable_error_responses", applicable, "assertions", assertions)));
            }
        }
        return applicable == 0 || !successfulControl ? Optional.empty() : Optional.of(outcome(
                Outcome.SATISFIED, "browser.normal-flow.subject-error-without-assertion",
                evidence.stream().distinct().toList(), Map.of("applicable_error_responses", applicable)));
    }

    private static Optional<CaseOutcome> bothAuthnRequestBindingsObserved(List<Parsed> messages) {
        var requests = messages.stream()
                .filter(value -> isRoot(value.document(), PROTOCOL, "AuthnRequest"))
                .toList();
        var methods = requests.stream()
                .map(value -> value.message().method().toUpperCase(java.util.Locale.ROOT))
                .collect(java.util.stream.Collectors.toCollection(java.util.LinkedHashSet::new));
        if (!methods.contains("GET") || !methods.contains("POST")) return Optional.empty();
        return Optional.of(outcome(
                Outcome.SATISFIED, "browser.normal-flow.authn-request-redirect-and-post-observed",
                evidence(requests), Map.of("request_methods", List.copyOf(methods))));
    }

    private static Optional<CaseOutcome> bearerRecipientAndExpiry(List<Parsed> messages) {
        var evidence = new ArrayList<EvidenceRef>();
        var destinations = new java.util.LinkedHashSet<String>();
        var confirmations = 0;
        for (var response : successfulResponses(messages)) {
            var actualAcs = response.message().url();
            if (actualAcs == null || actualAcs.isBlank()) continue;
            var issueInstant = instant(response.document().getDocumentElement().getAttribute("IssueInstant"));
            for (var confirmation : elements(response.document(), ASSERTION, "SubjectConfirmation")) {
                if (!BEARER.equals(confirmation.getAttribute("Method"))) continue;
                var data = direct(confirmation, ASSERTION, "SubjectConfirmationData");
                if (data == null) continue;
                confirmations++;
                evidence.add(response.evidence());
                var recipient = data.getAttribute("Recipient");
                var notOnOrAfter = instant(data.getAttribute("NotOnOrAfter"));
                if (!actualAcs.equals(recipient)) {
                    return Optional.of(outcome(
                            Outcome.VIOLATED, "browser.normal-flow.bearer-recipient-mismatch",
                            evidence, Map.of(
                                    "actual_acs", actualAcs,
                                    "recipient", recipient,
                                    "bearer_confirmations", confirmations)));
                }
                var responseTime = issueInstant == null ? response.message().timestamp() : issueInstant;
                if (notOnOrAfter == null || !notOnOrAfter.isAfter(responseTime)) {
                    return Optional.of(outcome(
                            Outcome.VIOLATED, "browser.normal-flow.bearer-expiry-missing-or-not-later",
                            evidence, Map.of(
                                    "recipient", recipient,
                                    "not_on_or_after", data.getAttribute("NotOnOrAfter"),
                                    "bearer_confirmations", confirmations)));
                }
                destinations.add(actualAcs);
            }
        }
        // A positive result requires the approved alternate-ACS control, not just one ordinary flow.
        if (confirmations == 0 || destinations.size() < 2) return Optional.empty();
        return Optional.of(outcome(
                Outcome.SATISFIED, "browser.normal-flow.bearer-recipient-and-expiry-valid",
                evidence.stream().distinct().toList(), Map.of(
                        "bearer_confirmations", confirmations,
                        "distinct_acs_destinations", destinations.size())));
    }

    private static Optional<CaseOutcome> responseIssuer(
            List<Parsed> messages, String expectedTargetEntityId) {
        if (expectedTargetEntityId == null || expectedTargetEntityId.isBlank()) return Optional.empty();
        var responses = responses(messages);
        if (responses.isEmpty()) return Optional.empty();
        var evidence = new ArrayList<EvidenceRef>();
        var present = 0;
        for (var response : responses) {
            evidence.add(response.evidence());
            var issuer = direct(response.document().getDocumentElement(), ASSERTION, "Issuer");
            if (issuer == null) continue; // The profile explicitly permits omission.
            present++;
            var format = issuer.getAttribute("Format");
            if ((!format.isBlank() && !"urn:oasis:names:tc:SAML:2.0:nameid-format:entity".equals(format))
                    || !expectedTargetEntityId.equals(issuer.getTextContent())) {
                return Optional.of(outcome(
                        Outcome.VIOLATED, "browser.normal-flow.response-issuer-invalid",
                        evidence, Map.of(
                                "issuers_present", present,
                                "expected_entity_id", expectedTargetEntityId,
                                "actual_entity_id", issuer.getTextContent(),
                                "format", format)));
            }
        }
        return Optional.of(outcome(
                present == 0 ? Outcome.SATISFIED_WITH_NOTE : Outcome.SATISFIED,
                present == 0
                        ? "browser.normal-flow.response-issuer-omitted"
                        : "browser.normal-flow.response-issuer-valid",
                evidence, Map.of("responses", responses.size(), "issuers_present", present)));
    }

    private static Optional<CaseOutcome> requiredResponseIssuerPresent(List<Parsed> messages) {
        var evidence = new ArrayList<EvidenceRef>();
        var applicable = 0;
        for (var response : responses(messages)) {
            var root = response.document().getDocumentElement();
            var signed = direct(root, DS, "Signature") != null;
            var encrypted = direct(root, ASSERTION, "EncryptedAssertion") != null;
            if (!signed && !encrypted) continue;
            applicable++;
            evidence.add(response.evidence());
            if (direct(root, ASSERTION, "Issuer") == null) {
                return Optional.of(outcome(
                        Outcome.VIOLATED, "browser.normal-flow.required-response-issuer-missing",
                        evidence, Map.of("signed", signed, "encrypted_assertion", encrypted)));
            }
        }
        return applicable == 0 ? Optional.empty() : Optional.of(outcome(
                Outcome.SATISFIED, "browser.normal-flow.required-response-issuer-present",
                evidence, Map.of("applicable_responses", applicable)));
    }

    private static Optional<CaseOutcome> assertionIssuers(
            List<Parsed> messages, String expectedTargetEntityId) {
        if (expectedTargetEntityId == null || expectedTargetEntityId.isBlank()) return Optional.empty();
        var evidence = new ArrayList<EvidenceRef>();
        var assertions = 0;
        for (var response : successfulResponses(messages)) {
            for (var assertion : elements(response.document(), ASSERTION, "Assertion")) {
                assertions++;
                evidence.add(response.evidence());
                var issuer = direct(assertion, ASSERTION, "Issuer");
                var value = issuer == null ? "" : issuer.getTextContent();
                var format = issuer == null ? "" : issuer.getAttribute("Format");
                if (issuer == null || !expectedTargetEntityId.equals(value)
                        || (!format.isBlank() && !ENTITY.equals(format))) {
                    return Optional.of(outcome(
                            Outcome.VIOLATED, "browser.normal-flow.assertion-issuer-invalid",
                            evidence, Map.of(
                                    "expected_entity_id", expectedTargetEntityId,
                                    "actual_entity_id", value,
                                    "format", format,
                                    "assertions", assertions)));
                }
            }
        }
        return assertions == 0 ? Optional.empty() : Optional.of(outcome(
                Outcome.SATISFIED, "browser.normal-flow.assertion-issuer-valid",
                evidence.stream().distinct().toList(), Map.of("assertions", assertions)));
    }

    private static Optional<CaseOutcome> authenticationStatements(List<Parsed> messages) {
        var requests = new LinkedHashMap<String, Instant>();
        for (var parsed : messages) {
            var root = parsed.document().getDocumentElement();
            if (PROTOCOL.equals(root.getNamespaceURI()) && "AuthnRequest".equals(root.getLocalName())) {
                var id = root.getAttribute("ID");
                var issued = instant(root.getAttribute("IssueInstant"));
                if (!id.isBlank() && issued != null) requests.put(id, issued);
            }
        }
        var evidence = new ArrayList<EvidenceRef>();
        var responses = 0;
        var statements = 0;
        for (var response : successfulResponses(messages)) {
            var inResponseTo = response.document().getDocumentElement().getAttribute("InResponseTo");
            var requestTime = requests.get(inResponseTo);
            if (requestTime == null) continue;
            responses++;
            evidence.add(response.evidence());
            var responseStatements = elements(response.document(), ASSERTION, "AuthnStatement");
            if (responseStatements.isEmpty()) {
                return Optional.of(outcome(
                        Outcome.VIOLATED, "browser.normal-flow.authn-statement-missing",
                        evidence, Map.of("correlated_responses", responses)));
            }
            for (var statement : responseStatements) {
                statements++;
                var authnInstant = instant(statement.getAttribute("AuthnInstant"));
                if (authnInstant == null) {
                    return Optional.of(outcome(
                            Outcome.VIOLATED, "browser.normal-flow.authn-instant-invalid",
                            evidence, Map.of(
                                    "authn_instant", statement.getAttribute("AuthnInstant"),
                                    "statements", statements)));
                }
            }
        }
        return responses == 0 ? Optional.empty() : Optional.of(outcome(
                Outcome.SATISFIED, "browser.normal-flow.authn-statements-valid",
                evidence, Map.of("correlated_responses", responses, "statements", statements)));
    }

    private static Optional<CaseOutcome> postAssertionsAreSigned(
            List<Parsed> messages, List<X509Certificate> certificates) {
        if (certificates == null || certificates.isEmpty()) return Optional.empty();
        var verifier = new XmlSignatureVerifier();
        var evidence = new ArrayList<EvidenceRef>();
        var assertions = 0;
        var responses = 0;
        for (var response : successfulResponses(messages)) {
            if (!"POST".equalsIgnoreCase(response.message().method())) continue;
            var root = response.document().getDocumentElement();
            var enclosed = elements(response.document(), ASSERTION, "Assertion");
            var responseSigned = certificates.stream()
                    .anyMatch(certificate -> verifier.hasValidEnvelopedSignature(root, certificate));
            if (responseSigned) {
                responses++;
                assertions += enclosed.size();
                evidence.add(response.evidence());
                continue;
            }
            // An encrypted signed Assertion cannot be verified without replacing the wrapper,
            // but doing that would invalidate an outer Response signature. Keep this passive
            // oracle inconclusive instead of declaring an unobservable inner signature absent.
            if (enclosed.isEmpty()
                    && !elements(response.document(), ASSERTION, "EncryptedAssertion").isEmpty()) {
                return Optional.empty();
            }
            if (enclosed.isEmpty()) continue;
            responses++;
            assertions += enclosed.size();
            evidence.add(response.evidence());
            var unsigned = enclosed.stream().filter(assertion -> certificates.stream()
                    .noneMatch(certificate -> verifier.hasValidEnvelopedSignature(assertion, certificate))).count();
            if (unsigned > 0) {
                return Optional.of(outcome(
                        Outcome.VIOLATED, "browser.normal-flow.post-assertions-not-signed",
                        evidence, Map.of(
                                "responses", responses,
                                "assertions", assertions,
                                "unprotected_assertions", unsigned)));
            }
        }
        return responses == 0 ? Optional.empty() : Optional.of(outcome(
                Outcome.SATISFIED, "browser.normal-flow.post-assertions-signed",
                evidence, Map.of("responses", responses, "assertions", assertions)));
    }

    private static Optional<CaseOutcome> consentResponsesAreSigned(
            List<Parsed> messages, List<X509Certificate> certificates) {
        if (certificates == null || certificates.isEmpty()) return Optional.empty();
        var applicable = responses(messages).stream().filter(value -> {
            var consent = value.document().getDocumentElement().getAttribute("Consent");
            return OBTAINED_CONSENT.contains(consent);
        }).toList();
        if (applicable.isEmpty()) {
            var observed = responses(messages);
            return observed.isEmpty() ? Optional.empty() : Optional.of(outcome(
                    Outcome.SATISFIED_WITH_NOTE, "browser.normal-flow.no-obtained-consent-attribute",
                    evidence(observed), Map.of("responses", observed.size(), "applicable_responses", 0)));
        }
        var verifier = new XmlSignatureVerifier();
        var unsigned = applicable.stream().filter(value -> certificates.stream().noneMatch(
                certificate -> verifier.hasValidEnvelopedSignature(
                        value.document().getDocumentElement(), certificate))).toList();
        return Optional.of(outcome(
                unsigned.isEmpty() ? Outcome.SATISFIED : Outcome.VIOLATED,
                unsigned.isEmpty()
                        ? "browser.normal-flow.consent-responses-signed"
                        : "browser.normal-flow.consent-response-not-signed",
                evidence(applicable), Map.of(
                        "applicable_responses", applicable.size(), "unprotected_responses", unsigned.size())));
    }

    private static Optional<CaseOutcome> browserResponsesAreSigned(
            List<Parsed> messages, List<X509Certificate> certificates) {
        if (certificates == null || certificates.isEmpty()) return Optional.empty();
        var observed = responses(messages);
        if (observed.isEmpty()) return Optional.empty();
        var verifier = new XmlSignatureVerifier();
        var unsigned = observed.stream().filter(value -> certificates.stream().noneMatch(
                certificate -> verifier.hasValidEnvelopedSignature(
                        value.document().getDocumentElement(), certificate))).toList();
        return Optional.of(outcome(
                unsigned.isEmpty() ? Outcome.SATISFIED : Outcome.VIOLATED,
                unsigned.isEmpty()
                        ? "browser.normal-flow.responses-signed"
                        : "browser.normal-flow.response-not-signed",
                evidence(observed), Map.of(
                        "responses", observed.size(), "unprotected_responses", unsigned.size())));
    }

    private static Optional<CaseOutcome> browserAssertionsAreProtected(
            List<Parsed> messages, List<X509Certificate> certificates) {
        if (certificates == null || certificates.isEmpty()) return Optional.empty();
        var verifier = new XmlSignatureVerifier();
        var evidence = new ArrayList<EvidenceRef>();
        var assertions = 0;
        var unprotected = 0;
        for (var response : successfulResponses(messages)) {
            var root = response.document().getDocumentElement();
            var responseSigned = certificates.stream().anyMatch(
                    certificate -> verifier.hasValidEnvelopedSignature(root, certificate));
            for (var assertion : elements(response.document(), ASSERTION, "Assertion")) {
                assertions++;
                evidence.add(response.evidence());
                if (!responseSigned && certificates.stream().noneMatch(
                        certificate -> verifier.hasValidEnvelopedSignature(assertion, certificate))) {
                    unprotected++;
                }
            }
            if (!elements(response.document(), ASSERTION, "EncryptedAssertion").isEmpty()
                    && !responseSigned) return Optional.empty();
        }
        if (assertions == 0) return Optional.empty();
        return Optional.of(outcome(
                unprotected == 0 ? Outcome.SATISFIED : Outcome.VIOLATED,
                unprotected == 0
                        ? "browser.normal-flow.assertions-protected"
                        : "browser.normal-flow.assertion-not-protected",
                evidence.stream().distinct().toList(), Map.of(
                        "assertions", assertions, "unprotected_assertions", unprotected)));
    }

    private static Optional<CaseOutcome> unsolicitedResponsesAreUncorrelated(List<Parsed> messages) {
        var unsolicited = successfulResponses(messages).stream().filter(value ->
                value.document().getDocumentElement().getAttribute("InResponseTo").isBlank()).toList();
        return unsolicited.isEmpty() ? Optional.empty() : Optional.of(outcome(
                Outcome.SATISFIED, "browser.normal-flow.unsolicited-response-without-correlation",
                evidence(unsolicited), Map.of("unsolicited_responses", unsolicited.size())));
    }

    private static Optional<CaseOutcome> unsolicitedSsoObserved(List<Parsed> messages) {
        var unsolicited = successfulResponses(messages).stream().filter(value ->
                value.document().getDocumentElement().getAttribute("InResponseTo").isBlank()).toList();
        return unsolicited.isEmpty() ? Optional.empty() : Optional.of(outcome(
                Outcome.SATISFIED_WITH_NOTE, "browser.normal-flow.unsolicited-sso-observed",
                evidence(unsolicited), Map.of("unsolicited_responses", unsolicited.size())));
    }

    private static Optional<CaseOutcome> sameAssertionIssuer(List<Parsed> messages) {
        var inspected = new ArrayList<EvidenceRef>();
        var observedAssertions = 0;
        var observedMultipleAssertions = false;
        for (var message : responses(messages)) {
            var assertions = elements(message.document(), ASSERTION, "Assertion");
            if (assertions.isEmpty()) continue;
            inspected.add(message.evidence());
            observedAssertions += assertions.size();
            observedMultipleAssertions |= assertions.size() > 1;
            var issuers = assertions.stream()
                    .map(assertion -> directText(assertion, ASSERTION, "Issuer"))
                    .distinct().toList();
            if (issuers.size() > 1) {
                return Optional.of(outcome(
                        Outcome.VIOLATED, "browser.normal-flow.assertion-issuers-differ",
                        inspected, Map.of("assertions", observedAssertions, "issuers", issuers)));
            }
        }
        if (!observedMultipleAssertions) {
            return observedAssertions == 0 ? Optional.empty() : Optional.of(outcome(
                    Outcome.SATISFIED_WITH_NOTE,
                    "browser.normal-flow.single-assertion-issuer-vacuously-consistent",
                    inspected, Map.of(
                            "assertions", observedAssertions,
                            "multiple_assertions_observed", false)));
        }
        return Optional.of(outcome(
                Outcome.SATISFIED, "browser.normal-flow.assertion-issuers-consistent", inspected,
                Map.of(
                        "assertions", observedAssertions,
                        "multiple_assertions_observed", true)));
    }

    private static Optional<CaseOutcome> noBearerNotBefore(List<Parsed> messages) {
        var evidence = new ArrayList<EvidenceRef>();
        var observed = 0;
        for (var message : responses(messages)) {
            for (var confirmation : elements(message.document(), ASSERTION, "SubjectConfirmation")) {
                if (!BEARER.equals(confirmation.getAttribute("Method"))) continue;
                var data = direct(confirmation, ASSERTION, "SubjectConfirmationData");
                if (data == null) continue;
                observed++;
                evidence.add(message.evidence());
                if (data.hasAttribute("NotBefore")) {
                    return Optional.of(outcome(
                            Outcome.VIOLATED, "browser.normal-flow.bearer-not-before-present",
                            evidence, Map.of("bearer_confirmations", observed)));
                }
            }
        }
        return observed == 0 ? Optional.empty() : Optional.of(outcome(
                Outcome.SATISFIED, "browser.normal-flow.bearer-not-before-absent",
                evidence, Map.of("bearer_confirmations", observed)));
    }

    private static Optional<CaseOutcome> everyAssertionHasBearerConfirmation(List<Parsed> messages) {
        var evidence = new ArrayList<EvidenceRef>();
        var assertions = 0;
        for (var response : successfulResponses(messages)) {
            for (var assertion : elements(response.document(), ASSERTION, "Assertion")) {
                // An accompanying assertion without an AuthnStatement can be outside this profile.
                // The approved negative control is an authentication assertion that offers only
                // another confirmation method, such as holder-of-key.
                if (elements(assertion, ASSERTION, "AuthnStatement").isEmpty()) continue;
                assertions++;
                evidence.add(response.evidence());
                var bearer = elements(assertion, ASSERTION, "SubjectConfirmation").stream()
                        .anyMatch(value -> BEARER.equals(value.getAttribute("Method")));
                if (!bearer) {
                    return Optional.of(outcome(
                            Outcome.VIOLATED, "browser.normal-flow.assertion-without-bearer",
                            evidence, Map.of("assertions", assertions)));
                }
            }
        }
        return assertions == 0 ? Optional.empty() : Optional.of(outcome(
                Outcome.SATISFIED, "browser.normal-flow.assertions-have-bearer",
                evidence, Map.of("assertions", assertions)));
    }

    private static Optional<CaseOutcome> everyBearerAssertionHasAudience(List<Parsed> messages) {
        var requests = requestsById(messages);
        var evidence = new ArrayList<EvidenceRef>();
        var bearerAssertions = 0;
        var responsesWithBearerAssertions = 0;
        for (var response : successfulResponses(messages)) {
            var requestId = response.document().getDocumentElement().getAttribute("InResponseTo");
            var request = requests.get(requestId);
            if (request == null) continue;
            var requester = directText(
                    request.document().getDocumentElement(), ASSERTION, "Issuer");
            if (requester.isBlank()) continue;
            var assertions = elements(response.document(), ASSERTION, "Assertion");
            var bearerInResponse = assertions.stream().filter(assertion ->
                    elements(assertion, ASSERTION, "SubjectConfirmation").stream()
                            .anyMatch(value -> BEARER.equals(value.getAttribute("Method")))).toList();
            if (!bearerInResponse.isEmpty()) responsesWithBearerAssertions++;
            for (var assertion : bearerInResponse) {
                var bearer = elements(assertion, ASSERTION, "SubjectConfirmation").stream()
                        .anyMatch(value -> BEARER.equals(value.getAttribute("Method")));
                if (!bearer) continue;
                bearerAssertions++;
                evidence.add(request.evidence());
                evidence.add(response.evidence());
                var audiences = elements(assertion, ASSERTION, "AudienceRestriction").stream()
                        .flatMap(value -> elements(value, ASSERTION, "Audience").stream())
                        .map(Element::getTextContent).toList();
                if (!audiences.contains(requester)) {
                    return Optional.of(outcome(
                            Outcome.VIOLATED, "browser.normal-flow.requester-audience-missing",
                            evidence, Map.of(
                                    "bearer_assertions", bearerAssertions,
                                    "requester", requester,
                                    "audiences", audiences)));
                }
            }
        }
        // Exercise the universal rule more than once. The assertions may be emitted in separate
        // successful responses; requiring a target to put multiple assertions in one Response
        // would add a Suite-specific capability that the source requirement does not impose.
        return bearerAssertions < 2 || responsesWithBearerAssertions < 2
                ? Optional.empty() : Optional.of(outcome(
                Outcome.SATISFIED, "browser.normal-flow.requester-audience-present",
                evidence, Map.of(
                        "bearer_assertions", bearerAssertions,
                        "responses_with_bearer_assertions", responsesWithBearerAssertions)));
    }

    private static Optional<CaseOutcome> correlatedResponses(
            List<Parsed> messages, boolean requireBearerConfirmation) {
        var requests = requestsById(messages);
        if (requests.isEmpty()) return Optional.empty();
        var correlated = new LinkedHashMap<String, Parsed>();
        var evidence = new ArrayList<EvidenceRef>();
        for (var response : successfulResponses(messages)) {
            var root = response.document().getDocumentElement();
            var inResponseTo = root.getAttribute("InResponseTo");
            if (inResponseTo.isBlank()) continue; // Unsolicited SSO is outside these obligations.
            evidence.add(response.evidence());
            if (!requests.containsKey(inResponseTo)) {
                return Optional.of(outcome(
                        Outcome.VIOLATED, "browser.normal-flow.response-correlation-unknown",
                        evidence, Map.of("in_response_to", inResponseTo)));
            }
            evidence.add(requests.get(inResponseTo).evidence());
            if (requireBearerConfirmation) {
                var confirmations = elements(response.document(), ASSERTION, "SubjectConfirmation").stream()
                        .filter(value -> BEARER.equals(value.getAttribute("Method"))).toList();
                if (confirmations.isEmpty()) continue;
                var mismatched = confirmations.stream()
                        .map(value -> direct(value, ASSERTION, "SubjectConfirmationData"))
                        .anyMatch(value -> value == null
                                || !inResponseTo.equals(value.getAttribute("InResponseTo")));
                if (mismatched) {
                    return Optional.of(outcome(
                            Outcome.VIOLATED, "browser.normal-flow.bearer-correlation-mismatch",
                            evidence, Map.of("in_response_to", inResponseTo)));
                }
            }
            correlated.put(inResponseTo, response);
        }
        // The approved controls require two consecutive flows so a target that reuses the prior
        // request ID cannot pass a one-message oracle.
        if (correlated.size() < 2) return Optional.empty();
        return Optional.of(outcome(
                Outcome.SATISFIED,
                requireBearerConfirmation
                        ? "browser.normal-flow.bearer-correlations-match"
                        : "browser.normal-flow.response-correlations-match",
                evidence.stream().distinct().toList(),
                Map.of("correlated_responses", correlated.size())));
    }

    private static Optional<CaseOutcome> noRedirectResponse(List<Parsed> messages) {
        var responses = responses(messages);
        if (responses.isEmpty()) return Optional.empty();
        var redirect = responses.stream().filter(value -> "GET".equalsIgnoreCase(value.message().method())).toList();
        if (!redirect.isEmpty()) return Optional.of(outcome(
                Outcome.VIOLATED, "browser.normal-flow.redirect-response",
                evidence(redirect), Map.of("responses", responses.size(), "redirect_responses", redirect.size())));
        var post = responses.stream().filter(value -> "POST".equalsIgnoreCase(value.message().method())).toList();
        var success = post.stream().anyMatch(value -> SUCCESS.equals(firstAttribute(
                value.document(), PROTOCOL, "StatusCode", "Value")));
        var error = post.stream().anyMatch(value -> !SUCCESS.equals(firstAttribute(
                value.document(), PROTOCOL, "StatusCode", "Value")));
        // The peer metadata advertises both POST and Redirect ACS endpoints. A positive result
        // therefore requires multiple exercised response paths (success and error) while every
        // observed response still uses POST. One ordinary success is not enough.
        return success && error ? Optional.of(outcome(
                Outcome.SATISFIED, "browser.normal-flow.responses-avoid-redirect",
                evidence(post), Map.of("responses", responses.size(), "post_responses", post.size(),
                        "success_path", true, "error_path", true))) : Optional.empty();
    }

    private static Optional<CaseOutcome> exchangesUseTls(List<Parsed> messages) {
        var requests = messages.stream().filter(value -> isRoot(value.document(), PROTOCOL, "AuthnRequest")).toList();
        var responses = responses(messages);
        if (requests.isEmpty() || responses.isEmpty()) return Optional.empty();
        var exchanges = new ArrayList<Parsed>();
        exchanges.addAll(requests);
        exchanges.addAll(responses);
        var insecure = exchanges.stream().filter(value -> !"https".equalsIgnoreCase(
                URI.create(value.message().url()).getScheme())).toList();
        return Optional.of(outcome(
                insecure.isEmpty() ? Outcome.SATISFIED : Outcome.VIOLATED,
                insecure.isEmpty() ? "browser.normal-flow.tls" : "browser.normal-flow.cleartext-http",
                evidence(exchanges), Map.of("exchanges", exchanges.size(), "insecure_exchanges", insecure.size())));
    }

    private static Optional<CaseOutcome> responseVersionNotHigher(List<Parsed> messages) {
        var requestVersions = new LinkedHashMap<String, Version>();
        for (var message : messages) {
            if (!isRoot(message.document(), PROTOCOL, "AuthnRequest")) continue;
            var root = message.document().getDocumentElement();
            var version = Version.parse(root.getAttribute("Version"));
            if (version != null && !root.getAttribute("ID").isBlank()) {
                requestVersions.put(root.getAttribute("ID"), version);
            }
        }
        var evidence = new ArrayList<EvidenceRef>();
        var compared = 0;
        for (var response : responses(messages)) {
            var root = response.document().getDocumentElement();
            var request = requestVersions.get(root.getAttribute("InResponseTo"));
            var version = Version.parse(root.getAttribute("Version"));
            if (request == null || version == null) continue;
            compared++;
            evidence.add(response.evidence());
            if (version.compareTo(request) > 0) {
                return Optional.of(outcome(
                        Outcome.VIOLATED, "browser.normal-flow.response-version-higher",
                        evidence, Map.of("compared_responses", compared)));
            }
        }
        return compared == 0 ? Optional.empty() : Optional.of(outcome(
                Outcome.SATISFIED, "browser.normal-flow.response-version-not-higher",
                evidence, Map.of("compared_responses", compared)));
    }

    private static Optional<CaseOutcome> responseVersionNotLower(List<Parsed> messages) {
        var requestVersions = requestVersions(messages);
        var evidence = new ArrayList<EvidenceRef>();
        var compared = 0;
        for (var response : responses(messages)) {
            var root = response.document().getDocumentElement();
            var request = requestVersions.get(root.getAttribute("InResponseTo"));
            var version = Version.parse(root.getAttribute("Version"));
            if (request == null || version == null) continue;
            compared++;
            evidence.add(response.evidence());
            if (version.major() >= request.major()) continue;
            var codes = elements(response.document(), PROTOCOL, "StatusCode");
            var requestVersionTooHigh = codes.size() > 1 &&
                    "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh"
                            .equals(codes.get(1).getAttribute("Value"));
            if (!requestVersionTooHigh) {
                return Optional.of(outcome(
                        Outcome.VIOLATED, "browser.normal-flow.response-version-lower",
                        evidence, Map.of(
                                "request_version", request.major() + "." + request.minor(),
                                "response_version", version.major() + "." + version.minor())));
            }
        }
        return compared == 0 ? Optional.empty() : Optional.of(outcome(
                Outcome.SATISFIED, "browser.normal-flow.response-version-not-lower",
                evidence, Map.of("compared_responses", compared)));
    }

    private static Optional<CaseOutcome> versionMismatchErrors(List<Parsed> messages) {
        var requestVersions = requestVersions(messages);
        var evidence = new ArrayList<EvidenceRef>();
        var observed = 0;
        for (var response : responses(messages)) {
            var root = response.document().getDocumentElement();
            var request = requestVersions.get(root.getAttribute("InResponseTo"));
            if (request == null || request.major() == 2) continue;
            observed++;
            evidence.add(response.evidence());
            var top = firstAttribute(response.document(), PROTOCOL, "StatusCode", "Value");
            if (!"urn:oasis:names:tc:SAML:2.0:status:VersionMismatch".equals(top)) {
                return Optional.of(outcome(
                        Outcome.VIOLATED, "browser.normal-flow.version-mismatch-status-missing",
                        evidence, Map.of("request_major", request.major(), "top_status", top)));
            }
        }
        return observed == 0 ? Optional.empty() : Optional.of(outcome(
                Outcome.SATISFIED, "browser.normal-flow.version-mismatch-status",
                evidence, Map.of("unsupported_version_responses", observed)));
    }

    private static Map<String, Version> requestVersions(List<Parsed> messages) {
        var result = new LinkedHashMap<String, Version>();
        for (var message : messages) {
            if (!isRoot(message.document(), PROTOCOL, "AuthnRequest")) continue;
            var root = message.document().getDocumentElement();
            var version = Version.parse(root.getAttribute("Version"));
            if (version != null && !root.getAttribute("ID").isBlank()) {
                result.put(root.getAttribute("ID"), version);
            }
        }
        return Map.copyOf(result);
    }

    private static Optional<CaseOutcome> successfulPostResponse(List<Parsed> messages) {
        var successful = responses(messages).stream()
                .filter(value -> SUCCESS.equals(firstAttribute(value.document(), PROTOCOL, "StatusCode", "Value")))
                .toList();
        if (successful.isEmpty()) return Optional.empty();
        var post = successful.stream().filter(value -> "POST".equalsIgnoreCase(value.message().method())).toList();
        if (post.isEmpty()) return Optional.empty();
        return Optional.of(outcome(
                Outcome.SATISFIED, "browser.normal-flow.post-response-supported",
                evidence(post), Map.of("successful_post_responses", post.size())));
    }

    private static Optional<CaseOutcome> successfulResponsesContainAssertions(List<Parsed> messages) {
        var evidence = new ArrayList<EvidenceRef>();
        var spInitiated = false;
        var unsolicited = false;
        var successful = 0;
        for (var response : successfulResponses(messages)) {
            successful++;
            evidence.add(response.evidence());
            var root = response.document().getDocumentElement();
            var count = response.document().getElementsByTagNameNS(ASSERTION, "Assertion").getLength()
                    + response.document().getElementsByTagNameNS(ASSERTION, "EncryptedAssertion").getLength();
            if (count == 0) {
                return Optional.of(outcome(
                        Outcome.VIOLATED, "browser.normal-flow.success-without-assertion",
                        evidence, Map.of("successful_responses", successful)));
            }
            if (root.getAttribute("InResponseTo").isBlank()) unsolicited = true;
            else spInitiated = true;
        }
        // The approved case covers both SP-initiated and IdP-initiated success paths.
        if (!spInitiated || !unsolicited) return Optional.empty();
        return Optional.of(outcome(
                Outcome.SATISFIED, "browser.normal-flow.success-responses-have-assertions",
                evidence, Map.of(
                        "successful_responses", successful,
                        "sp_initiated", true,
                        "unsolicited", true)));
    }

    private static Optional<CaseOutcome> errorResponsesUsePost(List<Parsed> messages) {
        var requests = requestsById(messages);
        if (requests.isEmpty()) return Optional.empty();
        // A reject-everything target cannot prove binding support. Keep the approved
        // normal-success positive control and correlate it to an issued request.
        var controls = successfulResponses(messages).stream().filter(response -> {
            var root = response.document().getDocumentElement();
            return requests.containsKey(root.getAttribute("InResponseTo"))
                    && "POST".equalsIgnoreCase(response.message().method())
                    && (elements(root, ASSERTION, "Assertion").size()
                        + elements(root, ASSERTION, "EncryptedAssertion").size()) > 0;
        }).limit(1).toList();
        if (controls.isEmpty()) return Optional.empty();
        var evidence = new ArrayList<EvidenceRef>();
        for (var control : controls) {
            evidence.add(requests.get(control.document().getDocumentElement()
                    .getAttribute("InResponseTo")).evidence());
            evidence.add(control.evidence());
        }
        var errorKinds = new java.util.LinkedHashSet<String>();
        for (var response : responses(messages)) {
            var root = response.document().getDocumentElement();
            var status = direct(root, PROTOCOL, "Status");
            var code = status == null ? null : direct(status, PROTOCOL, "StatusCode");
            if (code == null || !java.util.Set.of(
                    "urn:oasis:names:tc:SAML:2.0:status:Requester",
                    "urn:oasis:names:tc:SAML:2.0:status:Responder",
                    "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch")
                    .contains(code.getAttribute("Value"))) continue;
            var request = requests.get(root.getAttribute("InResponseTo"));
            if (request == null) continue;
            var kind = errorTriggerKind(request.document());
            if (kind == null) continue;
            evidence.add(request.evidence());
            evidence.add(response.evidence());
            if (!"POST".equalsIgnoreCase(response.message().method())) {
                return Optional.of(outcome(
                        Outcome.VIOLATED, "browser.normal-flow.error-response-not-post",
                        evidence.stream().distinct().toList(),
                        Map.of("error_kind", kind, "method", response.message().method())));
            }
            errorKinds.add(kind);
        }
        // The approved IdP variant requires an unsatisfiable request with a POST
        // error Response; it does not prescribe two distinct error-trigger kinds.
        return errorKinds.isEmpty() ? Optional.empty() : Optional.of(outcome(
                Outcome.SATISFIED, "browser.normal-flow.error-responses-use-post",
                evidence.stream().distinct().toList(), Map.of(
                        "error_kinds", List.copyOf(errorKinds),
                        "successful_control_responses", controls.size())));
    }

    private static String errorTriggerKind(Document request) {
        var root = request.getDocumentElement();
        var version = Version.parse(root.getAttribute("Version"));
        if (version != null && version.major() != 2) return "unsupported_version";
        if ("true".equals(root.getAttribute("IsPassive"))) return "is_passive";
        if (root.hasAttribute("ProtocolBinding")
                && !"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                .equals(root.getAttribute("ProtocolBinding"))) return "protocol_binding";
        var policies = elements(root, PROTOCOL, "NameIDPolicy");
        if (policies.stream().anyMatch(value -> value.getAttribute("Format").startsWith(
                "urn:samlscope:probe:unknown-nameid-format:"))) return "unknown_nameid_format";
        if (!elements(root, PROTOCOL, "RequestedAuthnContext").isEmpty()) return "requested_authn_context";
        if (!elements(root, ASSERTION, "Subject").isEmpty()) return "subject";
        return null;
    }

    private static Optional<CaseOutcome> nameIdLength(
            List<Parsed> messages, String format, String label) {
        var evidence = new ArrayList<EvidenceRef>();
        var observed = 0;
        var longest = 0;
        for (var response : responses(messages)) {
            for (var nameId : elements(response.document(), ASSERTION, "NameID")) {
                if (!format.equals(nameId.getAttribute("Format"))) continue;
                observed++;
                evidence.add(response.evidence());
                var length = nameId.getTextContent().codePointCount(0, nameId.getTextContent().length());
                longest = Math.max(longest, length);
                if (length > 256) {
                    return Optional.of(outcome(
                            Outcome.VIOLATED, "browser.normal-flow." + label + "-nameid-too-long",
                            evidence, Map.of("observed_nameids", observed, "longest_code_points", longest)));
                }
            }
        }
        return observed == 0 ? Optional.empty() : Optional.of(outcome(
                Outcome.SATISFIED, "browser.normal-flow." + label + "-nameid-length",
                evidence, Map.of("observed_nameids", observed, "longest_code_points", longest)));
    }

    private static Optional<CaseOutcome> transientIdentifierProperties(List<Parsed> messages) {
        var evidence = new ArrayList<EvidenceRef>();
        var values = new java.util.LinkedHashSet<String>();
        var observed = 0;
        for (var response : responses(messages)) {
            for (var nameId : elements(response.document(), ASSERTION, "NameID")) {
                if (!TRANSIENT.equals(nameId.getAttribute("Format"))) continue;
                observed++;
                evidence.add(response.evidence());
                var value = nameId.getTextContent();
                if (!isXmlName(value)) {
                    return Optional.of(outcome(
                            Outcome.VIOLATED, "browser.normal-flow.transient-nameid-invalid-lexical-form",
                            evidence, Map.of("observed_nameids", observed, "value", value)));
                }
                values.add(value);
            }
        }
        if (observed < 2 || values.size() < 2) return Optional.empty();
        return Optional.of(outcome(
                Outcome.SATISFIED, "browser.normal-flow.transient-nameids-valid-and-changing",
                evidence.stream().distinct().toList(), Map.of(
                        "observed_nameids", observed,
                        "distinct_values", values.size())));
    }

    private static boolean isXmlName(String value) {
        if (value == null || value.isEmpty()) return false;
        var first = value.codePointAt(0);
        if (!isXmlNameStart(first)) return false;
        for (var offset = Character.charCount(first); offset < value.length();) {
            var codePoint = value.codePointAt(offset);
            if (!isXmlNamePart(codePoint)) return false;
            offset += Character.charCount(codePoint);
        }
        return true;
    }

    private static boolean isXmlNameStart(int value) {
        return value == '_' || value >= 'A' && value <= 'Z'
                || value >= 'a' && value <= 'z'
                || value >= 0xC0 && value <= 0xD6 || value >= 0xD8 && value <= 0xF6
                || value >= 0xF8 && value <= 0x2FF || value >= 0x370 && value <= 0x37D
                || value >= 0x37F && value <= 0x1FFF || value >= 0x200C && value <= 0x200D
                || value >= 0x2070 && value <= 0x218F || value >= 0x2C00 && value <= 0x2FEF
                || value >= 0x3001 && value <= 0xD7FF || value >= 0xF900 && value <= 0xFDCF
                || value >= 0xFDF0 && value <= 0xFFFD || value >= 0x10000 && value <= 0xEFFFF;
    }

    private static boolean isXmlNamePart(int value) {
        return isXmlNameStart(value) || value == '-' || value == '.' || value >= '0' && value <= '9'
                || value == 0xB7 || value >= 0x300 && value <= 0x36F
                || value >= 0x203F && value <= 0x2040;
    }

    private static Optional<CaseOutcome> requestedNameIdFormat(
            List<Parsed> messages, String requestedFormat, String label) {
        var requests = new LinkedHashMap<String, Parsed>();
        for (var message : messages) {
            if (!isRoot(message.document(), PROTOCOL, "AuthnRequest")) continue;
            var root = message.document().getDocumentElement();
            var policies = elements(root, PROTOCOL, "NameIDPolicy");
            if (policies.stream().anyMatch(value -> requestedFormat.equals(value.getAttribute("Format")))) {
                requests.put(root.getAttribute("ID"), message);
            }
        }
        if (requests.isEmpty()) return Optional.empty();
        for (var response : successfulResponses(messages)) {
            var root = response.document().getDocumentElement();
            var request = requests.get(root.getAttribute("InResponseTo"));
            if (request == null) continue;
            var nameIds = elements(response.document(), ASSERTION, "NameID");
            if (nameIds.isEmpty()) return Optional.empty();
            var evidence = List.of(request.evidence(), response.evidence());
            if (nameIds.stream().noneMatch(value -> requestedFormat.equals(value.getAttribute("Format")))) {
                return Optional.of(outcome(
                        Outcome.VIOLATED, "browser.normal-flow." + label + "-nameid-not-returned",
                        evidence, Map.of("requested_format", requestedFormat)));
            }
            return Optional.of(outcome(
                    Outcome.SATISFIED, "browser.normal-flow." + label + "-nameid-returned",
                    evidence, Map.of("requested_format", requestedFormat)));
        }
        return Optional.empty();
    }

    private static Optional<CaseOutcome> encryptionChoice(List<Parsed> messages) {
        var responses = responses(messages);
        if (responses.isEmpty()) return Optional.empty();
        if (responses.stream().anyMatch(value ->
                value.document().getElementsByTagNameNS(ASSERTION, "EncryptedAssertion").getLength() > 0)) {
            // The choice inside an encrypted assertion is not visible without a decryption observation.
            return Optional.empty();
        }
        var encryptedIds = responses.stream()
                .mapToInt(value -> value.document().getElementsByTagNameNS(ASSERTION, "EncryptedID").getLength()).sum();
        var encryptedAttributes = responses.stream()
                .mapToInt(value -> value.document().getElementsByTagNameNS(ASSERTION, "EncryptedAttribute").getLength()).sum();
        return Optional.of(outcome(
                Outcome.SATISFIED_WITH_NOTE, "browser.normal-flow.encryption-choice-recorded",
                evidence(responses), Map.of(
                        "encrypted_ids", encryptedIds,
                        "encrypted_attributes", encryptedAttributes)));
    }

    private static List<Parsed> parse(List<Message> messages) {
        var result = new ArrayList<Parsed>();
        for (var message : messages == null ? List.<Message>of() : messages) {
            try {
                result.add(new Parsed(message, SecureXml.parse(message.xml()),
                        new EvidenceRef("transcript", message.evidenceRef())));
            } catch (SamlException ignored) {
                // A normal-flow oracle cannot safely conclude from malformed evidence; manual review remains available.
            }
        }
        return List.copyOf(result);
    }

    private static List<Parsed> responses(List<Parsed> messages) {
        return messages.stream().filter(value -> isRoot(value.document(), PROTOCOL, "Response")).toList();
    }

    private static List<Parsed> successfulResponses(List<Parsed> messages) {
        return responses(messages).stream()
                .filter(value -> SUCCESS.equals(firstAttribute(
                        value.document(), PROTOCOL, "StatusCode", "Value")))
                .toList();
    }

    private static Map<String, Parsed> requestsById(List<Parsed> messages) {
        var result = new LinkedHashMap<String, Parsed>();
        for (var message : messages) {
            if (!isRoot(message.document(), PROTOCOL, "AuthnRequest")) continue;
            var root = message.document().getDocumentElement();
            var id = root.getAttribute("ID");
            if (!id.isBlank()) result.put(id, message);
        }
        return Map.copyOf(result);
    }

    private static boolean isRoot(Document document, String namespace, String localName) {
        var root = document.getDocumentElement();
        return namespace.equals(root.getNamespaceURI()) && localName.equals(root.getLocalName());
    }

    private static List<Element> elements(Document document, String namespace, String localName) {
        var nodes = document.getElementsByTagNameNS(namespace, localName);
        var result = new ArrayList<Element>();
        for (var index = 0; index < nodes.getLength(); index++) result.add((Element) nodes.item(index));
        return result;
    }

    private static List<Element> elements(Element parent, String namespace, String localName) {
        var nodes = parent.getElementsByTagNameNS(namespace, localName);
        var result = new ArrayList<Element>();
        for (var index = 0; index < nodes.getLength(); index++) result.add((Element) nodes.item(index));
        return result;
    }

    private static Element direct(Element parent, String namespace, String localName) {
        for (var child = parent.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (child instanceof Element element
                    && namespace.equals(element.getNamespaceURI())
                    && localName.equals(element.getLocalName())) return element;
        }
        return null;
    }

    private static String directText(Element parent, String namespace, String localName) {
        var value = direct(parent, namespace, localName);
        return value == null ? "" : value.getTextContent();
    }

    private static String firstAttribute(Document document, String namespace, String localName, String attribute) {
        var nodes = document.getElementsByTagNameNS(namespace, localName);
        return nodes.getLength() == 0 ? "" : ((Element) nodes.item(0)).getAttribute(attribute);
    }

    private static List<EvidenceRef> evidence(List<Parsed> messages) {
        return messages.stream().map(Parsed::evidence).distinct().toList();
    }

    private static Instant instant(String value) {
        if (value == null || value.isBlank()) return null;
        try { return Instant.parse(value); }
        catch (DateTimeParseException invalid) { return null; }
    }

    private static CaseOutcome outcome(
            Outcome outcome, String reasonCode, List<EvidenceRef> evidence, Map<String, Object> details) {
        return new CaseOutcome(outcome, null, reasonCode, reasonCode, evidence, details);
    }

    record Message(String evidenceRef, String method, String url, Instant timestamp, byte[] xml, boolean inbound) {
        public Message(String evidenceRef, String method, String url, Instant timestamp, byte[] xml) {
            this(evidenceRef, method, url, timestamp, xml, true);
        }
        Message {
            if (evidenceRef == null || evidenceRef.isBlank()) throw new IllegalArgumentException("evidenceRef is required");
            if (method == null || method.isBlank()) throw new IllegalArgumentException("method is required");
            URI.create(url);
            timestamp = timestamp == null ? Instant.EPOCH : timestamp;
            if (xml == null || xml.length == 0) throw new IllegalArgumentException("xml is required");
            xml = xml.clone();
        }
        @Override public byte[] xml() { return xml.clone(); }
    }

    private record Parsed(Message message, Document document, EvidenceRef evidence) {}

    private record Version(int major, int minor) implements Comparable<Version> {
        static Version parse(String value) {
            if (value == null || !value.matches("[0-9]+\\.[0-9]+")) return null;
            var parts = value.split("\\.");
            try { return new Version(Integer.parseInt(parts[0]), Integer.parseInt(parts[1])); }
            catch (NumberFormatException invalid) { return null; }
        }
        @Override public int compareTo(Version other) {
            var majorValue = Integer.compare(major, other.major);
            return majorValue == 0 ? Integer.compare(minor, other.minor) : majorValue;
        }
    }
}
