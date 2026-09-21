package com.samlscope.runner.cases;

import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.xml.XMLConstants;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.transcript.Direction;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.core.transcript.TranscriptEntry;
import com.samlscope.core.transcript.TranscriptRecorder;
import com.samlscope.saml.normal.SamlSchemaValidation;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.saml.binding.RedirectSignatureVerifier;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import org.w3c.dom.Element;

/** Passive Core/Profile checks over target-issued SLO messages and their Suite-side counterparts. */
public final class LogoutTranscriptProfileCase {
    public enum Rule {
        UNIQUE_IDS, IN_RESPONSE_TO, CONSENT_SIGNATURE, TOP_LEVEL_STATUS,
        RESPONSE_VERSION_CEILING, RESPONSE_VERSION_FLOOR, REQUEST_VERSION_SUPPORTED,
        REQUEST_VERSION_2, SCHEMA_STRUCTURE, ASYNC_PLACEMENT, ASYNC_CHOICE,
        RESPONSE_ISSUER_COUNT, RESPONSE_ISSUER_VALUE, RESPONSE_ISSUER_FORMAT, RESPONSE_SIGNATURE,
        REQUEST_ISSUER_COUNT, REQUEST_ISSUER_VALUE, REQUEST_ISSUER_FORMAT, REQUEST_SIGNATURE,
        REQUEST_NOT_ON_OR_AFTER, REQUEST_IDENTIFIER_MATCH, REQUEST_NOT_ON_OR_AFTER_BOUND,
        REDIRECT_LOGOUT_REQUEST_ACCEPTED, TARGET_REDIRECT_LOGOUT_REQUEST, TARGET_REDIRECT_RESPONSE_CONSUMED,
        INFORMATIONAL_PROPAGATION, TARGET_PROPAGATION_CONTINUE, TARGET_PARTIAL_LOGOUT
    }

    private static final String PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String DS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String ASYNC = "urn:oasis:names:tc:SAML:2.0:protocol:ext:async-slo";
    private static final String STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
    private static final String PARTIAL_LOGOUT_STATUS = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout";
    private static final Set<String> TOP_STATUS = Set.of(
            STATUS_SUCCESS,
            "urn:oasis:names:tc:SAML:2.0:status:Requester",
            "urn:oasis:names:tc:SAML:2.0:status:Responder",
            "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch");
    private final Rule rule;
    private final List<X509Certificate> verificationKeys;
    private final String expectedTargetEntityId;
    private final java.security.PrivateKey decryptionKey;
    private final XmlSignatureVerifier xmlSignatures = new XmlSignatureVerifier();
    private final RedirectSignatureVerifier redirectSignatures = new RedirectSignatureVerifier();

    public LogoutTranscriptProfileCase(Rule rule, List<X509Certificate> verificationKeys) {
        this(rule, verificationKeys, null);
    }

    public LogoutTranscriptProfileCase(
            Rule rule, List<X509Certificate> verificationKeys, String expectedTargetEntityId) {
        this(rule, verificationKeys, expectedTargetEntityId, null);
    }

    public LogoutTranscriptProfileCase(Rule rule, List<X509Certificate> verificationKeys,
            String expectedTargetEntityId, java.security.PrivateKey decryptionKey) {
        this.rule = java.util.Objects.requireNonNull(rule, "rule");
        this.verificationKeys = List.copyOf(verificationKeys == null ? List.of() : verificationKeys);
        this.expectedTargetEntityId = expectedTargetEntityId;
        this.decryptionKey = decryptionKey;
    }

    public CaseOutcome evaluate(
            String runId, TranscriptRecorder transcript, TranscriptContentReader content) {
        var snapshot = messages(runId, transcript, content);
        if (!snapshot.issues().isEmpty()) return new CaseOutcome(
                Outcome.NOT_VERIFIED, "logout_evidence_incomplete",
                "slo.evidence.incomplete", "slo.evidence.incomplete",
                snapshot.evidence(), Map.of("evidence_issues", snapshot.issues()));
        var all = snapshot.messages();
        var target = all.stream().filter(value -> value.entry().direction() == Direction.INBOUND).toList();
        var targetLogout = target.stream().filter(value -> value.logout() != null).toList();
        if (targetLogout.isEmpty()) return absent();
        return switch (rule) {
            case UNIQUE_IDS -> unique(targetLogout);
            case IN_RESPONSE_TO -> inResponseTo(targetLogout, all);
            case CONSENT_SIGNATURE -> consentSignature(targetLogout);
            case TOP_LEVEL_STATUS -> topLevelStatus(targetLogout);
            case RESPONSE_VERSION_CEILING -> responseVersionCeiling(targetLogout, all);
            case RESPONSE_VERSION_FLOOR -> responseVersionFloor(targetLogout, all);
            case REQUEST_VERSION_SUPPORTED -> requestVersionSupported(targetLogout, all);
            case REQUEST_VERSION_2 -> requestVersion2(targetLogout);
            case SCHEMA_STRUCTURE -> schema(targetLogout);
            case ASYNC_PLACEMENT -> asyncPlacement(target);
            case ASYNC_CHOICE -> informationalAsync(targetLogout);
            case RESPONSE_ISSUER_COUNT -> issuerCount(targetLogout, "LogoutResponse");
            case RESPONSE_ISSUER_VALUE -> issuerValue(targetLogout, "LogoutResponse");
            case RESPONSE_ISSUER_FORMAT -> issuerFormat(targetLogout, "LogoutResponse");
            case RESPONSE_SIGNATURE -> targetSignature(targetLogout, "LogoutResponse");
            case REQUEST_ISSUER_COUNT -> issuerCount(targetLogout, "LogoutRequest");
            case REQUEST_ISSUER_VALUE -> issuerValue(targetLogout, "LogoutRequest");
            case REQUEST_ISSUER_FORMAT -> issuerFormat(targetLogout, "LogoutRequest");
            case REQUEST_SIGNATURE -> targetSignature(targetLogout, "LogoutRequest");
            case REQUEST_NOT_ON_OR_AFTER -> requestNotOnOrAfter(targetLogout);
            case REQUEST_IDENTIFIER_MATCH -> requestIdentifierMatches(targetLogout, all);
            case REQUEST_NOT_ON_OR_AFTER_BOUND -> requestNotOnOrAfterBound(targetLogout, all);
            case REDIRECT_LOGOUT_REQUEST_ACCEPTED -> redirectLogoutRequestAccepted(targetLogout, all);
            case TARGET_REDIRECT_LOGOUT_REQUEST -> targetRedirectLogoutRequest(targetLogout);
            case TARGET_REDIRECT_RESPONSE_CONSUMED -> targetRedirectResponseConsumed(
                    targetLogout, all, snapshot.entries());
            case INFORMATIONAL_PROPAGATION -> informationalPropagation(targetLogout);
            case TARGET_PROPAGATION_CONTINUE -> targetPropagationContinue(targetLogout, all);
            case TARGET_PARTIAL_LOGOUT -> targetPartialLogout(targetLogout, all);
        };
    }

    static CaseOutcome incompleteHistory() {
        return new CaseOutcome(Outcome.NOT_VERIFIED, "logout_evidence_incomplete",
                "slo.evidence.incomplete", "slo.evidence.incomplete", List.of(),
                Map.of("evidence_issues", List.of("history_incomplete")));
    }

    private CaseOutcome requestIdentifierMatches(List<Message> targetLogout, List<Message> all) {
        var issued = issuedSessionIdentifiers(all);
        if (issued.isEmpty()) return CaseOutcome.notVerified(
                "issued_session_identifier_unavailable", "slo.identifier.assertion-unavailable");
        var requests = targetLogout.stream().filter(value -> is(value.logout(), "LogoutRequest")).toList();
        if (requests.isEmpty()) return optionalNotObserved("slo.LogoutRequest.not-observed");
        var violations = new ArrayList<String>();
        var unobservable = new ArrayList<String>();
        var matched = 0;
        for (var request : requests) {
            var nameIds = directElements(request.logout(), ASSERTION, "NameID");
            var identifierCount = nameIds.size()
                    + directElements(request.logout(), ASSERTION, "BaseID").size()
                    + directElements(request.logout(), ASSERTION, "EncryptedID").size();
            if (identifierCount != 1 || nameIds.size() != 1) {
                // EncryptedID/BaseID needs a dedicated semantic/decryption oracle. A missing or
                // malformed identifier choice is likewise incapable of proving a strong match.
                unobservable.add(request.reference());
                continue;
            }
            var requestedSessions = directElements(request.logout(), PROTOCOL, "SessionIndex").stream()
                    .map(Element::getTextContent).filter(value -> value != null && !value.isBlank()).collect(
                            java.util.stream.Collectors.toSet());
            List<IssuedSessionIdentifier> candidates;
            if (requestedSessions.isEmpty()) {
                candidates = issued;
            } else {
                candidates = issued.stream().filter(candidate -> candidate.sessionIndexes().stream()
                        .anyMatch(requestedSessions::contains)).toList();
                var knownSessions = candidates.stream().flatMap(candidate -> candidate.sessionIndexes().stream())
                        .collect(java.util.stream.Collectors.toSet());
                if (!knownSessions.containsAll(requestedSessions)) {
                    unobservable.add(request.reference());
                    continue;
                }
            }
            var expected = candidates.stream().map(IssuedSessionIdentifier::identifierKey)
                    .collect(java.util.stream.Collectors.toSet());
            if (expected.isEmpty() || requestedSessions.isEmpty() && expected.size() != 1) {
                unobservable.add(request.reference());
            } else if (expected.size() == 1 && expected.contains(identifierKey(nameIds.getFirst()))) {
                matched++;
            } else {
                violations.add(request.reference());
            }
        }
        if (!violations.isEmpty()) {
            return outcome(requests, violations, "slo.logout-request.identifier-strong-match");
        }
        if (!unobservable.isEmpty()) return new CaseOutcome(
                Outcome.NOT_VERIFIED, "logout_identifier_strong_match_unobservable",
                "slo.identifier.strong-match-unobservable", "slo.identifier.strong-match-unobservable",
                evidence(requests), Map.of(
                        "observed", requests.size(), "matched", matched,
                        "unobservable", List.copyOf(unobservable)));
        return outcome(requests, List.of(), "slo.logout-request.identifier-strong-match");
    }

    private CaseOutcome requestNotOnOrAfterBound(List<Message> targetLogout, List<Message> all) {
        var issued = issuedNameIds(all);
        if (issued.isEmpty()) return notVerifiedWithEvidence(targetLogout,
                "issued_session_expiry_unavailable", "slo.not-on-or-after.assertion-unavailable");
        var inspected = new ArrayList<Message>();
        var violations = new ArrayList<String>();
        for (var request : targetLogout.stream().filter(value -> is(value.logout(), "LogoutRequest")).toList()) {
            var nameId = direct(request.logout(), ASSERTION, "NameID");
            if (nameId == null) continue;
            var expiry = issued.get(identifierKey(nameId));
            if (expiry == null) continue;
            try {
                var requestExpiry = java.time.Instant.parse(request.logout().getAttribute("NotOnOrAfter"));
                inspected.add(request);
                if (requestExpiry.isBefore(expiry)) violations.add(request.reference());
            } catch (java.time.format.DateTimeParseException invalid) {
                inspected.add(request);
                violations.add(request.reference());
            }
        }
        if (inspected.isEmpty()) return notVerifiedWithEvidence(targetLogout,
                "logout_session_expiry_correlation_unavailable", "slo.not-on-or-after.correlation-unavailable");
        return outcome(inspected, violations, "slo.logout-request.not-on-or-after-bound");
    }

    private CaseOutcome redirectLogoutRequestAccepted(List<Message> targetLogout, List<Message> all) {
        var redirectRequests = all.stream()
                .filter(value -> value.entry().direction() == Direction.OUTBOUND)
                .filter(value -> is(value.logout(), "LogoutRequest"))
                .filter(value -> "GET".equalsIgnoreCase(value.entry().method()))
                .toList();
        if (redirectRequests.isEmpty()) return optionalNotObserved("slo.redirect.logout-request.not-observed");
        var ids = redirectRequests.stream().map(value -> value.logout().getAttribute("ID")).collect(
                java.util.stream.Collectors.toSet());
        var responses = targetLogout.stream()
                .filter(value -> is(value.logout(), "LogoutResponse"))
                .filter(value -> ids.contains(value.logout().getAttribute("InResponseTo")))
                .toList();
        if (responses.isEmpty()) return CaseOutcome.notVerified(
                "redirect_logout_response_unavailable", "slo.redirect.logout-response-unavailable");
        var violations = responses.stream()
                .filter(value -> !STATUS_SUCCESS.equals(topStatus(value.logout())))
                .map(Message::reference).toList();
        return outcome(responses, violations, "slo.redirect.logout-request-accepted");
    }

    private Map<String, java.time.Instant> issuedNameIds(List<Message> all) {
        var result = new LinkedHashMap<String, java.time.Instant>();
        for (var message : all) {
            if (!isAcceptedNormalResponse(message)) continue;
            for (var assertion : elements(message.document().getDocumentElement(), ASSERTION, "Assertion")) {
                var subject = direct(assertion, ASSERTION, "Subject");
                var nameId = direct(subject, ASSERTION, "NameID");
                if (nameId == null) continue;
                java.time.Instant expiry = null;
                var conditions = direct(assertion, ASSERTION, "Conditions");
                if (conditions != null && !conditions.getAttribute("NotOnOrAfter").isBlank()) {
                    try { expiry = java.time.Instant.parse(conditions.getAttribute("NotOnOrAfter")); }
                    catch (java.time.format.DateTimeParseException ignored) { }
                }
                var current = result.get(identifierKey(nameId));
                if (expiry != null && (current == null || expiry.isAfter(current))) {
                    result.put(identifierKey(nameId), expiry);
                } else if (!result.containsKey(identifierKey(nameId))) {
                    result.put(identifierKey(nameId), null);
                }
            }
        }
        return result;
    }

    private List<IssuedSessionIdentifier> issuedSessionIdentifiers(List<Message> all) {
        var result = new ArrayList<IssuedSessionIdentifier>();
        for (var message : all) {
            if (!isAcceptedNormalResponse(message)) continue;
            for (var assertion : elements(message.document().getDocumentElement(), ASSERTION, "Assertion")) {
                var subject = direct(assertion, ASSERTION, "Subject");
                var nameId = direct(subject, ASSERTION, "NameID");
                if (nameId == null) continue;
                var sessionIndexes = elements(assertion, ASSERTION, "AuthnStatement").stream()
                        .map(statement -> statement.getAttribute("SessionIndex"))
                        .filter(value -> !value.isBlank())
                        .collect(java.util.stream.Collectors.toUnmodifiableSet());
                result.add(new IssuedSessionIdentifier(identifierKey(nameId), sessionIndexes));
            }
        }
        return List.copyOf(result);
    }

    private boolean isAcceptedNormalResponse(Message message) {
        return message.entry().direction() == Direction.INBOUND
                && message.logout() == null
                && "Response".equals(message.entry().samlSummary().get("type"))
                && Boolean.TRUE.equals(message.entry().samlSummary().get("normalFlowAccepted"));
    }

    private String identifierKey(Element nameId) {
        var attributes = new ArrayList<String>();
        for (var index = 0; index < nameId.getAttributes().getLength(); index++) {
            var attribute = nameId.getAttributes().item(index);
            if (XMLConstants.XMLNS_ATTRIBUTE_NS_URI.equals(attribute.getNamespaceURI())) continue;
            var localName = attribute.getLocalName() == null ? attribute.getNodeName() : attribute.getLocalName();
            attributes.add("{" + java.util.Objects.toString(attribute.getNamespaceURI(), "") + "}"
                    + localName + "=" + attribute.getNodeValue());
        }
        attributes.sort(String::compareTo);
        return nameId.getTextContent() + "\u0000" + String.join("\u0000", attributes);
    }

    private List<Element> elements(Element parent, String namespace, String localName) {
        var result = new ArrayList<Element>();
        if (parent == null) return result;
        var nodes = parent.getElementsByTagNameNS(namespace, localName);
        for (var index = 0; index < nodes.getLength(); index++) result.add((Element) nodes.item(index));
        return result;
    }

    private CaseOutcome issuerCount(List<Message> messages, String type) {
        var scoped = messages.stream().filter(value -> is(value.logout(), type)).toList();
        if (scoped.isEmpty()) return optionalNotObserved("slo." + type + ".not-observed");
        var violations = scoped.stream().filter(value ->
                directElements(value.logout(), ASSERTION, "Issuer").size() != 1)
                .map(Message::reference).toList();
        return outcome(scoped, violations, "slo." + type + ".issuer-count");
    }

    private CaseOutcome issuerValue(List<Message> messages, String type) {
        if (expectedTargetEntityId == null || expectedTargetEntityId.isBlank()) {
            return CaseOutcome.notVerified(
                    "target_entity_id_unavailable", "slo.issuer.target-entity-id-unavailable");
        }
        var scoped = messages.stream().filter(value -> is(value.logout(), type)).toList();
        if (scoped.isEmpty()) return optionalNotObserved("slo." + type + ".not-observed");
        var violations = scoped.stream().filter(value -> {
            var issuers = directElements(value.logout(), ASSERTION, "Issuer");
            return issuers.size() != 1 || !expectedTargetEntityId.equals(issuers.getFirst().getTextContent());
        }).map(Message::reference).toList();
        return outcome(scoped, violations, "slo." + type + ".issuer-value");
    }

    private CaseOutcome issuerFormat(List<Message> messages, String type) {
        var scoped = messages.stream().filter(value -> is(value.logout(), type)).toList();
        if (scoped.isEmpty()) return optionalNotObserved("slo." + type + ".not-observed");
        var entity = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";
        var violations = scoped.stream().filter(value -> directElements(value.logout(), ASSERTION, "Issuer").stream()
                .anyMatch(issuer -> !issuer.getAttribute("Format").isBlank()
                        && !entity.equals(issuer.getAttribute("Format"))))
                .map(Message::reference).toList();
        return outcome(scoped, violations, "slo." + type + ".issuer-format");
    }

    private CaseOutcome targetSignature(List<Message> messages, String type) {
        var scoped = messages.stream().filter(value -> is(value.logout(), type)).toList();
        if (scoped.isEmpty()) return optionalNotObserved("slo." + type + ".not-observed");
        var violations = new ArrayList<String>();
        var unverifiable = new ArrayList<String>();
        for (var message : scoped) {
            var xml = direct(message.logout(), DS, "Signature") != null;
            var redirect = "GET".equalsIgnoreCase(message.entry().method()) && message.entry().rawQuery() != null
                    && message.entry().rawQuery().matches("(^|.*&)Signature=[^&]+(&.*|$)");
            if (!xml && !redirect) {
                violations.add(message.reference());
                continue;
            }
            if (verificationKeys.isEmpty()) {
                unverifiable.add(message.reference());
                continue;
            }
            var valid = verificationKeys.stream().anyMatch(certificate ->
                    xml && xmlSignatures.hasValidEnvelopedSignature(message.logout(), certificate)
                            || redirect && redirectSignatures.isValidForMessage(message.entry().rawQuery(), certificate, message.xml()));
            if (!valid) violations.add(message.reference());
        }
        if (violations.isEmpty() && !unverifiable.isEmpty()) return new CaseOutcome(
                Outcome.NOT_VERIFIED, "target_signing_key_unavailable",
                "slo.signature.key-unavailable", "slo.signature.key-unavailable",
                evidence(scoped), Map.of("unverifiable", List.copyOf(unverifiable)));
        return outcome(scoped, violations, "slo." + type + ".signature");
    }

    private CaseOutcome requestNotOnOrAfter(List<Message> messages) {
        var requests = messages.stream().filter(value -> is(value.logout(), "LogoutRequest")).toList();
        if (requests.isEmpty()) return optionalNotObserved("slo.LogoutRequest.not-observed");
        var violations = new ArrayList<String>();
        for (var request : requests) {
            var lexical = request.logout().getAttribute("NotOnOrAfter");
            try {
                if (!lexical.endsWith("Z")) throw new java.time.format.DateTimeParseException("not UTC", lexical, 0);
                java.time.Instant.parse(lexical);
            } catch (java.time.format.DateTimeParseException invalid) {
                violations.add(request.reference());
            }
        }
        return outcome(requests, violations, "slo.logout-request.not-on-or-after");
    }

    private CaseOutcome unique(List<Message> messages) {
        var seen = new HashMap<String, String>();
        var violations = new ArrayList<String>();
        for (var message : messages) {
            var id = message.logout().getAttribute("ID");
            if (id.isBlank()) continue;
            var previous = seen.putIfAbsent(id, message.digest());
            if (previous != null && !previous.equals(message.digest())) violations.add(id);
        }
        return outcome(messages, violations, "slo.id-uniqueness");
    }

    private CaseOutcome inResponseTo(List<Message> target, List<Message> all) {
        var requests = new LinkedHashMap<String, Element>();
        all.stream().filter(value -> value.entry().direction() == Direction.OUTBOUND)
                .filter(value -> is(value.logout(), "LogoutRequest"))
                .forEach(value -> requests.put(value.logout().getAttribute("ID"), value.logout()));
        var responses = target.stream().filter(value -> is(value.logout(), "LogoutResponse")).toList();
        if (responses.isEmpty()) return optionalNotObserved("slo.logout-response.not-observed");
        var violations = new ArrayList<String>();
        for (var response : responses) {
            var value = response.logout().getAttribute("InResponseTo");
            if (value.isBlank() || !requests.containsKey(value)) violations.add(response.reference());
        }
        return outcome(responses, violations, "slo.in-response-to");
    }

    private CaseOutcome consentSignature(List<Message> messages) {
        var scoped = messages.stream().filter(value -> !value.logout().getAttribute("Consent").isBlank()).toList();
        if (scoped.isEmpty()) return optionalNotObserved("slo.consent.not-observed");
        var violations = new ArrayList<String>();
        var unverifiable = new ArrayList<String>();
        for (var message : scoped) {
            var xmlSignature = message.logout().getElementsByTagNameNS(DS, "Signature").getLength() > 0;
            var bindingSignature = "GET".equalsIgnoreCase(message.entry().method()) && message.entry().rawQuery() != null
                    && message.entry().rawQuery().matches("(^|.*&)Signature=[^&]+(&.*|$)");
            if (!xmlSignature && !bindingSignature) {
                violations.add(message.reference());
                continue;
            }
            if (verificationKeys.isEmpty()) {
                unverifiable.add(message.reference());
                continue;
            }
            var xmlValid = xmlSignature && verificationKeys.stream().anyMatch(
                    certificate -> xmlSignatures.hasValidEnvelopedSignature(message.logout(), certificate));
            var redirectValid = bindingSignature && verificationKeys.stream().anyMatch(
                    certificate -> redirectSignatures.isValidForMessage(message.entry().rawQuery(), certificate, message.xml()));
            if (!xmlValid && !redirectValid) violations.add(message.reference());
        }
        if (violations.isEmpty() && !unverifiable.isEmpty()) return new CaseOutcome(
                Outcome.NOT_VERIFIED, "target_signing_key_unavailable",
                "slo.consent-signature.key-unavailable", "slo.consent-signature.key-unavailable",
                evidence(scoped), Map.of("unverifiable", List.copyOf(unverifiable)));
        return outcome(scoped, violations, "slo.consent-signature");
    }

    private CaseOutcome topLevelStatus(List<Message> messages) {
        var responses = messages.stream().filter(value -> is(value.logout(), "LogoutResponse")).toList();
        if (responses.isEmpty()) return optionalNotObserved("slo.logout-response.not-observed");
        var violations = new ArrayList<String>();
        for (var response : responses) {
            var status = direct(direct(response.logout(), PROTOCOL, "Status"), PROTOCOL, "StatusCode");
            if (status == null || !TOP_STATUS.contains(status.getAttribute("Value"))) {
                violations.add(response.reference());
            }
        }
        return outcome(responses, violations, "slo.top-level-status");
    }

    private CaseOutcome responseVersionCeiling(List<Message> target, List<Message> all) {
        return compareResponseVersions(target, all, true);
    }

    private CaseOutcome responseVersionFloor(List<Message> target, List<Message> all) {
        return compareResponseVersions(target, all, false);
    }

    private CaseOutcome compareResponseVersions(List<Message> target, List<Message> all, boolean ceiling) {
        var requestVersions = requestVersions(all, Direction.OUTBOUND);
        var responses = target.stream().filter(value -> is(value.logout(), "LogoutResponse")).toList();
        if (responses.isEmpty()) return optionalNotObserved("slo.logout-response.not-observed");
        var inspected = new ArrayList<Message>();
        var violations = new ArrayList<String>();
        for (var response : responses) {
            var requestVersion = requestVersions.get(response.logout().getAttribute("InResponseTo"));
            if (requestVersion == null) continue;
            inspected.add(response);
            var responseVersion = response.logout().getAttribute("Version");
            var comparison = compareVersion(responseVersion, requestVersion);
            if (ceiling && comparison > 0) violations.add(response.reference());
            if (!ceiling && major(responseVersion) < major(requestVersion)
                    && !secondaryStatus(response.logout()).endsWith(":RequestVersionTooHigh")) {
                violations.add(response.reference());
            }
        }
        if (inspected.isEmpty()) return CaseOutcome.notVerified(
                "corresponding_logout_request_unavailable", "slo.version.correlation-unavailable");
        return outcome(inspected, violations, ceiling ? "slo.response-version-ceiling" : "slo.response-version-floor");
    }

    private CaseOutcome requestVersionSupported(List<Message> target, List<Message> all) {
        var requests = target.stream().filter(value -> is(value.logout(), "LogoutRequest"))
                .filter(value -> value.logout().getElementsByTagNameNS(ASYNC, "Asynchronous").getLength() == 0).toList();
        if (requests.isEmpty()) return optionalNotObserved("slo.logout-request.not-observed");
        var responses = all.stream().filter(value -> value.entry().direction() == Direction.OUTBOUND)
                .filter(value -> is(value.logout(), "LogoutResponse")).toList();
        var responseByRequest = new HashMap<String, Message>();
        responses.forEach(value -> responseByRequest.put(value.logout().getAttribute("InResponseTo"), value));
        var unobserved = new ArrayList<String>();
        var violations = new ArrayList<String>();
        for (var request : requests) {
            var response = responseByRequest.get(request.logout().getAttribute("ID"));
            if (response == null) unobserved.add(request.reference());
            else if (PROTOCOL.concat(":VersionMismatch").equals(topStatus(response.logout()))) {
                violations.add(request.reference());
            }
        }
        if (!violations.isEmpty()) return outcome(requests, violations, "slo.request-version-supported");
        if (!unobserved.isEmpty()) return new CaseOutcome(
                Outcome.NOT_VERIFIED, "logout_response_consumption_not_observed",
                "slo.response-consumption.not-observed", "slo.response-consumption.not-observed",
                evidence(requests), Map.of("unobserved_requests", unobserved));
        return outcome(requests, List.of(), "slo.request-version-supported");
    }

    private CaseOutcome requestVersion2(List<Message> messages) {
        var requests = messages.stream().filter(value -> is(value.logout(), "LogoutRequest")).toList();
        if (requests.isEmpty()) return optionalNotObserved("slo.logout-request.not-observed");
        var violations = requests.stream().filter(value -> !"2.0".equals(value.logout().getAttribute("Version")))
                .map(Message::reference).toList();
        return outcome(requests, violations, "slo.request-version-2");
    }

    private CaseOutcome schema(List<Message> messages) {
        var violations = new ArrayList<String>();
        for (var message : messages) {
            var root = message.logout();
            var valid = SamlSchemaValidation.isValid(root, SamlSchemaValidation.SchemaKind.PROTOCOL)
                    && !root.getAttribute("ID").isBlank()
                    && "2.0".equals(root.getAttribute("Version"))
                    && !root.getAttribute("IssueInstant").isBlank();
            if (is(root, "LogoutRequest")) {
                valid &= root.getElementsByTagNameNS(ASSERTION, "NameID").getLength() > 0
                        || root.getElementsByTagNameNS(ASSERTION, "EncryptedID").getLength() > 0
                        || root.getElementsByTagNameNS(ASSERTION, "BaseID").getLength() > 0;
            } else {
                valid &= direct(root, PROTOCOL, "Status") != null;
            }
            if (!valid) violations.add(message.reference());
        }
        return outcome(messages, violations, "slo.schema-structure");
    }

    private CaseOutcome asyncPlacement(List<Message> targetMessages) {
        var asynchronous = new ArrayList<Message>();
        var violations = new ArrayList<String>();
        for (var message : targetMessages) {
            var all = message.document().getElementsByTagNameNS(ASYNC, "Asynchronous");
            if (all.getLength() == 0) continue;
            asynchronous.add(message);
            if (!is(message.logout(), "LogoutRequest")) {
                violations.add(message.reference());
                continue;
            }
            var extensions = direct(message.logout(), PROTOCOL, "Extensions");
            if (extensions == null || direct(extensions, ASYNC, "Asynchronous") == null) {
                violations.add(message.reference());
            }
        }
        if (asynchronous.isEmpty()) return optionalNotObserved("slo.async.not-observed");
        return outcome(asynchronous, violations, "slo.async-placement");
    }

    private CaseOutcome informationalAsync(List<Message> messages) {
        var requests = messages.stream().filter(value -> is(value.logout(), "LogoutRequest")).toList();
        return new CaseOutcome(
                Outcome.SATISFIED_WITH_NOTE, null, "slo.async.choice-recorded", "slo.async.choice-recorded",
                evidence(requests), Map.of(
                        "observed_requests", requests.size(),
                        "asynchronous_requests", requests.stream().filter(value ->
                                value.logout().getElementsByTagNameNS(ASYNC, "Asynchronous").getLength() > 0).count()));
    }

    private CaseOutcome absent() {
        return switch (rule) {
            case ASYNC_CHOICE -> informationalAsync(List.of());
            case TARGET_REDIRECT_LOGOUT_REQUEST -> notVerifiedWithEvidence(List.of(),
                    "slo.redirect-request.not-observed", "slo.redirect-request.not-observed");
            case TARGET_REDIRECT_RESPONSE_CONSUMED -> notVerifiedWithEvidence(List.of(),
                    "slo.redirect-response.not-observed", "slo.redirect-response.not-observed");
            case INFORMATIONAL_PROPAGATION -> notVerifiedWithEvidence(List.of(),
                    "slo.propagation.not-observed", "slo.propagation.not-observed");
            case TARGET_PROPAGATION_CONTINUE -> notVerifiedWithEvidence(List.of(),
                    "slo.propagation.not-observed", "slo.propagation.not-observed");
            case TARGET_PARTIAL_LOGOUT -> notVerifiedWithEvidence(List.of(),
                    "slo.partial-logout.not-observed", "slo.partial-logout.not-observed");
            default -> optionalNotObserved("slo.target-message.not-observed");
        };
    }

    private CaseOutcome targetPropagationContinue(List<Message> targetLogout, List<Message> all) {
        var initiators = all.stream()
                .filter(value -> value.entry().direction() == Direction.OUTBOUND)
                .filter(value -> is(value.logout(), "LogoutRequest"))
                .toList();
        if (initiators.isEmpty()) {
            // Local logout propagation: the target initiates, so the run itself is the processing
            // unit. Exactly one issued failure response keeps the attribution unambiguous.
            var failing = targetLogout.stream()
                    .filter(value -> "SloFailParticipant".equals(value.entry().samlSummary().get("type")))
                    .filter(value -> Integer.valueOf(500)
                            .equals(value.entry().samlSummary().get("http_status")))
                    .toList();
            if (failing.isEmpty()) {
                return notVerified("slo.propagation.failure-induction-unavailable",
                        "slo.propagation.failure-induction-unavailable");
            }
            if (failing.size() > 1) {
                return notVerified("slo.propagation.processing-ambiguous",
                        "slo.propagation.processing-ambiguous");
            }
            var failureAt = failing.getFirst().entry().timestamp();
            var remaining = targetLogout.stream()
                    .filter(value -> is(value.logout(), "LogoutRequest"))
                    .filter(value -> !"SloFailParticipant".equals(value.entry().samlSummary().get("type")))
                    .filter(value -> value.entry().timestamp().isAfter(failureAt))
                    .toList();
            if (remaining.isEmpty()) {
                return notVerified("slo.propagation.continuation-unobserved",
                        "slo.propagation.continuation-unobserved");
            }
            var answered = remaining.stream().anyMatch(value -> all.stream()
                    .filter(candidate -> candidate.entry().direction() == Direction.OUTBOUND)
                    .filter(candidate -> is(candidate.logout(), "LogoutResponse"))
                    .anyMatch(candidate -> !candidate.entry().timestamp().isBefore(value.entry().timestamp())));
            if (!answered) {
                return notVerified("slo.propagation.continuation-response-unavailable",
                        "slo.propagation.continuation-response-unavailable");
            }
            var localEvidence = new java.util.ArrayList<EvidenceRef>();
            localEvidence.addAll(evidence(failing));
            localEvidence.addAll(evidence(remaining));
            return new CaseOutcome(Outcome.SATISFIED, null, "slo.propagation.continue-after-failure",
                    "slo.propagation.continue-after-failure", localEvidence,
                    Map.of("processing_unit", "local-logout",
                            "failing_attempts", failing.size(),
                            "remaining_endpoints", remaining.stream()
                                    .map(value -> String.valueOf(value.entry().url())).distinct().count()));
        }
        // Each initiating request defines one logout processing bounded by its correlated final
        // response. Evidence outside the window, or windows that cannot be attributed separately,
        // must never combine into a Success.
        var windows = new java.util.ArrayList<Processing>();
        for (var initiator : initiators) {
            var responses = all.stream()
                    .filter(value -> value.entry().direction() == Direction.INBOUND)
                    .filter(value -> is(value.logout(), "LogoutResponse"))
                    .filter(value -> initiator.logout().getAttribute("ID")
                            .equals(value.logout().getAttribute("InResponseTo")))
                    .toList();
            if (responses.isEmpty()) continue;
            var end = responses.stream().map(value -> value.entry().timestamp())
                    .max(java.util.Comparator.naturalOrder()).orElseThrow();
            windows.add(new Processing(initiator, responses, initiator.entry().timestamp(), end));
        }
        if (windows.isEmpty()) {
            return notVerified("slo.propagation.initiator-response-unavailable",
                    "slo.propagation.initiator-response-unavailable");
        }
        // A straggler from another processing in the same run can arrive inside this window at
        // the same participant endpoint, so a run with several processings cannot attribute
        // continuation until participant endpoints are allocated per processing.
        if (windows.size() > 1) {
            return notVerified("slo.propagation.processing-ambiguous",
                    "slo.propagation.processing-ambiguous");
        }
        var bestReason = "slo.propagation.not-observed";
        var bestEvidence = new java.util.ArrayList<EvidenceRef>();
        for (var processing : windows) {
            if (!processing.start().isBefore(processing.end())) {
                bestReason = "slo.propagation.processing-ambiguous";
                continue;
            }
            var within = targetLogout.stream()
                    .filter(value -> !value.entry().timestamp().isBefore(processing.start()))
                    .filter(value -> !value.entry().timestamp().isAfter(processing.end()))
                    .toList();
            // The failure evidence is the Suite's issued failure response, not the arrival time.
            var failing = within.stream()
                    .filter(value -> "SloFailParticipant".equals(value.entry().samlSummary().get("type")))
                    .filter(value -> Integer.valueOf(500)
                            .equals(value.entry().samlSummary().get("http_status")))
                    .toList();
            if (failing.isEmpty()) {
                bestReason = "slo.propagation.failure-induction-unavailable";
                bestEvidence = new java.util.ArrayList<>(evidence(within));
                continue;
            }
            var failureAt = failing.stream().map(value -> value.entry().timestamp())
                    .max(java.util.Comparator.naturalOrder()).orElseThrow();
            var failingEndpoints = failing.stream().map(value -> String.valueOf(value.entry().url()))
                    .collect(java.util.stream.Collectors.toSet());
            var continuation = within.stream()
                    .filter(value -> is(value.logout(), "LogoutRequest"))
                    .filter(value -> !"SloFailParticipant".equals(value.entry().samlSummary().get("type")))
                    .filter(value -> !failingEndpoints.contains(String.valueOf(value.entry().url())))
                    .filter(value -> value.entry().timestamp().isAfter(failureAt))
                    .toList();
            if (continuation.isEmpty()) {
                bestReason = "slo.propagation.continuation-unobserved";
                bestEvidence = new java.util.ArrayList<>(evidence(within));
                continue;
            }
            // The Suite must have answered the remaining participant inside the same processing.
            var answered = continuation.stream().anyMatch(value -> all.stream()
                    .filter(candidate -> candidate.entry().direction() == Direction.OUTBOUND)
                    .filter(candidate -> is(candidate.logout(), "LogoutResponse"))
                    .anyMatch(candidate -> !candidate.entry().timestamp().isBefore(value.entry().timestamp())
                            && !candidate.entry().timestamp().isAfter(processing.end())));
            if (!answered) {
                bestReason = "slo.propagation.continuation-response-unavailable";
                bestEvidence = new java.util.ArrayList<>(evidence(continuation));
                continue;
            }
            var satisfiedEvidence = new java.util.ArrayList<EvidenceRef>();
            satisfiedEvidence.addAll(evidence(List.of(processing.initiator())));
            satisfiedEvidence.addAll(evidence(processing.responses()));
            satisfiedEvidence.addAll(evidence(failing));
            satisfiedEvidence.addAll(evidence(continuation));
            return new CaseOutcome(Outcome.SATISFIED, null, "slo.propagation.continue-after-failure",
                    "slo.propagation.continue-after-failure", satisfiedEvidence,
                    Map.of("processing_start", processing.start().toString(),
                            "processing_end", processing.end().toString(),
                            "failing_attempts", failing.size(),
                            "remaining_endpoints", continuation.stream()
                                    .map(value -> String.valueOf(value.entry().url())).distinct().count(),
                            "partial_logout_final", processing.responses().stream().anyMatch(value ->
                                    PARTIAL_LOGOUT_STATUS.equals(secondaryStatus(value.logout())))));
        }
        return new CaseOutcome(Outcome.NOT_VERIFIED, bestReason, bestReason, bestReason,
                bestEvidence, Map.of());
    }

    private CaseOutcome notVerified(String reasonCode, String detail) {
        return new CaseOutcome(Outcome.NOT_VERIFIED, detail, reasonCode, reasonCode, List.of(), Map.of());
    }

    private record Processing(Message initiator, List<Message> responses,
            java.time.Instant start, java.time.Instant end) {
        boolean overlaps(Processing other) {
            return start.isBefore(other.end) && other.start.isBefore(end);
        }
    }

    private java.util.Set<String> sessionIndexes(Element request) {
        var values = new java.util.LinkedHashSet<String>();
        for (var index : elements(request, PROTOCOL, "SessionIndex")) {
            var text = index.getTextContent();
            if (text != null && !text.isBlank()) values.add(text.trim());
        }
        return values;
    }

    private CaseOutcome targetPartialLogout(List<Message> targetLogout, List<Message> all) {
        var requests = targetLogout.stream().filter(value -> is(value.logout(), "LogoutRequest")).toList();
        if (requests.isEmpty()) {
            return notVerifiedWithEvidence(List.of(), "slo.partial-logout.not-observed",
                    "slo.partial-logout.not-observed");
        }
        var responses = all.stream()
                .filter(value -> value.entry().direction() == Direction.INBOUND)
                .filter(value -> is(value.logout(), "LogoutResponse")).toList();
        var partial = responses.stream()
                .filter(value -> PARTIAL_LOGOUT_STATUS.equals(secondaryStatus(value.logout()))).toList();
        if (!partial.isEmpty()) {
            return new CaseOutcome(Outcome.SATISFIED, null, "slo.partial-logout.observed",
                    "slo.partial-logout.observed", evidence(partial),
                    Map.of("partial_logout_responses", partial.size()));
        }
        return notVerifiedWithEvidence(responses.isEmpty() ? requests : responses,
                "slo.partial-logout.unobserved", "slo.partial-logout.unobserved");
    }

    private CaseOutcome informationalPropagation(List<Message> targetLogout) {
        var requests = targetLogout.stream().filter(value -> is(value.logout(), "LogoutRequest")).toList();
        return new CaseOutcome(Outcome.SATISFIED_WITH_NOTE, null, "slo.propagation.choice-recorded",
                "slo.propagation.choice-recorded", evidence(requests),
                Map.of("propagated", !requests.isEmpty(), "observed_requests", requests.size()));
    }

    private CaseOutcome targetRedirectLogoutRequest(List<Message> targetLogout) {
        var requests = targetLogout.stream().filter(value -> is(value.logout(), "LogoutRequest")).toList();
        if (requests.isEmpty()) {
            return notVerifiedWithEvidence(List.of(), "slo.redirect-request.not-observed",
                    "slo.redirect-request.not-observed");
        }
        var methods = new java.util.LinkedHashSet<String>();
        for (var message : requests) {
            methods.add(String.valueOf(message.entry().method()).toUpperCase(java.util.Locale.ROOT));
        }
        var misleading = requests.stream()
                .filter(value -> !"GET".equalsIgnoreCase(value.entry().method()))
                .map(Message::reference).toList();
        return new CaseOutcome(misleading.isEmpty() ? Outcome.SATISFIED : Outcome.VIOLATED, null,
                misleading.isEmpty() ? "slo.redirect-request.observed" : "slo.redirect-request.binding-violated",
                misleading.isEmpty() ? "slo.redirect-request.observed" : "slo.redirect-request.binding-violated",
                evidence(requests), Map.of("methods", List.copyOf(methods), "violations", misleading));
    }

    private CaseOutcome targetRedirectResponseConsumed(List<Message> targetLogout, List<Message> all,
            List<TranscriptEntry> entries) {
        var requests = targetLogout.stream().filter(value -> is(value.logout(), "LogoutRequest")).toList();
        if (requests.isEmpty()) {
            return notVerifiedWithEvidence(List.of(), "slo.redirect-response.not-observed",
                    "slo.redirect-response.not-observed");
        }
        var ids = requests.stream().map(value -> value.logout().getAttribute("ID"))
                .collect(java.util.stream.Collectors.toSet());
        var responses = all.stream()
                .filter(value -> value.entry().direction() == Direction.OUTBOUND)
                .filter(value -> is(value.logout(), "LogoutResponse"))
                .filter(value -> ids.contains(value.logout().getAttribute("InResponseTo")))
                .toList();
        if (responses.isEmpty()) {
            return notVerifiedWithEvidence(requests, "slo.redirect-response.unavailable",
                    "slo.redirect-response.unavailable");
        }
        var nonRedirect = responses.stream().filter(value -> !String.valueOf(
                        value.entry().samlSummary().getOrDefault("binding", "")).endsWith(":HTTP-Redirect"))
                .map(Message::reference).toList();
        if (!nonRedirect.isEmpty()) {
            return new CaseOutcome(Outcome.VIOLATED, null, "slo.redirect-response.binding-violated",
                    "slo.redirect-response.binding-violated", evidence(responses),
                    Map.of("violations", nonRedirect));
        }
        var lastResponseAt = responses.stream().map(value -> value.entry().timestamp())
                .max(java.util.Comparator.naturalOrder()).orElse(null);
        var observations = entries.stream()
                .filter(entry -> "BROWSER".equalsIgnoreCase(entry.method()))
                .filter(entry -> lastResponseAt == null || !entry.timestamp().isBefore(lastResponseAt))
                .toList();
        if (observations.isEmpty()) {
            return notVerifiedWithEvidence(responses, "slo.redirect-response.consumption-unobserved",
                    "slo.redirect-response.consumption-unobserved");
        }
        var failed = observations.stream().anyMatch(entry -> Boolean.TRUE.equals(
                entry.samlSummary().getOrDefault("failure_indicated",
                        entry.status() != null && entry.status() >= 400)));
        if (failed) {
            return new CaseOutcome(Outcome.VIOLATED, null, "slo.redirect-response.not-consumed",
                    "slo.redirect-response.not-consumed", evidence(responses),
                    Map.of("observations", observations.size()));
        }
        // A successful page load does not prove that the IdP consumed the response.
        return notVerifiedWithEvidence(responses, "slo.redirect-response.consumption-unobserved",
                "slo.redirect-response.consumption-unobserved");
    }

    private CaseOutcome optionalNotObserved(String reasonCode) {
        return new CaseOutcome(
                Outcome.SATISFIED_WITH_NOTE, null, reasonCode, reasonCode, List.of(), Map.of("observed", 0));
    }

    private CaseOutcome outcome(List<Message> messages, List<String> violations, String code) {
        return new CaseOutcome(
                violations.isEmpty() ? Outcome.SATISFIED : Outcome.VIOLATED, null,
                violations.isEmpty() ? code + ".satisfied" : code + ".violated",
                violations.isEmpty() ? code + ".satisfied" : code + ".violated",
                evidence(messages), Map.of("observed", messages.size(), "violations", List.copyOf(violations)));
    }

    /** A rule-level "cannot prove" result must stay reviewable instead of waiting forever. */
    private CaseOutcome notVerifiedWithEvidence(List<Message> messages, String detail, String code) {
        return new CaseOutcome(Outcome.NOT_VERIFIED, detail, code, code, evidence(messages), Map.of());
    }

    private List<EvidenceRef> evidence(List<Message> messages) {
        return messages.stream().map(value -> new EvidenceRef("transcript", value.reference())).distinct().toList();
    }

    private Map<String, String> requestVersions(List<Message> all, Direction direction) {
        var values = new HashMap<String, String>();
        all.stream().filter(value -> value.entry().direction() == direction)
                .filter(value -> is(value.logout(), "LogoutRequest"))
                .forEach(value -> values.put(value.logout().getAttribute("ID"), value.logout().getAttribute("Version")));
        return values;
    }

    private String topStatus(Element response) {
        var status = direct(direct(response, PROTOCOL, "Status"), PROTOCOL, "StatusCode");
        return status == null ? "" : status.getAttribute("Value");
    }

    private String secondaryStatus(Element response) {
        var status = direct(direct(response, PROTOCOL, "Status"), PROTOCOL, "StatusCode");
        var secondary = direct(status, PROTOCOL, "StatusCode");
        return secondary == null ? "" : secondary.getAttribute("Value");
    }

    private int compareVersion(String left, String right) {
        var l = parts(left); var r = parts(right);
        for (var index = 0; index < Math.max(l.length, r.length); index++) {
            var lv = index < l.length ? l[index] : 0;
            var rv = index < r.length ? r[index] : 0;
            if (lv != rv) return Integer.compare(lv, rv);
        }
        return 0;
    }

    private int major(String value) { var parts = parts(value); return parts.length == 0 ? -1 : parts[0]; }
    private int[] parts(String value) {
        try { return java.util.Arrays.stream(value.split("\\.")).mapToInt(Integer::parseInt).toArray(); }
        catch (RuntimeException invalid) { return new int[] {-1}; }
    }

    private Snapshot messages(String runId, TranscriptRecorder transcript, TranscriptContentReader content) {
        var result = new ArrayList<Message>();
        var issues = new java.util.LinkedHashSet<String>();
        var refs = new ArrayList<EvidenceRef>();
        final List<TranscriptEntry> entries;
        try { entries = List.copyOf(transcript.list(runId)); }
        catch (RuntimeException unavailable) {
            return new Snapshot(List.of(), List.of("history_unavailable"), List.of(), List.of());
        }
        var ids = new java.util.HashSet<String>();
        for (var entry : entries) {
            if (!runId.equals(entry.runId())) { issues.add("run_mismatch"); continue; }
            if (entry.id() == null || entry.id().isBlank() || !ids.add(entry.id())) {
                issues.add("ambiguous_entry_id"); continue;
            }
            if ("SOAP".equals(entry.samlSummary().get("transport"))
                    && "invalid-soap-message-scope".equals(entry.samlSummary().get("parseStatus"))) {
                refs.add(new EvidenceRef("transcript", "transcript:" + entry.id()));
                issues.add("logout_message_scope_unresolved"); continue;
            }
            if ("BrowserResponseObservation".equals(entry.samlSummary().get("type"))) continue;
            var recordedType = entry.samlSummary().get("type");
            boolean recordedLogout = "LogoutRequest".equals(recordedType) || "LogoutResponse".equals(recordedType);
            if (entry.decodedSamlRef() == null && entry.decodedSamlBytes() == 0 && !recordedLogout) continue;
            refs.add(new EvidenceRef("transcript", "transcript:" + entry.id()));
            if (entry.decodedSamlRef() == null || entry.decodedSamlBytes() <= 0) {
                issues.add("decoded_content_missing"); continue;
            }
            try {
                var xml = content.readDecodedSaml(entry);
                if (xml == null || xml.length != entry.decodedSamlBytes()) {
                    issues.add("decoded_content_size_mismatch"); continue;
                }
                if ("GET".equalsIgnoreCase(entry.method()) && entry.rawQuery() != null
                        && entry.rawQuery().matches("(^|.*&)(SAMLRequest|SAMLResponse)=.*")
                        && !redirectSignatures.matchesMessage(entry.rawQuery(), xml)) {
                    issues.add("redirect_message_mismatch"); continue;
                }
                var document = SecureXml.parse(xml);
                if (decryptionKey != null) {
                    decryptAssertions(document);
                    decryptIdentifiers(document);
                }
                Element logout = null;
                var root = document.getDocumentElement();
                if (is(root, "LogoutRequest") || is(root, "LogoutResponse")) {
                    logout = root;
                } else {
                    // A descendant of an arbitrary extension/Advice/header is not an exchanged message.
                    var soap = root.getNamespaceURI();
                    if ("Envelope".equals(root.getLocalName()) &&
                            ("http://schemas.xmlsoap.org/soap/envelope/".equals(soap)
                            || "http://www.w3.org/2003/05/soap-envelope".equals(soap))) {
                        var bodies = directElements(root, soap, "Body");
                        if (bodies.size() == 1) {
                            var children = new ArrayList<Element>();
                            for (var node = bodies.getFirst().getFirstChild(); node != null; node = node.getNextSibling())
                                if (node instanceof Element element) children.add(element);
                            if (children.size() == 1 && (is(children.getFirst(), "LogoutRequest")
                                    || is(children.getFirst(), "LogoutResponse"))) logout = children.getFirst();
                        }
                    }
                    if (logout == null && (recordedLogout
                            || document.getElementsByTagNameNS(PROTOCOL, "LogoutRequest").getLength() > 0
                            || document.getElementsByTagNameNS(PROTOCOL, "LogoutResponse").getLength() > 0)) {
                        issues.add("logout_message_scope_unresolved"); continue;
                    }
                }
                if (recordedLogout && logout != null && !recordedType.equals(logout.getLocalName())) {
                    issues.add("logout_type_mismatch"); continue;
                }
                result.add(new Message(entry, document, logout, "transcript:" + entry.id(), sha256(xml), xml.clone()));
            } catch (RuntimeException unreadable) {
                // Missing/unparseable evidence cannot silently disappear from a successful snapshot.
                issues.add("decoded_content_unreadable");
            }
        }
        return new Snapshot(List.copyOf(result), List.copyOf(issues), List.copyOf(refs), List.copyOf(entries));
    }

    /** In-memory view only: identifiers inside an encrypted login Assertion must be readable. */
    private void decryptAssertions(org.w3c.dom.Document document) {
        var wrappers = document.getElementsByTagNameNS(ASSERTION, "EncryptedAssertion");
        var pending = new ArrayList<Element>();
        for (var index = 0; index < wrappers.getLength(); index++) {
            pending.add((Element) wrappers.item(index));
        }
        for (var wrapper : pending) {
            try {
                var plaintext = new com.samlscope.saml.crypto.SamlXmlDecrypter()
                        .decrypt(wrapper, decryptionKey);
                wrapper.getParentNode().replaceChild(document.importNode(plaintext, true), wrapper);
            } catch (RuntimeException undecryptable) {
                // Leave the wrapper in place; the rule reports the identifiers as unavailable.
            }
        }
    }

    /**
     * In-memory view only: a target-emitted LogoutRequest may carry the principal as an
     * EncryptedID addressed to the Suite participant. The Suite holds that key, so decrypt it
     * here; the identifier-strong-match rule must judge the plaintext NameID, not treat the
     * encrypted choice as inherently unobservable.
     */
    private void decryptIdentifiers(org.w3c.dom.Document document) {
        var wrappers = document.getElementsByTagNameNS(ASSERTION, "EncryptedID");
        var pending = new ArrayList<Element>();
        for (var index = 0; index < wrappers.getLength(); index++) {
            pending.add((Element) wrappers.item(index));
        }
        for (var wrapper : pending) {
            try {
                var plaintext = new com.samlscope.saml.crypto.SamlXmlDecrypter()
                        .decrypt(wrapper, decryptionKey);
                wrapper.getParentNode().replaceChild(document.importNode(plaintext, true), wrapper);
            } catch (RuntimeException undecryptable) {
                // Leave the wrapper in place; the rule reports the identifiers as unavailable.
            }
        }
    }

    private Element direct(Element parent, String namespace, String localName) {
        if (parent == null) return null;
        for (var child = parent.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (child instanceof Element element && namespace.equals(element.getNamespaceURI())
                    && localName.equals(element.getLocalName())) return element;
        }
        return null;
    }
    private List<Element> directElements(Element parent, String namespace, String localName) {
        var result = new ArrayList<Element>();
        if (parent == null) return result;
        for (var child = parent.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (child instanceof Element element && namespace.equals(element.getNamespaceURI())
                    && localName.equals(element.getLocalName())) result.add(element);
        }
        return result;
    }
    private boolean is(Element value, String localName) {
        return value != null && PROTOCOL.equals(value.getNamespaceURI()) && localName.equals(value.getLocalName());
    }
    private String sha256(byte[] value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value)); }
        catch (java.security.NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }

    private record Message(
            TranscriptEntry entry, org.w3c.dom.Document document, Element logout, String reference, String digest, byte[] xml) {}
    private record Snapshot(
            List<Message> messages, List<String> issues, List<EvidenceRef> evidence,
            List<TranscriptEntry> entries) {}
    private record IssuedSessionIdentifier(String identifierKey, Set<String> sessionIndexes) {}
}
