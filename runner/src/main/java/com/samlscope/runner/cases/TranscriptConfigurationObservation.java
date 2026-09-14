package com.samlscope.runner.cases;

import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.saml.crypto.SamlElementDecrypter;
import com.samlscope.saml.normal.SamlException;
import com.samlscope.saml.normal.SecureXml;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/** Passive CONFIG outcomes proven by target-generated SAML already present in the Run. */
final class TranscriptConfigurationObservation {
    private static final String PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";

    private TranscriptConfigurationObservation() {}

    static boolean supports(String caseId) {
        return List.of(
                "IIP-IDP09-a-idp-01",
                "IIP-SSO01-ez-idp-01",
                "IIP-SSO01-fd-idp-01",
                "IIP-SSO01-fe-idp-01").contains(caseId);
    }

    static Optional<CaseOutcome> evaluate(
            String caseId,
            List<Message> messages,
            PrivateKey decryptionKey,
            SamlElementDecrypter decrypter) {
        if (!supports(caseId)) return Optional.empty();
        var parsed = parse(messages);
        if (parsed.isEmpty()) return Optional.empty();
        return switch (caseId) {
            case "IIP-IDP09-a-idp-01" -> encryptedAssertionCapability(parsed, decryptionKey, decrypter);
            case "IIP-SSO01-ez-idp-01" -> encryptedAssertionPlacement(parsed);
            case "IIP-SSO01-fd-idp-01" -> encryptedChildPlacement(
                    parsed, decryptionKey, decrypter, "EncryptedID", "NameID", "Subject",
                    "configuration.passive.encrypted-id-placement");
            case "IIP-SSO01-fe-idp-01" -> encryptedChildPlacement(
                    parsed, decryptionKey, decrypter, "EncryptedAttribute", "Attribute", "AttributeStatement",
                    "configuration.passive.encrypted-attribute-placement");
            default -> Optional.empty();
        };
    }

    private static Optional<CaseOutcome> encryptedAssertionCapability(List<Parsed> messages,
            PrivateKey key, SamlElementDecrypter decrypter) {
        if (key == null) return Optional.empty();
        var observed = new ArrayList<Parsed>();
        for (var message : messages) {
            var root = message.document().getDocumentElement();
            var status = directElements(root, PROTOCOL, "Status");
            if (status.size() != 1) continue;
            var codes = directElements(status.getFirst(), PROTOCOL, "StatusCode");
            if (codes.size() != 1 || !"urn:oasis:names:tc:SAML:2.0:status:Success".equals(
                    codes.getFirst().getAttribute("Value"))) continue;
            for (var wrapper : directElements(root, ASSERTION, "EncryptedAssertion")) {
                try {
                    var plaintext = decrypter.decrypt(wrapper, key);
                    if (ASSERTION.equals(plaintext.getNamespaceURI()) && "Assertion".equals(plaintext.getLocalName())) {
                        observed.add(message);
                        break;
                    }
                } catch (SamlException unavailable) {
                    // Missing or unusable encrypted content proves no capability and no failure.
                }
            }
        }
        if (observed.isEmpty()) return Optional.empty();
        return Optional.of(outcome(
                Outcome.SATISFIED, "configuration.passive.assertion-encryption-capability",
                observed, Map.of("encrypted_assertions", observed.size())));
    }

    private static Optional<CaseOutcome> encryptedAssertionPlacement(List<Parsed> messages) {
        var observed = 0;
        var invalid = new ArrayList<String>();
        var evidence = new ArrayList<Parsed>();
        for (var message : messages) {
            var root = message.document().getDocumentElement();
            var encrypted = elements(message.document(), ASSERTION, "EncryptedAssertion");
            if (encrypted.isEmpty()) continue;
            observed += encrypted.size();
            evidence.add(message);
            var directPlaintext = directElements(root, ASSERTION, "Assertion").size();
            for (var value : encrypted) {
                if (value.getParentNode() != root) invalid.add(message.evidenceRef() + ":wrong-parent");
            }
            if (directPlaintext > 0) invalid.add(message.evidenceRef() + ":plaintext-retained");
        }
        if (observed == 0) {
            return Optional.of(outcome(
                    Outcome.SATISFIED_WITH_NOTE, "configuration.passive.no-encrypted-assertion",
                    messages, Map.of("encrypted_assertions", 0)));
        }
        return Optional.of(outcome(
                invalid.isEmpty() ? Outcome.SATISFIED : Outcome.VIOLATED,
                invalid.isEmpty()
                        ? "configuration.passive.encrypted-assertion-placement"
                        : "configuration.passive.encrypted-assertion-placement-invalid",
                evidence, Map.of("encrypted_assertions", observed, "violations", invalid)));
    }

    private static Optional<CaseOutcome> encryptedChildPlacement(
            List<Parsed> messages,
            PrivateKey decryptionKey,
            SamlElementDecrypter decrypter,
            String encryptedLocalName,
            String plaintextLocalName,
            String requiredParent,
            String code) {
        var documents = new ArrayList<Parsed>();
        for (var message : messages) {
            var decrypted = decryptAssertions(message.document(), decryptionKey, decrypter);
            if (decrypted.isEmpty()) return Optional.empty();
            documents.add(new Parsed(message.evidenceRef(), decrypted.orElseThrow()));
        }
        var observed = 0;
        var invalid = new ArrayList<String>();
        var evidence = new ArrayList<Parsed>();
        for (var message : documents) {
            var encrypted = elements(message.document(), ASSERTION, encryptedLocalName);
            if (encrypted.isEmpty()) continue;
            observed += encrypted.size();
            evidence.add(message);
            for (var value : encrypted) {
                var parent = value.getParentNode() instanceof Element element ? element : null;
                if (parent == null || !ASSERTION.equals(parent.getNamespaceURI())
                        || !requiredParent.equals(parent.getLocalName())) {
                    invalid.add(message.evidenceRef() + ":wrong-parent");
                } else if (!directElements(parent, ASSERTION, plaintextLocalName).isEmpty()) {
                    invalid.add(message.evidenceRef() + ":plaintext-retained");
                }
            }
        }
        if (observed == 0) {
            return Optional.of(outcome(
                    Outcome.SATISFIED_WITH_NOTE, code + ".not-observed",
                    documents, Map.of("encrypted_elements", 0)));
        }
        return Optional.of(outcome(
                invalid.isEmpty() ? Outcome.SATISFIED : Outcome.VIOLATED,
                invalid.isEmpty() ? code : code + ".invalid",
                evidence, Map.of("encrypted_elements", observed, "violations", invalid)));
    }

    private static Optional<Document> decryptAssertions(
            Document source, PrivateKey key, SamlElementDecrypter decrypter) {
        try {
            var copy = SecureXml.parse(SecureXml.serialize(source));
            var encrypted = elements(copy, ASSERTION, "EncryptedAssertion");
            if (!encrypted.isEmpty() && key == null) return Optional.empty();
            for (var wrapper : List.copyOf(encrypted)) {
                var plaintext = decrypter.decrypt(wrapper, key);
                wrapper.getParentNode().replaceChild(copy.importNode(plaintext, true), wrapper);
            }
            return Optional.of(copy);
        } catch (SamlException unavailable) {
            return Optional.empty();
        }
    }

    private static List<Parsed> parse(List<Message> messages) {
        var result = new ArrayList<Parsed>();
        for (var message : messages == null ? List.<Message>of() : messages) {
            try {
                var document = SecureXml.parse(message.xml());
                var root = document.getDocumentElement();
                if (PROTOCOL.equals(root.getNamespaceURI()) && "Response".equals(root.getLocalName())) {
                    result.add(new Parsed(message.evidenceRef(), document));
                }
            } catch (SamlException ignored) {
                // The approved questionnaire remains available when the Transcript is malformed.
            }
        }
        return List.copyOf(result);
    }

    private static List<Element> elements(Document document, String namespace, String localName) {
        var nodes = document.getElementsByTagNameNS(namespace, localName);
        var result = new ArrayList<Element>();
        for (var index = 0; index < nodes.getLength(); index++) result.add((Element) nodes.item(index));
        return result;
    }

    private static List<Element> directElements(Element parent, String namespace, String localName) {
        var result = new ArrayList<Element>();
        for (var child = parent.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (child instanceof Element element && namespace.equals(element.getNamespaceURI())
                    && localName.equals(element.getLocalName())) result.add(element);
        }
        return result;
    }

    private static CaseOutcome outcome(
            Outcome outcome, String code, List<Parsed> messages, Map<String, Object> details) {
        return new CaseOutcome(
                outcome, null, code, code,
                messages.stream().map(value -> new EvidenceRef("transcript", value.evidenceRef())).distinct().toList(),
                new LinkedHashMap<>(details));
    }

    record Message(String evidenceRef, byte[] xml) {
        Message {
            if (evidenceRef == null || evidenceRef.isBlank()) throw new IllegalArgumentException("evidenceRef is required");
            if (xml == null || xml.length == 0) throw new IllegalArgumentException("xml is required");
            xml = xml.clone();
        }
        @Override public byte[] xml() { return xml.clone(); }
    }

    private record Parsed(String evidenceRef, Document document) {}
}
