package com.samlscope.runner.cases;

import static com.samlscope.runner.cases.MetadataAlgorithmEvidence.children;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.*;
import org.w3c.dom.Element;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.SecureXml;

/** Reads comparison markers only after signature and matching-key decryption checks. */
final class AttributePolicyAttributeReader {
    private static final String S = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String P = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String DS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String PREFIX = "urn:samlscope:test:policy:";
    private static final String FORMAT = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";
    private static final Set<String> MARKERS = Set.of("anchor", "entity", "required", "optional", "surname");

    // This is a same-input witness, not independently a proof of authenticated user identity.
    // Keep its fingerprint in memory only; never put it or raw values in public diagnostics.
    record Observation(Set<String> markers, String attributeInputFingerprint) {
        Observation { markers = Set.copyOf(markers); }
        @Override public String toString() { return "AttributePolicyObservation[markers=" + markers + "]"; }
    }

    static Observation read(String runId, Element response, String targetEntity,
                            List<X509Certificate> targetSigningKeys, Element preparedMetadata,
                            Optional<PlanCredentials> encryptionKey) {
        return read(runId, response, targetEntity, targetSigningKeys, preparedMetadata, encryptionKey,
                PREFIX, MARKERS, null, null);
    }

    static Observation readRelyingParty(String runId, Element response, String targetEntity,
            List<X509Certificate> targetSigningKeys, Element preparedMetadata,
            Optional<PlanCredentials> encryptionKey, String requestId, String recipient) {
        require(requestId != null && !requestId.isBlank() && recipient != null && !recipient.isBlank());
        return read(runId, response, targetEntity, targetSigningKeys, preparedMetadata, encryptionKey,
                "urn:samlscope:test:relying-party:", Set.of("anchor", "first", "second"), requestId, recipient);
    }

    private static Observation read(String runId, Element response, String targetEntity,
            List<X509Certificate> targetSigningKeys, Element preparedMetadata,
            Optional<PlanCredentials> encryptionKey, String prefix, Set<String> markers,
            String requestId, String recipient) {
        try {
            require(runId != null && !runId.isBlank());
            require(P.equals(response.getNamespaceURI()) && "Response".equals(response.getLocalName()));
            var status = children(response, P, "Status");
            require(status.size() == 1 && children(status.getFirst(), P, "StatusCode").size() == 1);
            require("urn:oasis:names:tc:SAML:2.0:status:Success".equals(children(status.getFirst(), P, "StatusCode").getFirst().getAttribute("Value")));
            var signatures = new VerifiedSignatureAlgorithms().read(response, targetEntity, targetSigningKeys);
            require(signatures.stream().anyMatch(s -> "Response".equals(s.element())));
            var plain = children(response, S, "Assertion");
            int expected = children(response, DS, "Signature").size()
                    + plain.stream().mapToInt(a -> children(a, DS, "Signature").size()).sum();
            require(signatures.size() == expected);
            var encrypted = children(response, S, "EncryptedAssertion");
            // Never combine an anchor from one Assertion with policy attributes from another.
            require(plain.size() + encrypted.size() == 1);
            Element assertion;
            if (!encrypted.isEmpty()) {
                require(preparedMetadata != null && MD.equals(preparedMetadata.getNamespaceURI())
                        && "EntityDescriptor".equals(preparedMetadata.getLocalName()));
                var roles = children(preparedMetadata, MD, "SPSSODescriptor");
                require(roles.size() == 1 && encryptionKey.isPresent());
                var key = encryptionKey.orElseThrow();
                MetadataEncryptionProof.descriptor(roles.getFirst(), key);
                assertion = new SamlXmlDecrypter().decrypt(encrypted.getFirst(), key.privateKey());
            } else {
                assertion = plain.getFirst();
            }
            require(S.equals(assertion.getNamespaceURI()) && "Assertion".equals(assertion.getLocalName()));
            var issuers = children(assertion, S, "Issuer");
            require(issuers.size() == 1 && targetEntity.equals(issuers.getFirst().getTextContent()));
            if (!children(assertion, DS, "Signature").isEmpty()) {
                var document = SecureXml.newDocument();
                var envelope = document.createElementNS(P, "p:Response");
                document.appendChild(envelope);
                envelope.appendChild(document.importNode(assertion, true));
                var verified = new VerifiedSignatureAlgorithms().read(envelope, targetEntity, targetSigningKeys);
                require(verified.size() == 1 && "Assertion".equals(verified.getFirst().element()));
            }
            if (requestId != null) {
                require(requestId.equals(response.getAttribute("InResponseTo"))
                        && recipient.equals(response.getAttribute("Destination")));
                require(preparedMetadata != null && !preparedMetadata.getAttribute("entityID").isBlank());
                String entity = preparedMetadata.getAttribute("entityID");
                var conditions = children(assertion, S, "Conditions");
                require(conditions.size() == 1);
                var restrictions = children(conditions.getFirst(), S, "AudienceRestriction");
                require(!restrictions.isEmpty());
                for (var restriction : restrictions) {
                    require(children(restriction, S, "Audience").stream().anyMatch(a -> entity.equals(a.getTextContent())));
                }
                var subjects = children(assertion, S, "Subject");
                require(subjects.size() == 1);
                var confirmations = children(subjects.getFirst(), S, "SubjectConfirmation");
                require(confirmations.size() == 1
                        && "urn:oasis:names:tc:SAML:2.0:cm:bearer".equals(confirmations.getFirst().getAttribute("Method")));
                var data = children(confirmations.getFirst(), S, "SubjectConfirmationData");
                require(data.size() == 1 && requestId.equals(data.getFirst().getAttribute("InResponseTo"))
                        && recipient.equals(data.getFirst().getAttribute("Recipient")));
            }
            var values = new HashMap<String, String>();
            for (var statement : children(assertion, S, "AttributeStatement")) {
                // An encrypted attribute could hide a marker; a partial set is not an absence control.
                require(children(statement, S, "EncryptedAttribute").isEmpty());
                for (var attribute : children(statement, S, "Attribute")) {
                    var name = attribute.getAttribute("Name");
                    if (!name.startsWith(prefix)) continue;
                    var marker = name.substring(prefix.length());
                    require(markers.contains(marker) && FORMAT.equals(attribute.getAttribute("NameFormat")));
                    var entries = children(attribute, S, "AttributeValue");
                    require(entries.size() == 1);
                    var value = entries.getFirst();
                    for (var node = value.getFirstChild(); node != null; node = node.getNextSibling()) {
                        require(!(node instanceof Element));
                    }
                    require(!value.hasAttributeNS("http://www.w3.org/2001/XMLSchema-instance", "nil"));
                    require(!value.getTextContent().isBlank());
                    require(values.put(marker, value.getTextContent()) == null);
                }
            }
            require(values.containsKey("anchor"));
            var anchor = values.get("anchor");
            require(values.values().stream().allMatch(anchor::equals));
            var digest = MessageDigest.getInstance("SHA-256");
            for (String value : List.of("attribute-policy-input-v1", runId, targetEntity, anchor)) {
                byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
                digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(bytes.length).array());
                digest.update(bytes);
            }
            return new Observation(values.keySet(), HexFormat.of().formatHex(digest.digest()));
        } catch (Exception unproven) {
            // Suppress XML/provider exception messages, which may contain target attribute values.
            throw new IllegalArgumentException("Attribute policy response evidence is unproven");
        }
    }

    private static void require(boolean condition) {
        if (!condition) throw new IllegalArgumentException("Unproven attribute evidence");
    }
}
