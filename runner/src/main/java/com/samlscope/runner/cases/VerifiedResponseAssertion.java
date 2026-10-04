package com.samlscope.runner.cases;

import static com.samlscope.runner.cases.MetadataAlgorithmEvidence.children;
import java.security.cert.X509Certificate;
import java.util.*;
import org.w3c.dom.Element;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.SecureXml;

/** Shared signed, decrypted Assertion boundary. Callers must still bind original transcript requests. */
final class VerifiedResponseAssertion {
    private static final String S = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String P = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String DS = "http://www.w3.org/2000/09/xmldsig#";

    static Element read(Element response, String targetEntity, List<X509Certificate> targetSigningKeys,
            Element preparedMetadata, Optional<PlanCredentials> encryptionKey,
            String requestId, String recipient) {
        try {
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
                if (encrypted.isEmpty()) {
                    // A plaintext Assertion was already verified in its original Response DOM above.
                    // Moving it into a synthetic document can discard an ancestor namespace declaration
                    // that was part of canonicalization and falsely reject a valid target signature.
                    require(signatures.stream().anyMatch(s -> "Assertion".equals(s.element())
                            && assertion.getAttribute("ID").equals(s.id())));
                } else {
                    // A decrypted Assertion was not visible to the outer signature scan.
                    var document = SecureXml.newDocument();
                    var envelope = document.createElementNS(P, "p:Response");
                    document.appendChild(envelope);
                    envelope.appendChild(document.importNode(assertion, true));
                    var verified = new VerifiedSignatureAlgorithms().read(envelope, targetEntity, targetSigningKeys);
                    require(verified.size() == 1 && "Assertion".equals(verified.getFirst().element()));
                }
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
            return assertion;
        } catch (Exception unproven) {
            // No provider exception, decrypted XML, or principal value crosses this boundary.
            throw new IllegalArgumentException("Verified response Assertion unavailable");
        }
    }

    private static void require(boolean condition) {
        if (!condition) throw new IllegalArgumentException("Unproven response Assertion");
    }
}
