package com.samlscope.runner.cases;

import static com.samlscope.runner.cases.MetadataAlgorithmEvidence.children;
import java.security.cert.X509Certificate;
import java.util.*;
import org.w3c.dom.Element;
import com.samlscope.saml.crypto.*;

/** Identifier shape only; never exposes the identifier or mistakes opaque ciphertext for absence. */
final class NameIdOmissionResponseEvidence {
    private static final String S = "urn:oasis:names:tc:SAML:2.0:assertion";
    enum Presence { NAME_ID, BASE_ID, OMITTED }

    static Presence read(Element response, String targetEntity, List<X509Certificate> signingKeys,
            Element preparedMetadata, Optional<PlanCredentials> encryptionKey, String requestId, String recipient) {
        try {
            if (requestId == null || requestId.isBlank() || recipient == null || recipient.isBlank()) {
                throw new IllegalArgumentException("Missing request correlation");
            }
            var assertion = VerifiedResponseAssertion.read(response, targetEntity, signingKeys,
                    preparedMetadata, encryptionKey, requestId, recipient);
            var subjects = children(assertion, S, "Subject");
            if (subjects.size() != 1) throw new IllegalArgumentException("Ambiguous Subject");
            var subject = subjects.getFirst();
            var names = children(subject, S, "NameID");
            var bases = children(subject, S, "BaseID");
            var encrypted = children(subject, S, "EncryptedID");
            if (names.size() + bases.size() + encrypted.size() > 1) {
                throw new IllegalArgumentException("Ambiguous identifier");
            }
            if (!names.isEmpty()) return Presence.NAME_ID;
            if (!bases.isEmpty()) return Presence.BASE_ID;
            if (encrypted.isEmpty()) return Presence.OMITTED;
            var key = encryptionKey.orElseThrow();
            var roles = children(preparedMetadata, "urn:oasis:names:tc:SAML:2.0:metadata", "SPSSODescriptor");
            if (roles.size() != 1) throw new IllegalArgumentException("Ambiguous encryption role");
            MetadataEncryptionProof.descriptor(roles.getFirst(), key);
            var decrypted = new SamlXmlDecrypter().decrypt(encrypted.getFirst(), key.privateKey());
            if (!S.equals(decrypted.getNamespaceURI())) throw new IllegalArgumentException("Unknown identifier");
            return switch (decrypted.getLocalName()) {
                case "NameID" -> Presence.NAME_ID;
                case "BaseID" -> Presence.BASE_ID;
                default -> throw new IllegalArgumentException("Unknown identifier");
            };
        } catch (Exception unproven) {
            throw new IllegalArgumentException("NameID omission response evidence unavailable");
        }
    }
}
