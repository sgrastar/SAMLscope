package com.samlscope.runner.cases;

import static com.samlscope.runner.cases.MetadataAlgorithmEvidence.children;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.*;
import org.w3c.dom.Element;
import com.samlscope.saml.crypto.*;

/** Reads comparison markers only after signature and matching-key decryption checks. */
final class AttributePolicyAttributeReader {
    private static final String S = "urn:oasis:names:tc:SAML:2.0:assertion";
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
            var assertion = VerifiedResponseAssertion.read(response, targetEntity, targetSigningKeys,
                    preparedMetadata, encryptionKey, requestId, recipient);
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
