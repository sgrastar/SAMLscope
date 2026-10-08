package com.samlscope.saml.artifact;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import com.samlscope.saml.normal.SecureXml;
import org.w3c.dom.Element;

/**
 * The type 0x0004 format from OASIS SAML Bindings 2.0 §3.6.4, not a product verdict.
 * SourceID is opaque; SHA-1(entityID) is only the specification's recommended mapping.
 * Endpoint selection remains bound to the Run's trusted target metadata. Authenticating the
 * resolved response, not comparing SourceID to that recommendation, proves the issuer.
 * https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf
 */
public final class SamlArtifact {
    public static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    public static final String P = "urn:oasis:names:tc:SAML:2.0:protocol";
    public static final String SOAP = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP";
    private final byte[] encoded;
    private SamlArtifact(byte[] encoded) { this.encoded = encoded.clone(); }

    public static SamlArtifact parse(String value) {
        require(value != null && value.length() == 60, "Unsupported artifact encoding");
        byte[] raw;
        try { raw = Base64.getDecoder().decode(value); }
        catch (IllegalArgumentException malformed) { throw new IllegalArgumentException("Invalid artifact base64"); }
        require(raw.length == 44 && raw[0] == 0 && raw[1] == 4, "Unsupported artifact type or size");
        require(value.equals(Base64.getEncoder().encodeToString(raw)), "Non-canonical artifact base64");
        return new SamlArtifact(raw);
    }

    public int endpointIndex() { return ((encoded[2] & 0xff) << 8) | (encoded[3] & 0xff); }
    public byte[] sourceId() { return Arrays.copyOfRange(encoded, 4, 24); }
    public byte[] messageHandle() { return Arrays.copyOfRange(encoded, 24, 44); }
    public byte[] bytes() { return encoded.clone(); }
    public String base64() { return Base64.getEncoder().encodeToString(encoded); }
    public String sha256() { return hash("SHA-256", encoded); }
    public boolean usesRecommendedSourceId(String entityId) {
        return entityId != null && MessageDigest.isEqual(sourceId(), digest("SHA-1", entityId.getBytes(StandardCharsets.UTF_8)));
    }

    /** The exact indexed IDP SOAP endpoint; no default-endpoint fallback on a missing index. */
    public URI resolutionEndpoint(byte[] originalMetadata, String targetEntityId) {
        require(targetEntityId != null && !targetEntityId.isBlank(), "Unproven artifact target entity");
        var root = SecureXml.parse(originalMetadata).getDocumentElement();
        require(MD.equals(root.getNamespaceURI()) && Set.of("EntityDescriptor", "EntitiesDescriptor")
                .contains(root.getLocalName()), "Not SAML metadata");
        var entities = new ArrayList<Element>();
        collectEntities(root, targetEntityId, entities);
        require(entities.size() == 1, "Ambiguous target metadata entity");
        var roles = children(entities.getFirst(), MD, "IDPSSODescriptor").stream()
                .filter(e -> Arrays.asList(e.getAttribute("protocolSupportEnumeration").trim().split("\\s+"))
                        .contains(P)).toList();
        require(roles.size() == 1, "Ambiguous target IdP role");
        var matches = new ArrayList<Element>();
        for (var endpoint : children(roles.getFirst(), MD, "ArtifactResolutionService")) {
            String index = endpoint.getAttribute("index");
            require(index.matches("[+-]?[0-9]+"), "Invalid artifact endpoint index");
            var number = new java.math.BigInteger(index);
            require(number.signum() >= 0 && number.compareTo(java.math.BigInteger.valueOf(65535)) <= 0,
                    "Artifact endpoint index out of range");
            if (number.intValue() == endpointIndex()) matches.add(endpoint);
        }
        require(matches.size() == 1, "Missing or duplicate artifact endpoint index");
        var endpoint = matches.getFirst();
        require(SOAP.equals(endpoint.getAttribute("Binding")) && !endpoint.hasAttribute("ResponseLocation"),
                "Unsupported artifact resolution endpoint");
        var uri = URI.create(endpoint.getAttribute("Location"));
        require(uri.isAbsolute() && uri.getHost() != null && Set.of("https", "http").contains(uri.getScheme().toLowerCase(Locale.ROOT))
                && uri.getRawUserInfo() == null && uri.getRawFragment() == null,
                "Invalid artifact resolution endpoint");
        return uri;
    }

    private static void collectEntities(Element root, String id, List<Element> entities) {
        if ("EntityDescriptor".equals(root.getLocalName())) {
            if (id.equals(root.getAttribute("entityID"))) entities.add(root);
        } else for (var child : children(root, MD, "EntityDescriptor")) collectEntities(child, id, entities);
        for (var child : children(root, MD, "EntitiesDescriptor")) collectEntities(child, id, entities);
    }
    static List<Element> children(Element root, String namespace, String name) {
        var result = new ArrayList<Element>();
        for (var node = root.getFirstChild(); node != null; node = node.getNextSibling()) {
            if (node instanceof Element e && namespace.equals(e.getNamespaceURI()) && name.equals(e.getLocalName())) result.add(e);
        }
        return List.copyOf(result);
    }
    static void require(boolean value, String message) { if (!value) throw new IllegalArgumentException(message); }
    static String hash(String name, byte[] bytes) { return HexFormat.of().formatHex(digest(name, bytes)); }
    private static byte[] digest(String name, byte[] bytes) {
        try { return MessageDigest.getInstance(name).digest(bytes); }
        catch (java.security.NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }
}
