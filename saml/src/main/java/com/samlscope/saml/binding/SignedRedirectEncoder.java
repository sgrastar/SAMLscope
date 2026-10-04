package com.samlscope.saml.binding;

import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.util.Base64;
import java.util.Set;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import org.w3c.dom.Element;
import com.samlscope.saml.crypto.PlanCredentials;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.saml.normal.SamlException;

/** SAML Bindings 3.4.4.1: encode a copy, retaining the exact query octets used for signing. */
public final class SignedRedirectEncoder {
    private static final String P = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String DS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String ALG = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    private static final Set<String> RESERVED = Set.of("SAMLRequest", "SAMLResponse", "RelayState", "SigAlg", "Signature", "SAMLEncoding");

    public Encoded encode(URI endpoint, byte[] xml, String relayState, PlanCredentials credentials) {
        if (endpoint == null || endpoint.getHost() == null || endpoint.getRawUserInfo() != null
                || endpoint.getRawFragment() != null || !Set.of("http", "https").contains(endpoint.getScheme()))
            throw new IllegalArgumentException("Redirect endpoint must be an HTTP URL without credentials or fragment");
        if (credentials == null || !"RSA".equals(credentials.privateKey().getAlgorithm()))
            throw new IllegalArgumentException("RSA signing credentials are required for this encoder");
        var originalQuery = endpoint.getRawQuery();
        if (originalQuery != null) for (var pair : originalQuery.split("&", -1)) {
            var key = pair.split("=", 2)[0];
            if (RESERVED.contains(URLDecoder.decode(key, StandardCharsets.UTF_8)))
                throw new IllegalArgumentException("Redirect endpoint has a reserved SAML query parameter");
        }
        var document = SecureXml.parse(xml);
        var root = document.getDocumentElement();
        if (!P.equals(root.getNamespaceURI()) || !Set.of("AuthnRequest", "LogoutRequest", "Response", "LogoutResponse").contains(root.getLocalName()))
            throw new IllegalArgumentException("Unsupported SAML protocol message for Redirect encoder");
        for (var node = root.getFirstChild(); node != null;) {
            var next = node.getNextSibling();
            if (node instanceof Element e && DS.equals(e.getNamespaceURI()) && "Signature".equals(e.getLocalName())) root.removeChild(node);
            node = next;
        }
        byte[] wireXml = SecureXml.serialize(document);
        try {
            var output = new ByteArrayOutputStream();
            var deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
            try (var stream = new DeflaterOutputStream(output, deflater)) { stream.write(wireXml); }
            finally { deflater.end(); }
            var parameter = root.getLocalName().endsWith("Request") ? "SAMLRequest" : "SAMLResponse";
            var signed = parameter + "=" + url(Base64.getEncoder().encodeToString(output.toByteArray()));
            if (relayState != null) signed += "&RelayState=" + url(relayState);
            signed += "&SigAlg=" + url(ALG);
            var signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(credentials.privateKey());
            signer.update(signed.getBytes(StandardCharsets.US_ASCII));
            var query = signed + "&Signature=" + url(Base64.getEncoder().encodeToString(signer.sign()));
            var separator = originalQuery == null ? "?" : originalQuery.isEmpty() || endpoint.toString().endsWith("&") ? "" : "&";
            var destination = URI.create(endpoint.toASCIIString() + separator + query);
            return new Encoded(destination, destination.getRawQuery(), wireXml);
        } catch (java.io.IOException | java.security.GeneralSecurityException failure) {
            throw new SamlException("Could not encode signed Redirect message", failure);
        }
    }

    private static String url(String value) { return URLEncoder.encode(value, StandardCharsets.UTF_8); }
    public record Encoded(URI destination, String rawQuery, byte[] decodedXml) {
        public Encoded { decodedXml = decodedXml.clone(); }
        @Override public byte[] decodedXml() { return decodedXml.clone(); }
    }
}
