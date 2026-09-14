package com.samlscope.saml.binding;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/** Verifies an HTTP-Redirect binding signature without reconstructing the signed query values. */
public final class RedirectSignatureVerifier {
    private static final Map<String, String> ALGORITHMS = Map.ofEntries(
            Map.entry("http://www.w3.org/2000/09/xmldsig#rsa-sha1", "SHA1withRSA"),
            Map.entry("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", "SHA256withRSA"),
            Map.entry("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", "SHA384withRSA"),
            Map.entry("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", "SHA512withRSA"),
            Map.entry("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", "SHA256withECDSA"),
            Map.entry("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384", "SHA384withECDSA"),
            Map.entry("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512", "SHA512withECDSA"));

    public boolean isValid(String rawQuery, X509Certificate certificate) {
        if (certificate == null) throw new IllegalArgumentException("certificate is required");
        try {
            var parameters = signedParameters(rawQuery);
            var algorithm = ALGORITHMS.get(decode(parameters.get("SigAlg")));
            if (algorithm == null) return false;
            var signatureBytes = Base64.getDecoder().decode(decode(parameters.get("Signature")));
            var verifier = Signature.getInstance(algorithm);
            verifier.initVerify(certificate.getPublicKey());
            verifier.update(RedirectSignatureInput.fromRawQuery(rawQuery));
            return verifier.verify(signatureBytes);
        } catch (Exception invalid) {
            return false;
        }
    }

    /** Verify the original query, then bind its compressed message to the exact XML being evaluated. */
    public boolean isValidForMessage(String rawQuery, X509Certificate certificate, byte[] expectedXml) {
        return isValid(rawQuery, certificate) && matchesMessage(rawQuery, expectedXml);
    }

    public boolean matchesMessage(String rawQuery, byte[] expectedXml) {
        if (rawQuery == null || expectedXml == null || expectedXml.length == 0 || expectedXml.length > 5 * 1024 * 1024) return false;
        try {
            String encoded = null;
            for (var pair : rawQuery.split("&", -1)) {
                var equals = pair.indexOf('=');
                if (equals < 0) continue;
                var name = pair.substring(0, equals);
                if (name.equals("SAMLRequest") || name.equals("SAMLResponse")) {
                    if (encoded != null) return false;
                    encoded = pair.substring(equals + 1);
                }
            }
            if (encoded == null) return false;
            var compressed = Base64.getDecoder().decode(decode(encoded));
            var inflater = new java.util.zip.Inflater(true);
            try (var input = new java.util.zip.InflaterInputStream(new java.io.ByteArrayInputStream(compressed), inflater)) {
                var actual = input.readNBytes(expectedXml.length + 1);
                return inflater.finished() && java.util.Arrays.equals(expectedXml, actual);
            } finally { inflater.end(); }
        } catch (Exception invalid) { return false; }
    }

    private Map<String, String> signedParameters(String rawQuery) {
        if (rawQuery == null) throw new IllegalArgumentException("rawQuery is required");
        var result = new LinkedHashMap<String, String>();
        for (var pair : rawQuery.split("&", -1)) {
            var equals = pair.indexOf('=');
            if (equals < 0) continue;
            var name = pair.substring(0, equals);
            if (name.equals("SigAlg") || name.equals("Signature")) {
                if (result.putIfAbsent(name, pair.substring(equals + 1)) != null) {
                    throw new IllegalArgumentException("Duplicate " + name);
                }
            }
        }
        if (!result.containsKey("SigAlg") || !result.containsKey("Signature")) {
            throw new IllegalArgumentException("SigAlg and Signature are required");
        }
        return result;
    }

    private String decode(String value) {
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }
}
