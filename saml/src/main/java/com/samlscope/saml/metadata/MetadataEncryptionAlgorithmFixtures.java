package com.samlscope.saml.metadata;

import java.util.List;
import javax.xml.XMLConstants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/** Negotiation inputs only. Publication does not prove target selection or successful decryption. */
final class MetadataEncryptionAlgorithmFixtures {
    private static final String XENC = "http://www.w3.org/2001/04/xmlenc#";
    private static final String XENC11 = "http://www.w3.org/2009/xmlenc11#";
    private static final String DS = "http://www.w3.org/2000/09/xmldsig#";
    private MetadataEncryptionAlgorithmFixtures() {}

    static Element apply(Document document, Element entity, MetadataService.Variant variant) {
        var sp = (Element) entity.getElementsByTagNameNS(MetadataService.MD, "SPSSODescriptor").item(0);
        if (sp == null) return entity;
        if (variant == MetadataService.Variant.ALGORITHM_SIGNING_256_KEYSIZE_EXCLUDED
                || variant == MetadataService.Variant.ALGORITHM_SIGNING_384_KEYSIZE_EXCLUDED) {
            signingSize(document, sp, variant == MetadataService.Variant.ALGORITHM_SIGNING_256_KEYSIZE_EXCLUDED);
            return entity;
        }
        var data = switch (variant) {
            case ALGORITHM_ENCRYPTION_AES128_CBC, ALGORITHM_ENCRYPTION_KEYSIZE_128 -> List.of(XENC + "aes128-cbc");
            case ALGORITHM_ENCRYPTION_AES256_CBC, ALGORITHM_ENCRYPTION_KEYSIZE_256 -> List.of(XENC + "aes256-cbc");
            case ALGORITHM_ENCRYPTION_AES128_GCM -> List.of(XENC11 + "aes128-gcm");
            case ALGORITHM_ENCRYPTION_AES256_GCM -> List.of(XENC11 + "aes256-gcm");
            case ALGORITHM_ENCRYPTION_ORDER_128_256 -> List.of(XENC11 + "aes128-gcm", XENC11 + "aes256-gcm");
            case ALGORITHM_ENCRYPTION_ORDER_256_128 -> List.of(XENC11 + "aes256-gcm", XENC11 + "aes128-gcm");
            case ALGORITHM_OAEP_10_SHA1, ALGORITHM_OAEP_10_SHA256, ALGORITHM_OAEP_11_SHA1,
                 ALGORITHM_OAEP_11_SHA256, ALGORITHM_OAEP_11_DEFAULT_MGF -> List.of(XENC11 + "aes128-gcm");
            // IIP-MD05.e variant 3: several methods in one KeyDescriptor, spanning a block cipher
            // (aes128-cbc), a stream/authenticated cipher (aes128-gcm) and descriptors elsewhere in
            // the metadata are independent inputs, not acceptance oracles.
            case ALGORITHM_ENCRYPTION_MULTIPLE -> List.of(XENC + "aes128-cbc", XENC11 + "aes128-gcm");
            default -> List.<String>of();
        };
        if (data.isEmpty()) return entity;
        for (var n = sp.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (!(n instanceof Element key) || !MetadataService.MD.equals(key.getNamespaceURI())
                    || !"KeyDescriptor".equals(key.getLocalName()) || "signing".equals(key.getAttribute("use"))) continue;
            for (var algorithm : data) {
                var method = method(document, key, algorithm);
                if (variant == MetadataService.Variant.ALGORITHM_ENCRYPTION_KEYSIZE_128
                        || variant == MetadataService.Variant.ALGORITHM_ENCRYPTION_KEYSIZE_256) {
                    var size = document.createElementNS(XENC, "xenc:KeySize");
                    size.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:xenc", XENC);
                    size.setTextContent(variant == MetadataService.Variant.ALGORITHM_ENCRYPTION_KEYSIZE_128 ? "128" : "256");
                    method.appendChild(size);
                }
            }
            boolean oldOaep = variant == MetadataService.Variant.ALGORITHM_OAEP_10_SHA1
                    || variant == MetadataService.Variant.ALGORITHM_OAEP_10_SHA256;
            boolean newOaep = variant == MetadataService.Variant.ALGORITHM_OAEP_11_SHA1
                    || variant == MetadataService.Variant.ALGORITHM_OAEP_11_SHA256
                    || variant == MetadataService.Variant.ALGORITHM_OAEP_11_DEFAULT_MGF;
            if (oldOaep || newOaep) {
                var transport = method(document, key, oldOaep ? XENC + "rsa-oaep-mgf1p" : XENC11 + "rsa-oaep");
                boolean sha1 = variant == MetadataService.Variant.ALGORITHM_OAEP_10_SHA1
                        || variant == MetadataService.Variant.ALGORITHM_OAEP_11_SHA1;
                var digest = document.createElementNS(DS, "ds:DigestMethod");
                digest.setAttribute("Algorithm", sha1 ? DS + "sha1" : XENC + "sha256");
                transport.appendChild(digest);
                if (newOaep && variant != MetadataService.Variant.ALGORITHM_OAEP_11_DEFAULT_MGF) {
                    var mgf = document.createElementNS(XENC11, "xenc11:MGF");
                    mgf.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:xenc11", XENC11);
                    mgf.setAttribute("Algorithm", XENC11 + (sha1 ? "mgf1sha1" : "mgf1sha256"));
                    transport.appendChild(mgf);
                }
            }
        }
        return entity;
    }

    private static Element method(Document document, Element key, String algorithm) {
        var method = document.createElementNS(MetadataService.MD, "md:EncryptionMethod");
        method.setAttribute("Algorithm", algorithm);
        key.appendChild(method);
        return method;
    }

    private static void signingSize(Document document, Element role, boolean exclude256) {
        var ext = document.createElementNS(MetadataService.MD, "md:Extensions");
        ext.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:alg", MetadataAlgorithmFixtures.ALG);
        for (int bits : exclude256 ? List.of(256, 384) : List.of(384, 256)) {
            var method = document.createElementNS(MetadataAlgorithmFixtures.ALG, "alg:SigningMethod");
            method.setAttribute("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha" + bits);
            // This is a deliberate incompatible input, not a Suite security threshold.
            if (bits == (exclude256 ? 256 : 384)) method.setAttribute("MaxKeySize", "1");
            ext.appendChild(method);
        }
        role.insertBefore(ext, role.getFirstChild());
    }
}
