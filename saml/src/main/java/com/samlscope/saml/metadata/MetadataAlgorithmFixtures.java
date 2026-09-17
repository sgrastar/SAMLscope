package com.samlscope.saml.metadata;

import java.util.List;
import javax.xml.XMLConstants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/** Inputs for algorithm ordering and per-type role precedence; not an acceptance oracle. */
final class MetadataAlgorithmFixtures {
    static final String ALG = "urn:oasis:names:tc:SAML:metadata:algsupport";
    private static final String MORE = "http://www.w3.org/2001/04/xmldsig-more#";
    private MetadataAlgorithmFixtures() {}

    static Element apply(Document document, Element entity, MetadataService.Variant variant) {
        var sp = (Element) entity.getElementsByTagNameNS(MetadataService.MD, "SPSSODescriptor").item(0);
        if (sp == null) return entity;
        switch (variant) {
            case ALGORITHM_ENTITY_SHA256 -> add(document, entity, List.of(256), List.of(256));
            case ALGORITHM_ENTITY_SHA384 -> add(document, entity, List.of(384), List.of(384));
            case ALGORITHM_ENTITY_ORDER_256_384 -> add(document, entity, List.of(256,384), List.of(256,384));
            case ALGORITHM_ENTITY_ORDER_384_256 -> add(document, entity, List.of(384,256), List.of(384,256));
            case ALGORITHM_ROLE_ORDER_256_384 -> add(document, sp, List.of(256,384), List.of(256,384));
            case ALGORITHM_ROLE_ORDER_384_256 -> add(document, sp, List.of(384,256), List.of(384,256));
            case ALGORITHM_ROLE_SIGNING_384 -> {
                add(document, entity, List.of(256), List.of(256));
                add(document, sp, List.of(), List.of(384));
            }
            case ALGORITHM_ROLE_DIGEST_384 -> {
                add(document, entity, List.of(256), List.of(256));
                add(document, sp, List.of(384), List.of());
            }
            case ALGORITHM_ROLE_BOTH_384 -> {
                add(document, entity, List.of(256), List.of(256));
                add(document, sp, List.of(384), List.of(384));
            }
            case ALGORITHM_ROLE_BOTH_256 -> {
                add(document, entity, List.of(384), List.of(384));
                add(document, sp, List.of(256), List.of(256));
            }
            case ALGORITHM_UNSUPPORTED_FIRST -> add(document, entity, List.of(0,256), List.of(0,256));
            // The explicit absence control uses the same metadata generation path without declarations.
            case ALGORITHM_ABSENT -> { }
            default -> { }
        }
        return entity;
    }

    private static void add(Document document, Element parent, List<Integer> digests, List<Integer> signatures) {
        var extensions = document.createElementNS(MetadataService.MD, "md:Extensions");
        extensions.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:alg", ALG);
        for (int bits : digests) {
            var method = document.createElementNS(ALG, "alg:DigestMethod");
            method.setAttribute("Algorithm", bits == 0 ? "urn:samlscope:test:unsupported-digest"
                    : bits == 256 ? "http://www.w3.org/2001/04/xmlenc#sha256" : MORE + "sha384");
            extensions.appendChild(method);
        }
        for (int bits : signatures) {
            var method = document.createElementNS(ALG, "alg:SigningMethod");
            method.setAttribute("Algorithm", bits == 0 ? "urn:samlscope:test:unsupported-signature" : MORE + "rsa-sha" + bits);
            extensions.appendChild(method);
        }
        parent.insertBefore(extensions, parent.getFirstChild());
    }
}
