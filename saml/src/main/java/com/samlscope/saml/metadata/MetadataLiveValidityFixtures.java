package com.samlscope.saml.metadata;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/** Fresh, signed campaign inputs whose actual loaded bytes expire without a second target write. */
final class MetadataLiveValidityFixtures {
    private MetadataLiveValidityFixtures() { }

    static Element apply(Document document, Element entity, MetadataService.Variant variant,
            Instant generatedAt, int lifetimeSeconds) {
        if (!java.util.Set.of(MetadataService.Variant.LIVE_VALIDITY_ROOT,
                MetadataService.Variant.LIVE_VALIDITY_PARENT,
                MetadataService.Variant.LIVE_VALIDITY_CHILD).contains(variant)) return entity;
        if (lifetimeSeconds < 1) throw new IllegalArgumentException("Live validity fixture needs a positive test lifetime");
        String expiry = generatedAt.plusSeconds(lifetimeSeconds).toString();
        String later = generatedAt.plus(14, ChronoUnit.DAYS).toString();
        if (variant == MetadataService.Variant.LIVE_VALIDITY_ROOT) {
            entity.setAttribute("validUntil", expiry);
            return entity;
        }
        entity.setAttribute("validUntil", later);
        var inner = group(document, entity, entity.getAttribute("ID") + "_validity_inner", later);
        var outer = group(document, inner, entity.getAttribute("ID") + "_validity_outer", later);
        (variant == MetadataService.Variant.LIVE_VALIDITY_PARENT ? outer : inner)
                .setAttribute("validUntil", expiry);
        return outer;
    }

    private static Element group(Document document, Element child, String id, String until) {
        var wrapper = document.createElementNS(MetadataService.MD, "md:EntitiesDescriptor");
        wrapper.setAttributeNS(javax.xml.XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:md", MetadataService.MD);
        wrapper.setAttributeNS(javax.xml.XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:ds", MetadataService.DS);
        wrapper.setAttribute("ID", id);
        wrapper.setAttribute("validUntil", until);
        var parent = child.getParentNode();
        if (parent != null) parent.replaceChild(wrapper, child);
        wrapper.appendChild(child);
        return wrapper;
    }
}
