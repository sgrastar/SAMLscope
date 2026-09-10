package com.samlscope.saml.metadata;

import com.samlscope.core.plan.TargetConnection;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.saml.normal.SecureXml;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.EnumSet;
import org.w3c.dom.Element;

/** Registration validation only. Acceptance here is not a conformance verdict. */
public final class TargetConnectionMetadata {
    private static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";

    public TargetConnection.Revision accept(String connectionId, String revisionId,
            String entityId, String xml, Instant now) {
        return accept(connectionId, revisionId, entityId, xml == null ? null : xml.getBytes(StandardCharsets.UTF_8), now);
    }

    public TargetConnection.Revision accept(String connectionId, String revisionId,
            String entityId, byte[] bytes, Instant now) {
        if (entityId == null || entityId.isBlank() || bytes == null || bytes.length == 0) {
            throw new IllegalArgumentException("Select an entity and supply its metadata");
        }
        bytes = bytes.clone();
        var document = SecureXml.parse(bytes);
        var root = document.getDocumentElement();
        var selected = MetadataEntitySelection.select(root, entityId);
        var roles = EnumSet.noneOf(TargetRole.class);
        for (var node = selected.getFirstChild(); node != null; node = node.getNextSibling()) {
            if (!(node instanceof Element element) || !MD.equals(element.getNamespaceURI())) continue;
            if (!java.util.Arrays.asList(element.getAttribute("protocolSupportEnumeration").trim().split("\\s+")).contains(PROTOCOL)) continue;
            if ("IDPSSODescriptor".equals(element.getLocalName())) roles.add(TargetRole.IDP);
            if ("SPSSODescriptor".equals(element.getLocalName())) roles.add(TargetRole.SP);
        }
        if (roles.isEmpty()) throw new IllegalArgumentException("Selected entity has no SAML 2.0 IdP or SP role");
        new TargetMetadataParser().parse(bytes, entityId);
        return TargetConnection.Revision.fromBytes(connectionId, revisionId, roles, bytes, now);
    }
}
