package com.samlscope.runner.cases;

import java.net.URI;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.saml.normal.SecureXml;
import org.w3c.dom.Element;

/** Publisher-side HTTPS recommendation; this does not test consumer URL handling (MD05.fh). */
public final class PublishedUiUrlTestCase implements TestCase {
    public static final String ID = "IIP-MD05-fi-idp-01";
    private static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String UI = "urn:oasis:names:tc:SAML:metadata:ui";
    private final Function<String, byte[]> metadata;
    private final Function<String, java.util.Optional<String>> entityIds;

    public PublishedUiUrlTestCase(Function<String, byte[]> metadata,
            Function<String, java.util.Optional<String>> entityIds) {
        this.metadata = java.util.Objects.requireNonNull(metadata);
        this.entityIds = java.util.Objects.requireNonNull(entityIds);
    }
    @Override public String id() { return ID; }
    @Override public TargetRole role() { return TargetRole.IDP; }
    @Override public CaseStep start(CaseContext context) {
        byte[] bytes;
        String entityId;
        try {
            bytes = metadata.apply(context.runId());
            entityId = entityIds.apply(context.runId()).orElse(null);
        } catch (RuntimeException unavailable) {
            return new CaseStep.Finish(unavailable());
        }
        return new CaseStep.Finish(evaluate(bytes, entityId));
    }
    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        throw new IllegalStateException("Published URL inspection finishes at start");
    }
    static CaseOutcome evaluate(byte[] bytes, String entityId) {
        if (bytes == null || bytes.length == 0 || entityId == null || entityId.isBlank()) return unavailable();
        final org.w3c.dom.Document document;
        try { document = SecureXml.parse(bytes); }
        catch (RuntimeException invalid) { return unavailable(); }
        var entities = document.getElementsByTagNameNS(MD, "EntityDescriptor");
        Element selected = null;
        for (int i = 0; i < entities.getLength(); i++) {
            var candidate = (Element) entities.item(i);
            if (!entityId.equals(candidate.getAttribute("entityID"))) continue;
            if (selected != null) return unavailable(); // Ambiguous target identity cannot supply evidence.
            selected = candidate;
        }
        if (selected == null) return unavailable();
        var violations = new ArrayList<String>();
        int observed = 0;
        boolean roleFound = false;
        for (var child = selected.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (!(child instanceof Element role) || !MD.equals(role.getNamespaceURI())
                    || !"IDPSSODescriptor".equals(role.getLocalName())) continue;
            roleFound = true;
            // UIInfo is defined under the role's Extensions, not arbitrary nested foreign content.
            for (var node = role.getFirstChild(); node != null; node = node.getNextSibling()) {
                if (!(node instanceof Element extensions) || !MD.equals(extensions.getNamespaceURI())
                        || !"Extensions".equals(extensions.getLocalName())) continue;
                for (var item = extensions.getFirstChild(); item != null; item = item.getNextSibling()) {
                    if (!(item instanceof Element info) || !UI.equals(info.getNamespaceURI())
                            || !"UIInfo".equals(info.getLocalName())) continue;
                    for (var value = info.getFirstChild(); value != null; value = value.getNextSibling()) {
                        if (!(value instanceof Element url) || !UI.equals(url.getNamespaceURI())
                                || !List.of("Logo", "InformationURL", "PrivacyStatementURL").contains(url.getLocalName())) continue;
                        observed++;
                        try {
                            // anyURI whitespace is collapsed by XML Schema; no URL is dereferenced.
                            var uri = URI.create(url.getTextContent().strip());
                            if (!"https".equalsIgnoreCase(uri.getScheme())) violations.add(url.getLocalName());
                        } catch (IllegalArgumentException malformed) {
                            return unavailable();
                        }
                    }
                }
            }
        }
        if (!roleFound) return unavailable();
        var outcome = !violations.isEmpty() ? Outcome.VIOLATED
                : observed == 0 ? Outcome.SATISFIED_WITH_NOTE : Outcome.SATISFIED;
        var code = !violations.isEmpty() ? "metadata.ui-https.not-recommended"
                : observed == 0 ? "metadata.ui-https.not-published" : "metadata.ui-https.satisfied";
        try {
            return new CaseOutcome(outcome, null, code, code,
                    List.of(new EvidenceRef("target-metadata", "sha256:" + HexFormat.of().formatHex(
                            MessageDigest.getInstance("SHA-256").digest(bytes)))),
                    Map.of("observed_urls", observed, "non_https_elements", List.copyOf(violations)));
        } catch (java.security.NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }
    private static CaseOutcome unavailable() {
        return CaseOutcome.notVerified("target_metadata_unavailable", "metadata.ui-https.unavailable");
    }
}
