package com.samlscope.saml.normal;

import java.net.URI;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import javax.xml.XMLConstants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/** Builds deterministic RequestedAuthnContext inputs without inventing a target strength ordering. */
public final class SamlRequestedAuthnContextRequestFactory {
    public static final String PASSWORD_PROTECTED_TRANSPORT =
            "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
    public static final String FIXTURE_DECLARATION = "urn:samlscope:fixture:authn-context-decl";
    private static final String PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";

    public enum Fixture { BASELINE, SATISFIABLE_CLASS, SATISFIABLE_DECLARATION, UNSATISFIABLE_CLASS }

    public enum Comparison { EXACT, MINIMUM, BETTER, MAXIMUM }
    public enum ReferenceKind { CLASS, DECLARATION }
    public record ContextRequest(Comparison comparison, ReferenceKind kind, java.util.List<String> references) {
        public ContextRequest {
            java.util.Objects.requireNonNull(comparison, "comparison");
            java.util.Objects.requireNonNull(kind, "kind");
            references = java.util.List.copyOf(references);
            if (references.isEmpty() || references.stream().anyMatch(String::isBlank)
                    || new java.util.HashSet<>(references).size() != references.size()) {
                throw new IllegalArgumentException("A nonempty ordered set of context references is required");
            }
        }
    }

    public byte[] build(Fixture fixture, String requestId, URI destination, String issuer, URI acs, Instant issueInstant) {
        java.util.Objects.requireNonNull(fixture, "fixture");
        requireText(requestId, "requestId");
        ContextRequest requested = switch (fixture) {
            case BASELINE -> null;
            case SATISFIABLE_CLASS -> new ContextRequest(Comparison.EXACT, ReferenceKind.CLASS,
                    java.util.List.of(PASSWORD_PROTECTED_TRANSPORT));
            case SATISFIABLE_DECLARATION -> new ContextRequest(Comparison.EXACT, ReferenceKind.DECLARATION,
                    java.util.List.of(FIXTURE_DECLARATION));
            case UNSATISFIABLE_CLASS -> new ContextRequest(Comparison.EXACT, ReferenceKind.CLASS,
                    java.util.List.of("urn:samlscope:probe:unavailable-authn-context:" + token(requestId)));
        };
        return buildInternal(requested, requestId, destination, issuer, acs, issueInstant);
    }

    /** References retain the caller's preference order; their positions do not imply strength. */
    public byte[] buildConfiguredContext(ContextRequest requested, String requestId, URI destination,
            String issuer, URI acs, Instant issueInstant) {
        java.util.Objects.requireNonNull(requested, "requested");
        return buildInternal(requested, requestId, destination, issuer, acs, issueInstant);
    }

    /** Sign after Issuer, before RequestedAuthnContext, preserving the SAML schema order. */
    public byte[] buildSignedContext(ContextRequest requested, String requestId, URI destination,
            String issuer, URI acs, Instant issueInstant, com.samlscope.saml.crypto.PlanCredentials credentials) {
        var document = SecureXml.parse(buildConfiguredContext(requested, requestId, destination, issuer, acs, issueInstant));
        var root = document.getDocumentElement();
        var context = (Element) root.getElementsByTagNameNS(PROTOCOL, "RequestedAuthnContext").item(0);
        new com.samlscope.saml.crypto.XmlSigner().sign(root, java.util.Objects.requireNonNull(credentials), context);
        return SecureXml.serialize(document);
    }

    private byte[] buildInternal(ContextRequest context, String requestId, URI destination,
            String issuer, URI acs, Instant issueInstant) {
        requireText(requestId, "requestId");
        requireText(issuer, "issuer");
        java.util.Objects.requireNonNull(destination, "destination");
        java.util.Objects.requireNonNull(acs, "acs");
        java.util.Objects.requireNonNull(issueInstant, "issueInstant");
        var document = SecureXml.newDocument();
        var request = element(document, PROTOCOL, "samlp:AuthnRequest");
        request.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:samlp", PROTOCOL);
        request.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:saml", ASSERTION);
        request.setAttribute("ID", requestId);
        request.setAttribute("Version", "2.0");
        request.setAttribute("IssueInstant", DateTimeFormatter.ISO_INSTANT.format(issueInstant));
        request.setAttribute("Destination", destination.toString());
        request.setAttribute("AssertionConsumerServiceURL", acs.toString());
        request.setAttribute("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
        document.appendChild(request);
        var issuerElement = element(document, ASSERTION, "saml:Issuer");
        issuerElement.setTextContent(issuer);
        request.appendChild(issuerElement);
        if (context != null) {
            var requested = element(document, PROTOCOL, "samlp:RequestedAuthnContext");
            requested.setAttribute("Comparison", context.comparison().name().toLowerCase(java.util.Locale.ROOT));
            for (String value : context.references()) {
                var reference = element(document, ASSERTION, context.kind() == ReferenceKind.CLASS
                        ? "saml:AuthnContextClassRef" : "saml:AuthnContextDeclRef");
                reference.setTextContent(value);
                requested.appendChild(reference);
            }
            request.appendChild(requested);
        }
        return SecureXml.serialize(document);
    }

    private Element element(Document document, String namespace, String qualifiedName) {
        return document.createElementNS(namespace, qualifiedName);
    }

    private String token(String requestId) {
        return requestId.startsWith("_") ? requestId.substring(1) : requestId;
    }

    private void requireText(String value, String name) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(name + " must not be blank");
    }
}
