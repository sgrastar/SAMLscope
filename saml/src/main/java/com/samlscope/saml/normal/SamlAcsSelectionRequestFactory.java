package com.samlscope.saml.normal;

import java.net.URI;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import javax.xml.XMLConstants;

/** Builds product-neutral AuthnRequest fixtures for ACS selection and response binding tests. */
public final class SamlAcsSelectionRequestFactory {
    private static final String PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";
    public static final String POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
    public static final String REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
    public static final String ARTIFACT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact";
    public static final String UNSUPPORTED = "urn:samlscope:unsupported:response-binding";

    public byte[] build(
            Fixture fixture,
            String requestId,
            URI destination,
            String issuer,
            URI defaultAcs,
            URI secondaryAcs,
            Instant issueInstant) {
        return build(
                fixture, requestId, destination, issuer, defaultAcs, secondaryAcs,
                otherEntityAcs(defaultAcs), issueInstant);
    }

    public byte[] build(
            Fixture fixture,
            String requestId,
            URI destination,
            String issuer,
            URI defaultAcs,
            URI secondaryAcs,
            URI otherEntityAcs,
            Instant issueInstant) {
        java.util.Objects.requireNonNull(fixture, "fixture");
        requireText(requestId, "requestId");
        requireText(issuer, "issuer");
        java.util.Objects.requireNonNull(destination, "destination");
        java.util.Objects.requireNonNull(defaultAcs, "defaultAcs");
        java.util.Objects.requireNonNull(secondaryAcs, "secondaryAcs");
        java.util.Objects.requireNonNull(otherEntityAcs, "otherEntityAcs");
        java.util.Objects.requireNonNull(issueInstant, "issueInstant");
        var document = SecureXml.newDocument();
        var request = document.createElementNS(PROTOCOL, "samlp:AuthnRequest");
        request.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:samlp", PROTOCOL);
        request.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:saml", ASSERTION);
        request.setAttribute("ID", requestId);
        request.setAttribute("Version", "2.0");
        request.setAttribute("IssueInstant", DateTimeFormatter.ISO_INSTANT.format(issueInstant));
        request.setAttribute("Destination", destination.toString());
        switch (fixture) {
            case DEFAULT -> { }
            case INDEX_ONE -> request.setAttribute("AssertionConsumerServiceIndex", "1");
            case UNKNOWN_INDEX -> request.setAttribute("AssertionConsumerServiceIndex", "999999");
            case URL_ONE -> request.setAttribute("AssertionConsumerServiceURL", secondaryAcs.toString());
            case UNKNOWN_URL -> request.setAttribute(
                    "AssertionConsumerServiceURL", defaultAcs.resolve("999999").toString());
            case OTHER_ENTITY_URL -> request.setAttribute(
                    "AssertionConsumerServiceURL", otherEntityAcs.toString());
            case POST_BINDING, REDIRECT_BINDING, ARTIFACT_BINDING, UNSUPPORTED_BINDING -> {
                request.setAttribute("AssertionConsumerServiceURL", defaultAcs.toString());
                request.setAttribute("ProtocolBinding", switch (fixture) {
                    case POST_BINDING -> POST;
                    case REDIRECT_BINDING -> REDIRECT;
                    case ARTIFACT_BINDING -> ARTIFACT;
                    default -> UNSUPPORTED;
                });
            }
        }
        document.appendChild(request);
        var issuerElement = document.createElementNS(ASSERTION, "saml:Issuer");
        issuerElement.setTextContent(issuer);
        request.appendChild(issuerElement);
        return SecureXml.serialize(document);
    }

    public enum Fixture {
        DEFAULT,
        INDEX_ONE,
        UNKNOWN_INDEX,
        URL_ONE,
        UNKNOWN_URL,
        OTHER_ENTITY_URL,
        POST_BINDING,
        REDIRECT_BINDING,
        ARTIFACT_BINDING,
        UNSUPPORTED_BINDING
    }

    public static URI otherEntityAcs(URI defaultAcs) {
        java.util.Objects.requireNonNull(defaultAcs, "defaultAcs");
        if (!defaultAcs.isAbsolute() || defaultAcs.getHost() == null) {
            throw new IllegalArgumentException("defaultAcs must be an absolute HTTP(S) URI");
        }
        var path = defaultAcs.getPath();
        var marker = "/sp/acs/";
        var markerAt = path == null ? -1 : path.lastIndexOf(marker);
        if (markerAt < 0) {
            throw new IllegalArgumentException("defaultAcs must use the Suite SP ACS path");
        }
        try {
            return new URI(
                    defaultAcs.getScheme(), null, defaultAcs.getHost(), defaultAcs.getPort(),
                    path.substring(0, markerAt) + "/samlscope-other-sp/acs", null, null);
        } catch (java.net.URISyntaxException impossible) {
            throw new IllegalArgumentException("Could not derive the other-entity ACS", impossible);
        }
    }

    private static void requireText(String value, String name) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(name + " must not be blank");
    }
}
