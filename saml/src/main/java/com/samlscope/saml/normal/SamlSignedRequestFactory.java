package com.samlscope.saml.normal;

import java.net.URI;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import javax.xml.XMLConstants;
import com.samlscope.saml.crypto.PlanCredentials;
import com.samlscope.saml.crypto.XmlSigner;
import org.w3c.dom.Element;

/** Builds and deliberately corrupts XML-signed AuthnRequest fixtures. */
public final class SamlSignedRequestFactory {
    private static final String PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String DS = "http://www.w3.org/2000/09/xmldsig#";
    private final XmlSigner signer;

    public enum Fixture {
        VALID,
        DEFAULT_ACS,
        TAMPERED_ACS,
        BAD_REFERENCE,
        BAD_SIGNATURE_VALUE,
        XPATH_EXCLUDE_ACS,
        XPATH_EXCLUDE_NAMEID_POLICY,
        XPATH_EXCLUDE_SCOPING,
        XPATH_EMPTY_CONTENT,
        SIGNED_WITH_OBJECT
    }

    public SamlSignedRequestFactory() { this(new XmlSigner()); }

    SamlSignedRequestFactory(XmlSigner signer) {
        this.signer = java.util.Objects.requireNonNull(signer, "signer");
    }

    public byte[] build(
            Fixture fixture,
            String requestId,
            URI destination,
            String issuer,
            URI acs,
            Instant issueInstant,
            PlanCredentials credentials) {
        return build(fixture, requestId, destination, issuer, acs, issueInstant, credentials, null);
    }

    /** The attribute service selector is part of the signed request, not a post-signature mutation. */
    public byte[] build(
            Fixture fixture,
            String requestId,
            URI destination,
            String issuer,
            URI acs,
            Instant issueInstant,
            PlanCredentials credentials,
            Integer attributeConsumingServiceIndex) {
        java.util.Objects.requireNonNull(fixture, "fixture");
        java.util.Objects.requireNonNull(credentials, "credentials");
        if (attributeConsumingServiceIndex != null
                && (attributeConsumingServiceIndex < 0 || attributeConsumingServiceIndex > 65535)) {
            throw new IllegalArgumentException("AttributeConsumingServiceIndex must be an unsigned short");
        }
        if (requestId == null || requestId.isBlank()) throw new IllegalArgumentException("requestId is required");
        if (issuer == null || issuer.isBlank()) throw new IllegalArgumentException("issuer is required");
        var document = SecureXml.newDocument();
        var request = document.createElementNS(PROTOCOL, "samlp:AuthnRequest");
        request.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:samlp", PROTOCOL);
        request.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:saml", ASSERTION);
        request.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:ds", DS);
        request.setAttribute("ID", requestId);
        request.setAttribute("Version", "2.0");
        request.setAttribute("IssueInstant", DateTimeFormatter.ISO_INSTANT.format(issueInstant));
        request.setAttribute("Destination", destination.toString());
        if (attributeConsumingServiceIndex != null) {
            request.setAttribute("AttributeConsumingServiceIndex", attributeConsumingServiceIndex.toString());
        }
        if (fixture != Fixture.DEFAULT_ACS) {
            request.setAttribute("AssertionConsumerServiceURL", acs.toString());
            request.setAttribute("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
        }
        document.appendChild(request);
        var issuerElement = document.createElementNS(ASSERTION, "saml:Issuer");
        issuerElement.setTextContent(issuer);
        request.appendChild(issuerElement);
        var policy = document.createElementNS(PROTOCOL, "samlp:NameIDPolicy");
        policy.setAttribute("Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:transient");
        request.appendChild(policy);
        if (fixture == Fixture.XPATH_EXCLUDE_SCOPING) {
            var scoping = document.createElementNS(PROTOCOL, "samlp:Scoping");
            scoping.setAttribute("ProxyCount", "1");
            request.appendChild(scoping);
        }
        signer.sign(request, credentials, policy, signatureOptions(fixture));
        switch (fixture) {
            case VALID, DEFAULT_ACS -> { }
            case TAMPERED_ACS -> request.setAttribute(
                    "AssertionConsumerServiceURL", alternateAcs(acs).toString());
            case BAD_REFERENCE -> {
                var references = request.getElementsByTagNameNS(DS, "Reference");
                if (references.getLength() != 1) throw new SamlException("Expected one signature Reference");
                ((Element) references.item(0)).setAttribute("URI", "#_samlscope-unrelated-element");
            }
            case BAD_SIGNATURE_VALUE -> {
                var values = request.getElementsByTagNameNS(DS, "SignatureValue");
                if (values.getLength() != 1) throw new SamlException("Expected one SignatureValue");
                var value = values.item(0).getTextContent().strip();
                values.item(0).setTextContent((value.startsWith("A") ? "B" : "A") + value.substring(1));
            }
            case XPATH_EXCLUDE_ACS, XPATH_EXCLUDE_NAMEID_POLICY,
                    XPATH_EXCLUDE_SCOPING, XPATH_EMPTY_CONTENT -> { }
            case SIGNED_WITH_OBJECT -> {
                var signatures = request.getElementsByTagNameNS(DS, "Signature");
                if (signatures.getLength() != 1) throw new SamlException("Expected one Signature");
                var object = document.createElementNS(DS, "ds:Object");
                object.setTextContent("samlscope signed-object fixture");
                signatures.item(0).appendChild(object);
            }
        }
        return SecureXml.serialize(document);
    }

    private XmlSigner.SignatureOptions signatureOptions(Fixture fixture) {
        var transforms = switch (fixture) {
            case XPATH_EXCLUDE_ACS -> signedWithXPath(
                    "not(self::node()[local-name()='AssertionConsumerServiceURL' and parent::samlp:AuthnRequest])");
            case XPATH_EXCLUDE_NAMEID_POLICY -> signedWithXPath(
                    "not(ancestor-or-self::samlp:NameIDPolicy)");
            case XPATH_EXCLUDE_SCOPING -> signedWithXPath(
                    "not(ancestor-or-self::samlp:Scoping)");
            case XPATH_EMPTY_CONTENT -> signedWithXPath("false()");
            default -> XmlSigner.SignatureOptions.standard().transforms();
        };
        return new XmlSigner.SignatureOptions(true, transforms);
    }

    private java.util.List<XmlSigner.TransformSpec> signedWithXPath(String expression) {
        return java.util.List.of(
                XmlSigner.TransformSpec.algorithm(
                        org.apache.xml.security.transforms.Transforms.TRANSFORM_ENVELOPED_SIGNATURE),
                XmlSigner.TransformSpec.xpath(expression),
                XmlSigner.TransformSpec.algorithm(
                        org.apache.xml.security.transforms.Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS));
    }

    private URI alternateAcs(URI acs) {
        var text = acs.toString();
        if (text.endsWith("/0")) return URI.create(text.substring(0, text.length() - 1) + "1");
        return URI.create(text + (text.endsWith("/") ? "1" : "/1"));
    }
}
