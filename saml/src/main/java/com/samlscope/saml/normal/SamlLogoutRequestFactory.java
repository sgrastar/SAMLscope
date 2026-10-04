package com.samlscope.saml.normal;

import java.net.URI;
import java.security.PublicKey;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import javax.xml.XMLConstants;
import org.w3c.dom.Element;
import com.samlscope.saml.crypto.PlanCredentials;
import com.samlscope.saml.crypto.SamlEncryptionFixtureFactory;
import com.samlscope.saml.crypto.XmlSigner;

/** SLO fixture construction only. The caller supplies stable IDs; Runner owns delivery and judgment. */
public final class SamlLogoutRequestFactory {
    public static final String PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
    public static final String ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";
    public static final String ASYNC = "urn:oasis:names:tc:SAML:2.0:protocol:ext:async-slo";

    /** Empty indexes, past expiry and alternative destinations remain expressible as separate fixtures. */
    public byte[] build(String id, URI destination, String issuer, Element identifier,
            List<String> sessionIndexes, Instant issueInstant, Instant notOnOrAfter, boolean asynchronous) {
        Objects.requireNonNull(destination); Objects.requireNonNull(identifier); Objects.requireNonNull(issueInstant);
        var indexes = List.copyOf(sessionIndexes);
        if (id == null || id.isBlank() || issuer == null || issuer.isBlank() || !destination.isAbsolute())
            throw new IllegalArgumentException("SLO fixture requires a stable ID, issuer and absolute destination");
        if (!ASSERTION.equals(identifier.getNamespaceURI())
                || !List.of("NameID", "EncryptedID").contains(identifier.getLocalName()))
            throw new IllegalArgumentException("Expected a NameID or EncryptedID fixture");
        var document = SecureXml.newDocument();
        var root = document.createElementNS(PROTOCOL, "samlp:LogoutRequest");
        root.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:samlp", PROTOCOL);
        root.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:saml", ASSERTION);
        document.appendChild(root);
        root.setAttribute("ID", id); root.setAttribute("Version", "2.0");
        root.setAttribute("IssueInstant", issueInstant.toString());
        root.setAttribute("Destination", destination.toString());
        if (notOnOrAfter != null) root.setAttribute("NotOnOrAfter", notOnOrAfter.toString());
        var issuerElement = document.createElementNS(ASSERTION, "saml:Issuer");
        issuerElement.setTextContent(issuer); root.appendChild(issuerElement);
        if (asynchronous) {
            var extensions = document.createElementNS(PROTOCOL, "samlp:Extensions");
            var async = document.createElementNS(ASYNC, "aslo:Asynchronous");
            async.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:aslo", ASYNC);
            extensions.appendChild(async); root.appendChild(extensions);
        }
        var copied = (Element) document.importNode(identifier, true);
        // Preserve inherited namespace bindings, including ones used only in QName-valued attributes.
        for (var ancestor = identifier; ancestor != null;
                ancestor = ancestor.getParentNode() instanceof Element parent ? parent : null) {
            var attrs = ancestor.getAttributes();
            for (int i = 0; i < attrs.getLength(); i++) {
                var attr = attrs.item(i);
                if (XMLConstants.XMLNS_ATTRIBUTE_NS_URI.equals(attr.getNamespaceURI())
                        && !copied.hasAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, attr.getLocalName()))
                    copied.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, attr.getNodeName(), attr.getNodeValue());
            }
        }
        root.appendChild(copied);
        for (var index : indexes) {
            var element = document.createElementNS(PROTOCOL, "samlp:SessionIndex");
            element.setTextContent(index); root.appendChild(element);
        }
        return SecureXml.serialize(document);
    }

    public Element encryptedIdentifier(Element nameId, PublicKey recipient,
            SamlEncryptionFixtureFactory.Algorithms algorithms) {
        if (!ASSERTION.equals(nameId.getNamespaceURI()) || !"NameID".equals(nameId.getLocalName()))
            throw new IllegalArgumentException("EncryptedID plaintext must be NameID");
        return new SamlEncryptionFixtureFactory().encrypt(
                SamlEncryptionFixtureFactory.Wrapper.EncryptedID, nameId, recipient, algorithms);
    }

    /** Sign once before outbox persistence; refuse to repair any already signed fixture. */
    public byte[] sign(byte[] request, PlanCredentials credentials) {
        var document = SecureXml.parse(request); var root = document.getDocumentElement();
        if (!PROTOCOL.equals(root.getNamespaceURI()) || !"LogoutRequest".equals(root.getLocalName()))
            throw new IllegalArgumentException("Expected LogoutRequest");
        if (root.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature").getLength() != 0)
            throw new IllegalArgumentException("SLO fixture already contains a signature");
        Element before = null;
        for (var node = root.getFirstChild(); node != null; node = node.getNextSibling()) {
            if (node instanceof Element element
                    && !(ASSERTION.equals(element.getNamespaceURI()) && "Issuer".equals(element.getLocalName()))) {
                before = element; break;
            }
        }
        new XmlSigner().sign(root, credentials, before);
        return SecureXml.serialize(document);
    }
}
