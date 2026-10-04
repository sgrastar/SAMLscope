package com.samlscope.saml.crypto;

import java.security.cert.X509Certificate;
import org.apache.xml.security.Init;
import org.apache.xml.security.signature.XMLSignature;
import org.w3c.dom.Element;

/** Cryptographic verification of a direct enveloped signature over one selected XML element. */
public final class XmlSignatureVerifier {
    private static final String DS = "http://www.w3.org/2000/09/xmldsig#";
    static { Init.init(); }

    public boolean hasValidEnvelopedSignature(Element target, X509Certificate certificate) {
        java.util.Objects.requireNonNull(target, "target");
        java.util.Objects.requireNonNull(certificate, "certificate");
        try {
            if (!target.hasAttribute("ID")) return false;
            target.setIdAttribute("ID", true);
            var signatureElement = directChild(target, DS, "Signature");
            if (signatureElement == null) return false;
            var signature = new XMLSignature(signatureElement, "");
            if (signature.getSignedInfo().getLength() != 1) return false;
            var reference = signature.getSignedInfo().item(0);
            if (!("#" + target.getAttribute("ID")).equals(reference.getURI())) return false;
            return signature.checkSignatureValue(certificate);
        } catch (Exception invalid) {
            return false;
        }
    }

    /** Check the unmodified content digest independently of a deliberately corrupted SignatureValue. */
    public boolean hasValidEnvelopedReferenceDigests(Element target) {
        try {
            if (!target.hasAttribute("ID") || target.getAttribute("ID").isBlank()) return false;
            target.setIdAttribute("ID", true);
            var element = directChild(target, DS, "Signature");
            if (element == null) return false;
            var signature = new XMLSignature(element, "");
            var info = signature.getSignedInfo();
            if (info.getLength() != 1 || !("#" + target.getAttribute("ID")).equals(info.item(0).getURI())) return false;
            var transforms = element.getElementsByTagNameNS(DS, "Transform");
            if (transforms.getLength() != 2
                    || !"http://www.w3.org/2000/09/xmldsig#enveloped-signature".equals(((Element) transforms.item(0)).getAttribute("Algorithm"))
                    || !"http://www.w3.org/2001/10/xml-exc-c14n#".equals(((Element) transforms.item(1)).getAttribute("Algorithm"))) return false;
            return info.verifyReferences();
        } catch (Exception invalid) { return false; }
    }

    private Element directChild(Element parent, String namespace, String localName) {
        for (var child = parent.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (child instanceof Element element
                    && namespace.equals(element.getNamespaceURI())
                    && localName.equals(element.getLocalName())) return element;
        }
        return null;
    }
}
