import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import javax.xml.XMLConstants;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/** Independently verifies original Keycloak Response and Assertion signatures. */
public final class VerifyKeycloakNameIdOriginals {
    private static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String DS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String P = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String A = "urn:oasis:names:tc:SAML:2.0:assertion";

    public static void main(String[] args) throws Exception {
        if (args.length != 5) throw new IllegalArgumentException("metadata plus four Response originals required");
        var metadata = parse(Path.of(args[0]));
        var descriptor = metadata.getDocumentElement();
        if (!MD.equals(descriptor.getNamespaceURI()) || !"EntityDescriptor".equals(descriptor.getLocalName())
                || !"http://localhost:18180/realms/samlscope".equals(descriptor.getAttribute("entityID"))) {
            throw new IllegalArgumentException("target metadata identity mismatch");
        }
        var roles = descriptor.getElementsByTagNameNS(MD, "IDPSSODescriptor");
        if (roles.getLength() != 1) throw new IllegalArgumentException("ambiguous IdP metadata role");
        var signing = new HashSet<String>();
        var keys = ((Element) roles.item(0)).getElementsByTagNameNS(MD, "KeyDescriptor");
        for (int index = 0; index < keys.getLength(); index++) {
            var key = (Element) keys.item(index);
            if (!key.getAttribute("use").isBlank() && !"signing".equals(key.getAttribute("use"))) continue;
            var certificates = key.getElementsByTagNameNS(DS, "X509Certificate");
            for (int item = 0; item < certificates.getLength(); item++) {
                signing.add(certificates.item(item).getTextContent().replaceAll("\\s+", ""));
            }
        }
        if (signing.size() != 1) throw new IllegalArgumentException("ambiguous target signing key");
        var encoded = signing.iterator().next();
        var certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
            .generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(encoded)));
        var statuses = new ArrayList<String>();
        for (int index = 1; index < args.length; index++) {
            var response = parse(Path.of(args[index])).getDocumentElement();
            if (!P.equals(response.getNamespaceURI()) || !"Response".equals(response.getLocalName())) {
                throw new IllegalArgumentException("not a SAML Response");
            }
            verifySignature(response, certificate, encoded);
            var statusParents = response.getElementsByTagNameNS(P, "Status");
            if (statusParents.getLength() != 1) throw new IllegalArgumentException("ambiguous status");
            var status = ((Element) statusParents.item(0)).getElementsByTagNameNS(P, "StatusCode");
            if (status.getLength() < 1) throw new IllegalArgumentException("status code absent");
            var value = ((Element) status.item(0)).getAttribute("Value");
            var assertions = response.getElementsByTagNameNS(A, "Assertion");
            if (index == 3) {
                if (!value.endsWith(":Responder") || assertions.getLength() != 0) {
                    throw new IllegalArgumentException("null mapper did not yield signed Responder without Assertion");
                }
            } else {
                if (!value.endsWith(":Success") || assertions.getLength() != 1) {
                    throw new IllegalArgumentException("normal condition did not yield Success Assertion");
                }
                var assertion = (Element) assertions.item(0);
                verifySignature(assertion, certificate, encoded);
                var subjects = assertion.getElementsByTagNameNS(A, "Subject");
                if (subjects.getLength() != 1 || ((Element) subjects.item(0))
                        .getElementsByTagNameNS(A, "NameID").getLength() != 1) {
                    throw new IllegalArgumentException("normal condition did not contain a Subject/NameID");
                }
            }
            statuses.add(value.substring(value.lastIndexOf(':') + 1));
        }
        System.out.println("{\"statuses\":\"" + String.join(",", statuses) + "\",\"signatures\":7}");
    }

    private static void verifySignature(Element parent, X509Certificate certificate, String encoded) throws Exception {
        var id = parent.getAttribute("ID");
        if (id.isBlank()) throw new IllegalArgumentException("signed ID missing");
        parent.setIdAttribute("ID", true);
        Element signatureElement = null;
        for (Node child = parent.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (child instanceof Element element && DS.equals(element.getNamespaceURI())
                    && "Signature".equals(element.getLocalName())) {
                if (signatureElement != null) throw new IllegalArgumentException("duplicate direct signature");
                signatureElement = element;
            }
        }
        if (signatureElement == null) throw new IllegalArgumentException("direct signature absent");
        var embedded = signatureElement.getElementsByTagNameNS(DS, "X509Certificate");
        if (embedded.getLength() != 1 || !encoded.equals(embedded.item(0).getTextContent().replaceAll("\\s+", ""))) {
            throw new IllegalArgumentException("wire signing key differs from metadata");
        }
        var context = new DOMValidateContext(certificate.getPublicKey(), signatureElement);
        context.setProperty("org.jcp.xml.dsig.secureValidation", Boolean.TRUE);
        var signature = XMLSignatureFactory.getInstance("DOM").unmarshalXMLSignature(context);
        if (signature.getSignedInfo().getReferences().size() != 1
                || !("#" + id).equals(signature.getSignedInfo().getReferences().getFirst().getURI())
                || !signature.validate(context)) {
            throw new IllegalArgumentException("invalid signature for " + id);
        }
    }

    private static org.w3c.dom.Document parse(Path path) throws Exception {
        var factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        return factory.newDocumentBuilder().parse(Files.newInputStream(path));
    }
}
