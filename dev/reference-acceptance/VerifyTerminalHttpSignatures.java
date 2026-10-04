import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.LinkedHashMap;
import javax.xml.XMLConstants;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Element;

/** Independently checks the valid/invalid signature state of SSO01.ak wire originals. */
public final class VerifyTerminalHttpSignatures {
    private static final String DS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String P = "urn:oasis:names:tc:SAML:2.0:protocol";

    public static void main(String[] args) throws Exception {
        if (args.length < 3 || args.length % 2 == 0) {
            throw new IllegalArgumentException("metadata followed by fixture/request pairs required");
        }
        var metadata = parse(Files.readAllBytes(Path.of(args[0]))).getDocumentElement();
        var certificates = metadata.getElementsByTagNameNS(DS, "X509Certificate");
        if (certificates.getLength() < 1) throw new IllegalArgumentException("Metadata certificate missing");
        var encoded = certificates.item(0).getTextContent().replaceAll("\\s+", "");
        var certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(encoded)));
        var results = new LinkedHashMap<String, Boolean>();
        for (int index = 1; index < args.length; index += 2) {
            var fixture = args[index];
            if (results.containsKey(fixture)) throw new IllegalArgumentException("Duplicate fixture");
            var document = parse(Files.readAllBytes(Path.of(args[index + 1])));
            var request = document.getDocumentElement();
            if (!P.equals(request.getNamespaceURI()) || !"AuthnRequest".equals(request.getLocalName())) {
                throw new IllegalArgumentException("Not an AuthnRequest");
            }
            var signatures = request.getElementsByTagNameNS(DS, "Signature");
            if (signatures.getLength() != 1 || !request.hasAttribute("ID")) {
                throw new IllegalArgumentException("Exactly one request signature is required");
            }
            var signatureElement = (Element) signatures.item(0);
            var embedded = signatureElement.getElementsByTagNameNS(DS, "X509Certificate");
            if (embedded.getLength() != 1
                    || !encoded.equals(embedded.item(0).getTextContent().replaceAll("\\s+", ""))) {
                throw new IllegalArgumentException("Wire certificate differs from Suite metadata");
            }
            request.setIdAttribute("ID", true);
            boolean valid;
            try {
                var context = new DOMValidateContext(certificate.getPublicKey(), signatureElement);
                context.setProperty("org.jcp.xml.dsig.secureValidation", Boolean.TRUE);
                valid = XMLSignatureFactory.getInstance("DOM")
                        .unmarshalXMLSignature(context).validate(context);
            } catch (Exception invalidSignature) {
                valid = false;
            }
            if ("valid".equals(fixture) != valid) {
                throw new IllegalArgumentException("Unexpected signature validity for " + fixture);
            }
            results.put(fixture, valid);
        }
        var text = new StringBuilder("{");
        for (var entry : results.entrySet()) {
            if (text.length() > 1) text.append(',');
            text.append('"').append(entry.getKey()).append("\":").append(entry.getValue());
        }
        System.out.println(text.append('}'));
    }

    private static org.w3c.dom.Document parse(byte[] raw) throws Exception {
        var factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        return factory.newDocumentBuilder().parse(new ByteArrayInputStream(raw));
    }
}
