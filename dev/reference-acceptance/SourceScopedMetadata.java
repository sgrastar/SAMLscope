import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.List;
import javax.xml.XMLConstants;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/** JDK-only helper for the source-scoped metadata trust acceptance campaign. */
public final class SourceScopedMetadata {
    private static final String DS = XMLSignature.XMLNS;

    public static void main(String[] args) throws Exception {
        if (args.length != 4 || !(args[0].equals("sign") || args[0].equals("verify"))) {
            throw new IllegalArgumentException("sign input key.pk8 cert.der | verify input cert.der output");
        }
        if (args[0].equals("sign")) {
            sign(Path.of(args[1]), Path.of(args[2]), Path.of(args[3]));
        } else {
            verify(Path.of(args[1]), Path.of(args[2]));
            Files.writeString(Path.of(args[3]), "verified\n");
        }
    }

    private static Document parse(Path path) throws Exception {
        var factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        return factory.newDocumentBuilder().parse(path.toFile());
    }

    private static X509Certificate certificate(Path path) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(Files.readAllBytes(path)));
    }

    private static void sign(Path input, Path keyPath, Path output) throws Exception {
        var certPath = Path.of(output.toString() + ".cert.der");
        if (!Files.isRegularFile(certPath)) throw new IllegalArgumentException("missing " + certPath);
        var document = parse(input);
        var root = document.getDocumentElement();
        var signatures = root.getElementsByTagNameNS(DS, "Signature");
        while (signatures.getLength() > 0) {
            var signature = signatures.item(0);
            signature.getParentNode().removeChild(signature);
        }
        var id = root.getAttribute("ID");
        if (id.isBlank()) {
            id = "_samlscope_source_scoped";
            root.setAttribute("ID", id);
        }
        root.setIdAttribute("ID", true);
        PrivateKey key = KeyFactory.getInstance("RSA").generatePrivate(
                new PKCS8EncodedKeySpec(Files.readAllBytes(keyPath)));
        var certificate = certificate(certPath);
        var factory = XMLSignatureFactory.getInstance("DOM");
        Reference reference = factory.newReference("#" + id,
                factory.newDigestMethod(DigestMethod.SHA256, null),
                List.of(factory.newTransform(Transform.ENVELOPED,
                                (javax.xml.crypto.dsig.spec.TransformParameterSpec) null),
                        factory.newTransform(CanonicalizationMethod.EXCLUSIVE,
                                (javax.xml.crypto.dsig.spec.TransformParameterSpec) null)), null, null);
        SignedInfo signedInfo = factory.newSignedInfo(
                factory.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE,
                        (javax.xml.crypto.dsig.spec.C14NMethodParameterSpec) null),
                factory.newSignatureMethod(SignatureMethod.RSA_SHA256, null), List.of(reference));
        KeyInfoFactory kif = factory.getKeyInfoFactory();
        X509Data x509 = kif.newX509Data(List.of(certificate));
        KeyInfo info = kif.newKeyInfo(List.of(x509));
        var context = new DOMSignContext(key, root);
        Node first = root.getFirstChild();
        if (first != null) context.setNextSibling(first);
        factory.newXMLSignature(signedInfo, info).sign(context);
        var transformers = TransformerFactory.newInstance();
        transformers.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        transformers.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
        var transformer = transformers.newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
        transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
        transformer.transform(new DOMSource(document), new StreamResult(output.toFile()));
    }

    private static void verify(Path input, Path certPath) throws Exception {
        var document = parse(input);
        Element root = document.getDocumentElement();
        if (root.hasAttribute("ID")) root.setIdAttribute("ID", true);
        NodeList signatures = root.getElementsByTagNameNS(DS, "Signature");
        if (signatures.getLength() != 1 || signatures.item(0).getParentNode() != root) {
            throw new IllegalArgumentException("expected one root metadata signature");
        }
        var context = new DOMValidateContext(certificate(certPath).getPublicKey(), signatures.item(0));
        if (!XMLSignatureFactory.getInstance("DOM").unmarshalXMLSignature(context).validate(context)) {
            throw new IllegalArgumentException("metadata signature verification failed");
        }
    }
}
