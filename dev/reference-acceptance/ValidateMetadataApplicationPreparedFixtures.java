import com.samlscope.saml.crypto.XmlSignatureVerifier;
import com.samlscope.saml.normal.SamlSchemaValidation;
import com.samlscope.saml.normal.SecureXml;
import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import org.w3c.dom.Element;

/** Public-only preparation check before native writes or authentication. No product verdict. */
public final class ValidateMetadataApplicationPreparedFixtures {
    private static final String MD="urn:oasis:names:tc:SAML:2.0:metadata", DS="http://www.w3.org/2000/09/xmldsig#";
    public static void main(String[] args) throws Exception {
        if (args.length != 2) throw new IllegalArgumentException("folder entityID");
        var folder=Path.of(args[0]);
        for (var variant:List.of("control","multiple-signing-keys-first","no-valid-until")) {
            var file=folder.resolve("prepared-preflight-"+variant+".xml");
            var root=SecureXml.parse(Files.readAllBytes(file)).getDocumentElement();
            require(MD.equals(root.getNamespaceURI())&&"EntityDescriptor".equals(root.getLocalName())&&args[1].equals(root.getAttribute("entityID")));
            require(SamlSchemaValidation.isValid(root,SamlSchemaValidation.SchemaKind.METADATA));
            var signature=only(root,DS,"Signature");
            var certificate=only(only(only(signature,DS,"KeyInfo"),DS,"X509Data"),DS,"X509Certificate");
            var der=Base64.getMimeDecoder().decode(certificate.getTextContent());
            var cert=(X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
            require(new XmlSignatureVerifier().hasValidEnvelopedSignature(root,cert));
            var sp=only(root,MD,"SPSSODescriptor");
            require("true".equals(sp.getAttribute("AuthnRequestsSigned")));
            require(children(sp,MD,"AssertionConsumerService").size()==4&&children(sp,MD,"SingleLogoutService").size()==3);
            require(!children(sp,MD,"KeyDescriptor").isEmpty());
            System.out.println(variant+" schema-valid signature-valid complete-role");
        }
    }
    private static List<Element> children(Element root,String ns,String local) {
        var out=new java.util.ArrayList<Element>();
        for(var n=root.getFirstChild();n!=null;n=n.getNextSibling()) if(n instanceof Element e&&ns.equals(e.getNamespaceURI())&&local.equals(e.getLocalName()))out.add(e);
        return out;
    }
    private static Element only(Element root,String ns,String local) {
        var values=children(root,ns,local);require(values.size()==1);return values.getFirst();
    }
    private static void require(boolean condition) {if(!condition)throw new IllegalArgumentException("Unqualified public metadata preparation");}
}
