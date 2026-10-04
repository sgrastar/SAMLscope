import com.samlscope.saml.crypto.SamlXmlDecrypter;
import com.samlscope.saml.normal.SecureXml;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.HexFormat;
import org.w3c.dom.Element;

/** Read-only, in-container audit of an encrypted RequestedAuthnContext response. */
public final class VerifyIdpErrorResponse {
    private static final String PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";

    public static void main(String[] args) throws Exception {
        if (args.length != 3) throw new IllegalArgumentException("request.xml response.xml plan-key.pk8 required");
        byte[] requestBytes = Files.readAllBytes(Path.of(args[0]));
        byte[] responseBytes = Files.readAllBytes(Path.of(args[1]));
        var request = SecureXml.parse(requestBytes).getDocumentElement();
        var response = SecureXml.parse(responseBytes).getDocumentElement();
        if (!PROTOCOL.equals(request.getNamespaceURI()) || !"AuthnRequest".equals(request.getLocalName())
                || !PROTOCOL.equals(response.getNamespaceURI()) || !"Response".equals(response.getLocalName())) {
            throw new IllegalArgumentException("Wrong SAML document types");
        }
        if (!request.getAttribute("ID").equals(response.getAttribute("InResponseTo"))) {
            throw new IllegalArgumentException("Response is not correlated with request");
        }
        var comparisons = request.getElementsByTagNameNS(PROTOCOL, "RequestedAuthnContext");
        if (comparisons.getLength() != 1
                || !"exact".equals(((Element) comparisons.item(0)).getAttribute("Comparison"))) {
            throw new IllegalArgumentException("RequestedAuthnContext is not exact");
        }
        var requestedRefs = request.getElementsByTagNameNS(ASSERTION, "AuthnContextClassRef");
        if (requestedRefs.getLength() != 1) throw new IllegalArgumentException("Expected one requested class");
        String requested = requestedRefs.item(0).getTextContent();
        var codes = response.getElementsByTagNameNS(PROTOCOL, "StatusCode");
        if (codes.getLength() != 1 || !"urn:oasis:names:tc:SAML:2.0:status:Success"
                .equals(((Element) codes.item(0)).getAttribute("Value"))) {
            throw new IllegalArgumentException("Response does not have top-level Success");
        }
        var wrappers = response.getElementsByTagNameNS(ASSERTION, "EncryptedAssertion");
        if (wrappers.getLength() != 1) throw new IllegalArgumentException("Expected one EncryptedAssertion");
        var key = KeyFactory.getInstance("RSA").generatePrivate(
                new PKCS8EncodedKeySpec(Files.readAllBytes(Path.of(args[2]))));
        var assertion = new SamlXmlDecrypter().decrypt((Element) wrappers.item(0), key);
        if (!ASSERTION.equals(assertion.getNamespaceURI()) || !"Assertion".equals(assertion.getLocalName())) {
            throw new IllegalArgumentException("Decryption did not yield an Assertion");
        }
        var refs = assertion.getElementsByTagNameNS(ASSERTION, "AuthnContextClassRef");
        if (refs.getLength() != 1) throw new IllegalArgumentException("Expected one actual class");
        var context = refs.item(0).getParentNode();
        var statement = context.getParentNode();
        if (!(context instanceof Element contextElement)
                || !(statement instanceof Element statementElement)
                || !ASSERTION.equals(contextElement.getNamespaceURI())
                || !"AuthnContext".equals(contextElement.getLocalName())
                || !ASSERTION.equals(statementElement.getNamespaceURI())
                || !"AuthnStatement".equals(statementElement.getLocalName())
                || statementElement.getParentNode() != assertion) {
            throw new IllegalArgumentException("Actual class is not in a direct AuthnStatement");
        }
        String actual = refs.item(0).getTextContent();
        if (requested.equals(actual)) throw new IllegalArgumentException("Actual class matches requested exact class");
        System.out.printf("{\"requestSha256\":\"%s\",\"responseSha256\":\"%s\",\"requestId\":\"%s\",\"requestedClass\":\"%s\",\"actualClass\":\"%s\",\"result\":\"different-class\"}%n",
                sha(requestBytes), sha(responseBytes), request.getAttribute("ID"), requested, actual);
    }

    private static String sha(byte[] data) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));
    }
}
