package com.samlscope.saml.crypto;

import static org.junit.jupiter.api.Assertions.*;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.spec.SecretKeySpec;
import org.apache.xml.security.encryption.XMLCipher;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;
import com.samlscope.saml.normal.SamlException;
import com.samlscope.saml.normal.SecureXml;

class SamlXmlSharedKeyDecrypterTest {
    @Test
    void gcmSharedKeysDecryptWithoutAKeyTransportAndPreserveTheRecordedCiphertext() throws Exception {
        for (var bits : new int[]{128,256}) {
            var key = key(bits, (byte) 3);
            var wrapper = encrypted(bits, key);
            var recorded = SecureXml.serialize(wrapper.getOwnerDocument());
            var plaintext = new SamlXmlDecrypter().decryptSharedKey(wrapper, key);
            assertEquals("Assertion", plaintext.getLocalName());
            assertEquals("principal", plaintext.getTextContent());
            assertArrayEquals(recorded, SecureXml.serialize(wrapper.getOwnerDocument()));
            assertThrows(SamlException.class, () -> new SamlXmlDecrypter().decryptSharedKey(wrapper, key(bits,(byte)7)));
        }
    }

    @Test
    void aModifiedGcmAuthenticationTagCannotBeUsedAsDecryptedEvidence() throws Exception {
        var key=key(128,(byte)3);
        var wrapper=encrypted(128,key);
        var value=(Element)wrapper.getElementsByTagNameNS("http://www.w3.org/2001/04/xmlenc#","CipherValue").item(0);
        var bytes=Base64.getMimeDecoder().decode(value.getTextContent());
        bytes[bytes.length-1]^=1;
        value.setTextContent(Base64.getEncoder().encodeToString(bytes));
        assertThrows(SamlException.class,()->new SamlXmlDecrypter().decryptSharedKey(wrapper,key));
    }

    private SecretKeySpec key(int bits, byte value) {
        var bytes=new byte[bits/8];Arrays.fill(bytes,value);return new SecretKeySpec(bytes,"AES");
    }

    private Element encrypted(int bits, SecretKeySpec key) throws Exception {
        org.apache.xml.security.Init.init();
        var document=SecureXml.parse(("<saml:EncryptedAssertion xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'>"
                + "<saml:Assertion>principal</saml:Assertion></saml:EncryptedAssertion>").getBytes(java.nio.charset.StandardCharsets.UTF_8));
        var cipher=XMLCipher.getInstance("http://www.w3.org/2009/xmlenc11#aes"+bits+"-gcm");
        cipher.init(XMLCipher.ENCRYPT_MODE,key);
        cipher.doFinal(document,(Element)document.getDocumentElement().getFirstChild(),false);
        return document.getDocumentElement();
    }
}
