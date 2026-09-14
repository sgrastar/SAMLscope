package com.samlscope.saml.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.KeyPairGenerator;
import javax.crypto.KeyGenerator;
import org.apache.xml.security.Init;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.utils.EncryptionConstants;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import com.samlscope.saml.normal.SamlException;
import com.samlscope.saml.normal.SecureXml;
import org.w3c.dom.Element;

class SamlXmlDecrypterTest {
    @BeforeAll static void initializeXmlSecurity() { Init.init(); }

    @Test
    void decryptsAnElementUsingOnlyTheRunScopedPrivateKey() throws Exception {
        var keys = KeyPairGenerator.getInstance("RSA");
        keys.initialize(2048);
        var pair = keys.generateKeyPair();
        var wrapper = encryptedWrapper("EncryptedAssertion", """
                <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a"/>
                """, pair.getPublic());

        var plaintext = new SamlXmlDecrypter().decrypt(wrapper, pair.getPrivate());

        assertEquals("Assertion", plaintext.getLocalName());
        assertEquals("_a", plaintext.getAttribute("ID"));
    }

    @Test
    void wrongKeyDoesNotBecomePlausiblePlaintext() throws Exception {
        var keys = KeyPairGenerator.getInstance("RSA");
        keys.initialize(2048);
        var pair = keys.generateKeyPair();
        var wrong = keys.generateKeyPair();
        var wrapper = encryptedWrapper("EncryptedID", """
                <saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">subject</saml:NameID>
                """, pair.getPublic());

        assertThrows(SamlException.class, () -> new SamlXmlDecrypter().decrypt(wrapper, wrong.getPrivate()));
    }

    @Test
    void decryptsKeycloakStyleAes256GcmAndRsaOaep11Sha256() throws Exception {
        var keys = KeyPairGenerator.getInstance("RSA");
        keys.initialize(3072);
        var pair = keys.generateKeyPair();
        var wrapper = encryptedWrapper(
                "EncryptedAssertion",
                """
                <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_keycloak"/>
                """,
                pair.getPublic(),
                XMLCipher.AES_256_GCM,
                XMLCipher.RSA_OAEP_11,
                XMLCipher.SHA256,
                EncryptionConstants.MGF1_SHA256);

        var plaintext = new SamlXmlDecrypter().decrypt(wrapper, pair.getPrivate());

        assertEquals("Assertion", plaintext.getLocalName());
        assertEquals("_keycloak", plaintext.getAttribute("ID"));
    }

    @Test
    void refusesUnencryptedDecoysAndNestedOrDuplicateEncryptedData() throws Exception {
        var generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(2048);
        var keys = generator.generateKeyPair();
        for (String mutation : java.util.List.of("prefix", "suffix", "nested", "duplicate", "text", "foreign-wrapper")) {
            var wrapper = encryptedWrapper("EncryptedID", "<saml:NameID xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'>real</saml:NameID>", keys.getPublic());
            var doc = wrapper.getOwnerDocument();
            var data = wrapper.getElementsByTagNameNS("http://www.w3.org/2001/04/xmlenc#", "EncryptedData").item(0);
            var decoy = doc.createElementNS("urn:oasis:names:tc:SAML:2.0:assertion", "saml:NameID");
            decoy.setTextContent("unencrypted-decoy");
            switch (mutation) {
                case "prefix" -> wrapper.insertBefore(decoy, data);
                case "suffix" -> wrapper.appendChild(decoy);
                case "nested" -> { wrapper.replaceChild(decoy, data); decoy.appendChild(data); }
                case "duplicate" -> wrapper.appendChild(data.cloneNode(true));
                case "text" -> wrapper.insertBefore(doc.createTextNode("unexpected"), data);
                case "foreign-wrapper" -> doc.renameNode(wrapper, "urn:foreign", "bad:EncryptedID");
                default -> throw new AssertionError();
            }
            assertThrows(SamlException.class, () -> new SamlXmlDecrypter().decrypt(wrapper, keys.getPrivate()), mutation);
        }
    }

    static Element encryptedWrapper(String wrapperName, String plaintextXml, java.security.PublicKey publicKey) throws Exception {
        return encryptedWrapper(
                wrapperName,
                plaintextXml,
                publicKey,
                XMLCipher.AES_128_GCM,
                XMLCipher.RSA_OAEP,
                null,
                null);
    }

    static Element encryptedWrapper(
            String wrapperName,
            String plaintextXml,
            java.security.PublicKey publicKey,
            String dataAlgorithm,
            String keyAlgorithm,
            String digestAlgorithm,
            String mgfAlgorithm) throws Exception {
        var document = SecureXml.parse(("""
                <saml:%s xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml:%s>
                """).formatted(wrapperName, plaintextXml, wrapperName).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        org.w3c.dom.Node child = document.getDocumentElement().getFirstChild();
        while (child != null && child.getNodeType() != org.w3c.dom.Node.ELEMENT_NODE) {
            child = child.getNextSibling();
        }
        var plaintext = (Element) child;
        var keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(XMLCipher.AES_256_GCM.equals(dataAlgorithm) ? 256 : 128);
        var dataKey = keyGenerator.generateKey();

        var dataCipher = XMLCipher.getInstance(dataAlgorithm);
        dataCipher.init(XMLCipher.ENCRYPT_MODE, dataKey);
        var keyCipher = digestAlgorithm == null
                ? XMLCipher.getInstance(keyAlgorithm)
                : XMLCipher.getInstance(keyAlgorithm, null, digestAlgorithm);
        keyCipher.init(XMLCipher.WRAP_MODE, publicKey);
        var encryptedKey = mgfAlgorithm == null
                ? keyCipher.encryptKey(document, dataKey)
                : keyCipher.encryptKey(document, dataKey, mgfAlgorithm, null);
        var keyInfo = new KeyInfo(document);
        keyInfo.add(encryptedKey);
        dataCipher.getEncryptedData().setKeyInfo(keyInfo);
        dataCipher.doFinal(document, plaintext);
        return document.getDocumentElement();
    }
}
