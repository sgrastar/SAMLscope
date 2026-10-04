package com.samlscope.saml.crypto;

import static org.junit.jupiter.api.Assertions.*;
import java.security.KeyPairGenerator;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;
import com.samlscope.saml.normal.SamlException;
import com.samlscope.saml.normal.SecureXml;

class SamlEncryptionFixtureFactoryTest {
    @Test void everyAlgorithmAndWrapperRoundTripsAndRejectsTheWrongKeyAndTampering() throws Exception {
        var keys=KeyPairGenerator.getInstance("RSA");keys.initialize(2048);
        var recipient=keys.generateKeyPair();var wrong=keys.generateKeyPair();
        var factory=new SamlEncryptionFixtureFactory();var decrypter=new SamlXmlDecrypter();
        var rows=SamlEncryptionFixtureFactory.matrix();
        assertEquals(24,rows.size());assertEquals(rows.size(),rows.stream().map(SamlEncryptionFixtureFactory.Algorithms::id).distinct().count());
        for(var wrapper:SamlEncryptionFixtureFactory.Wrapper.values())for(var row:rows) {
            String name=switch(wrapper){case EncryptedAssertion->"Assertion";case EncryptedID->"NameID";case EncryptedAttribute->"Attribute";};
            String body=switch(wrapper) {
                case EncryptedAssertion -> "<saml:Issuer>https://issuer.example</saml:Issuer>";
                case EncryptedID -> "\u65e5\u672c\u8a9e &amp; text";
                case EncryptedAttribute -> "<saml:AttributeValue>\u65e5\u672c\u8a9e &amp; text</saml:AttributeValue>";
            };
            String attributes=switch(wrapper) {
                case EncryptedAssertion -> " ID='_fixture' Version='2.0' IssueInstant='2026-09-14T00:00:00Z'";
                case EncryptedID -> " Format='urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'";
                case EncryptedAttribute -> " Name='fixture'";
            };
            var input=SecureXml.parse(("<saml:"+name+" xmlns:saml='"+SamlEncryptionFixtureFactory.SAML+"'"+attributes+">"+body+"</saml:"+name+">").getBytes(StandardCharsets.UTF_8)).getDocumentElement();
            assertTrue(com.samlscope.saml.normal.SamlSchemaValidation.isValid(input,
                    com.samlscope.saml.normal.SamlSchemaValidation.SchemaKind.ASSERTION));
            var before=SecureXml.serialize(input.getOwnerDocument());
            var encrypted=factory.encrypt(wrapper,input,recipient.getPublic(),row);
            assertTrue(com.samlscope.saml.normal.SamlSchemaValidation.isValid(encrypted,
                    com.samlscope.saml.normal.SamlSchemaValidation.SchemaKind.ASSERTION), row.id());
            var roundTrip=decrypter.decrypt(encrypted,recipient.getPrivate());
            assertEquals(name,roundTrip.getLocalName(),row.id());
            assertEquals(SamlEncryptionFixtureFactory.SAML,roundTrip.getNamespaceURI());
            assertEquals(input.getTextContent(),roundTrip.getTextContent());
            assertArrayEquals(before,SecureXml.serialize(input.getOwnerDocument()));
            assertThrows(SamlException.class,()->decrypter.decrypt(encrypted,wrong.getPrivate()),row.id());
            var methods=encrypted.getElementsByTagNameNS("http://www.w3.org/2001/04/xmlenc#","EncryptionMethod");
            assertEquals(row.content().uri(),((Element)methods.item(0)).getAttribute("Algorithm"));
            assertEquals(row.transport().uri(),((Element)methods.item(1)).getAttribute("Algorithm"));
            var digest=((Element)methods.item(1)).getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#","DigestMethod");
            if(row.digest()==SamlEncryptionFixtureFactory.Digest.DEFAULT)assertEquals(0,digest.getLength());
            else assertEquals(row.digest().uri(),((Element)digest.item(0)).getAttribute("Algorithm"));
            var mgf=((Element)methods.item(1)).getElementsByTagNameNS("http://www.w3.org/2009/xmlenc11#","MGF");
            if(row.mgf()==SamlEncryptionFixtureFactory.Mgf.DEFAULT)assertEquals(0,mgf.getLength());
            else assertEquals(row.mgf().uri(),((Element)mgf.item(0)).getAttribute("Algorithm"));
            var values=encrypted.getElementsByTagNameNS("http://www.w3.org/2001/04/xmlenc#","CipherValue");
            var ciphertext=values.item(values.getLength()-1);
            var decoded=Base64.getMimeDecoder().decode(ciphertext.getTextContent());decoded[decoded.length-1]^=1;
            ciphertext.setTextContent(Base64.getEncoder().encodeToString(decoded));
            assertThrows(SamlException.class,()->decrypter.decrypt(encrypted,recipient.getPrivate()),row.id());
        }
    }
    @Test void preservesInheritedNamespaceContextAndRejectsUnsupportedInputs() throws Exception {
        var keys=KeyPairGenerator.getInstance("RSA");keys.initialize(2048);var recipient=keys.generateKeyPair();
        var doc=SecureXml.parse(("<root xmlns:custom='urn:custom:type'><saml:Attribute xmlns:saml='"+SamlEncryptionFixtureFactory.SAML+"' xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' xsi:type='custom:Value'/></root>").getBytes(StandardCharsets.UTF_8));
        var input=(Element)doc.getDocumentElement().getFirstChild();
        var factory=new SamlEncryptionFixtureFactory();
        var encrypted=factory.encrypt(SamlEncryptionFixtureFactory.Wrapper.EncryptedAttribute,input,recipient.getPublic(),SamlEncryptionFixtureFactory.matrix().getFirst());
        assertEquals("urn:custom:type",new SamlXmlDecrypter().decrypt(encrypted,recipient.getPrivate()).lookupNamespaceURI("custom"));
        assertThrows(IllegalArgumentException.class,()->new SamlEncryptionFixtureFactory.Algorithms(
                SamlEncryptionFixtureFactory.Content.AES128_GCM,SamlEncryptionFixtureFactory.Transport.RSA_OAEP,
                SamlEncryptionFixtureFactory.Digest.SHA1,SamlEncryptionFixtureFactory.Mgf.SHA256));
        var ec=KeyPairGenerator.getInstance("EC").generateKeyPair();
        assertThrows(IllegalArgumentException.class,()->factory.encrypt(SamlEncryptionFixtureFactory.Wrapper.EncryptedID,input,ec.getPublic(),SamlEncryptionFixtureFactory.matrix().getFirst()));
    }
}
