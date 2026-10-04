package com.samlscope.saml.crypto;

import java.security.PublicKey;
import java.util.*;
import javax.crypto.KeyGenerator;
import javax.xml.XMLConstants;
import org.apache.xml.security.Init;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.utils.EncryptionConstants;
import org.w3c.dom.Element;
import com.samlscope.saml.normal.SamlException;
import com.samlscope.saml.normal.SecureXml;

/** Protocol fixture bytes only; Runner owns delivery and outcomes. */
public final class SamlEncryptionFixtureFactory {
    static { Init.init(); }
    public static final String SAML = "urn:oasis:names:tc:SAML:2.0:assertion";
    public enum Wrapper { EncryptedAssertion, EncryptedID, EncryptedAttribute }
    public enum Content {
        AES128_GCM(XMLCipher.AES_128_GCM,128), AES256_GCM(XMLCipher.AES_256_GCM,256);
        private final String uri; private final int bits;
        Content(String uri,int bits){this.uri=uri;this.bits=bits;}
        public String uri(){return uri;}
    }
    public enum Transport {
        /** Explicit legacy transport for prevention-control fixtures; omitted from {@link #matrix()}. */
        RSA_1_5(XMLCipher.RSA_v1dot5),
        RSA_OAEP(XMLCipher.RSA_OAEP), RSA_OAEP_11(XMLCipher.RSA_OAEP_11);
        private final String uri; Transport(String uri){this.uri=uri;}
        public String uri(){return uri;}
    }
    public enum Digest {
        DEFAULT(null), SHA1(XMLCipher.SHA1), SHA256(XMLCipher.SHA256);
        private final String uri; Digest(String uri){this.uri=uri;}
        public String uri(){return uri;}
    }
    public enum Mgf {
        DEFAULT(null), SHA1(EncryptionConstants.MGF1_SHA1), SHA256(EncryptionConstants.MGF1_SHA256);
        private final String uri; Mgf(String uri){this.uri=uri;}
        public String uri(){return uri;}
    }
    public record Algorithms(Content content,Transport transport,Digest digest,Mgf mgf) {
        public Algorithms {
            Objects.requireNonNull(content);Objects.requireNonNull(transport);
            Objects.requireNonNull(digest);Objects.requireNonNull(mgf);
            if(transport==Transport.RSA_1_5 && (digest!=Digest.DEFAULT || mgf!=Mgf.DEFAULT))
                throw new IllegalArgumentException("RSA v1.5 has no OAEP digest or MGF parameters");
            if(transport==Transport.RSA_OAEP && mgf!=Mgf.DEFAULT)
                throw new IllegalArgumentException("XML Encryption 1.0 OAEP uses its fixed MGF without an XML Encryption 1.1 MGF parameter");
        }
        public String id(){return (content+"-"+transport+"-digest-"+digest+"-mgf-"+mgf).toLowerCase(Locale.ROOT).replace('_','-');}
    }
    /** Explicit and omitted parameter forms remain distinct inputs. No combination implies a verdict. */
    public static List<Algorithms> matrix() {
        var rows=new ArrayList<Algorithms>();
        for(var content:Content.values())for(var transport:List.of(Transport.RSA_OAEP,Transport.RSA_OAEP_11))for(var digest:Digest.values())for(var mgf:Mgf.values()) {
            if(transport==Transport.RSA_OAEP && mgf!=Mgf.DEFAULT)continue;
            rows.add(new Algorithms(content,transport,digest,mgf));
        }
        return List.copyOf(rows);
    }
    public Element encrypt(Wrapper wrapper,Element plaintext,PublicKey recipient,Algorithms algorithms) {
        Objects.requireNonNull(wrapper);Objects.requireNonNull(plaintext);Objects.requireNonNull(recipient);Objects.requireNonNull(algorithms);
        if(!"RSA".equals(recipient.getAlgorithm()))throw new IllegalArgumentException("RSA-OAEP requires an RSA recipient key");
        try {
            var document=SecureXml.newDocument();
            var root=document.createElementNS(SAML,"saml:"+wrapper.name());
            root.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI,"xmlns:saml",SAML);
            document.appendChild(root);
            var input=(Element)document.importNode(plaintext,true);
            // Keep namespace context used by QName-valued attributes in the plaintext.
            for(var ancestor=plaintext;ancestor!=null;ancestor=ancestor.getParentNode() instanceof Element parent?parent:null) {
                var attributes=ancestor.getAttributes();
                for(int i=0;i<attributes.getLength();i++) {
                    var attribute=attributes.item(i);
                    if(XMLConstants.XMLNS_ATTRIBUTE_NS_URI.equals(attribute.getNamespaceURI())
                            && !input.hasAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI,attribute.getLocalName()))
                        input.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI,attribute.getNodeName(),attribute.getNodeValue());
                }
            }
            root.appendChild(input);
            var generator=KeyGenerator.getInstance("AES");generator.init(algorithms.content.bits);
            var key=generator.generateKey();
            var contentCipher=XMLCipher.getInstance(algorithms.content.uri);contentCipher.init(XMLCipher.ENCRYPT_MODE,key);
            var transportCipher=XMLCipher.getInstance(algorithms.transport.uri,null,
                    algorithms.digest==Digest.DEFAULT ? XMLCipher.SHA1 : algorithms.digest.uri);
            transportCipher.init(XMLCipher.WRAP_MODE,recipient);
            var encryptedKey=transportCipher.encryptKey(document,key,
                    algorithms.mgf==Mgf.DEFAULT ? EncryptionConstants.MGF1_SHA1 : algorithms.mgf.uri,null);
            var keyInfo=new KeyInfo(document);keyInfo.add(encryptedKey);contentCipher.getEncryptedData().setKeyInfo(keyInfo);
            contentCipher.doFinal(document,input);
            // Santuario may serialize defaults explicitly. Omitted-parameter fixtures must
            // actually omit them while retaining the SHA-1 / MGF1-SHA1 operation above.
            var keyElement=(Element)root.getElementsByTagNameNS("http://www.w3.org/2001/04/xmlenc#","EncryptedKey").item(0);
            if(algorithms.digest==Digest.DEFAULT)removeParameter(keyElement,"http://www.w3.org/2000/09/xmldsig#","DigestMethod");
            if(algorithms.mgf==Mgf.DEFAULT)removeParameter(keyElement,"http://www.w3.org/2009/xmlenc11#","MGF");
            return root;
        } catch(Exception failure){throw new SamlException("Could not generate encrypted SAML fixture",failure);}
    }
    private static void removeParameter(Element encryptedKey,String namespace,String localName) {
        var values=encryptedKey.getElementsByTagNameNS(namespace,localName);
        while(values.getLength()>0){var value=values.item(0);value.getParentNode().removeChild(value);}
    }
}
