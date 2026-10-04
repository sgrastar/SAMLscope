package com.samlscope.saml.metadata;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.RSAPublicKeySpec;
import java.util.*;
import org.w3c.dom.Element;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.saml.normal.SamlException;
import com.samlscope.saml.normal.SecureXml;

/** Role-bound public keys for constructing encrypted test inputs; not a metadata verdict. */
public final class TargetEncryptionKeys {
    private static final String MD="urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String DS="http://www.w3.org/2000/09/xmldsig#";
    public List<PublicKey> rsaKeys(byte[] metadata,String entityId,TargetRole role) {
        Objects.requireNonNull(role);
        var entity=MetadataEntitySelection.select(SecureXml.parse(metadata).getDocumentElement(),entityId);
        var keys=new LinkedHashMap<String,PublicKey>();
        String roleName=role==TargetRole.IDP?"IDPSSODescriptor":"SPSSODescriptor";
        try {
            for(var descriptor:children(entity,MD,roleName)) {
                if(!Arrays.asList(descriptor.getAttribute("protocolSupportEnumeration").trim().split("\\s+")).contains("urn:oasis:names:tc:SAML:2.0:protocol"))continue;
                for(var key:children(descriptor,MD,"KeyDescriptor")) {
                    var use=key.getAttribute("use");
                    if(!use.isEmpty()&&!"encryption".equals(use))continue;
                    for(var info:children(key,DS,"KeyInfo")) {
                        for(var data:children(info,DS,"X509Data"))for(var cert:children(data,DS,"X509Certificate")) {
                            var certificate=(X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(decode(cert)));
                            add(keys,certificate.getPublicKey());
                        }
                        for(var value:children(info,DS,"KeyValue"))for(var rsa:children(value,DS,"RSAKeyValue")) {
                            var moduli=children(rsa,DS,"Modulus");var exponents=children(rsa,DS,"Exponent");
                            if(moduli.size()!=1||exponents.size()!=1)throw new SamlException("RSA KeyValue has ambiguous or missing parameters");
                            add(keys,KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(new BigInteger(1,decode(moduli.getFirst())),new BigInteger(1,decode(exponents.getFirst())))));
                        }
                    }
                }
            }
            return List.copyOf(keys.values());
        } catch(Exception invalid){throw new SamlException("Could not obtain the selected role's encryption keys",invalid);}
    }
    private static byte[] decode(Element element){return Base64.getDecoder().decode(element.getTextContent().replaceAll("\\s+",""));}
    private static void add(Map<String,PublicKey> keys,PublicKey key){if("RSA".equals(key.getAlgorithm()))keys.putIfAbsent(Base64.getEncoder().encodeToString(key.getEncoded()),key);}
    private static List<Element> children(Element parent,String ns,String local){
        var found=new ArrayList<Element>();
        for(var child=parent.getFirstChild();child!=null;child=child.getNextSibling())if(child instanceof Element e && ns.equals(e.getNamespaceURI()) && local.equals(e.getLocalName()))found.add(e);
        return found;
    }
}
