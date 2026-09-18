package com.samlscope.runner.cases;

import static com.samlscope.runner.cases.MetadataAlgorithmEvidence.children;
import java.util.*;
import java.security.interfaces.*;
import java.security.cert.*;
import org.w3c.dom.Element;
import com.samlscope.saml.crypto.*;

/** Matching-key decryption of original, signed metadata-campaign exchanges. Never persists plaintext. */
final class MetadataEncryptionProof {
    private static final String MD="urn:oasis:names:tc:SAML:2.0:metadata",DS="http://www.w3.org/2000/09/xmldsig#",S="urn:oasis:names:tc:SAML:2.0:assertion";
    static Element descriptor(Element role,PlanCredentials key) throws Exception {
        var descriptors=children(role,MD,"KeyDescriptor").stream().filter(k->k.getAttribute("use").isEmpty() || "encryption".equals(k.getAttribute("use"))).toList();
        require(descriptors.size()==1);
        var descriptor=descriptors.getFirst();
        require(key.privateKey() instanceof RSAPrivateKey && key.certificate().getPublicKey() instanceof RSAPublicKey);
        require(((RSAPrivateKey)key.privateKey()).getModulus().equals(((RSAPublicKey)key.certificate().getPublicKey()).getModulus()));
        var certificateBytes=new ArrayList<byte[]>();
        for(var info:children(descriptor,DS,"KeyInfo"))for(var data:children(info,DS,"X509Data"))for(var certificate:children(data,DS,"X509Certificate")) {
            var parsed=(X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(Base64.getDecoder().decode(certificate.getTextContent().replaceAll("\\s+",""))));
            certificateBytes.add(parsed.getPublicKey().getEncoded());
        }
        require(certificateBytes.size()==1 && Arrays.equals(certificateBytes.getFirst(),key.certificate().getPublicKey().getEncoded()));
        return descriptor;
    }
    static List<VerifiedSignatureAlgorithms.Observation> decrypt(MetadataAlgorithmEvidence.Exchange e,Element wrapper,PlanCredentials key) {
        var signatures=new ArrayList<VerifiedSignatureAlgorithms.Observation>();
            var plain=new SamlXmlDecrypter().decrypt(wrapper,key.privateKey());
            require(S.equals(plain.getNamespaceURI()) && "Assertion".equals(plain.getLocalName()));
            require(children(plain,S,"Issuer").size()==1 && children(e.response(),S,"Issuer").getFirst().getTextContent().equals(children(plain,S,"Issuer").getFirst().getTextContent()));
            if(!children(plain,DS,"Signature").isEmpty()) {
                var document=com.samlscope.saml.normal.SecureXml.newDocument();
                var envelope=document.createElementNS("urn:oasis:names:tc:SAML:2.0:protocol","p:Response");document.appendChild(envelope);
                envelope.appendChild(document.importNode(plain,true));
                var verified=new com.samlscope.saml.crypto.VerifiedSignatureAlgorithms().read(envelope,
                        children(e.response(),S,"Issuer").getFirst().getTextContent(),e.signingKeys());
                require(verified.size()==1 && "Assertion".equals(verified.getFirst().element()));signatures.addAll(verified);
            }
        return List.copyOf(signatures);
    }
    private static void require(boolean condition) { if(!condition)throw new IllegalArgumentException("Unproven encryption evidence"); }
}
