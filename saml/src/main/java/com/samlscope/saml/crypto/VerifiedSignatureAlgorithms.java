package com.samlscope.saml.crypto;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.w3c.dom.Element;

/** Reads algorithms only from a direct, verified signature over the selected SAML element. */
public final class VerifiedSignatureAlgorithms {
    private static final String DS="http://www.w3.org/2000/09/xmldsig#";
    private static final String SAML="urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String PROTOCOL="urn:oasis:names:tc:SAML:2.0:protocol";
    private static final Set<String> TRANSFORMS=Set.of(
            DS+"enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#",
            "http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments");

    public record Observation(String element, String id, String signatureAlgorithm, String digestAlgorithm,
                              String signingKeySha256) {}

    /** Trust keys must come from the Run's pinned target metadata, never the message's KeyInfo. */
    public List<Observation> read(Element response, String expectedIssuer, List<X509Certificate> trustedKeys) {
        if (!PROTOCOL.equals(response.getNamespaceURI()) || !"Response".equals(response.getLocalName())
                || expectedIssuer==null || expectedIssuer.isBlank() || trustedKeys.isEmpty() || duplicateIds(response))
            return List.of();
        var candidates=new ArrayList<Element>(); candidates.add(response);
        candidates.addAll(children(response,SAML,"Assertion"));
        var result=new ArrayList<Observation>();
        for(var element:candidates) {
            var issuers=children(element,SAML,"Issuer");
            var signatures=children(element,DS,"Signature");
            if(issuers.size()!=1 || !expectedIssuer.equals(issuers.getFirst().getTextContent()) || signatures.size()!=1)continue;
            var signedInfo=children(signatures.getFirst(),DS,"SignedInfo");
            if(signedInfo.size()!=1)continue;
            var methods=children(signedInfo.getFirst(),DS,"SignatureMethod");
            var references=children(signedInfo.getFirst(),DS,"Reference");
            if(methods.size()!=1 || references.size()!=1 || element.getAttribute("ID").isBlank()
                    || !("#"+element.getAttribute("ID")).equals(references.getFirst().getAttribute("URI")))continue;
            var digests=children(references.getFirst(),DS,"DigestMethod");
            var transformContainers=children(references.getFirst(),DS,"Transforms");
            if(digests.size()!=1 || transformContainers.size()!=1)continue;
            var transforms=children(transformContainers.getFirst(),DS,"Transform");
            if(transforms.isEmpty() || transforms.stream().anyMatch(t -> !TRANSFORMS.contains(t.getAttribute("Algorithm"))))continue;
            if(transforms.stream().noneMatch(t -> (DS+"enveloped-signature").equals(t.getAttribute("Algorithm"))))continue;
            for(var key:trustedKeys) {
                if(!new XmlSignatureVerifier().hasValidEnvelopedSignature(element,key))continue;
                try {
                    var hash=java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(key.getPublicKey().getEncoded()));
                    result.add(new Observation(element.getLocalName(),element.getAttribute("ID"),
                            methods.getFirst().getAttribute("Algorithm"),digests.getFirst().getAttribute("Algorithm"),hash));
                } catch(java.security.NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
                break;
            }
        }
        return List.copyOf(result);
    }

    private static boolean duplicateIds(Element root) {
        var ids=new HashSet<String>();
        var all=root.getOwnerDocument().getElementsByTagName("*");
        for(int i=0;i<all.getLength();i++) {
            var element=(Element)all.item(i);
            if(element.hasAttribute("ID") && !ids.add(element.getAttribute("ID")))return true;
        }
        return false;
    }

    private static List<Element> children(Element parent,String namespace,String name) {
        var result=new ArrayList<Element>();
        for(var node=parent.getFirstChild();node!=null;node=node.getNextSibling())
            if(node instanceof Element element && namespace.equals(element.getNamespaceURI()) && name.equals(element.getLocalName()))result.add(element);
        return result;
    }
}
