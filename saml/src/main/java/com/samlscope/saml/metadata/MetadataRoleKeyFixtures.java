package com.samlscope.saml.metadata;

import com.samlscope.saml.crypto.PlanCredentials;
import java.util.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/** Campaign-only dual-role fixtures. Existing metadata variants remain byte-for-byte unchanged. */
final class MetadataRoleKeyFixtures {
    private static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String DS = "http://www.w3.org/2000/09/xmldsig#";

    static Element apply(Document document, Element entity, PlanCredentials primary,
            PlanCredentials second, PlanCredentials third, MetadataService.Variant variant) {
        boolean explicit, secondRoleFirst;
        switch (variant) {
            case ROLE_KEYS_SP_FIRST_EXPLICIT_A -> { explicit=true; secondRoleFirst=false; }
            case ROLE_KEYS_IDP_FIRST_EXPLICIT_B -> { explicit=true; secondRoleFirst=true; }
            case ROLE_KEYS_SP_FIRST_OMITTED_A -> { explicit=false; secondRoleFirst=false; }
            case ROLE_KEYS_IDP_FIRST_OMITTED_B -> { explicit=false; secondRoleFirst=true; }
            default -> { return entity; }
        }
        Element sp=role(entity,"SPSSODescriptor"), idp=role(entity,"IDPSSODescriptor");
        var operative=secondRoleFirst?second:primary;
        var peer=secondRoleFirst?primary:second;
        removeKeys(sp); removeKeys(idp);
        if(explicit) {
            // Distinct operative signing/encryption keys expose both role and purpose flattening.
            insertKey(document,sp,"signing",operative);
            insertKey(document,sp,"encryption",third);
            insertKey(document,idp,"signing",peer);
            insertKey(document,idp,"encryption",peer);
        } else {
            insertKey(document,sp,null,operative);
            insertKey(document,idp,null,peer);
        }
        if(secondRoleFirst) entity.insertBefore(idp,sp);
        return entity;
    }

    private static Element role(Element entity,String local) {
        Element result=null;
        for(var node=entity.getFirstChild();node!=null;node=node.getNextSibling())
            if(node instanceof Element e && MD.equals(e.getNamespaceURI())&&local.equals(e.getLocalName())) {
                if(result!=null)throw new IllegalArgumentException("Exactly one role required");
                result=e;
            }
        if(result==null)throw new IllegalArgumentException("Missing role");
        return result;
    }
    private static void removeKeys(Element role) {
        for(var node=role.getFirstChild();node!=null;) {
            var next=node.getNextSibling();
            if(node instanceof Element e && MD.equals(e.getNamespaceURI())&&"KeyDescriptor".equals(e.getLocalName()))role.removeChild(node);
            node=next;
        }
    }
    private static void insertKey(Document document,Element role,String use,PlanCredentials credential) {
        try {
            var descriptor=document.createElementNS(MD,"md:KeyDescriptor");
            if(use!=null)descriptor.setAttribute("use",use);
            var info=document.createElementNS(DS,"ds:KeyInfo");
            var data=document.createElementNS(DS,"ds:X509Data");
            var certificate=document.createElementNS(DS,"ds:X509Certificate");
            certificate.setTextContent(Base64.getEncoder().encodeToString(credential.certificate().getEncoded()));
            data.appendChild(certificate); info.appendChild(data); descriptor.appendChild(info);
            // Keys precede endpoint declarations and retain their declared signing/encryption order.
            var first=role.getFirstChild();
            while(first instanceof Element e && MD.equals(e.getNamespaceURI())&&"KeyDescriptor".equals(e.getLocalName()))first=first.getNextSibling();
            role.insertBefore(descriptor,first);
        } catch(java.security.cert.CertificateEncodingException invalid) {
            throw new IllegalStateException("Cannot encode role credential",invalid);
        }
    }
}
