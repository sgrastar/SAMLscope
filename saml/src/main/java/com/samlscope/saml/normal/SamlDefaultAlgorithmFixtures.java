package com.samlscope.saml.normal;

import com.samlscope.saml.crypto.PlanCredentials;
import java.net.URI;
import java.time.Instant;
import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.Element;
import java.security.cert.X509Certificate;

/** Explicit weak-algorithm test inputs. This helper never changes normal signing defaults. */
public final class SamlDefaultAlgorithmFixtures {
    public static final String SHA256_DIGEST="http://www.w3.org/2001/04/xmlenc#sha256";
    public static final String RSA_SHA256="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    public static final String MD5_DIGEST="http://www.w3.org/2001/04/xmldsig-more#md5";
    public static final String RSA_MD5="http://www.w3.org/2001/04/xmldsig-more#rsa-md5";
    private static final String DS="http://www.w3.org/2000/09/xmldsig#";
    static {Init.init();}
    public enum Fixture {SHA256_CONTROL,INVALID_SHA256_SIGNATURE,MD5_DIGEST,RSA_MD5}

    /** Mathematical input verification only; this is never an authentication/trust validator. */
    public boolean hasValidInputSignature(Fixture fixture,Element request,X509Certificate certificate) {
        try {var signature=inputSignature(fixture,request);return signature.checkSignatureValue(certificate);}
        catch(Exception invalid){return false;}
    }
    /** Verify the exact one enveloped Reference independently of a corrupted SignatureValue. */
    public boolean hasValidInputDigests(Fixture fixture,Element request) {
        try {return inputSignature(fixture,request).getSignedInfo().verifyReferences();}
        catch(Exception invalid){return false;}
    }
    private static XMLSignature inputSignature(Fixture fixture,Element request)throws Exception {
        if(!"urn:oasis:names:tc:SAML:2.0:protocol".equals(request.getNamespaceURI())||!"AuthnRequest".equals(request.getLocalName())
                ||request.getAttribute("ID").isBlank())throw new IllegalArgumentException("Explicit AuthnRequest fixture required");
        var signatures=request.getElementsByTagNameNS(DS,"Signature");if(signatures.getLength()!=1||signatures.item(0).getParentNode()!=request)
            throw new IllegalArgumentException("One direct input signature required");
        request.setIdAttribute("ID",true);
        // Only the two deliberately weak input kinds opt out. Normal inputs retain Santuario's
        // existing secure validation, including ordinary verification elsewhere in the product.
        boolean secure=fixture!=Fixture.MD5_DIGEST&&fixture!=Fixture.RSA_MD5;
        var signature=new XMLSignature((Element)signatures.item(0),"",secure);var info=signature.getSignedInfo();
        if(info.getLength()!=1||!("#"+request.getAttribute("ID")).equals(info.item(0).getURI()))throw new IllegalArgumentException("Exact input Reference required");
        var methods=request.getElementsByTagNameNS(DS,"SignatureMethod");var digests=request.getElementsByTagNameNS(DS,"DigestMethod");
        var transforms=request.getElementsByTagNameNS(DS,"Transform");
        if(methods.getLength()!=1||digests.getLength()!=1||transforms.getLength()!=2
                ||!(fixture==Fixture.RSA_MD5?RSA_MD5:RSA_SHA256).equals(((Element)methods.item(0)).getAttribute("Algorithm"))
                ||!(fixture==Fixture.MD5_DIGEST?MD5_DIGEST:SHA256_DIGEST).equals(((Element)digests.item(0)).getAttribute("Algorithm"))
                ||!Transforms.TRANSFORM_ENVELOPED_SIGNATURE.equals(((Element)transforms.item(0)).getAttribute("Algorithm"))
                ||!Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS.equals(((Element)transforms.item(1)).getAttribute("Algorithm")))
            throw new IllegalArgumentException("Explicit fixture algorithms and transforms required");
        return signature;
    }

    public byte[] authnRequest(Fixture fixture,String requestId,URI destination,String issuer,
            URI acs,Instant issueInstant,PlanCredentials credentials) {
        java.util.Objects.requireNonNull(fixture);java.util.Objects.requireNonNull(credentials);
        if(!"RSA".equals(credentials.privateKey().getAlgorithm()))
            throw new IllegalArgumentException("RSA default-prevention fixtures require an RSA signing key");
        var normal=new SamlSignedRequestFactory().build(fixture==Fixture.INVALID_SHA256_SIGNATURE
                ?SamlSignedRequestFactory.Fixture.BAD_SIGNATURE_VALUE:SamlSignedRequestFactory.Fixture.VALID,
                requestId,destination,issuer,acs,issueInstant,credentials);
        if(fixture==Fixture.SHA256_CONTROL||fixture==Fixture.INVALID_SHA256_SIGNATURE)return normal;
        var document=SecureXml.parse(normal);var request=document.getDocumentElement();
        var old=request.getElementsByTagNameNS(DS,"Signature");
        if(old.getLength()!=1||old.item(0).getParentNode()!=request)
            throw new IllegalArgumentException("Expected one direct normal signature");
        var next=old.item(0).getNextSibling();request.removeChild(old.item(0));
        try {
            request.setIdAttribute("ID",true);
            var signature=new XMLSignature(document,"",fixture==Fixture.RSA_MD5?RSA_MD5:RSA_SHA256,
                    Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
            request.insertBefore(signature.getElement(),next);
            var transforms=new Transforms(document);
            transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
            transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
            signature.addDocument("#"+requestId,transforms,fixture==Fixture.MD5_DIGEST?MD5_DIGEST:SHA256_DIGEST);
            signature.addKeyInfo(credentials.certificate());
            // Santuario's construction path enables secure validation for References. Only
            // this deliberately weak test input may calculate an MD5 digest; normal signers
            // and all authentication verification continue using their existing policy.
            var explicitWeakSignature=new XMLSignature(signature.getElement(),"",false);
            // References from the parsing constructor are lazy; populate the single allowed
            // Reference before Santuario's signing loop calculates its digest.
            explicitWeakSignature.getSignedInfo().item(0);
            explicitWeakSignature.sign(credentials.privateKey());
            return SecureXml.serialize(document);
        } catch(Exception unavailable) {throw new SamlException("Could not build an explicit default-prevention fixture",unavailable);}
    }
}
