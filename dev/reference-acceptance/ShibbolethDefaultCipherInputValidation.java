import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.security.interfaces.*;
import java.security.spec.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.xml.parsers.*;
import org.w3c.dom.*;

/** Input-only mathematics. This helper never invokes or claims the target's algorithm policy. */
public final class ShibbolethDefaultCipherInputValidation {
    static final String P="urn:oasis:names:tc:SAML:2.0:protocol",A="urn:oasis:names:tc:SAML:2.0:assertion",X="http://www.w3.org/2001/04/xmlenc#";
    static final String PRIVATE="/opt/reference-idp/credentials/idp-encryption.key",CERTIFICATE="/opt/reference-idp/credentials/idp-encryption.crt";
    public static void main(String[] args)throws Exception {
        if(args.length!=3||!args[0].matches("run_[0-9A-HJKMNP-TV-Z]{26}"))throw new IllegalArgumentException("Bound run, public request, producer source required");
        byte[] input=Files.readAllBytes(Path.of(args[1]));Element request=parse(input);
        if(!P.equals(request.getNamespaceURI())||!"LogoutRequest".equals(request.getLocalName()))throw new IllegalArgumentException("Only public LogoutRequest input");
        String requestId=request.getAttribute("ID");if(requestId.isEmpty())throw new IllegalArgumentException("Request identity absent");
        Element encrypted=one(request,A,"EncryptedID"),data=one(encrypted,X,"EncryptedData"),key=one(data,X,"EncryptedKey",true);
        String contentAlgorithm=one(data,X,"EncryptionMethod").getAttribute("Algorithm");
        if(!"http://www.w3.org/2009/xmlenc11#aes128-gcm".equals(contentAlgorithm))throw new IllegalArgumentException("Unexpected content cipher");
        String transport=one(key,X,"EncryptionMethod").getAttribute("Algorithm");
        byte[] cipherKey=b64(one(one(key,X,"CipherData"),X,"CipherValue").getTextContent());
        byte[] cipherData=b64(one(one(data,X,"CipherData"),X,"CipherValue").getTextContent());
        // Private material never leaves this JVM and is never written to an artifact.
        byte[] privateBytes=Files.readAllBytes(Path.of(PRIVATE));PrivateKey privateKey=decodeNativePrivateKey(privateBytes);
        byte[] certBytes=Files.readAllBytes(Path.of(CERTIFICATE));X509Certificate certificate=(X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(certBytes));
        validateCredential(privateKey,certificate.getPublicKey());
        Cipher unwrap;
        if("http://www.w3.org/2001/04/xmlenc#rsa-1_5".equals(transport)) {unwrap=Cipher.getInstance("RSA/ECB/PKCS1Padding");unwrap.init(Cipher.DECRYPT_MODE,privateKey);}
        else if("http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p".equals(transport)) {
            Element method=one(key,X,"EncryptionMethod");if(method.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#","DigestMethod").getLength()>0||method.getElementsByTagNameNS("http://www.w3.org/2009/xmlenc11#","MGF").getLength()>0)throw new IllegalArgumentException("Non-default OAEP parameters unsupported by input-only helper");
            unwrap=Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");unwrap.init(Cipher.DECRYPT_MODE,privateKey,new OAEPParameterSpec("SHA-1","MGF1",MGF1ParameterSpec.SHA1,PSource.PSpecified.DEFAULT));
        }else throw new IllegalArgumentException("Unexpected transport cipher");
        byte[] contentKey=unwrap.doFinal(cipherKey);if(contentKey.length!=16||cipherData.length<28)throw new IllegalArgumentException("Malformed AES-GCM input");
        Cipher decrypt=Cipher.getInstance("AES/GCM/NoPadding");decrypt.init(Cipher.DECRYPT_MODE,new SecretKeySpec(contentKey,"AES"),new GCMParameterSpec(128,Arrays.copyOfRange(cipherData,0,12)));
        byte[] plaintext=decrypt.doFinal(cipherData,12,cipherData.length-12);Element name=parse(plaintext);
        if(!A.equals(name.getNamespaceURI())||!"NameID".equals(name.getLocalName())||name.getTextContent().isBlank())throw new IllegalArgumentException("Decrypted input is not a NameID");
        String json="{\"schema\":\"samlscope-shibboleth-cipher-input-validation-v1\",\"runId\":"+quoted(args[0])+",\"requestId\":"+quoted(requestId)
                +",\"requestSha256\":"+quoted(hash(input))+",\"inputValidationOnly\":true,\"productAlgorithmPolicyEvaluated\":false"
                +",\"producerSourceSha256\":"+quoted(hash(Files.readAllBytes(Path.of(args[2]))))+",\"nativeEncryptionCertificateSha256\":"+quoted(hash(certificate.getEncoded()))
                +",\"nativeEncryptionSpkiSha256\":"+quoted(hash(certificate.getPublicKey().getEncoded()))+",\"transportAlgorithm\":"+quoted(transport)
                +",\"decryptedNameIdBase64\":"+quoted(Base64.getEncoder().encodeToString(plaintext))+",\"decryptedNameIdSha256\":"+quoted(hash(plaintext))+",\"authenticatedGcm\":true,\"privateKeyExported\":false}";
        System.out.println(json);Arrays.fill(privateBytes,(byte)0);Arrays.fill(contentKey,(byte)0);
    }
    /** PKCS#1 is wrapped only in this JVM's memory; no converted credential is written. */
    static PrivateKey decodeNativePrivateKey(byte[] privateBytes)throws Exception {
        String pem=new String(privateBytes,StandardCharsets.US_ASCII).strip();boolean pkcs1=pem.startsWith("-----BEGIN RSA PRIVATE KEY-----");
        String begin=pkcs1?"-----BEGIN RSA PRIVATE KEY-----":"-----BEGIN PRIVATE KEY-----",end=pkcs1?"-----END RSA PRIVATE KEY-----":"-----END PRIVATE KEY-----";
        if(!pem.startsWith(begin)||!pem.endsWith(end))throw new IllegalArgumentException("Unknown native key encoding");
        byte[] der=b64(pem.substring(begin.length(),pem.length()-end.length()));byte[] encoded=null;
        try {
            if(pkcs1){byte[] version={2,1,0},algorithm={48,13,6,9,42,(byte)134,72,(byte)134,(byte)247,13,1,1,1,5,0};byte[] octet=der(4,der);byte[] payload=new byte[version.length+algorithm.length+octet.length];System.arraycopy(version,0,payload,0,version.length);System.arraycopy(algorithm,0,payload,version.length,algorithm.length);System.arraycopy(octet,0,payload,version.length+algorithm.length,octet.length);encoded=der(48,payload);Arrays.fill(octet,(byte)0);Arrays.fill(payload,(byte)0);}
            else encoded=der.clone();
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(encoded));
        }finally{Arrays.fill(der,(byte)0);if(encoded!=null)Arrays.fill(encoded,(byte)0);}
    }
    static byte[] der(int tag,byte[] value){int size=value.length,lengthBytes=size<128?1:size<=255?2:size<=65535?3:4;byte[] out=new byte[1+lengthBytes+size];out[0]=(byte)tag;if(size<128)out[1]=(byte)size;else{out[1]=(byte)(128+lengthBytes-1);for(int i=0;i<lengthBytes-1;i++)out[2+i]=(byte)(size>>>(8*(lengthBytes-2-i)));}System.arraycopy(value,0,out,1+lengthBytes,size);return out;}
    static void validateCredential(PrivateKey key,PublicKey certificateKey){if(!(key instanceof RSAPrivateKey rsa)||!(certificateKey instanceof RSAPublicKey pub)||!rsa.getModulus().equals(pub.getModulus())||(key instanceof RSAPrivateCrtKey crt&&!crt.getPublicExponent().equals(pub.getPublicExponent())))throw new IllegalArgumentException("Native encryption credential mismatch");}
    static Element parse(byte[] bytes)throws Exception {var f=DocumentBuilderFactory.newInstance();f.setNamespaceAware(true);f.setFeature("http://apache.org/xml/features/disallow-doctype-decl",true);f.setFeature("http://xml.org/sax/features/external-general-entities",false);f.setFeature("http://xml.org/sax/features/external-parameter-entities",false);return f.newDocumentBuilder().parse(new ByteArrayInputStream(bytes)).getDocumentElement();}
    static Element one(Element parent,String ns,String local)throws Exception{return one(parent,ns,local,false);}
    static Element one(Element parent,String ns,String local,boolean descendants)throws Exception {var matches=new ArrayList<Element>();if(descendants){var nodes=parent.getElementsByTagNameNS(ns,local);for(int i=0;i<nodes.getLength();i++)matches.add((Element)nodes.item(i));}else for(Node child=parent.getFirstChild();child!=null;child=child.getNextSibling())if(child instanceof Element e&&ns.equals(e.getNamespaceURI())&&local.equals(e.getLocalName()))matches.add(e);if(matches.size()!=1)throw new IllegalArgumentException("Ambiguous public cipher structure");return matches.get(0);}
    static byte[] b64(String text){return Base64.getDecoder().decode(text.replaceAll("\\s+",""));}
    static String hash(byte[] bytes)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));}
    static String quoted(String value){return "\""+value.replace("\\","\\\\").replace("\"","\\\"").replace("\n","\\n").replace("\r","\\r")+"\"";}
}
