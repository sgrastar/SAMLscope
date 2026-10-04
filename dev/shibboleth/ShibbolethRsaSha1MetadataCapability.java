import java.io.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.*;
import java.util.*;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.metadata.resolver.filter.MetadataFilterContext;
import org.opensaml.saml.metadata.resolver.filter.impl.SignatureValidationFilter;
import org.opensaml.security.crypto.KeySupport;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.security.credential.impl.StaticCredentialResolver;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.support.SignatureSupport;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;
import com.fasterxml.jackson.databind.ObjectMapper;

/** Observations from installed Shibboleth libraries only; never assigns a Suite outcome. */
public final class ShibbolethRsaSha1MetadataCapability {
    static final String SHA1="http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    static final String C14N="http://www.w3.org/2001/10/xml-exc-c14n#";
    static EntityDescriptor parse(byte[] raw) throws Exception {
        var parsed=XMLObjectSupport.unmarshallFromInputStream(
                XMLObjectProviderRegistrySupport.getParserPool(), new ByteArrayInputStream(raw));
        if (!(parsed instanceof EntityDescriptor entity) || entity.getEntityID()==null)
            throw new IllegalArgumentException("One EntityDescriptor is required");
        return entity;
    }
    static byte[] bytes(EntityDescriptor entity) throws Exception {
        var out=new ByteArrayOutputStream();XMLObjectSupport.marshallToOutputStream(entity,out);return out.toByteArray();
    }
    static Map<String,Object> validation(byte[] raw,X509Certificate trusted) throws Exception {
        var credential=new BasicX509Credential(trusted);
        var trust=new ExplicitKeySignatureTrustEngine(new StaticCredentialResolver(credential),
                new StaticKeyInfoCredentialResolver(credential));
        var filter=new SignatureValidationFilter(trust);filter.setRequireSignedRoot(true);
        filter.setAlwaysVerifyTrustedSource(true);filter.initialize();
        try {
            var result=filter.filter(parse(raw),new MetadataFilterContext());
            return Map.of("accepted",result!=null,"exception","");
        } catch (org.opensaml.saml.metadata.resolver.filter.FilterException rejected) {
            return Map.of("accepted",false,"exception",rejected.getClass().getName()+":"+rejected.getMessage());
        } finally {filter.destroy();}
    }
    static X509Certificate certificate(String file) throws Exception {
        try(var input=Files.newInputStream(Path.of(file))) {
            return (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(input);
        }
    }
    static String sha(byte[] raw) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));
    }
    public static void main(String[] args) throws Exception {
        if(args.length!=5 || !Set.of("sign-and-verify","verify").contains(args[0]))
            throw new IllegalArgumentException("sign-and-verify|verify metadata.xml native-privatekey.pem trusted.crt wrong.crt");
        InitializationService.initialize();
        byte[] input=Files.readAllBytes(Path.of(args[1]));
        var certificate=certificate(args[3]);var wrong=certificate(args[4]);
        if(Arrays.equals(certificate.getPublicKey().getEncoded(),wrong.getPublicKey().getEncoded()))
            throw new IllegalArgumentException("Wrong-key control must use a distinct key");
        byte[] signed;
        if(args[0].equals("sign-and-verify")) {
            var entity=parse(input);if(entity.isSigned())throw new IllegalArgumentException("Input must be unsigned");
            // Supply the required metadata signing ID through the native object API before signing.
            if(entity.getID()==null || entity.getID().isBlank())entity.setID("_samlscope_rsa_sha1_"+sha(input).substring(0,16));
            var privateKey=KeySupport.decodePrivateKey(Path.of(args[2]).toFile(),null);
            if(!KeySupport.matchKeyPair(certificate.getPublicKey(),privateKey))throw new IllegalArgumentException("Native key mismatch");
            var params=new SignatureSigningParameters();params.setSigningCredential(new BasicX509Credential(certificate,privateKey));
            params.setSignatureAlgorithm(SHA1);params.setSignatureReferenceDigestMethod("http://www.w3.org/2000/09/xmldsig#sha1");
            params.setSignatureCanonicalizationAlgorithm(C14N);params.setSignatureReferenceCanonicalizationAlgorithm(C14N);
            var info=new X509KeyInfoGeneratorFactory();info.setEmitEntityCertificate(true);params.setKeyInfoGenerator(info.newInstance());
            SignatureSupport.signObject(entity,params);signed=bytes(entity);Files.write(Path.of(args[1]+".signed"),signed);
        } else signed=input;
        var entity=parse(signed);if(!entity.isSigned() || !SHA1.equals(entity.getSignature().getSignatureAlgorithm()))
            throw new IllegalArgumentException("RSA-SHA1 metadata signature is required");
        // Updating an OpenSAML object invalidates its cached SignatureValue. Change only the
        // original entityID attribute bytes, preserving the entire original signature.
        String xml=new String(signed,StandardCharsets.UTF_8);
        String marker="entityID=\""+entity.getEntityID()+"\"";
        if(xml.indexOf(marker)<0 || xml.indexOf(marker)!=xml.lastIndexOf(marker))
            throw new IllegalArgumentException("One original entityID attribute is required");
        byte[] changed=xml.replace(marker,"entityID=\""+entity.getEntityID()+"#tampered\"").getBytes(StandardCharsets.UTF_8);
        var unsigned=parse(signed);unsigned.setSignature(null);byte[] absent=bytes(unsigned);
        var origins=new TreeMap<String,String>();
        for(var clazz:List.of(SignatureSupport.class,SignatureValidationFilter.class,InitializationService.class,
                org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine.class,
                net.shibboleth.idp.Version.class))
            origins.put(clazz.getName(),clazz.getProtectionDomain().getCodeSource().getLocation().toString());
        var output=new LinkedHashMap<String,Object>();
        output.put("schema","samlscope-shibboleth-rsa-sha1-native-observation-v1");output.put("mode",args[0]);
        output.put("productVersion",net.shibboleth.idp.Version.getVersion());
        output.put("inputSha256",sha(input));output.put("signedSha256",sha(signed));output.put("targetEntityId",entity.getEntityID());
        output.put("trustedCertificateSha256",sha(certificate.getEncoded()));output.put("wrongCertificateSha256",sha(wrong.getEncoded()));
        output.put("nativeClassOrigins",origins);output.put("positive",validation(signed,certificate));
        output.put("tampered",validation(changed,certificate));output.put("wrongKey",validation(signed,wrong));output.put("unsigned",validation(absent,certificate));
        output.put("tamperedInputBase64",Base64.getEncoder().encodeToString(changed));output.put("unsignedInputBase64",Base64.getEncoder().encodeToString(absent));
        System.out.println(new ObjectMapper().writeValueAsString(output));
    }
}
