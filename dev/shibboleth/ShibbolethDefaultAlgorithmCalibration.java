import java.io.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.*;
import java.time.Instant;
import java.util.*;
import com.fasterxml.jackson.databind.*;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.security.crypto.KeySupport;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.signature.support.impl.SignatureAlgorithmValidator;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.support.SignatureSupport;
import org.apache.xml.security.signature.XMLSignature;
import org.w3c.dom.Element;

/** Public-input detector fixture. Neither mode is live product evidence or a product verdict. */
public final class ShibbolethDefaultAlgorithmCalibration {
    static final ObjectMapper M=new ObjectMapper();
    static final String STOCK="stock-policy",MUTANT="developer-missing-default-prevention";
    static final String MD5="http://www.w3.org/2001/04/xmldsig-more#md5",RSA_MD5="http://www.w3.org/2001/04/xmldsig-more#rsa-md5",HMAC_MD5="http://www.w3.org/2001/04/xmldsig-more#hmac-md5";
    static String sha(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
    static String esc(String s){return s.replace("&","&amp;").replace("'","&apos;").replace("<","&lt;").replace(">","&gt;");}
    static byte[] classBytes(Class<?> type)throws Exception {try(var input=type.getResourceAsStream("/"+type.getName().replace('.','/')+".class")){if(input==null)throw new IllegalArgumentException("Native class bytes absent");return input.readAllBytes();}}
    record FixtureDecision(boolean mathematicalValid,boolean allowed,String error) {}
    static FixtureDecision signatureDecision(Element root,X509Certificate certificate,SignatureAlgorithmValidator validator)throws Exception {
        root.setIdAttribute("ID",true);var elements=root.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#","Signature");
        if(elements.getLength()!=1)throw new IllegalArgumentException("Public signature ambiguous");Element signature=(Element)elements.item(0);
        // Input mathematics only. This does not weaken the deployed native verifier.
        boolean mathematicalValid=new XMLSignature(signature,"",false).checkSignatureValue(certificate);
        // Stock decoding rejects RSA-MD5 before policy validation. Select only the actual
        // validator, retaining raw SignedInfo and all Reference digest methods.
        var selectedSignature=new org.opensaml.xmlsec.signature.impl.SignatureBuilder().buildObject();selectedSignature.setDOM(signature);
        boolean allowed;String error="";try{validator.validate(selectedSignature);allowed=true;}catch(org.opensaml.xmlsec.signature.support.SignatureException rejected){allowed=false;error=rejected.getMessage();}
        return new FixtureDecision(mathematicalValid,allowed,error);
    }
    public static void main(String[] args)throws Exception {
        if(args.length!=3||!Set.of(STOCK,MUTANT).contains(args[0]))throw new IllegalArgumentException("Selected mode, public input, producer source required");
        String mode=args[0];byte[] inputBytes=Files.readAllBytes(Path.of(args[1]));var input=M.readTree(inputBytes);String run=input.path("runId").asText();
        if(!run.matches("run_[0-9A-HJKMNP-TV-Z]{26}"))throw new IllegalArgumentException("Same Run public input required");
        InitializationService.initialize();var parser=XMLObjectProviderRegistrySupport.getParserPool();
        byte[] suite=Files.readAllBytes(Path.of(input.path("suiteMetadataFile").asText()));var suiteDom=parser.parse(new ByteArrayInputStream(suite)).getDocumentElement();
        if(!sha(suite).equals(input.path("suiteMetadataSha256").asText())||!suiteDom.getAttribute("entityID").equals(input.path("suiteEntityId").asText()))throw new IllegalArgumentException("Foreign metadata");
        var certificate=(X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(Base64.getMimeDecoder().decode(suiteDom.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#","X509Certificate").item(0).getTextContent())));
        var nativeCert=(X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(Files.newInputStream(Path.of("/opt/reference-idp/credentials/idp-signing.crt")));
        var nativeKey=KeySupport.decodePrivateKey(Path.of("/opt/reference-idp/credentials/idp-signing.key").toFile(),null);
        if(!KeySupport.matchKeyPair(nativeCert.getPublicKey(),nativeKey))throw new IllegalArgumentException("Native credential mismatch");
        var params=new SignatureSigningParameters();params.setSigningCredential(new BasicX509Credential(nativeCert,nativeKey));params.setSignatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");params.setSignatureReferenceDigestMethod("http://www.w3.org/2001/04/xmlenc#sha256");params.setSignatureCanonicalizationAlgorithm("http://www.w3.org/2001/10/xml-exc-c14n#");params.setSignatureReferenceCanonicalizationAlgorithm("http://www.w3.org/2001/10/xml-exc-c14n#");var info=new X509KeyInfoGeneratorFactory();info.setEmitEntityCertificate(true);params.setKeyInfoGenerator(info.newInstance());
        var stock=DefaultSecurityConfigurationBootstrap.buildDefaultSignatureValidationConfiguration();var stockExcluded=new TreeSet<>(stock.getExcludedAlgorithms());
        if(!stockExcluded.containsAll(Set.of(MD5,RSA_MD5,HMAC_MD5)))throw new IllegalArgumentException("Unknown native stock default");
        var selectedExcluded=new TreeSet<>(stockExcluded);if(MUTANT.equals(mode))selectedExcluded.removeAll(Set.of(MD5,RSA_MD5,HMAC_MD5));
        var validator=new SignatureAlgorithmValidator(stock.getIncludedAlgorithms(),selectedExcluded);var records=new ArrayList<Map<String,Object>>();
        for(var row:input.path("records")) {
            String fixture=row.path("fixtureId").asText();if(!Set.of("sha256-control","invalid-sha256-signature","md5-digest","rsa-md5").contains(fixture))throw new IllegalArgumentException("Only four signature detector inputs");
            byte[] raw=Files.readAllBytes(Path.of(row.path("requestFile").asText()));if(!sha(raw).equals(row.path("requestSha256").asText()))throw new IllegalArgumentException("Public request hash changed");
            var document=parser.parse(new ByteArrayInputStream(raw));var root=document.getDocumentElement();
            if(!"urn:oasis:names:tc:SAML:2.0:protocol".equals(root.getNamespaceURI())||!"AuthnRequest".equals(root.getLocalName())||!root.getAttribute("ID").equals(row.path("requestId").asText())
                    ||root.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion","Issuer").getLength()!=1||!root.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion","Issuer").item(0).getTextContent().equals(suiteDom.getAttribute("entityID")))throw new IllegalArgumentException("Foreign request");
            var decision=signatureDecision(root,certificate,validator);boolean mathematicalValid=decision.mathematicalValid(),allowed=decision.allowed();String error=decision.error();
            boolean accepted=mathematicalValid&&allowed;var result=new TreeMap<String,Object>();result.put("fixtureId",fixture);result.put("requestId",root.getAttribute("ID"));result.put("requestSha256",sha(raw));result.put("mathematicalSignatureValid",mathematicalValid);result.put("nativeAlgorithmPolicyAccepted",allowed);result.put("nativeAlgorithmPolicyError",error);result.put("selectedConsumerAccepted",accepted);
            if(accepted) {
                String request=esc(root.getAttribute("ID")),recipient=esc(root.getAttribute("AssertionConsumerServiceURL")),entity=esc(suiteDom.getAttribute("entityID")),issuer=esc(input.path("targetEntityId").asText());String at=Instant.parse(root.getAttribute("IssueInstant")).toString(),until=Instant.parse(at).plusSeconds(300).toString(),suffix=sha(raw).substring(0,24);
                String xml="<p:Response xmlns:p='urn:oasis:names:tc:SAML:2.0:protocol' xmlns:s='urn:oasis:names:tc:SAML:2.0:assertion' ID='_default_calibration_response_"+suffix+"' Version='2.0' IssueInstant='"+at+"' InResponseTo='"+request+"' Destination='"+recipient+"'><s:Issuer>"+issuer+"</s:Issuer><p:Status><p:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:Success'/></p:Status><s:Assertion ID='_default_calibration_assertion_"+suffix+"' Version='2.0' IssueInstant='"+at+"'><s:Issuer>"+issuer+"</s:Issuer><s:Subject><s:NameID Format='urn:oasis:names:tc:SAML:2.0:nameid-format:transient'>synthetic-default-calibration-subject</s:NameID><s:SubjectConfirmation Method='urn:oasis:names:tc:SAML:2.0:cm:bearer'><s:SubjectConfirmationData InResponseTo='"+request+"' Recipient='"+recipient+"' NotOnOrAfter='"+until+"'/></s:SubjectConfirmation></s:Subject><s:Conditions NotBefore='"+at+"' NotOnOrAfter='"+until+"'><s:AudienceRestriction><s:Audience>"+entity+"</s:Audience></s:AudienceRestriction></s:Conditions><s:AuthnStatement AuthnInstant='"+at+"' SessionIndex='synthetic-default-calibration-session'><s:AuthnContext><s:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</s:AuthnContextClassRef></s:AuthnContext></s:AuthnStatement></s:Assertion></p:Response>";
                var response=(Response)XMLObjectSupport.unmarshallFromInputStream(parser,new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));SignatureSupport.signObject(response.getAssertions().get(0),params);SignatureSupport.signObject(response,params);var output=new ByteArrayOutputStream();XMLObjectSupport.marshallToOutputStream(response,output);byte[] reply=output.toByteArray();result.put("responseBase64",Base64.getEncoder().encodeToString(reply));result.put("responseSha256",sha(reply));
            }
            records.add(result);
        }
        if(records.size()!=4)throw new IllegalArgumentException("Four complete signature controls required");
        var classes=new TreeMap<String,String>();for(var type:List.of(SignatureAlgorithmValidator.class,DefaultSecurityConfigurationBootstrap.class))classes.put(type.getName(),sha(classBytes(type)));
        var output=new TreeMap<String,Object>();output.put("schema","samlscope-shibboleth-default-algorithm-calibration-v1");output.put("runId",run);output.put("selectedPath",mode);output.put("selectedConsumer","native-SignatureAlgorithmValidator-fixture-only");output.put("stockDecoderAcceptanceEvaluated",false);output.put("counterfactualCalibrationOnly",MUTANT.equals(mode));output.put("diagnosticOnly",true);output.put("productFinding",false);output.put("privateKeyExported",false);output.put("producerSourceSha256",sha(Files.readAllBytes(Path.of(args[2]))));output.put("inputSha256",sha(inputBytes));output.put("suiteMetadataSha256",sha(suite));output.put("targetMetadataSha256",input.path("targetMetadataSha256").asText());output.put("stockExcludedAlgorithms",stockExcluded);output.put("selectedExcludedAlgorithms",selectedExcluded);output.put("nativeClasses",classes);output.put("nativeSigningCertificateSha256",sha(nativeCert.getEncoded()));output.put("records",records);
        System.out.println(M.writeValueAsString(output));
    }
}
