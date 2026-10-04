import java.io.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.*;
import java.time.*;
import java.util.*;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.security.crypto.KeySupport;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.support.SignatureSupport;
import com.fasterxml.jackson.databind.ObjectMapper;

/** Expiry-behavior detector fixture only: native credentials stay in memory, no network or native settings. */
public final class ShibbolethMetadataValidityProducer {
 static String sha(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
 static String esc(String text){return text.replace("&","&amp;").replace("\"","&quot;").replace("<","&lt;").replace(">","&gt;");}
 public static void main(String[]args)throws Exception {
  if(args.length!=8)throw new IllegalArgumentException("out issuer entity request recipient nativeKey nativeCert instant");
  InitializationService.initialize();var out=Path.of(args[0]);Files.createDirectories(out);String issuer=esc(args[1]),entity=esc(args[2]),request=esc(args[3]),recipient=esc(args[4]);
  var cert=(X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(Files.newInputStream(Path.of(args[6])));var key=KeySupport.decodePrivateKey(Path.of(args[5]).toFile(),null);if(!KeySupport.matchKeyPair(cert.getPublicKey(),key))throw new IllegalArgumentException("Native credential mismatch");
  var params=new SignatureSigningParameters();params.setSigningCredential(new BasicX509Credential(cert,key));params.setSignatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");params.setSignatureReferenceDigestMethod("http://www.w3.org/2001/04/xmlenc#sha256");params.setSignatureCanonicalizationAlgorithm("http://www.w3.org/2001/10/xml-exc-c14n#");params.setSignatureReferenceCanonicalizationAlgorithm("http://www.w3.org/2001/10/xml-exc-c14n#");var info=new X509KeyInfoGeneratorFactory();info.setEmitEntityCertificate(true);params.setKeyInfoGenerator(info.newInstance());
  String now=Instant.parse(args[7]).toString(),until=Instant.parse(args[7]).plusSeconds(300).toString();
  String xml="<p:Response xmlns:p='urn:oasis:names:tc:SAML:2.0:protocol' xmlns:s='urn:oasis:names:tc:SAML:2.0:assertion' ID='_validity_mutant_response' Version='2.0' IssueInstant='"+now+"' InResponseTo='"+request+"' Destination='"+recipient+"'><s:Issuer>"+issuer+"</s:Issuer><p:Status><p:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:Success'/></p:Status><s:Assertion ID='_validity_mutant_assertion' Version='2.0' IssueInstant='"+now+"'><s:Issuer>"+issuer+"</s:Issuer><s:Subject><s:NameID Format='urn:oasis:names:tc:SAML:2.0:nameid-format:transient'>synthetic-expiry-mutant-subject</s:NameID><s:SubjectConfirmation Method='urn:oasis:names:tc:SAML:2.0:cm:bearer'><s:SubjectConfirmationData InResponseTo='"+request+"' Recipient='"+recipient+"' NotOnOrAfter='"+until+"'/></s:SubjectConfirmation></s:Subject><s:Conditions NotBefore='"+now+"' NotOnOrAfter='"+until+"'><s:AudienceRestriction><s:Audience>"+entity+"</s:Audience></s:AudienceRestriction></s:Conditions><s:AuthnStatement AuthnInstant='"+now+"' SessionIndex='synthetic-expiry-mutant-session'><s:AuthnContext><s:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</s:AuthnContextClassRef></s:AuthnContext></s:AuthnStatement></s:Assertion></p:Response>";
  var response=(Response)XMLObjectSupport.unmarshallFromInputStream(XMLObjectProviderRegistrySupport.getParserPool(),new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));SignatureSupport.signObject(response.getAssertions().get(0),params);SignatureSupport.signObject(response,params);var bytes=new ByteArrayOutputStream();XMLObjectSupport.marshallToOutputStream(response,bytes);var raw=bytes.toByteArray();Files.write(out.resolve("expired-parent-success.xml"),raw);
  System.out.println(new ObjectMapper().writeValueAsString(Map.of("schema","samlscope-shibboleth-metadata-validity-calibration-v1","targetEntityId",args[1],"spEntityId",args[2],"requestId",args[3],"recipient",args[4],"files",Map.of("expired-parent-success",sha(raw)),"nativePrivateKeyExported",false,"controlsAdopted",false,"productConfigurationWrites",0,"protocolOperations",0)));
 }
}
