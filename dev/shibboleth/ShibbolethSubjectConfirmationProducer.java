import java.io.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.*;
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

/** Native signed semantic calibration only; no private key leaves the target and controls are not product outcomes. */
public final class ShibbolethSubjectConfirmationProducer {
 static String sha(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
 static String escape(String text){return text.replace("&","&amp;").replace("\"","&quot;").replace("<","&lt;").replace(">","&gt;");}
 public static void main(String[] args)throws Exception {
  if(args.length!=7)throw new IllegalArgumentException("out issuer entity request recipient privatekey cert");
  InitializationService.initialize();var out=Path.of(args[0]);Files.createDirectories(out);
  String issuer=escape(args[1]),entity=escape(args[2]),request=escape(args[3]),recipient=escape(args[4]);
  var cert=(X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(Files.newInputStream(Path.of(args[6])));
  var key=KeySupport.decodePrivateKey(Path.of(args[5]).toFile(),null);if(!KeySupport.matchKeyPair(cert.getPublicKey(),key))throw new IllegalArgumentException("Native credential mismatch");
  var params=new SignatureSigningParameters();params.setSigningCredential(new BasicX509Credential(cert,key));params.setSignatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");params.setSignatureReferenceDigestMethod("http://www.w3.org/2001/04/xmlenc#sha256");params.setSignatureCanonicalizationAlgorithm("http://www.w3.org/2001/10/xml-exc-c14n#");params.setSignatureReferenceCanonicalizationAlgorithm("http://www.w3.org/2001/10/xml-exc-c14n#");var info=new X509KeyInfoGeneratorFactory();info.setEmitEntityCertificate(true);params.setKeyInfoGenerator(info.newInstance());
  String now="2026-10-01T08:00:00Z";String data="<saml:SubjectConfirmationData InResponseTo=\""+request+"\" Recipient=\""+recipient+"\" NotOnOrAfter=\"2026-10-01T08:05:00Z\"/>";
  String one="<saml:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">urn:samlscope:attester-control:one</saml:NameID>",two="<saml:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">urn:samlscope:attester-control:two</saml:NameID>";
  var hashes=new TreeMap<String,String>();for(String kind:List.of("foreign-positive","foreign-missing-identifier","multiple-positive","multiple-packed-identifiers")) {
   String prefix="<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">",suffix=data+"</saml:SubjectConfirmation>";
   String sc=switch(kind){case "foreign-positive"->prefix+one+suffix;case "foreign-missing-identifier"->prefix+suffix;case "multiple-positive"->prefix+one+suffix+prefix+two+suffix;default->prefix+one+two+suffix;};
   String xml="<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_sc_calibration_response\" Version=\"2.0\" IssueInstant=\""+now+"\" InResponseTo=\""+request+"\" Destination=\""+recipient+"\"><saml:Issuer>"+issuer+"</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status><saml:Assertion ID=\"_sc_calibration_assertion\" Version=\"2.0\" IssueInstant=\""+now+"\"><saml:Issuer>"+issuer+"</saml:Issuer><saml:Subject><saml:NameID>synthetic-attester-calibration-subject</saml:NameID>"+sc+"</saml:Subject><saml:Conditions NotBefore=\""+now+"\" NotOnOrAfter=\"2026-10-01T08:05:00Z\"><saml:AudienceRestriction><saml:Audience>"+entity+"</saml:Audience></saml:AudienceRestriction></saml:Conditions></saml:Assertion></samlp:Response>";
   var response=(Response)XMLObjectSupport.unmarshallFromInputStream(XMLObjectProviderRegistrySupport.getParserPool(),new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
   SignatureSupport.signObject(response.getAssertions().get(0),params);SignatureSupport.signObject(response,params);var bytes=new ByteArrayOutputStream();XMLObjectSupport.marshallToOutputStream(response,bytes);byte[] raw=bytes.toByteArray();Files.write(out.resolve(kind+".xml"),raw);hashes.put(kind,sha(raw));
  }
  var origins=new TreeMap<String,String>();for(var clazz:List.of(SignatureSupport.class,InitializationService.class,org.opensaml.saml.saml2.profile.impl.AddSubjectConfirmationToSubjects.class,net.shibboleth.idp.Version.class))origins.put(clazz.getName(),clazz.getProtectionDomain().getCodeSource().getLocation().toString());
  System.out.println(new ObjectMapper().writeValueAsString(Map.of("schema","samlscope-shibboleth-attester-calibration-v1","targetEntityId",args[1],"spEntityId",args[2],"requestId",args[3],"recipient",args[4],"files",hashes,"nativeClassOrigins",origins,"nativePrivateKeyExported",false,"controlsAdopted",false,"productVersion",net.shibboleth.idp.Version.getVersion())));
 }
}
