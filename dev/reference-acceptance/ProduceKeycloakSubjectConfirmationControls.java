package com.samlscope.runner.cases;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.net.*;
import java.io.*;
import java.security.*;
import java.time.Instant;
import java.math.BigInteger;
import java.util.*;
import org.w3c.dom.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
/** Calibration only. The ephemeral private key lives in this JVM and is never persisted. */
public final class ProduceKeycloakSubjectConfirmationControls {
 static final String S="urn:oasis:names:tc:SAML:2.0:assertion",P="urn:oasis:names:tc:SAML:2.0:protocol",DS="http://www.w3.org/2000/09/xmldsig#",BEARER="urn:oasis:names:tc:SAML:2.0:cm:bearer";
 static List<Element> children(Element root,String ns,String name){var list=new ArrayList<Element>();for(var n=root.getFirstChild();n!=null;n=n.getNextSibling())if(n instanceof Element e&&ns.equals(e.getNamespaceURI())&&name.equals(e.getLocalName()))list.add(e);return list;}
 static void removeSignatures(Element e){for(var n=e.getFirstChild();n!=null;){var next=n.getNextSibling();if(n instanceof Element c){if(DS.equals(c.getNamespaceURI())&&"Signature".equals(c.getLocalName()))e.removeChild(c);else removeSignatures(c);}n=next;}}
 public static void main(String[] args)throws Exception{
  if(args.length!=3)throw new IllegalArgumentException("source jars output");var source=Path.of(args[0]);var jars=Path.of(args[1]);var out=Path.of(args[2]);Files.createDirectory(out);byte[] original=Files.readAllBytes(source);var urls=new ArrayList<URL>();try(var paths=Files.list(jars)){for(var path:paths.filter(p->p.getFileName().toString().endsWith(".jar")&&!p.getFileName().toString().contains("services")).toList())urls.add(path.toUri().toURL());}
  var generator=KeyPairGenerator.getInstance("RSA");generator.initialize(2048);var pair=generator.generateKeyPair();var instant=Instant.now();var name=new X500Name("CN=SAMLscope ephemeral oracle calibration; not a product signer");var cert=new JcaX509v3CertificateBuilder(name,new BigInteger(128,new SecureRandom()),Date.from(instant.minusSeconds(60)),Date.from(instant.plusSeconds(86400)),name,pair.getPublic());var certificate=new JcaX509CertificateConverter().getCertificate(cert.build(new JcaContentSignerBuilder("SHA256withRSA").build(pair.getPrivate())));var credentials=new PlanCredentials(pair.getPrivate(),certificate);Files.write(out.resolve("control-signer.der"),certificate.getEncoded());var names=List.of("urn:samlscope:attester-control:one","urn:samlscope:attester-control:two");
  try(var loader=new URLClassLoader(urls.toArray(URL[]::new),ClassLoader.getPlatformClassLoader())){
   var responseClass=loader.loadClass("org.keycloak.saml.processing.api.saml.v2.response.SAML2Response");var statusClass=loader.loadClass("org.keycloak.dom.saml.v2.protocol.StatusResponseType");var scClass=loader.loadClass("org.keycloak.dom.saml.v2.assertion.SubjectConfirmationType");var nameClass=loader.loadClass("org.keycloak.dom.saml.v2.assertion.NameIDType");var dataClass=loader.loadClass("org.keycloak.dom.saml.v2.assertion.SubjectConfirmationDataType");
   for(String kind:List.of("foreign-positive","foreign-missing-identifier","multiple-positive","multiple-packed-identifiers")){
    var converter=responseClass.getConstructor().newInstance();var model=responseClass.getMethod("getResponseType",InputStream.class).invoke(converter,new ByteArrayInputStream(original));var assertions=(List<?>)model.getClass().getMethod("getAssertions").invoke(model);var assertion=assertions.getFirst().getClass().getMethod("getAssertion").invoke(assertions.getFirst());var subject=assertion.getClass().getMethod("getSubject").invoke(assertion);var confirmations=(List<?>)subject.getClass().getMethod("getConfirmation").invoke(subject);if(confirmations.size()!=1)throw new IllegalStateException("One native bearer required");var data=scClass.getMethod("getSubjectConfirmationData").invoke(confirmations.getFirst());for(var previous:new ArrayList<>(confirmations))subject.getClass().getMethod("removeConfirmation",scClass).invoke(subject,previous);
    int count=kind.equals("multiple-positive")?2:1;for(int i=0;i<count;i++){var sc=scClass.getConstructor().newInstance();scClass.getMethod("setMethod",String.class).invoke(sc,BEARER);scClass.getMethod("setSubjectConfirmationData",dataClass).invoke(sc,data);if(!kind.equals("foreign-missing-identifier")){var id=nameClass.getConstructor().newInstance();nameClass.getMethod("setValue",String.class).invoke(id,kind.equals("multiple-packed-identifiers")?String.join(" ",names):names.get(i));scClass.getMethod("setNameID",nameClass).invoke(sc,id);}subject.getClass().getMethod("addConfirmation",scClass).invoke(subject,sc);}
    var document=(Document)responseClass.getMethod("convert",statusClass).invoke(null,model);removeSignatures(document.getDocumentElement());var signer=new XmlSigner();for(var a:children(document.getDocumentElement(),S,"Assertion"))signer.sign(a,credentials,children(a,S,"Subject").getFirst());signer.sign(document.getDocumentElement(),credentials,children(document.getDocumentElement(),P,"Status").getFirst());Files.write(out.resolve(kind+".xml"),SecureXml.serialize(document));
   }
  }
  var report=new LinkedHashMap<String,Object>();report.put("purpose","oracle-calibration-only");report.put("nativePrivateKeyRead",false);report.put("ephemeralPrivateKeyPersisted",false);report.put("productNetworkOperations",0);report.put("targetTrustChanges",0);report.put("baseResponseSha256",HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(original)));report.put("attesters",names);report.put("expected",Map.of("foreign-positive",true,"foreign-missing-identifier",false,"multiple-positive",true,"multiple-packed-identifiers",false));new JsonCodec().mapper().writerWithDefaultPrettyPrinter().writeValue(out.resolve("calibration.json").toFile(),report);
 }
}
