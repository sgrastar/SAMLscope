package com.samlscope.runner.cases;
import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
class ShibbolethTransientAllowCreateEvidenceTest {
 @TempDir Path data;
 @Test void malformedMarkerSidecarAndSymlinksRemainOwned()throws Exception{
  String run="run_00000000000000000000000000";var reader=new ShibbolethTransientAllowCreateEvidence(data,e->new byte[0],r->new byte[0],r->Optional.empty());assertFalse(reader.exists(run));
  Path marker=Files.writeString(data.resolve(run+".shibboleth-transient-allow-create.json"),"malformed");assertTrue(reader.exists(run));Files.delete(marker);Path sidecar=Files.createDirectory(data.resolve(run+".shibboleth-transient-allow-create"));assertTrue(reader.exists(run));Files.delete(sidecar);Files.createSymbolicLink(sidecar,data.resolve("missing"));assertTrue(reader.exists(run));assertFalse(reader.exists("../foreign"));
 }
 @Test void factoryDetectorDoesNotTreatOrdinarySessionStorageAsFailure(){
  String s="urn:oasis:names:tc:SAML:2.0:assertion";String xml="<s:Assertion xmlns:s='"+s+"'><s:Subject><s:NameID Format='urn:oasis:names:tc:SAML:2.0:nameid-format:transient'>opaque</s:NameID></s:Subject><s:AuthnStatement AuthnInstant='2026-01-01T00:00:00Z' SessionIndex='ordinary-session'><s:AuthnContext><s:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</s:AuthnContextClassRef></s:AuthnContext></s:AuthnStatement><s:AttributeStatement><s:Attribute Name='uid'><s:AttributeValue>principal</s:AttributeValue></s:Attribute></s:AttributeStatement></s:Assertion>";
  var a=com.samlscope.saml.normal.SecureXml.parse(xml.getBytes()).getDocumentElement();assertTrue(ShibbolethTransientAllowCreateEvidence.consistentTransientAssertion(a,"principal","2026-01-01T00:00:00Z/urn:oasis:names:tc:SAML:2.0:ac:classes:Password"));
  ((org.w3c.dom.Element)a.getElementsByTagNameNS(s,"AuthnStatement").item(0)).setAttribute("SessionIndex","ordinary-other-session");assertTrue(ShibbolethTransientAllowCreateEvidence.consistentTransientAssertion(a,"principal","2026-01-01T00:00:00Z/urn:oasis:names:tc:SAML:2.0:ac:classes:Password"));assertFalse(ShibbolethTransientAllowCreateEvidence.consistentTransientAssertion(a,"foreign","2026-01-01T00:00:00Z/urn:oasis:names:tc:SAML:2.0:ac:classes:Password"));
 }
}
