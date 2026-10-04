package com.samlscope.runner.cases;
import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.saml.normal.SecureXml;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
class ShibbolethSubjectConfirmationEvidenceTest {
 private static final String S="urn:oasis:names:tc:SAML:2.0:assertion",BEARER="urn:oasis:names:tc:SAML:2.0:cm:bearer";
 @TempDir Path data;
 private org.w3c.dom.Element assertion(String confirmations){return SecureXml.parse(("<s:Assertion xmlns:s='"+S+"'><s:Subject><s:NameID>subject</s:NameID>"+confirmations+"</s:Subject></s:Assertion>").getBytes(StandardCharsets.UTF_8)).getDocumentElement();}
 private String confirmation(String identifiers){return "<s:SubjectConfirmation Method='"+BEARER+"'>"+identifiers+"<s:SubjectConfirmationData/></s:SubjectConfirmation>";}
 @Test void foreignAttesterRequiresIdentifierRatherThanOrdinaryBearerOrRecipient(){
  assertTrue(ShibbolethSubjectConfirmationEvidence.ordinaryBearer(assertion(confirmation(""))));
  assertFalse(ShibbolethSubjectConfirmationEvidence.identifiesSeparateAttesters(assertion(confirmation("")),List.of("foreign")));
  var foreign=assertion(confirmation("<s:NameID>foreign</s:NameID>"));
  assertFalse(ShibbolethSubjectConfirmationEvidence.ordinaryBearer(foreign));assertTrue(ShibbolethSubjectConfirmationEvidence.identifiesSeparateAttesters(foreign,List.of("foreign")));
 }
 @Test void permittedAttestersMustHaveDistinctSeparateConfirmations(){
  var separate=assertion(confirmation("<s:NameID>one</s:NameID>")+confirmation("<s:NameID>two</s:NameID>"));
  assertTrue(ShibbolethSubjectConfirmationEvidence.identifiesSeparateAttesters(separate,List.of("one","two")));
  assertFalse(ShibbolethSubjectConfirmationEvidence.identifiesSeparateAttesters(assertion(confirmation("<s:NameID>one</s:NameID><s:NameID>two</s:NameID>")),List.of("one","two")));
  assertFalse(ShibbolethSubjectConfirmationEvidence.identifiesSeparateAttesters(assertion(confirmation("<s:NameID>one</s:NameID>")+confirmation("<s:NameID>one</s:NameID>")),List.of("one","two")));
 }
 @Test void missingAllPermittedIdentifierFormsCannotSatisfyForeignAttester(){
  for(var kind:List.of("NameID","BaseID","EncryptedID"))assertFalse(ShibbolethSubjectConfirmationEvidence.ordinaryBearer(assertion(confirmation("<s:"+kind+">foreign</s:"+kind+">"))));
  assertFalse(ShibbolethSubjectConfirmationEvidence.identifiesSeparateAttesters(assertion(confirmation("")),List.of("foreign")));
 }
 @Test void malformedMarkerAndSidecarRemainOwnedIncludingSymlinks()throws Exception{
  var run="run_00000000000000000000000000";var evidence=new ShibbolethSubjectConfirmationEvidence(data,e->new byte[0],r->"browser_sso_idp",(r,v)->Optional.empty());assertFalse(evidence.exists(run));
  var marker=Files.writeString(data.resolve(run+".shibboleth-subject-confirmation.json"),"{}");assertTrue(evidence.exists(run));Files.delete(marker);
  var folder=Files.createDirectory(data.resolve(run+".shibboleth-subject-confirmation"));assertTrue(evidence.exists(run));Files.delete(folder);Files.createSymbolicLink(folder,data.resolve("missing"));assertTrue(evidence.exists(run));assertFalse(evidence.exists("../foreign"));
 }
}
