package com.samlscope.runner.cases;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.saml.normal.SecureXml;
import java.nio.charset.StandardCharsets;
class ShibbolethRequestedSubjectMatchEvidenceTest {
 private static final String S="urn:oasis:names:tc:SAML:2.0:assertion",P="urn:oasis:names:tc:SAML:2.0:protocol";
 private org.w3c.dom.Element request(String policy)throws Exception{return SecureXml.parse(("<p:AuthnRequest xmlns:p='"+P+"' xmlns:s='"+S+"'><s:Subject><s:NameID Format='urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'>same</s:NameID></s:Subject>"+policy+"</p:AuthnRequest>").getBytes(StandardCharsets.UTF_8)).getDocumentElement();}
 private org.w3c.dom.Element returned(String value,String attributes)throws Exception{return SecureXml.parse(("<s:NameID xmlns:s='"+S+"' "+attributes+">"+value+"</s:NameID>").getBytes(StandardCharsets.UTF_8)).getDocumentElement();}
 @Test void differentDecryptedValueWithoutPolicyIsDecisive()throws Exception {assertTrue(ShibbolethRequestedSubjectMatchEvidence.decisiveMismatch(request(""),returned("different","")));}
 @Test void equalValueWithDefaultOrExplicitQualifierDifferenceIsNotDecisive()throws Exception {assertFalse(ShibbolethRequestedSubjectMatchEvidence.decisiveMismatch(request(""),returned("same","NameQualifier='idp' SPNameQualifier='sp' SPProvidedID='provided'")));}
 @Test void differentFormatPolicyExceptionIsNotUsedAsCounterexample()throws Exception {assertFalse(ShibbolethRequestedSubjectMatchEvidence.decisiveMismatch(request("<p:NameIDPolicy Format='urn:oasis:names:tc:SAML:2.0:nameid-format:transient'/>"),returned("different","Format='urn:oasis:names:tc:SAML:2.0:nameid-format:transient'")));}
}
