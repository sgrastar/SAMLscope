package com.samlscope.runner.cases;
import static org.junit.jupiter.api.Assertions.*;
import com.fasterxml.jackson.databind.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.saml.normal.SecureXml;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
class KeycloakUiSafetyEvidenceTest {
 @TempDir Path directory;
 private static final ObjectMapper JSON=new ObjectMapper();
 private static final String SVG="<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"180\" height=\"48\"><rect width=\"180\" height=\"48\" fill=\"#1d4ed8\"/><script>alert('SAMLscope-UI-safety-v1')</script></svg>";
 private static CaseContext context(String run){var recorder=new TranscriptRecorder(){public List<TranscriptEntry>list(String id){return List.of();}public TranscriptEntry record(TranscriptInput input){throw new UnsupportedOperationException();}public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary){throw new UnsupportedOperationException();}};return new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,true);}
 @Test void absentReceiptPreservesLegacyFallback(){assertTrue(new KeycloakUiSafetyEvidence(directory,e->null).evaluate(context("run_00000000000000000000000000"),new byte[]{1}).isEmpty());}
 @Test void ownedMissingManifestAndSymlinkFailClosed()throws Exception{var run="run_00000000000000000000000000";Files.createDirectory(directory.resolve(run+".keycloak-ui-safety"));var r=new KeycloakUiSafetyEvidence(directory,e->null);assertTrue(r.exists(run));assertEquals(com.samlscope.core.evaluation.Outcome.NOT_VERIFIED,r.evaluate(context(run),new byte[]{1}).orElseThrow().outcome());Files.writeString(directory.resolve("foreign"),"{}");Files.createSymbolicLink(directory.resolve(run+".keycloak-ui-safety.json"),directory.resolve("foreign"));assertEquals(com.samlscope.core.evaluation.Outcome.NOT_VERIFIED,r.evaluate(context(run),new byte[]{1}).orElseThrow().outcome());}
 @Test void onlyScriptCapableMetadataLogoIsAccepted()throws Exception{String uri="data:image/svg+xml;base64,"+Base64.getEncoder().encodeToString(SVG.getBytes(java.nio.charset.StandardCharsets.UTF_8));var attrs=JSON.createObjectNode().put("logoUri",uri);assertEquals(uri,KeycloakUiSafetyEvidence.verifyUiInput(metadata(uri),"ui-safety-logo-data",attrs));String inert=uri.substring(0,uri.indexOf(','))+","+Base64.getEncoder().encodeToString(SVG.replace("<script>alert('SAMLscope-UI-safety-v1')</script>","").getBytes(java.nio.charset.StandardCharsets.UTF_8));assertThrows(IllegalArgumentException.class,()->KeycloakUiSafetyEvidence.verifyUiInput(metadata(inert),"ui-safety-logo-data",JSON.createObjectNode().put("logoUri",inert)));}
 @Test void missingActiveDetectorCannotTurnAbsenceIntoSafety()throws Exception{var observed=JSON.createObjectNode().set("nativeDialogs",JSON.createArrayNode());assertThrows(IllegalArgumentException.class,()->KeycloakUiSafetyEvidence.safetyObservation(observed,"control","",Instant.now(),Instant.now().plusSeconds(1)));}
 @Test void publicProductionConstructorRejectsAllCounterfactualPayloads()throws Exception{String run="run_00000000000000000000000000";Files.writeString(directory.resolve(run+".keycloak-ui-safety.json"),"{\"counterfactualCalibrationOnly\":true}");assertEquals(com.samlscope.core.evaluation.Outcome.NOT_VERIFIED,new KeycloakUiSafetyEvidence(directory,e->null).evaluate(context(run),new byte[]{1}).orElseThrow().outcome());}
 @Test void operationLedgerCannotHideSecondCredentialOrFailure()throws Exception{var v=JSON.readTree("{\"configurationWriteAttempts\":7,\"successfulConfigurationWrites\":6,\"browserAttempts\":3,\"actualSamlSubmissions\":3,\"credentialSubmissions\":1,\"browserContexts\":1,\"productRestarts\":0,\"humanOperations\":0,\"restored\":true}");assertDoesNotThrow(()->KeycloakUiSafetyEvidence.verifyCounts(v,3,1));((com.fasterxml.jackson.databind.node.ObjectNode)v).put("credentialSubmissions",2);assertThrows(IllegalArgumentException.class,()->KeycloakUiSafetyEvidence.verifyCounts(v,3,1));}
 private static org.w3c.dom.Element metadata(String uri)throws Exception{return SecureXml.parse(("<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:mdui=\"urn:oasis:names:tc:SAML:metadata:ui\"><md:SPSSODescriptor><md:Extensions><mdui:UIInfo><mdui:DisplayName xml:lang=\"en\">SAMLscope URL policy control</mdui:DisplayName><mdui:Logo width=\"180\" height=\"48\">"+uri+"</mdui:Logo></mdui:UIInfo></md:Extensions></md:SPSSODescriptor></md:EntityDescriptor>").getBytes(java.nio.charset.StandardCharsets.UTF_8)).getDocumentElement();}
}
