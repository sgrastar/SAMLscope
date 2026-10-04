package com.samlscope.runner.cases;
import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
class KeycloakNativeUiConsumerEvidenceTest {
 @TempDir Path directory;
 private static CaseContext context(String run){
  var recorder=new TranscriptRecorder(){public List<TranscriptEntry>list(String id){return List.of();}public TranscriptEntry record(TranscriptInput input){throw new UnsupportedOperationException();}public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary){throw new UnsupportedOperationException();}};
  return new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,true);
 }
 @Test void absentNativeReceiptPreservesOriginalCaseFallback(){
  assertTrue(new KeycloakNativeUiConsumerEvidence(directory,e->null).read(context("run_00000000000000000000000000"),new byte[]{1},KeycloakNativeUiConsumerEvidence.LOGO).isEmpty());
 }
 @Test void exactNativePublicConsentUsesPolicyLinkWithoutNetworkSuccess()throws Exception{
  var value=KeycloakNativeUiConsumerEvidence.html(publicHtml("file:///fixture", "en").getBytes(StandardCharsets.UTF_8));assertTrue(value.consent&&value.accept&&value.nativeGrant);assertEquals("en",value.language);assertEquals(List.of("file:///fixture"),value.links);assertTrue(value.images.isEmpty());
 }
 @Test void unrelatedSameLengthHtmlDoesNotBecomeNativeConsent()throws Exception{
  var before=publicHtml("file:///fixture","en");var changed=before.replace("kc-oauth","no-oauth");assertEquals(before.length(),changed.length());var value=KeycloakNativeUiConsumerEvidence.html(changed.getBytes(StandardCharsets.UTF_8));assertFalse(value.consent);assertTrue(value.links.isEmpty());
 }
 @Test void ProjectedOriginalRejectsCredentialsAndCsrfState(){
  assertThrows(IllegalArgumentException.class,()->KeycloakNativeUiConsumerEvidence.html((publicHtml("file:///fixture","en")+"<input name=\"password\" value=\"x\">").getBytes(StandardCharsets.UTF_8)));
  assertThrows(IllegalArgumentException.class,()->KeycloakNativeUiConsumerEvidence.html((publicHtml("file:///fixture","en")+"<script>state</script>").getBytes(StandardCharsets.UTF_8)));
 }
 @Test void ReceiptSymlinkCannotSupplyNativeEvidence()throws Exception{
  var target=directory.resolve("foreign.json");Files.writeString(target,"{}");var run="run_00000000000000000000000000";Files.createSymbolicLink(directory.resolve(run+".keycloak-ui-consumer.json"),target);var reader=new KeycloakNativeUiConsumerEvidence(directory,e->null);assertTrue(reader.exists(run));assertEquals(com.samlscope.core.evaluation.Outcome.NOT_VERIFIED,reader.read(context(run),new byte[]{1},KeycloakNativeUiConsumerEvidence.LOGO).orElseThrow().outcome());
 }
 @Test void ownedReceiptDirectoryFailsClosed()throws Exception{var run="run_00000000000000000000000000";Files.createDirectory(directory.resolve(run+".keycloak-ui-consumer.json"));var reader=new KeycloakNativeUiConsumerEvidence(directory,e->null);assertTrue(reader.exists(run));assertEquals(com.samlscope.core.evaluation.Outcome.NOT_VERIFIED,reader.read(context(run),new byte[]{1},KeycloakNativeUiConsumerEvidence.LOGO).orElseThrow().outcome());}
 private static String publicHtml(String uri,String language){return "<html lang=\""+language+"\"><body data-page-id=\"login-login-oauth-grant\"><div id=\"kc-oauth\"><a href=\""+uri+"\">privacy policy.</a><form action=\"/realms/samlscope/login-actions/consent\"><input type=\"hidden\" name=\"code\"><button name=\"accept\">Yes</button></form></div></body></html>";}
}
