package com.samlscope.runner.cases;
import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.transcript.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.runner.DefaultCaseContext;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
class SimpleSamlPhpTransientAllowCreateEvidenceTest {
    @TempDir Path directory;private static final String RUN="run_00000000000000000000000000";
    private DefaultCaseContext context(){return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,new TranscriptRecorder(){public List<TranscriptEntry> list(String run){return List.of();}public TranscriptEntry record(TranscriptInput input){throw new AssertionError();}public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary){throw new AssertionError();}},true);}
    @Test void absentDoesNotShadowLegacyAndOwnedClaimsCannotManufactureProof()throws Exception{
        var reader=new SimpleSamlPhpTransientAllowCreateEvidence(directory,e->{throw new AssertionError();},run->new byte[0],run->Optional.empty());assertFalse(reader.exists(RUN));assertTrue(reader.evaluate(context()).isEmpty());var folder=Files.createDirectory(directory.resolve(RUN));Files.writeString(folder.resolve("manifest.json"),"{\"restored\":true,\"ignoresAllowCreate\":true}");assertTrue(reader.exists(RUN));assertEquals(Outcome.NOT_VERIFIED,reader.evaluate(context()).orElseThrow().outcome());
    }
    @Test void fileAndSymlinkRemainOwnedAndFailClosed()throws Exception{
        var reader=new SimpleSamlPhpTransientAllowCreateEvidence(directory,e->{throw new AssertionError();},run->new byte[0],run->Optional.empty());var folder=Files.writeString(directory.resolve(RUN),"{}");assertEquals(Outcome.NOT_VERIFIED,reader.evaluate(context()).orElseThrow().outcome());Files.delete(folder);Files.createSymbolicLink(folder,Files.createDirectory(directory.resolve("foreign")));assertEquals(Outcome.NOT_VERIFIED,reader.evaluate(context()).orElseThrow().outcome());assertFalse(reader.exists("../"+RUN));
    }
    @Test void sixPoliciesDistinguishAbsentAttributesFromFalseAndTransientFromImplicit(){
        var factory=new com.samlscope.saml.normal.SamlNameIdPolicyRequestFactory();for(var key:SimpleSamlPhpTransientAllowCreateEvidence.KEYS){String value=key.substring(key.lastIndexOf('-')+1);var raw=factory.build("_request",java.net.URI.create("https://idp.example/sso"),"https://sp.example",java.net.URI.create("https://sp.example/acs"),Instant.EPOCH,new com.samlscope.saml.normal.SamlNameIdPolicyRequestFactory.Policy(true,key.startsWith("implicit-")?null:com.samlscope.saml.normal.SamlNameIdPolicyRequestFactory.TRANSIENT,null,value.equals("omitted")?null:Boolean.valueOf(value)));var request=com.samlscope.saml.normal.SecureXml.parse(raw).getDocumentElement();assertTrue(SimpleSamlPhpTransientAllowCreateEvidence.policyMatchesRequest(request,key));assertTrue(SimpleSamlPhpTransientAllowCreateEvidence.KEYS.stream().filter(other->SimpleSamlPhpTransientAllowCreateEvidence.policyMatchesRequest(request,other)).toList().equals(List.of(key)));}
    }
    @Test void noValueOrOpacityRuleCanReplaceReturnedFormat(){
        var a=com.samlscope.saml.normal.SecureXml.parse("<Assertion xmlns='urn:oasis:names:tc:SAML:2.0:assertion'><Subject><NameID Format='urn:oasis:names:tc:SAML:2.0:nameid-format:transient'>public-identifying-value</NameID></Subject></Assertion>".getBytes(java.nio.charset.StandardCharsets.UTF_8)).getDocumentElement();assertTrue(SimpleSamlPhpTransientAllowCreateEvidence.transientAssertion(a));((org.w3c.dom.Element)a.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion","NameID").item(0)).setAttribute("Format","urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");assertFalse(SimpleSamlPhpTransientAllowCreateEvidence.transientAssertion(a));
    }
    @Test void projectedPublicBindingInputsMustReconstructTheExactNativeResponseBody()throws Exception{
        byte[] response="<Response/>".getBytes(java.nio.charset.StandardCharsets.UTF_8),body="SAMLRequest=cmVxdWVzdA%3D%3D&RelayState=public-relay".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        String projected="<input type=\"hidden\" name=\"SAMLResponse\" value=\"[REDACTED]\"><input type=\"hidden\" name=\"RelayState\" value=\"[REDACTED]\">";
        String original=projected.replace("name=\"SAMLResponse\" value=\"[REDACTED]\"","name=\"SAMLResponse\" value=\""+Base64.getEncoder().encodeToString(response)+"\"").replace("name=\"RelayState\" value=\"[REDACTED]\"","name=\"RelayState\" value=\"public-relay\"");
        String digest=HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(original.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        assertTrue(SimpleSamlPhpTransientAllowCreateEvidence.nativeResponseProjectionMatches(projected.getBytes(),body,response,digest));
        assertFalse(SimpleSamlPhpTransientAllowCreateEvidence.nativeResponseProjectionMatches(projected.getBytes(),body,"<Unrelated/>".getBytes(),digest));
        assertFalse(SimpleSamlPhpTransientAllowCreateEvidence.nativeResponseProjectionMatches(projected.getBytes(),body,response,"0".repeat(64)));
    }
    @Test void unknownRedactedInputsOrDuplicateBindingSlotsCannotBeReconstructed()throws Exception{
        byte[] response="<Response/>".getBytes(),body="SAMLRequest=cmVxdWVzdA%3D%3D&RelayState=public-relay".getBytes();String page="<input name=\"SAMLResponse\" value=\"[REDACTED]\"><input name=\"RelayState\" value=\"[REDACTED]\">";
        assertFalse(SimpleSamlPhpTransientAllowCreateEvidence.nativeResponseProjectionMatches((page+"<input name=\"AuthState\" value=\"[REDACTED]\">").getBytes(),body,response,"0".repeat(64)));
        assertFalse(SimpleSamlPhpTransientAllowCreateEvidence.nativeResponseProjectionMatches((page+page).getBytes(),body,response,"0".repeat(64)));
        assertFalse(SimpleSamlPhpTransientAllowCreateEvidence.nativeResponseProjectionMatches(page.getBytes(),(new String(body)+"&RelayState=other").getBytes(),response,"0".repeat(64)));
    }
}
