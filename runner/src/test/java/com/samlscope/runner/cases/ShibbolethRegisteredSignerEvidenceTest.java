package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.caseexec.ActionIds;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.saml.crypto.PlanCredentials;
import com.samlscope.saml.crypto.FilePlanKeyStore;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import com.samlscope.saml.normal.*;
import com.samlscope.store.JsonCodec;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Native refusal cannot be replaced by an HTTP error, another peer, or another signed request. */
class ShibbolethRegisteredSignerEvidenceTest {
    private static final String RUN="run_00000000000000000000000000";
    private static final String ENTITY="http://localhost:18080/p/plan_00000000000000000000000000";
    private static final String PROFILE="http://shibboleth.net/ns/profiles/saml2/sso/browser";
    private static final Instant NOW=Instant.parse("2026-10-02T13:00:00Z");
    @TempDir Path directory;

    private DefaultCaseContext context(boolean complete) {
        return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(),Reachability.CONFIRMED,new TranscriptRecorder(){
                    public List<TranscriptEntry> list(String run){return List.of();}
                    public TranscriptEntry record(TranscriptInput input){throw new AssertionError("No product interactions");}
                    public TranscriptEntry updateSamlAnalysis(String a,String b,Map<String,Object> fields){throw new AssertionError("No original changes");}
                },complete);
    }
    private ShibbolethRegisteredSignerEvidence reader() {
        return new ShibbolethRegisteredSignerEvidence(directory,e->{throw new AssertionError("No original read needed");},
                r->new byte[0],(r,v)->Optional.empty());
    }
    @Test void absenceKeepsFallbackButAnyOwnedIncompleteProofClosesIt() throws Exception {
        assertFalse(reader().exists(RUN));assertTrue(reader().evaluate(context(true)).isEmpty());
        Files.createDirectory(directory.resolve(RUN));assertTrue(reader().exists(RUN));assertFalse(reader().hasFinalProof(RUN));
        assertEquals(Outcome.NOT_VERIFIED,reader().evaluate(context(true)).orElseThrow().outcome());
        Files.writeString(directory.resolve(RUN).resolve("manifest.json"),"{\"restored\":true,\"rejected\":true}");
        assertEquals(Outcome.NOT_VERIFIED,reader().evaluate(context(true)).orElseThrow().outcome());
        assertEquals(Outcome.NOT_VERIFIED,reader().evaluate(context(false)).orElseThrow().outcome());
        assertTrue(reader().probeInputs(context(true)).isEmpty());
    }
    @Test void symlinkOwnerCannotEscapeToManualSuccessOrForeignRun() throws Exception {
        var other=Files.createDirectory(directory.resolve("other"));Files.writeString(other.resolve("manifest.json"),"{}");
        Files.createSymbolicLink(directory.resolve(RUN),other);
        assertTrue(reader().exists(RUN));assertFalse(reader().exists("../"+RUN));
        assertEquals(Outcome.NOT_VERIFIED,reader().evaluate(context(true)).orElseThrow().outcome());
        assertTrue(reader().probeInputs(context(true)).isEmpty());
    }
    private static byte[] audit(String id,String entity,String event,String status,String signature,String binding,String profile,Instant timestamp) {
        return ("SAMLscope-signature-v1|"+id+"|"+entity+"|"+event+"|"+status+"|"+signature+"|"+binding+"|"+profile+"|"+timestamp+"\n").getBytes(StandardCharsets.UTF_8);
    }
    @Test void nativeAuditRequiresExactRequestEntityProfileBindingAndClockWindow() {
        var correct=audit("_request",ENTITY,"MessageAuthenticationError","","false","POST",PROFILE,NOW);
        assertEquals("MessageAuthenticationError",ShibbolethRegisteredSignerEvidence.nativeAudit(correct,"_request",ENTITY,NOW.minusSeconds(1),NOW.plusSeconds(1))[3]);
        for(var wrong:List.of(audit("_other",ENTITY,"MessageAuthenticationError","","false","POST",PROFILE,NOW),
                audit("_request","foreign","MessageAuthenticationError","","false","POST",PROFILE,NOW),
                audit("_request",ENTITY,"MessageAuthenticationError","","false","GET",PROFILE,NOW),
                audit("_request",ENTITY,"MessageAuthenticationError","","false","POST","foreign",NOW),
                audit("_request",ENTITY,"MessageAuthenticationError","","false","POST",PROFILE,NOW.minusSeconds(2))))
            assertThrows(IllegalArgumentException.class,()->ShibbolethRegisteredSignerEvidence.nativeAudit(wrong,"_request",ENTITY,NOW.minusSeconds(1),NOW.plusSeconds(1)));
    }
    @Test void duplicateAuditAndReversedClockSamplesCannotChooseAConvenientEvent() {
        var line=new String(audit("_request",ENTITY,"","Success","true","POST",PROFILE,NOW),StandardCharsets.UTF_8);
        assertEquals("Success",ShibbolethRegisteredSignerEvidence.nativeAudit(line.getBytes(StandardCharsets.UTF_8),"_request",ENTITY,NOW,NOW)[4]);
        assertThrows(IllegalArgumentException.class,()->ShibbolethRegisteredSignerEvidence.nativeAudit((line+line).getBytes(StandardCharsets.UTF_8),"_request",ENTITY,NOW,NOW));
        assertThrows(IllegalArgumentException.class,()->ShibbolethRegisteredSignerEvidence.nativeAudit(line.getBytes(StandardCharsets.UTF_8),"_request",ENTITY,NOW.plusSeconds(1),NOW));
    }
    @Test void HTTPErrorOrQuotedErrorIsNotANativeSignatureRefusal() {
        assertTrue(ShibbolethRegisteredSignerEvidence.nativeSignatureRejectionPage("<h1>Message Security Error</h1>".getBytes(StandardCharsets.UTF_8)));
        for(var wrong:List.of("HTTP400","<script>Message Security Error</script>","<style>Message Security Error</style>",
                "<h1>Message Security Error</h1><form/>","<h1>Message Security Error</h1><INPUT name='password'>",
                "Message Security Error SAMLResponse","Message Security Error Cookie: secret"))
            assertFalse(ShibbolethRegisteredSignerEvidence.nativeSignatureRejectionPage(wrong.getBytes(StandardCharsets.UTF_8)));
    }
    @Test void recursivelySensitiveReadbackFieldsCannotBeSavedAsPublicProof() throws Exception {
        var mapper=new JsonCodec().mapper();assertFalse(ShibbolethRegisteredSignerEvidence.sensitive(mapper.readTree("{\"keys\":[{\"X509Certificate\":\"public\"}]}")));
        for(var name:List.of("Cookie","set-cookie","Authorization","password","private_key","access-token"))
            assertTrue(ShibbolethRegisteredSignerEvidence.sensitive(mapper.readTree("{\"nested\":[{\""+name+"\":\"redacted\"}]}")));
    }
    private PlanCredentials credentials(String name) {
        return new FilePlanKeyStore(directory.resolve(name),Clock.fixed(NOW,ZoneOffset.UTC))
                .getOrCreate("plan_00000000000000000000000000");
    }
    private static byte[] request(String fixture,PlanCredentials signer,SamlSignedRequestFactory.Fixture kind) {
        String action=ActionIds.derive(RUN,RegisteredSignerObservationTestCase.CASE,"await-fixture-"+fixture,0);
        return new SamlSignedRequestFactory().build(kind,"_"+action,URI.create("http://localhost:18280/idp/profile/SAML2/POST/SSO"),
                ENTITY,URI.create(ENTITY+"/sp/acs/0"),NOW,signer);
    }
    @Test void otherSignerControlIsMathematicallyValidAndDifferentFromBadSignature() throws Exception {
        var own=credentials("own");var other=credentials("other");var verifier=new XmlSignatureVerifier();
        var normal=request("local-normal",own,SamlSignedRequestFactory.Fixture.VALID);
        var cross=request("local-other-signer",other,SamlSignedRequestFactory.Fixture.VALID);
        var invalid=request("local-invalid-signature",own,SamlSignedRequestFactory.Fixture.BAD_SIGNATURE_VALUE);
        for(var row:List.of(Map.entry("local-normal",normal),Map.entry("local-other-signer",cross),Map.entry("local-invalid-signature",invalid)))
            ShibbolethRegisteredSignerEvidence.validateRequest(RUN,row.getKey(),row.getValue(),URI.create("http://localhost:18280/idp/profile/SAML2/POST/SSO"),ENTITY,URI.create(ENTITY+"/sp/acs/0"),row.getKey().equals("local-other-signer")?other:own);
        assertTrue(verifier.hasValidEnvelopedSignature(SecureXml.parse(cross).getDocumentElement(),other.certificate()));
        assertFalse(verifier.hasValidEnvelopedSignature(SecureXml.parse(cross).getDocumentElement(),own.certificate()));
        assertFalse(verifier.hasValidEnvelopedSignature(SecureXml.parse(invalid).getDocumentElement(),own.certificate()));
    }
    @Test void anotherValidSignedRequestCannotSubstituteForTheExactControl() throws Exception {
        var own=credentials("own");var other=credentials("other");
        for(var wrong:List.of(request("local-other-signer",own,SamlSignedRequestFactory.Fixture.VALID),
                request("local-other-signer",other,SamlSignedRequestFactory.Fixture.VALID_NO_NAMEID_POLICY),
                request("local-normal",other,SamlSignedRequestFactory.Fixture.VALID)))
            assertThrows(IllegalArgumentException.class,()->ShibbolethRegisteredSignerEvidence.validateRequest(RUN,"local-other-signer",wrong,
                    URI.create("http://localhost:18280/idp/profile/SAML2/POST/SSO"),ENTITY,URI.create(ENTITY+"/sp/acs/0"),other));
    }
}
