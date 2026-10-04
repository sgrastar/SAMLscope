package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SimpleSamlPhpRegisteredSignerEvidenceTest {
    private static final String RUN="run_00000000000000000000000000", ENTITY="http://localhost:18080/p/plan_00000000000000000000000000";
    @TempDir Path directory;
    private DefaultCaseContext context(boolean complete){return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,
        new TranscriptRecorder(){public List<TranscriptEntry> list(String run){return List.of();}public TranscriptEntry record(TranscriptInput i){throw new AssertionError("No interactions");}public TranscriptEntry updateSamlAnalysis(String a,String b,Map<String,Object>s){throw new AssertionError("No original mutation");}},complete);}
    private SimpleSamlPhpRegisteredSignerEvidence reader(){return new SimpleSamlPhpRegisteredSignerEvidence(directory,e->{throw new AssertionError();},r->new byte[0],(r,v)->Optional.empty());}
    @Test void absencePreservesFallbackAndInvalidOwnedProofIsUnverified()throws Exception {
        assertFalse(reader().exists(RUN));assertTrue(reader().evaluate(context(true)).isEmpty());
        var folder=Files.createDirectory(directory.resolve(RUN));Files.writeString(folder.resolve("manifest.json"),"{\"restored\":true,\"accepted\":false}");
        assertEquals(Outcome.NOT_VERIFIED,reader().evaluate(context(true)).orElseThrow().outcome());
        assertEquals(Outcome.NOT_VERIFIED,reader().evaluate(context(false)).orElseThrow().outcome());assertTrue(reader().probeInputs(context(true)).isEmpty());
    }
    @Test void symlinkAndForeignOwnerCannotProduceAConclusion()throws Exception {
        var other=Files.createDirectory(directory.resolve("other"));Files.writeString(other.resolve("manifest.json"),"{}");Files.createSymbolicLink(directory.resolve(RUN),other);
        assertFalse(reader().exists("../"+RUN));assertEquals(Outcome.NOT_VERIFIED,reader().evaluate(context(true)).orElseThrow().outcome());
    }
    private static String error(String issuer,String selected,String element){return "<pre>SimpleSAML\\Error\\Error: {&quot;errorCode&quot;:&quot;NOTVALIDCERTSIGNATURE&quot;,&quot;%ELEMENT%&quot;:&quot;"+element+"&quot;,&quot;%ISSUER%&quot;:&quot;"+issuer+"&quot;,&quot;%ENTITYID%&quot;:&quot;"+selected+"&quot;}</pre>";}
    @Test void nativeErrorRequiresBothActualIssuerAndSelectedMetadataEntity(){
        var correct=error(ENTITY,ENTITY,"SAML2\\\\AuthnRequest");assertTrue(SimpleSamlPhpRegisteredSignerEvidence.nativeSignatureRejection(correct,ENTITY));
        for(var wrong:List.of(error("foreign",ENTITY,"SAML2\\\\AuthnRequest"),error(ENTITY,"foreign","SAML2\\\\AuthnRequest"),error(ENTITY,ENTITY,"SAML2\\\\Response"),"HTTP500 NOTVALIDCERTSIGNATURE",correct+correct,"<script>"+correct+"</script>"))assertFalse(SimpleSamlPhpRegisteredSignerEvidence.nativeSignatureRejection(wrong,ENTITY));
    }
    @Test void LoginOrSamlFormsAreNeverNativeErrorEvidence(){
        var correct=error(ENTITY,ENTITY,"SAML2\\\\AuthnRequest");for(String extra:List.of("<input name='password'>","<INPUT name='password'>","SAMLResponse","SAMLRequest","Authorization: secret","Cookie: secret"))assertFalse(SimpleSamlPhpRegisteredSignerEvidence.nativeSignatureRejection(correct+extra,ENTITY));
    }
    @Test void recursivelySensitiveNativeReadbacksAreRejected()throws Exception {
        var mapper=new JsonCodec().mapper();assertFalse(SimpleSamlPhpRegisteredSignerEvidence.sensitive(mapper.readTree("{\"keys\":[{\"X509Certificate\":\"public\"}]}")));
        for(String name:List.of("Cookie","set-cookie","Authorization","password","private_key","access-token"))assertTrue(SimpleSamlPhpRegisteredSignerEvidence.sensitive(mapper.readTree("{\"nested\":[{\""+name+"\":\"redacted\"}]}")));
    }
}
