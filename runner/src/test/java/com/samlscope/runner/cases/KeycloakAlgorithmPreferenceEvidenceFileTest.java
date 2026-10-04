package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.saml.crypto.VerifiedSignatureAlgorithms;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;

class KeycloakAlgorithmPreferenceEvidenceFileTest {
    @TempDir Path directory;
    private static final String D="http://www.w3.org/2001/04/xmlenc#sha",S="http://www.w3.org/2001/04/xmldsig-more#rsa-sha";
    private Map<String,MetadataAlgorithmEvidence.Exchange> correct() {
        var result=new HashMap<String,MetadataAlgorithmEvidence.Exchange>();
        for(var variant:KeycloakAlgorithmPreferenceEvidenceFile.REQUIRED) {
            int first=variant.endsWith("512-256")||variant.equals("algorithm-entity-sha512")?512:256;
            var digest=variant.contains("-signing-")?256:first;
            var signature=variant.contains("-digest-")?256:first;
            result.put(variant,new MetadataAlgorithmEvidence.Exchange("poll_one",variant,null,null,
                List.of(new VerifiedSignatureAlgorithms.Observation("Response","_id",S+signature,D+digest,"key")),List.of(),List.of()));
        }
        return result;
    }
    private void change(Map<String,MetadataAlgorithmEvidence.Exchange> samples,String variant,int digest,int signature) {
        var old=samples.get(variant);samples.put(variant,new MetadataAlgorithmEvidence.Exchange(old.campaign(),variant,null,null,
            List.of(new VerifiedSignatureAlgorithms.Observation("Response","_id",S+signature,D+digest,"key")),List.of(),List.of()));
    }
    @Test void verifiesIndividualTypesAndBothOrders() {
        for(var id:KeycloakAlgorithmPreferenceEvidenceFile.CASES)assertTrue(KeycloakAlgorithmPreferenceEvidenceFile.preferenceMismatches(id,correct()).isEmpty());
        var samples=correct();change(samples,"algorithm-entity-digest-order-512-256",256,256);
        assertEquals(List.of("algorithm-entity-digest-order-512-256:digest-not-first-permitted"),
            KeycloakAlgorithmPreferenceEvidenceFile.preferenceMismatches("IIP-MD05-e7-idp-01",samples));
        samples=correct();change(samples,"algorithm-entity-signing-order-512-256",256,256);
        assertEquals(List.of("algorithm-entity-signing-order-512-256:signature-not-first-permitted"),
            KeycloakAlgorithmPreferenceEvidenceFile.preferenceMismatches("IIP-MD05-e7-idp-01",samples));
    }
    @Test void fixedKnownSupportedSelectorDoesNotMasqueradeAsOrderFollowing() {
        var samples=correct();for(var variant:KeycloakAlgorithmPreferenceEvidenceFile.REQUIRED)change(samples,variant,256,256);
        for(var id:KeycloakAlgorithmPreferenceEvidenceFile.CASES)assertFalse(KeycloakAlgorithmPreferenceEvidenceFile.preferenceMismatches(id,samples).isEmpty());
    }
    @Test void unsupportedFirstMustBeSkipped() {
        var samples=correct();var variant="algorithm-unsupported-first";var old=samples.get(variant);
        samples.put(variant,new MetadataAlgorithmEvidence.Exchange(old.campaign(),variant,null,null,
            List.of(new VerifiedSignatureAlgorithms.Observation("Response","_id","urn:samlscope:test:unsupported-signature",
                "urn:samlscope:test:unsupported-digest","key")),List.of(),List.of()));
        assertEquals(2,KeycloakAlgorithmPreferenceEvidenceFile.preferenceMismatches("IIP-MD05-e9-idp-01",samples).size());
    }
    @Test void noReceiptOrOpaqueClaimsRemainUnverified()throws Exception {
        var run="run_00000000000000000000000001";
        var recorder=new TranscriptRecorder() {
            public List<TranscriptEntry> list(String id){return List.of();}
            public TranscriptEntry record(TranscriptInput input){throw new UnsupportedOperationException();}
            public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary){throw new UnsupportedOperationException();}
        };
        var context=new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,true);
        var reader=new KeycloakAlgorithmPreferenceEvidenceFile(directory,e->new byte[0]);
        for(var id:KeycloakAlgorithmPreferenceEvidenceFile.CASES)assertEquals(Outcome.NOT_VERIFIED,reader.evaluate(id,context,new byte[0]).outcome());
        Files.writeString(directory.resolve(run+".algorithm-preference.json"),"{\"runId\":\""+run+"\",\"local_policy_verified\":true,\"restored\":true}");
        for(var id:KeycloakAlgorithmPreferenceEvidenceFile.CASES)assertEquals(Outcome.NOT_VERIFIED,reader.evaluate(id,context,new byte[0]).outcome());
    }
}
