package com.samlscope.runner.cases;
import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.transcript.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.runner.DefaultCaseContext;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SimpleSamlPhpKeyValueRuntimeEvidenceTest {
    private static final String RUN="run_00000000000000000000000000";
    @TempDir Path directory;
    private DefaultCaseContext context(){return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,
        new TranscriptRecorder(){public List<TranscriptEntry> list(String run){return List.of();}public TranscriptEntry record(TranscriptInput input){throw new AssertionError("Reader must not send or record");}
            public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary){throw new AssertionError("Reader must not mutate originals");}},true);}
    @Test void missingOriginalsNeverOverrideExistingCase(){
        var reader=new SimpleSamlPhpKeyValueRuntimeEvidence(directory,e->{throw new AssertionError();});
        assertFalse(reader.exists(RUN));for(var id:SimpleSamlPhpKeyValueRuntimeEvidence.CASES)assertTrue(reader.evaluate(id,context(),new byte[0]).isEmpty());
    }
    @Test void bareMissingCertificateClaimCannotEstablishProductViolation()throws Exception{
        Path folder=Files.createDirectory(directory.resolve(RUN));Files.writeString(folder.resolve("manifest.json"),"{\"missingCertificate\":true,\"restored\":true}");
        var reader=new SimpleSamlPhpKeyValueRuntimeEvidence(directory,e->{throw new AssertionError();});
        for(var id:SimpleSamlPhpKeyValueRuntimeEvidence.CASES)assertEquals(Outcome.NOT_VERIFIED,reader.evaluate(id,context(),new byte[0]).orElseThrow().outcome());
    }
    @Test void unsupportedCasesAndFolderTraversalNeverUseThisAdapter()throws Exception{
        Files.createDirectory(directory.resolve(RUN));var reader=new SimpleSamlPhpKeyValueRuntimeEvidence(directory,e->{throw new AssertionError();});
        assertFalse(reader.exists("../"+RUN));assertTrue(reader.evaluate(MetadataKeySelectionComparison.PUBLIC_KEY,context(),new byte[0]).isEmpty());
        assertEquals(Set.of("IIP-MD05-cd-idp-01","IIP-MD06-a5-idp-01","IIP-MD06-a7-idp-01"),SimpleSamlPhpKeyValueRuntimeEvidence.CASES);
    }
    @Test void symlinkFoldersAndManifestAreUnproven()throws Exception{
        Path outside=Files.createDirectory(directory.resolve("outside"));Files.createSymbolicLink(directory.resolve(RUN),outside);
        var reader=new SimpleSamlPhpKeyValueRuntimeEvidence(directory,e->{throw new AssertionError();});assertTrue(reader.exists(RUN));assertEquals(Outcome.NOT_VERIFIED,reader.evaluate(MetadataKeySelectionComparison.REPRESENTATION,context(),new byte[0]).orElseThrow().outcome());
        Files.delete(directory.resolve(RUN));Path folder=Files.createDirectory(directory.resolve(RUN));Path fake=Files.writeString(outside.resolve("manifest.json"),"{}");
        Files.createSymbolicLink(folder.resolve("manifest.json"),fake);
        assertEquals(Outcome.NOT_VERIFIED,reader.evaluate(MetadataKeySelectionComparison.REPRESENTATION,context(),new byte[0]).orElseThrow().outcome());
    }
}
