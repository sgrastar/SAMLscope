package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.saml.normal.SecureXml;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SimpleSamlPhpMetadataValidityEvidenceTest {
    private static final String RUN="run_00000000000000000000000000",MD="urn:oasis:names:tc:SAML:2.0:metadata";
    @TempDir Path directory;
    private DefaultCaseContext context(boolean complete){return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,
        new TranscriptRecorder(){public List<TranscriptEntry> list(String run){return List.of();}public TranscriptEntry record(TranscriptInput i){throw new AssertionError("No interactions");}public TranscriptEntry updateSamlAnalysis(String a,String b,Map<String,Object>s){throw new AssertionError("No original mutation");}},complete);}
    private SimpleSamlPhpMetadataValidityEvidence reader(){return new SimpleSamlPhpMetadataValidityEvidence(directory,e->{throw new AssertionError();},r->new byte[0],(r,v)->Optional.empty());}
    @Test void noOwnerPreservesFallbackAndMalformedOwnerIsUnverified()throws Exception {assertFalse(reader().exists(RUN));assertTrue(reader().evaluate(context(true)).isEmpty());Files.writeString(directory.resolve(RUN),"not a directory");assertTrue(reader().exists(RUN));assertEquals(Outcome.NOT_VERIFIED,reader().evaluate(context(true)).orElseThrow().outcome());}
    @Test void declarationAndIncompleteHistoryCannotSubstituteForOriginals()throws Exception {var f=Files.createDirectory(directory.resolve(RUN));Files.writeString(f.resolve("manifest.json"),"{\"restored\":true,\"expired\":true}");assertEquals(Outcome.NOT_VERIFIED,reader().evaluate(context(false)).orElseThrow().outcome());assertEquals(Outcome.NOT_VERIFIED,reader().evaluate(context(true)).orElseThrow().outcome());}
    @Test void symlinkOwnersAndTraversalAreNeverReadAsNativeEvidence()throws Exception {var other=Files.createDirectory(directory.resolve("other"));Files.createSymbolicLink(directory.resolve(RUN),other);assertTrue(reader().exists(RUN));assertFalse(reader().exists("../"+RUN));assertEquals(Outcome.NOT_VERIFIED,reader().evaluate(context(true)).orElseThrow().outcome());}
    @Test void earlierParentOrChildAndFractionalExpiryArePreserved(){String early="2026-10-02T03:00:00.900Z",later="2026-10-03T03:00:00Z";for(String variant:List.of("live-validity-parent","live-validity-child")){var root=SecureXml.parse(("<md:EntitiesDescriptor xmlns:md='"+MD+"' validUntil='"+(variant.endsWith("parent")?early:later)+"'><md:EntitiesDescriptor validUntil='"+(variant.endsWith("child")?early:later)+"'><md:EntityDescriptor entityID='peer' validUntil='"+later+"'/></md:EntitiesDescriptor></md:EntitiesDescriptor>").getBytes()).getDocumentElement();assertEquals(Instant.parse(early),SimpleSamlPhpMetadataValidityEvidence.effectiveExpiry(root,variant,"peer"));assertThrows(IllegalArgumentException.class,()->SimpleSamlPhpMetadataValidityEvidence.effectiveExpiry(root,variant.endsWith("parent")?"live-validity-child":"live-validity-parent","peer"));assertThrows(IllegalArgumentException.class,()->SimpleSamlPhpMetadataValidityEvidence.effectiveExpiry(root,variant,"foreign"));}}
    @Test void decodedOriginalReferencesRemainInTheSameRun(){String id="tx_00000000000000000000000000";var correct=new TranscriptEntry(id,RUN,Direction.INBOUND,Instant.EPOCH,null,"POST","http://localhost",200,Map.of(),null,0,"transcripts/"+RUN+"/"+id+".saml.xml",1,"application/xml",null,Map.of());assertTrue(SimpleSamlPhpMetadataValidityEvidence.sameRunOriginal(RUN,correct));var foreign=new TranscriptEntry(id,RUN,Direction.INBOUND,Instant.EPOCH,null,"POST","http://localhost",200,Map.of(),null,0,"transcripts/run_00000000000000000000000001/"+id+".saml.xml",1,"application/xml",null,Map.of());assertFalse(SimpleSamlPhpMetadataValidityEvidence.sameRunOriginal(RUN,foreign));}
    @Test void tiedExpiryDoesNotProveEarlierParentOrChild(){var root=SecureXml.parse(("<md:EntitiesDescriptor xmlns:md='"+MD+"' validUntil='2026-10-02T03:00:00Z'><md:EntitiesDescriptor validUntil='2026-10-02T03:00:00Z'><md:EntityDescriptor entityID='peer' validUntil='2026-10-03T03:00:00Z'/></md:EntitiesDescriptor></md:EntitiesDescriptor>").getBytes()).getDocumentElement();for(String variant:List.of("live-validity-parent","live-validity-child"))assertThrows(IllegalArgumentException.class,()->SimpleSamlPhpMetadataValidityEvidence.effectiveExpiry(root,variant,"peer"));}
}
