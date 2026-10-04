package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.caseexec.CaseContext;
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

class MetadataValidityEvidenceTest {
    private static final String RUN="run_0123456789ABCDEFGHJKMNPQRS",MD="urn:oasis:names:tc:SAML:2.0:metadata";
    @TempDir Path directory;
    @Test void malformedAndSymlinkOwnedEvidenceNeverBecomesAnAbsentPrerequisite()throws Exception {
        var reader=reader();assertFalse(reader.exists(RUN));Files.writeString(directory.resolve(RUN),"not a directory");assertTrue(reader.exists(RUN));assertTrue(reader.evaluate(context(true)).isEmpty());Files.delete(directory.resolve(RUN));
        var external=directory.resolve("external");Files.createDirectory(external);Files.writeString(external.resolve("manifest.json"),"{}");Files.createSymbolicLink(directory.resolve(RUN),external);assertTrue(reader.exists(RUN));assertTrue(reader.evaluate(context(true)).isEmpty());
    }
    @Test void IncompleteHistoryAndManifestCannotConcludeFromFlags()throws Exception {
        Files.createDirectory(directory.resolve(RUN));Files.writeString(directory.resolve(RUN).resolve("manifest.json"),"{\"schema\":\""+MetadataValidityEvidence.SCHEMA+"\",\"adapter\":\""+MetadataValidityEvidence.ADAPTER+"\",\"runId\":\""+RUN+"\",\"expired\":true,\"restored\":true}");assertTrue(reader().evaluate(context(false)).isEmpty());assertTrue(reader().evaluate(context(true)).isEmpty());
    }
    @Test void OnlyTheGenuinelyEarliestAncestorCanRepresentParentAndChildExpiry()throws Exception {
        var early="2026-10-02T04:00:00Z";var later="2026-10-03T04:00:00Z";
        for(var variant:List.of("live-validity-parent","live-validity-child")){
            var root=SecureXml.parse(("<md:EntitiesDescriptor xmlns:md='"+MD+"' validUntil='"+(variant.endsWith("parent")?early:later)+"'><md:EntitiesDescriptor validUntil='"+(variant.endsWith("child")?early:later)+"'><md:EntityDescriptor entityID='peer' validUntil='"+later+"'/></md:EntitiesDescriptor></md:EntitiesDescriptor>").getBytes()).getDocumentElement();
            assertEquals(Instant.parse(early),MetadataValidityEvidence.effectiveExpiry(root,variant,"peer"));assertThrows(IllegalArgumentException.class,()->MetadataValidityEvidence.effectiveExpiry(root,variant.endsWith("parent")?"live-validity-child":"live-validity-parent","peer"));assertThrows(IllegalArgumentException.class,()->MetadataValidityEvidence.effectiveExpiry(root,variant,"another-peer"));
        }
    }
    private MetadataValidityEvidence reader(){return new MetadataValidityEvidence(directory,e->new byte[0],r->new byte[0],(r,v)->Optional.empty());}
    private static CaseContext context(boolean complete){var recorder=new TranscriptRecorder(){public List<TranscriptEntry> list(String run){return List.of();}public TranscriptEntry record(TranscriptInput input){throw new UnsupportedOperationException();}public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary){throw new UnsupportedOperationException();}};return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.systemUTC(),new TestPlan.Parameters(180,30,"reference"),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,complete);}
}
