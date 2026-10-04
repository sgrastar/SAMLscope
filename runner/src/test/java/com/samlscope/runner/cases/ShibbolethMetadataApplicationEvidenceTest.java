package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ShibbolethMetadataApplicationEvidenceTest {
    static final String RUN="run_0123456789ABCDEFGHJKMNPQRS";
    @TempDir Path directory;
    final AtomicInteger reads=new AtomicInteger();
    ShibbolethMetadataApplicationEvidence reader() {
        return new ShibbolethMetadataApplicationEvidence(directory,e->{reads.incrementAndGet();throw new AssertionError("Unbound original read");},
            r->{reads.incrementAndGet();throw new AssertionError("Unexpected target read");},(r,v)->{reads.incrementAndGet();return Optional.empty();},r->Optional.empty());
    }
    CaseContext context(boolean complete) {
        var recorder=new TranscriptRecorder(){public List<TranscriptEntry> list(String r){return List.of();}public TranscriptEntry record(TranscriptInput input){throw new AssertionError("No sending during observation");}public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary){throw new AssertionError("No original edits");}};
        return new com.samlscope.runner.DefaultCaseContext(RUN,TargetRole.IDP,Clock.systemUTC(),new TestPlan.Parameters(180,45,"reference"),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,complete);
    }
    @Test void absentOriginalsDoNotRequestAnotherBrowserAction() {
        assertFalse(reader().exists(RUN));assertEquals(Outcome.NOT_VERIFIED,reader().evaluate(MetadataSupersessionProbeTestCase.APPLICATION,context(true)).outcome());assertEquals(0,reads.get());
    }
    @Test void partiallyOwnedDirectoryFailsClosed() throws Exception {
        Files.createDirectory(directory.resolve(RUN));assertTrue(reader().exists(RUN));assertEquals(Outcome.NOT_VERIFIED,reader().evaluate(MetadataSupersessionProbeTestCase.SUPERSESSION,context(true)).outcome());assertEquals(0,reads.get());
    }
    @Test void symlinkOwnedOriginalsRemainUnverified() throws Exception {
        Path actual=Files.createDirectory(directory.resolve("actual"));Files.createSymbolicLink(directory.resolve(RUN),actual);assertTrue(reader().exists(RUN));assertEquals(Outcome.NOT_VERIFIED,reader().evaluate(MetadataSupersessionProbeTestCase.APPLICATION,context(true)).outcome());assertEquals(0,reads.get());
    }
    @Test void publicRuntimeCannotEnableDeveloperCalibrationByReceiptLabel() throws Exception {
        Path own=Files.createDirectory(directory.resolve(RUN));String raw="{\"schema\":\""+ShibbolethMetadataApplicationEvidence.SCHEMA+"\",\"adapter\":\""+ShibbolethMetadataApplicationEvidence.ADAPTER+"\",\"campaignId\":\""+ShibbolethMetadataApplicationEvidence.CAMPAIGN+"\",\"runId\":\""+RUN+"\",\"calibration\":{\"selectedConsumer\":\"retain-conflicting-old-a-acs\"}}";Files.writeString(own.resolve("manifest.json"),raw);
        assertEquals(Outcome.NOT_VERIFIED,reader().evaluate(MetadataSupersessionProbeTestCase.APPLICATION,context(true)).outcome());assertEquals(0,reads.get());
    }
    @Test void incompleteHistoryCannotUseExistingNativeReceipt() throws Exception {
        Files.createDirectory(directory.resolve(RUN));assertEquals(Outcome.NOT_VERIFIED,reader().evaluate(MetadataSupersessionProbeTestCase.SUPERSESSION,context(false)).outcome());assertEquals(0,reads.get());
    }
}
