package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ClockSkewEvidenceTest {
    @TempDir Path directory;
    private ClockSkewEvidence reader() throws Exception {
        return new ClockSkewEvidence(directory.toRealPath(),entry->{throw new AssertionError("Blocked proof must not read protocol bytes");},
                run->{throw new AssertionError("Missing originals must block before target/key access");},
                (run,variant)->{throw new AssertionError("No key generation or lookup for blocked proof");});
    }
    @Test void ownedMalformedFolderAndSymlinkCannotBecomeReady() throws Exception {
        var r=reader();var run=ClockSkewEvidenceTestCaseTest.RUN;
        assertFalse(r.exists(run));Files.writeString(directory.resolve(run),"not a folder");
        assertTrue(r.exists(run));assertTrue(r.evaluate(ClockSkewEvidenceTestCaseTest.context(true)).isEmpty());
        Files.delete(directory.resolve(run));var other=Files.createDirectory(directory.resolve("other"));
        Files.writeString(other.resolve("manifest.json"),"{}");Files.createSymbolicLink(directory.resolve(run),other);
        assertTrue(r.exists(run));assertTrue(r.evaluate(ClockSkewEvidenceTestCaseTest.context(true)).isEmpty());
    }
    @Test void foreignRunAndCrossRunSourceFailBeforeCalibrationOrConsumerAccess() throws Exception {
        var run=ClockSkewEvidenceTestCaseTest.RUN;var folder=Files.createDirectory(directory.resolve(run));
        for(var foreign:List.of("runId","sourceRunId")) {
            String json="{\"schema\":\""+ClockSkewEvidence.SCHEMA+"\",\"runId\":\""+run+"\",\"caseId\":\""+ClockSkewEvidence.CASE
                    +"\",\"campaignId\":\""+ClockSkewEvidence.CAMPAIGN+"\",\"counterfactualCalibrationOnly\":false";
            if(foreign.equals("runId"))json=json.replace(run,"run_11111111111111111111111111");
            else json+=",\"sourceRunId\":\"run_11111111111111111111111111\"";
            Files.writeString(folder.resolve("manifest.json"),json+"}");
            assertTrue(reader().evaluate(ClockSkewEvidenceTestCaseTest.context(true)).isEmpty(),foreign);
        }
    }
    @Test void productionReaderRejectsDeveloperPermissionBeforeAnyNativeAdapterRuns() throws Exception {
        var run=ClockSkewEvidenceTestCaseTest.RUN;var folder=Files.createDirectory(directory.resolve(run));
        Files.writeString(folder.resolve("manifest.json"),"{\"schema\":\""+ClockSkewEvidence.SCHEMA+"\",\"runId\":\""+run
                +"\",\"caseId\":\""+ClockSkewEvidence.CASE+"\",\"campaignId\":\""+ClockSkewEvidence.CAMPAIGN+"\",\"counterfactualCalibrationOnly\":true}");
        assertTrue(reader().evaluate(ClockSkewEvidenceTestCaseTest.context(true)).isEmpty());
    }
    @Test void unverifiedRestoreAndSuiteToleranceLabelsCannotReplaceOriginals() throws Exception {
        var run=ClockSkewEvidenceTestCaseTest.RUN;var folder=Files.createDirectory(directory.resolve(run));
        Files.writeString(folder.resolve("manifest.json"),"{\"schema\":\""+ClockSkewEvidence.SCHEMA+"\",\"runId\":\""+run
                +"\",\"caseId\":\""+ClockSkewEvidence.CASE+"\",\"campaignId\":\""+ClockSkewEvidence.CAMPAIGN
                +"\",\"counterfactualCalibrationOnly\":false,\"suiteTolerance\":180,\"restored\":true,\"observations\":[]}");
        assertTrue(reader().evaluate(ClockSkewEvidenceTestCaseTest.context(true)).isEmpty());
    }
}
