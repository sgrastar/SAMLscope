package com.samlscope.runner;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.result.RunArtifactRepository;
import com.samlscope.runner.result.HistoricalArtifactCacheReader;
import java.util.*;
import org.junit.jupiter.api.Test;

class HistoricalArtifactCacheReaderTest {
    @Test void oldResultMissingReportRendersExactOriginalWithoutStoreOrReevaluation() {
        var repository=new Memory();repository.result=new byte[]{1,2,3};var original=repository.result.clone();
        var reader=new HistoricalArtifactCacheReader(repository,bytes->{assertArrayEquals(original,bytes);bytes[0]=9;return new byte[]{4,5};});
        assertArrayEquals(new byte[]{4,5},reader.report("owned",()->{throw new AssertionError("No owning re-evaluation for an existing partner");}));
        assertArrayEquals(original,repository.result);assertNull(repository.report);assertEquals(0,repository.stores);
    }
    @Test void oldReportMissingResultReturnsConflictAndPreservesPartnerWithoutStore() {
        var repository=new Memory();repository.report=new byte[]{4,5};var original=repository.report.clone();
        var reader=new HistoricalArtifactCacheReader(repository,bytes->{throw new AssertionError("Cannot infer original JSON from HTML");});
        var unavailable=assertThrows(HistoricalRunReadPolicy.DefinitionUnavailable.class,()->reader.result("owned",()->{throw new AssertionError("No re-evaluation");}));
        assertEquals(409,unavailable.httpStatus());assertEquals("historical-artifact-pair-incomplete",unavailable.code());
        assertArrayEquals(original,repository.report);assertNull(repository.result);assertEquals(0,repository.stores);
    }
    @Test void onlyBothMissingAllowsOwningSnapshotCreationAndExistingPairReadsNeverStore() {
        var repository=new Memory();var reader=new HistoricalArtifactCacheReader(repository,bytes->new byte[]{9});
        assertArrayEquals(new byte[]{7},reader.report("owned",()->{repository.saveResult("owned",new byte[]{6});repository.saveReport("owned",new byte[]{7});return new byte[]{6};}));
        assertEquals(2,repository.stores);
        assertArrayEquals(new byte[]{6},reader.result("owned",()->{throw new AssertionError("Pair exists");}));
        assertArrayEquals(new byte[]{7},reader.report("owned",()->{throw new AssertionError("Pair exists");}));
        assertEquals(2,repository.stores);
    }
    static final class Memory implements RunArtifactRepository {
        byte[] result,report;int stores;
        public Optional<byte[]> findResult(String run){return Optional.ofNullable(result).map(byte[]::clone);}
        public Optional<byte[]> findReport(String run){return Optional.ofNullable(report).map(byte[]::clone);}
        public void saveResult(String run,byte[] bytes){stores++;result=bytes.clone();}
        public void saveReport(String run,byte[] bytes){stores++;report=bytes.clone();}
    }
}
