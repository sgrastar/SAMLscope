package com.samlscope.runner.result;

import com.samlscope.core.result.RunArtifactRepository;
import com.samlscope.runner.HistoricalRunReadPolicy;
import java.util.*;
import java.util.function.*;

/** Neither half of a historical artifact pair may be overwritten by reading its missing partner. */
public final class HistoricalArtifactCacheReader {
    private final RunArtifactRepository artifacts;
    private final Function<byte[],byte[]> renderReport;
    public HistoricalArtifactCacheReader(RunArtifactRepository artifacts,Function<byte[],byte[]> renderReport) {
        this.artifacts=Objects.requireNonNull(artifacts);this.renderReport=Objects.requireNonNull(renderReport);
    }
    public synchronized byte[] result(String runId,Supplier<byte[]> owningSnapshotWhenBothMissing) {
        var result=artifacts.findResult(runId);
        if(result.isPresent())return result.get().clone();
        if(artifacts.findReport(runId).isPresent())throw HistoricalRunReadPolicy.incompleteArtifactPair();
        return Objects.requireNonNull(owningSnapshotWhenBothMissing.get()).clone();
    }
    public synchronized byte[] report(String runId,Supplier<byte[]> owningSnapshotWhenBothMissing) {
        var report=artifacts.findReport(runId);
        if(report.isPresent())return report.get().clone();
        var result=artifacts.findResult(runId);
        if(result.isPresent())return Objects.requireNonNull(renderReport.apply(result.get().clone())).clone();
        owningSnapshotWhenBothMissing.get();
        return artifacts.findReport(runId).orElseThrow(()->new IllegalStateException("Owning snapshot did not create its report")).clone();
    }
}
