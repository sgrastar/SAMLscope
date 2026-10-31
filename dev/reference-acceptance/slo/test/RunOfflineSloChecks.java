package com.samlscope.runner.cases;

import org.junit.platform.engine.discovery.DiscoverySelectors;
import org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder;
import org.junit.platform.launcher.core.LauncherFactory;
import org.junit.platform.launcher.listeners.SummaryGeneratingListener;

/** In-process fallback when the sandbox denies Gradle's local lock-listener socket. */
public final class RunOfflineSloChecks {
    public static void main(String[] args) {
        var request = LauncherDiscoveryRequestBuilder.request()
                .selectors(DiscoverySelectors.selectClass(ReadSloStoredEvidenceTest.class)).build();
        var listener = new SummaryGeneratingListener();
        LauncherFactory.create().execute(request, listener);
        var writer = new java.io.PrintWriter(System.out, true);
        listener.getSummary().printTo(writer);
        listener.getSummary().printFailuresTo(writer);
        if (listener.getSummary().getTestsFoundCount() != 14 || listener.getSummary().getTotalFailureCount() != 0)
            System.exit(1);
    }
}
