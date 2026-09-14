package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

class MetadataProbeCorrelationTest {
    @Test
    void requiresExactUniqueQueryValues() {
        assertTrue(MetadataProbeCorrelation.matches("https://suite/acs?mdv=entity-root&run=run_1", "run_1", "entity-root"));
        assertTrue(MetadataProbeCorrelation.matches("/acs?run=run%5F1&mdv=entity%2Droot", "run_1", "entity-root"));
        for (var query : java.util.List.of(
                "mdv=entity-root-other&run=run_1", "mdv=entity-root&run=run_10",
                "mdv=entity-root&run=run_1&run=run_1", "mdv=entity-root&mdv=entity-root&run=run_1",
                "other=mdv=entity-root&run=run_1", "mdv=entity-root&other=run=run_1",
                "mdv=entity-root#run=run_1", "mdv=entity-root&run=%ZZ", "mdv=entity-root&run")) {
            assertFalse(MetadataProbeCorrelation.matches("/acs?" + query, "run_1", "entity-root"), query);
        }
        assertFalse(MetadataProbeCorrelation.matches(null, "run_1", "entity-root"));
    }
}
