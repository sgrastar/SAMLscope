package com.samlscope.runner.cases;

import com.samlscope.core.evaluation.Outcome;
import java.util.Set;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class NativeIdentifierConstructionComparisonTest {
    @Test void randomShapeWithoutNativeProducerBindingIsUnverified() {
        assertEquals(Outcome.NOT_VERIFIED,NativeIdentifierConstructionComparison.compare(false,"G-13abca15-8b2b-41ed-90ba-51a6f7a9b520",Set.of("principal")));
    }
    @Test void missingPrincipalInventoryIsUnverified() {
        assertEquals(Outcome.NOT_VERIFIED,NativeIdentifierConstructionComparison.compare(true,"opaque",Set.of()));
    }
    @Test void genuineConstructionAndOriginalSavedValueCanSatisfy() {
        assertEquals(Outcome.SATISFIED,NativeIdentifierConstructionComparison.compare(true,"opaque",Set.of("principal")));
    }
    @Test void actualPrincipalValuedSavedAttributeDetectsTheApprovedMutant() {
        assertEquals(Outcome.VIOLATED,NativeIdentifierConstructionComparison.compare(true,"principal",Set.of("principal")));
    }
    @Test void emailAndDirectoryBusinessIdentifiersAreDetected() {
        assertEquals(Outcome.VIOLATED,NativeIdentifierConstructionComparison.compare(true,"test@example.invalid",Set.of("principal")));
        assertEquals(Outcome.VIOLATED,NativeIdentifierConstructionComparison.compare(true,"uid=test,dc=example,dc=invalid",Set.of("principal")));
    }
}
