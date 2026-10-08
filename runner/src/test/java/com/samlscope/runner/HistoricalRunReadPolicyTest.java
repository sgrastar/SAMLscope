package com.samlscope.runner;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.profile.*;
import com.samlscope.core.evaluation.Rfc2119Level;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class HistoricalRunReadPolicyTest {
    private final FunctionalDefinitionIdentity unknown = new FunctionalDefinitionIdentity(FunctionalProfile.METADATA_IDP,"earlier-c204","sha256:"+"c".repeat(64));
    @Test void unavailableHistoryStillReadsByteExactCachedResultAndReportWithoutLiveWork() {
        var policy = new HistoricalRunReadPolicy(new FunctionalReleaseRegistry(List.of(),List.of()));
        var calls = new AtomicInteger(); var original = "{\n \"old_scope\":true\n}\n".getBytes();
        var returned = policy.read(unknown,()->Optional.of(original),()->{calls.incrementAndGet();throw new AssertionError("No reconciliation is permitted");});
        assertArrayEquals(original,returned); returned[0]^=1; assertNotEquals(returned[0],original[0]);
        assertEquals(0,calls.get()); assertTrue(policy.availability(unknown).readOnlyStored());
        assertFalse(policy.availability(unknown).liveEvaluationAvailable());
    }
    @Test void unknownEmptyOrOngoingRunCannotGenerateOrStartUnderTheLatestDefinition() {
        var policy = new HistoricalRunReadPolicy(new FunctionalReleaseRegistry(List.of(),List.of()));
        var calls = new AtomicInteger();
        var unavailable = assertThrows(HistoricalRunReadPolicy.DefinitionUnavailable.class,()->policy.read(unknown,Optional::<byte[]>empty,()->{calls.incrementAndGet();return new byte[]{1};}));
        assertEquals(409,unavailable.httpStatus()); assertEquals("historical-definition-unavailable",unavailable.code());
        assertThrows(HistoricalRunReadPolicy.DefinitionUnavailable.class,()->policy.requireEvaluation(unknown)); assertEquals(0,calls.get());
    }
    @Test void knownHistoricalEmptyRunCanUseItsExactOwnedContextWithoutMigratingScope() {
        var old = FunctionalReleaseRegistryTest.fixture("old-v1",'a',Rfc2119Level.MUST,FunctionalReleaseContext.Kind.HISTORICAL);
        var policy = new HistoricalRunReadPolicy(new FunctionalReleaseRegistry(List.of(),List.of(old)));
        assertEquals("retained-definition-read-only",policy.availability(old.identity()).code());
        assertEquals(old,policy.requireEvaluation(old.identity()));
        assertArrayEquals(new byte[]{4,5},policy.read(old.identity(),Optional::<byte[]>empty,()->new byte[]{4,5}));
        assertFalse(policy.availability(old.identity()).liveEvaluationAvailable());
        var held=assertThrows(HistoricalRunReadPolicy.DefinitionUnavailable.class,()->policy.requireExecution(old.identity()));
        assertEquals("retained-definition-read-only",held.code());
        assertEquals(409,held.httpStatus());
    }
    @Test void activeCachedReadKeepsExistingReconciliationAndDoesNotReadHistoricalCache() {
        var current = FunctionalReleaseRegistryTest.fixture("current-v1",'b',Rfc2119Level.MUST,FunctionalReleaseContext.Kind.CURRENT);
        var policy = new HistoricalRunReadPolicy(new FunctionalReleaseRegistry(List.of(current),List.of()));
        var calls=new AtomicInteger();
        assertArrayEquals(new byte[]{9},policy.readForRuntime(current.identity(),()->{throw new AssertionError("Active read must keep the prior current path");},
                ()->{calls.incrementAndGet();return new byte[]{9};},()->{throw new AssertionError("No history fallback");}));
        assertEquals(1,calls.get());
    }
    @Test void historicalTerminalAndUnknownNullLegacyCachesNeverReconcile() {
        var old = FunctionalReleaseRegistryTest.fixture("old-v1",'a',Rfc2119Level.MUST,FunctionalReleaseContext.Kind.HISTORICAL);
        var policy = new HistoricalRunReadPolicy(new FunctionalReleaseRegistry(List.of(),List.of(old)));
        for (var identity : Arrays.asList(old.identity(),unknown,null)) {
            assertArrayEquals(new byte[]{7},policy.readForRuntime(identity,()->Optional.of(new byte[]{7}),
                    ()->{throw new AssertionError("No active reconciliation");},()->{throw new AssertionError("Cache exists");}));
        }
        assertFalse(policy.availability(null).definitionAvailable());
    }
}
