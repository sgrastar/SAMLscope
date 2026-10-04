package com.samlscope.runner;

import static org.junit.jupiter.api.Assertions.*;

import java.time.*;
import org.junit.jupiter.api.Test;

class TargetInitiatedIntentsTest {
    private static final Instant NOW = Instant.parse("2026-09-15T00:00:00Z");
    private final Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);

    @Test
    void anIntentIsSingleUseAndReplacesThePreviousOne() {
        var intents = new TargetInitiatedIntents();
        intents.prepare("run_a", "plan", TargetInitiatedIntents.Kind.UNSOLICITED_SSO, Duration.ofMinutes(5), clock);
        assertTrue(intents.consumeForRun("run_a", TargetInitiatedIntents.Kind.UNSOLICITED_SSO, clock));
        assertFalse(intents.consumeForRun("run_a", TargetInitiatedIntents.Kind.UNSOLICITED_SSO, clock));

        intents.prepare("run_a", "plan", TargetInitiatedIntents.Kind.UNSOLICITED_SSO, Duration.ofMinutes(5), clock);
        intents.prepare("run_a", "plan", TargetInitiatedIntents.Kind.TARGET_LOGOUT, Duration.ofMinutes(5), clock);
        assertFalse(intents.consumeForRun("run_a", TargetInitiatedIntents.Kind.UNSOLICITED_SSO, clock));
        assertTrue(intents.consumeForRun("run_a", TargetInitiatedIntents.Kind.TARGET_LOGOUT, clock));
    }

    @Test
    void expiredIntentsAreNeverConsumedOrResolved() {
        var intents = new TargetInitiatedIntents();
        intents.prepare("run_a", "plan", TargetInitiatedIntents.Kind.TARGET_LOGOUT, Duration.ofMinutes(5), clock);
        var later = Clock.fixed(NOW.plus(Duration.ofMinutes(6)), ZoneOffset.UTC);
        assertFalse(intents.consumeForRun("run_a", TargetInitiatedIntents.Kind.TARGET_LOGOUT, later));
        assertTrue(intents.resolvePlan("plan", TargetInitiatedIntents.Kind.TARGET_LOGOUT, later).isEmpty());
        assertTrue(intents.find("run_a", later).isEmpty());
        assertEquals(0, intents.activeCount(later));
    }

    @Test
    void planResolutionRequiresExactlyOneAwaitingRun() {
        var intents = new TargetInitiatedIntents();
        assertTrue(intents.resolvePlan("plan", TargetInitiatedIntents.Kind.TARGET_LOGOUT, clock).isEmpty());
        intents.prepare("run_a", "plan", TargetInitiatedIntents.Kind.TARGET_LOGOUT, Duration.ofMinutes(5), clock);
        intents.prepare("run_b", "plan", TargetInitiatedIntents.Kind.TARGET_LOGOUT, Duration.ofMinutes(5), clock);
        assertTrue(intents.resolvePlan("plan", TargetInitiatedIntents.Kind.TARGET_LOGOUT, clock).isEmpty(),
                "ambiguous waits must not be consumed");
        intents.clear("run_b");
        assertEquals("run_a", intents.resolvePlan("plan", TargetInitiatedIntents.Kind.TARGET_LOGOUT, clock)
                .orElseThrow().runId());
        assertTrue(intents.resolvePlan("plan", TargetInitiatedIntents.Kind.TARGET_LOGOUT, clock).isEmpty());
    }

    @Test
    void anotherPlanNeverConsumesThisPlansIntent() {
        var intents = new TargetInitiatedIntents();
        intents.prepare("run_a", "plan_a", TargetInitiatedIntents.Kind.TARGET_LOGOUT, Duration.ofMinutes(5), clock);
        assertTrue(intents.resolvePlan("plan_b", TargetInitiatedIntents.Kind.TARGET_LOGOUT, clock).isEmpty());
        assertTrue(intents.find("run_a", clock).isPresent());
    }
}
