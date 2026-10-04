package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.time.*;
import org.junit.jupiter.api.Test;

class ClockSkewTimingTest {
    private static final Instant NATIVE = Instant.parse("2026-10-03T09:00:00Z");
    private static final Duration T = Duration.ofSeconds(75);
    private static final ClockSkewTiming.ClockInterval CLOCK = new ClockSkewTiming.ClockInterval(NATIVE,NATIVE.plusSeconds(2));
    @Test void insideRequiresTheWholeProductClockBracketToRemainBelowItsOwnTolerance() {
        assertEquals(ClockSkewTiming.Position.STRICTLY_WITHIN, ClockSkewTiming.classify(NATIVE.plusSeconds(50),CLOCK,T,ClockSkewTiming.Direction.FUTURE));
        assertEquals(ClockSkewTiming.Position.STRICTLY_WITHIN, ClockSkewTiming.classify(NATIVE.minusSeconds(50),CLOCK,T,ClockSkewTiming.Direction.PAST));
        assertEquals(ClockSkewTiming.Position.AMBIGUOUS, ClockSkewTiming.classify(NATIVE.plusSeconds(76),CLOCK,T,ClockSkewTiming.Direction.FUTURE));
        assertEquals(ClockSkewTiming.Position.AMBIGUOUS, ClockSkewTiming.classify(NATIVE.minusSeconds(74),CLOCK,T,ClockSkewTiming.Direction.PAST));
    }
    @Test void equalityWrongDirectionAndClockOverlapAreNotAWithinToleranceCounterexample() {
        for(var value:new Instant[]{NATIVE.plusSeconds(75),NATIVE.plusSeconds(1),NATIVE.minusSeconds(20)})
            assertEquals(ClockSkewTiming.Position.AMBIGUOUS,ClockSkewTiming.classify(value,CLOCK,T,ClockSkewTiming.Direction.FUTURE));
        assertThrows(IllegalArgumentException.class,()->new ClockSkewTiming.ClockInterval(NATIVE,NATIVE.minusSeconds(1)));
    }
    @Test void outsideIsAnObservationWithoutAnyVerdictAndHasNoUniversalThreshold() {
        assertEquals(ClockSkewTiming.Position.STRICTLY_OUTSIDE,ClockSkewTiming.classify(NATIVE.plusSeconds(100),CLOCK,T,ClockSkewTiming.Direction.FUTURE));
        assertEquals(ClockSkewTiming.Position.STRICTLY_WITHIN,ClockSkewTiming.classify(NATIVE.plusSeconds(100),CLOCK,Duration.ofSeconds(120),ClockSkewTiming.Direction.FUTURE));
        assertThrows(IllegalArgumentException.class,()->ClockSkewTiming.classify(NATIVE.plusSeconds(50),CLOCK,Duration.ZERO,ClockSkewTiming.Direction.FUTURE));
        assertThrows(IllegalArgumentException.class,()->ClockSkewTiming.classify(NATIVE.plusSeconds(50),CLOCK,null,ClockSkewTiming.Direction.FUTURE));
    }
}
