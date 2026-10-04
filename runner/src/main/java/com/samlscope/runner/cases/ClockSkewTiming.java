package com.samlscope.runner.cases;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/** Compare temporal inputs only to an original-backed clock interval in the product's domain. */
final class ClockSkewTiming {
    enum Direction { PAST, FUTURE }
    enum Position { STRICTLY_WITHIN, STRICTLY_OUTSIDE, AMBIGUOUS }

    record ClockInterval(Instant startedAt, Instant completedAt) {
        ClockInterval {
            Objects.requireNonNull(startedAt); Objects.requireNonNull(completedAt);
            if (completedAt.isBefore(startedAt)) throw new IllegalArgumentException("Clock interval reversed");
        }
    }
    static Position classify(Instant input, ClockInterval nativeClock, Duration targetTolerance, Direction direction) {
        Objects.requireNonNull(input); Objects.requireNonNull(nativeClock); Objects.requireNonNull(direction);
        if (targetTolerance == null || targetTolerance.isZero() || targetTolerance.isNegative())
            throw new IllegalArgumentException("Target policy tolerance must be proven and positive");
        var minimum = direction == Direction.FUTURE
                ? Duration.between(nativeClock.completedAt(), input) : Duration.between(input, nativeClock.startedAt());
        var maximum = direction == Direction.FUTURE
                ? Duration.between(nativeClock.startedAt(), input) : Duration.between(input, nativeClock.completedAt());
        // Equality at T, a clock interval straddling T, or an input not shifted in the claimed
        // direction cannot establish the approved strict T-delta / T+delta comparison.
        if (minimum.isNegative() || minimum.isZero()) return Position.AMBIGUOUS;
        if (maximum.compareTo(targetTolerance) < 0) return Position.STRICTLY_WITHIN;
        if (minimum.compareTo(targetTolerance) > 0) return Position.STRICTLY_OUTSIDE;
        return Position.AMBIGUOUS;
    }
    private ClockSkewTiming() { }
}
