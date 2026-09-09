package com.samlscope.core.evaluation;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import com.samlscope.core.plan.TargetRole;

public record CoverageCatalog(List<Obligation> obligations) {
    public CoverageCatalog {
        obligations = List.copyOf(obligations == null ? List.of() : obligations);
        var keys = new LinkedHashMap<String, Obligation>();
        for (var obligation : obligations) {
            Objects.requireNonNull(obligation, "obligation");
            if (keys.put(obligation.key(), obligation) != null) {
                throw new IllegalArgumentException("Duplicate obligation key: " + obligation.key());
            }
        }
    }

    public Map<String, Obligation> byKey() {
        var result = new LinkedHashMap<String, Obligation>();
        for (var obligation : obligations) result.put(obligation.key(), obligation);
        return Map.copyOf(result);
    }

    public record Obligation(
            String key,
            String requirementId,
            Rfc2119Level level,
            List<TargetRole> roles,
            String condition,
            Testability testability,
            ProfileScope profileScope) {

        public Obligation {
            requireText(key, "key");
            requireText(requirementId, "requirementId");
            Objects.requireNonNull(level, "level");
            roles = List.copyOf(roles == null ? List.of() : roles);
            if (roles.isEmpty()) throw new IllegalArgumentException("roles must not be empty");
            Objects.requireNonNull(testability, "testability");
            Objects.requireNonNull(profileScope, "profileScope");
            if (condition != null && condition.isBlank()) {
                throw new IllegalArgumentException("condition must not be blank");
            }
        }

    }

    public enum Testability { AUTOMATED, BROWSER, ATTESTED, CONFIG, NOT_OBSERVABLE }
    public enum ProfileScope { CORE, FULL }

    private static void requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
    }
}
