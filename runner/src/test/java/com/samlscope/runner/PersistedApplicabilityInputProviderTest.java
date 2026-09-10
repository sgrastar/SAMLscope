package com.samlscope.runner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import com.samlscope.core.evaluation.ApplicabilityInput;
import com.samlscope.core.evaluation.ApplicabilityInputRepository;
import com.samlscope.core.evaluation.PredicateCatalog;
import com.samlscope.core.evaluation.PredicateCatalog.ConflictPolicy;
import com.samlscope.core.evaluation.PredicateKind;
import com.samlscope.core.plan.MetadataDeliveryKind;
import com.samlscope.core.plan.MetadataSourceKind;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.plan.TargetKind;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.run.RunStatus;
import com.samlscope.core.run.TestRun;

class PersistedApplicabilityInputProviderTest {
    private static final Instant NOW = Instant.parse("2026-08-29T13:00:00Z");

    @Test
    void returnsPersistedInputAndTreatsAbsenceAsUnknown() {
        var stored = new AtomicReference<ApplicabilityInput>();
        ApplicabilityInputRepository repository = repository(stored);
        var provider = new PersistedApplicabilityInputProvider(repository);

        assertEquals(new ApplicabilityInput(null, null, List.of(), null),
                provider.input(definition(), run(), plan()));

        var observed = new ApplicabilityInput(false, true, List.of("transcript:1"), null);
        stored.set(observed);
        assertEquals(observed, provider.input(definition(), run(), plan()));
    }

    @Test
    void rejectsRunAndPlanFromDifferentScopes() {
        var provider = new PersistedApplicabilityInputProvider(repository(new AtomicReference<>()));
        var otherRun = new TestRun(
                "run_0123456789ABCDEFGHJKMNPQRS", "plan_other_123456789ABCDEFGHJKMNPQ",
                RunStatus.RUNNING, Reachability.CONFIRMED, Map.of(), NOW, NOW);
        assertThrows(IllegalArgumentException.class, () -> provider.input(definition(), otherRun, plan()));
    }

    private ApplicabilityInputRepository repository(AtomicReference<ApplicabilityInput> stored) {
        return new ApplicabilityInputRepository() {
            @Override
            public Optional<ApplicabilityInput> find(String runId, String predicate) {
                return Optional.ofNullable(stored.get());
            }

            @Override
            public void save(String runId, String predicate, ApplicabilityInput input, Instant updatedAt) {
                stored.set(input);
            }
        };
    }

    private PredicateCatalog.Definition definition() {
        return new PredicateCatalog.Definition(
                "feature", PredicateKind.CAPABILITY_BASED, List.of("declared.feature"),
                List.of("observed.feature"), ConflictPolicy.INCONSISTENT, null);
    }

    private TestPlan plan() {
        return new TestPlan(
                "plan_0123456789ABCDEFGHJKMNPQRS", "Applicability persistence", FunctionalProfile.BROWSER_SSO_IDP,
                new TestPlan.Target(
                        TargetKind.IDP, "https://idp.example/entity",
                        new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://idp.example/metadata")),
                MetadataDeliveryKind.MANUAL, Map.of(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), NOW, NOW);
    }

    private TestRun run() {
        return new TestRun(
                "run_0123456789ABCDEFGHJKMNPQRS", "plan_0123456789ABCDEFGHJKMNPQRS",
                RunStatus.RUNNING, Reachability.CONFIRMED, Map.of(), NOW, NOW);
    }
}
