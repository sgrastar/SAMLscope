package com.samlscope.store;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.plan.MetadataDeliveryKind;
import com.samlscope.core.plan.MetadataSourceKind;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.plan.TargetKind;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.evaluation.ApplicabilityInput;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.run.RunStatus;
import com.samlscope.core.run.TestRun;

class SqliteRepositoriesTest {
    @TempDir java.nio.file.Path directory;

    @Test
    void persistsPlansAndRuns() {
        var database = new SqliteDatabase(directory);
        var json = new JsonCodec();
        var plans = new SqlitePlanRepository(database, json);
        var runs = new SqliteRunRepository(database, json);
        var applicability = new SqliteApplicabilityInputRepository(database, json);
        var now = Instant.parse("2026-08-29T00:00:00Z");
        var plan = new TestPlan(
                "plan_0123456789ABCDEFGHJKMNPQRS",
                "Example IdP",
                FunctionalProfile.BROWSER_SSO_IDP,
                new TestPlan.Target(TargetKind.IDP, "https://idp.example/entity",
                        new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://idp.example/metadata")),
                MetadataDeliveryKind.HTTP_URL,
                Map.of("single_logout", true),
                TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(),
                now,
                now);
        plans.save(plan);
        var run = new TestRun("run_0123456789ABCDEFGHJKMNPQRS", plan.id(), RunStatus.CREATED,
                Reachability.UNKNOWN, Map.of(), now, now);
        runs.save(run);
        var exclusion = new ApplicabilityInput.ExclusionDeclaration(
                "Target is in the excluded classification", "operator", now);
        var input = new ApplicabilityInput(false, null, List.of(), exclusion);
        applicability.save(run.id(), "classification", input, now);

        assertEquals(plan, plans.find(plan.id()).orElseThrow());
        assertEquals(run, runs.find(run.id()).orElseThrow());
        assertEquals(1, plans.list().size());
        assertEquals(1, runs.listForPlan(plan.id()).size());
        assertEquals(input, applicability.find(run.id(), "classification").orElseThrow());

        var observed = new ApplicabilityInput(true, true, List.of("transcript:1"), null);
        applicability.save(run.id(), "classification", observed, now.plusSeconds(1));
        assertEquals(observed, applicability.find(run.id(), "classification").orElseThrow());
        assertTrue(plans.delete(plan.id()));
        assertTrue(applicability.find(run.id(), "classification").isEmpty());
    }
}
