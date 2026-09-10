package com.samlscope.runner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.plan.MetadataDeliveryKind;
import com.samlscope.core.plan.MetadataSourceKind;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.plan.TargetKind;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.run.RunStatus;
import com.samlscope.core.run.TestRun;
import com.samlscope.saml.metadata.TargetMetadataParser;
import com.samlscope.store.JsonCodec;
import com.samlscope.store.MetadataCache;
import com.samlscope.store.SqliteDatabase;
import com.samlscope.store.SqlitePlanRepository;
import com.samlscope.store.SqliteRunRepository;

class PreflightServiceTest {
    private static final String PLAN_ID = "plan_0123456789ABCDEFGHJKMNPQRS";
    private static final String RUN_ID = "run_0123456789ABCDEFGHJKMNPQRS";
    private static final Instant NOW = Instant.parse("2026-08-30T00:00:00Z");

    @TempDir java.nio.file.Path directory;

    @Test
    void repeatedPreflightDoesNotRegressACompletedProtocolRun() {
        var database = new SqliteDatabase(directory);
        var json = new JsonCodec();
        var plans = new SqlitePlanRepository(database, json);
        var runs = new SqliteRunRepository(database, json);
        plans.save(plan());
        runs.save(new TestRun(RUN_ID, PLAN_ID, RunStatus.COMPLETED,
                Reachability.CONFIRMED, Map.of("m0RoundTrip", "completed"), NOW, NOW));
        var clock = Clock.fixed(NOW, ZoneOffset.UTC);
        var service = new PreflightService(
                URI.create("http://127.0.0.1:8080"), plans, runs,
                new RunService(plans, runs, new RunEventBus(), clock),
                new MetadataCache(directory), new TargetMetadataParser(),
                new OutboundPolicy(true), clock, json.mapper());

        var report = service.execute(RUN_ID);

        assertFalse(report.hasFailure());
        var saved = runs.find(RUN_ID).orElseThrow();
        assertEquals(RunStatus.COMPLETED, saved.status());
        assertEquals("completed", saved.context().get("m0RoundTrip"));
    }

    private TestPlan plan() {
        return new TestPlan(
                PLAN_ID, "Completed preflight", FunctionalProfile.BROWSER_SSO_IDP,
                new TestPlan.Target(TargetKind.IDP, "https://idp.example/entity",
                        new TestPlan.MetadataSource(MetadataSourceKind.UPLOAD, "manual.xml")),
                MetadataDeliveryKind.MANUAL, Map.of(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), NOW, NOW);
    }
}
