package com.samlscope.store;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.access.RunAccessGrant;
import com.samlscope.core.plan.MetadataDeliveryKind;
import com.samlscope.core.plan.MetadataSourceKind;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.plan.TargetKind;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.run.RunStatus;
import com.samlscope.core.run.TestRun;

class SqliteRunAccessGrantRepositoryTest {
    @TempDir java.nio.file.Path directory;

    @Test
    void storesOnlyDigestsBoundToTheRun() {
        var database = new SqliteDatabase(directory);
        var json = new JsonCodec();
        var plan = plan();
        new SqlitePlanRepository(database, json).save(plan);
        new SqliteRunRepository(database, json).save(new TestRun(
                "run_0123456789ABCDEFGHJKMNPQRS", plan.id(), RunStatus.CREATED,
                Reachability.UNKNOWN, Map.of(), Instant.EPOCH, Instant.EPOCH));
        var repository = new SqliteRunAccessGrantRepository(database);
        var grant = new RunAccessGrant("run_0123456789ABCDEFGHJKMNPQRS", digest('a'), digest('b'), digest('c'),
                Instant.EPOCH, false);
        repository.save(grant);

        assertEquals(grant, repository.find(grant.runId()).orElseThrow());
        assertFalse(repository.find("run_00000000000000000000000000").isPresent());
    }

    private TestPlan plan() {
        return new TestPlan("plan_0123456789ABCDEFGHJKMNPQRS", "Access", FunctionalProfile.BROWSER_SSO_IDP,
                new TestPlan.Target(TargetKind.IDP, "https://idp.example/entity",
                        new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://idp.example/metadata")),
                MetadataDeliveryKind.MANUAL, Map.of(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), Instant.EPOCH, Instant.EPOCH);
    }

    private String digest(char value) { return "sha256:" + String.valueOf(value).repeat(64); }
}
