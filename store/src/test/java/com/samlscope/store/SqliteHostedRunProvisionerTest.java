package com.samlscope.store;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.access.RunAccessGrant;
import com.samlscope.core.plan.MetadataDeliveryKind;
import com.samlscope.core.plan.MetadataSourceKind;
import com.samlscope.core.plan.PlanProfile;
import com.samlscope.core.plan.TargetKind;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.run.RunStatus;
import com.samlscope.core.run.TestRun;

class SqliteHostedRunProvisionerTest {
    @TempDir java.nio.file.Path directory;

    @Test
    void persistsPlanRunAndGrantAsOneProvisioningOperation() {
        var fixture = fixture();
        var plan = plan("plan_first", "https://target.example/idp");
        var run = run("run_first", plan.id(), RunStatus.CREATED);
        var grant = grant(run.id(), 'a');

        assertTrue(fixture.provisioner.createPlanWithInitialRun(plan, run, grant));
        assertEquals(plan, fixture.plans.find(plan.id()).orElseThrow());
        assertEquals(run, fixture.runs.find(run.id()).orElseThrow());
        assertEquals(grant, fixture.grants.find(run.id()).orElseThrow());
    }

    @Test
    void preservesOneAnonymousOwnerAcrossPlansAndTheirReplacementRuns() {
        var fixture = fixture();
        var firstPlan = plan("plan_first", "https://first.example/idp");
        var firstRun = run("run_first", firstPlan.id(), RunStatus.CREATED);
        assertTrue(fixture.provisioner.createPlanWithInitialRun(
                firstPlan, firstRun, grant(firstRun.id(), 'a'), "sha256:shared-owner"));
        fixture.runs.save(run(firstRun.id(), firstPlan.id(), RunStatus.COMPLETED));

        var secondPlan = plan("plan_second", "https://second.example/idp");
        var secondRun = run("run_second", secondPlan.id(), RunStatus.CREATED);
        assertTrue(fixture.provisioner.createPlanWithInitialRun(
                secondPlan, secondRun, grant(secondRun.id(), 'b'), "sha256:shared-owner"));
        fixture.runs.save(run(secondRun.id(), secondPlan.id(), RunStatus.COMPLETED));
        var replacement = run("run_replacement", secondPlan.id(), RunStatus.CREATED);
        assertTrue(fixture.provisioner.createRun(replacement, grant(replacement.id(), 'c')));

        assertEquals("sha256:shared-owner", fixture.provisioner.ownerForRun(firstRun.id()));
        assertEquals("sha256:shared-owner", fixture.provisioner.ownerForRun(secondRun.id()));
        assertEquals("sha256:shared-owner", fixture.provisioner.ownerForRun(replacement.id()));
    }

    @Test
    void rejectsAnotherActiveRunForTheSameTargetWithoutPersistingAnyRecord() {
        var fixture = fixture();
        var firstPlan = plan("plan_first", "https://target.example/idp");
        var firstRun = run("run_first", firstPlan.id(), RunStatus.CREATED);
        assertTrue(fixture.provisioner.createPlanWithInitialRun(
                firstPlan, firstRun, grant(firstRun.id(), 'a')));

        var rejectedPlan = plan("plan_rejected", firstPlan.target().entityId());
        var rejectedRun = run("run_rejected", rejectedPlan.id(), RunStatus.CREATED);
        assertFalse(fixture.provisioner.createPlanWithInitialRun(
                rejectedPlan, rejectedRun, grant(rejectedRun.id(), 'b')));

        assertFalse(fixture.plans.find(rejectedPlan.id()).isPresent());
        assertFalse(fixture.runs.find(rejectedRun.id()).isPresent());
        assertFalse(fixture.grants.find(rejectedRun.id()).isPresent());
    }

    @Test
    void permitsAReplacementAfterThePriorRunBecomesTerminal() {
        var fixture = fixture();
        var firstPlan = plan("plan_first", "https://target.example/idp");
        var firstRun = run("run_first", firstPlan.id(), RunStatus.CREATED);
        assertTrue(fixture.provisioner.createPlanWithInitialRun(
                firstPlan, firstRun, grant(firstRun.id(), 'a')));
        fixture.runs.save(run(firstRun.id(), firstPlan.id(), RunStatus.COMPLETED));

        var nextRun = run("run_next", firstPlan.id(), RunStatus.CREATED);
        assertTrue(fixture.provisioner.createRun(nextRun, grant(nextRun.id(), 'b')));
        assertEquals(nextRun, fixture.runs.find(nextRun.id()).orElseThrow());
        assertEquals(1, fixture.plans.list().size());
    }

    @Test
    void signingModeRemainsFixedAfterHostedRunCompletion() {
        var fixture = fixture();
        var plan = plan("plan_signing", "https://first.example/idp");
        var run = run("run_signing", plan.id(), RunStatus.CREATED);
        assertTrue(fixture.provisioner.createPlanWithInitialRun(plan, run, grant(run.id(), 'a')));
        fixture.runs.save(run(run.id(), plan.id(), RunStatus.COMPLETED));
        var changed = new TestPlan(plan.id(), "Changed", plan.profile(), plan.target(), plan.suiteMetadataDelivery(),
                plan.declaredFeatures(), new TestPlan.Parameters(180, 300, "", TestPlan.RequestSigningMode.REQUIRED),
                plan.interaction(), plan.createdAt(), Instant.ofEpochSecond(1));
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
                () -> fixture.provisioner.updatePlanUnlessActiveRetarget(changed));
        assertEquals(plan, fixture.plans.find(plan.id()).orElseThrow());
    }

    @Test
    void preventsRetargetingAPlanWithAnActiveRunButAllowsOtherEdits() {
        var fixture = fixture();
        var plan = plan("plan_active", "https://first.example/idp");
        var run = run("run_active", plan.id(), RunStatus.CREATED);
        assertTrue(fixture.provisioner.createPlanWithInitialRun(plan, run, grant(run.id(), 'a')));

        var renamed = new TestPlan(
                plan.id(), "Renamed", plan.profile(), plan.target(), plan.suiteMetadataDelivery(),
                plan.declaredFeatures(), plan.parameters(), plan.interaction(), plan.createdAt(), Instant.ofEpochSecond(1));
        assertTrue(fixture.provisioner.updatePlanUnlessActiveRetarget(renamed));
        assertEquals("Renamed", fixture.plans.find(plan.id()).orElseThrow().name());

        var retargeted = plan(plan.id(), "https://second.example/idp");
        assertFalse(fixture.provisioner.updatePlanUnlessActiveRetarget(retargeted));
        assertEquals(plan.target().entityId(), fixture.plans.find(plan.id()).orElseThrow().target().entityId());
    }

    @Test
    void permitsRetargetingAfterThePlansRunBecomesTerminal() {
        var fixture = fixture();
        var plan = plan("plan_terminal", "https://first.example/idp");
        var run = run("run_terminal", plan.id(), RunStatus.CREATED);
        assertTrue(fixture.provisioner.createPlanWithInitialRun(plan, run, grant(run.id(), 'a')));
        fixture.runs.save(run(run.id(), plan.id(), RunStatus.ABORTED));

        var retargeted = plan(plan.id(), "https://second.example/idp");
        assertTrue(fixture.provisioner.updatePlanUnlessActiveRetarget(retargeted));
        assertEquals(retargeted.target().entityId(),
                fixture.plans.find(plan.id()).orElseThrow().target().entityId());
    }

    @Test
    void serializesRetargetingAgainstRunCreationUsingTheCurrentStoredTarget() throws Exception {
        var fixture = fixture();
        var occupied = plan("plan_occupied", "https://occupied.example/idp");
        var occupiedRun = run("run_occupied", occupied.id(), RunStatus.CREATED);
        assertTrue(fixture.provisioner.createPlanWithInitialRun(
                occupied, occupiedRun, grant(occupiedRun.id(), 'a')));

        var candidate = plan("plan_candidate", "https://free.example/idp");
        fixture.plans.save(candidate);
        var retargeted = plan(candidate.id(), occupied.target().entityId());
        var candidateRun = run("run_candidate", candidate.id(), RunStatus.CREATED);
        var ready = new CountDownLatch(2);
        var start = new CountDownLatch(1);
        try (var executor = Executors.newFixedThreadPool(2)) {
            var update = executor.submit(() -> {
                ready.countDown();
                assertTrue(start.await(2, TimeUnit.SECONDS));
                return fixture.provisioner.updatePlanUnlessActiveRetarget(retargeted);
            });
            var create = executor.submit(() -> {
                ready.countDown();
                assertTrue(start.await(2, TimeUnit.SECONDS));
                return fixture.provisioner.createRun(candidateRun, grant(candidateRun.id(), 'b'));
            });
            assertTrue(ready.await(2, TimeUnit.SECONDS));
            start.countDown();

            assertEquals(1, (update.get() ? 1 : 0) + (create.get() ? 1 : 0));
        }
        var storedCandidate = fixture.plans.find(candidate.id()).orElseThrow();
        if (fixture.runs.find(candidateRun.id()).isPresent()) {
            assertEquals(candidate.target().entityId(), storedCandidate.target().entityId());
        } else {
            assertEquals(retargeted.target().entityId(), storedCandidate.target().entityId());
        }
    }

    @Test
    void rollsBackThePlanWhenAChildInsertFails() {
        var fixture = fixture();
        var existingPlan = plan("plan_existing", "https://existing.example/idp");
        var existingRun = run("run_collision", existingPlan.id(), RunStatus.COMPLETED);
        fixture.plans.save(existingPlan);
        fixture.runs.save(existingRun);

        var rejectedPlan = plan("plan_rolled_back", "https://other.example/idp");
        var collidingRun = run(existingRun.id(), rejectedPlan.id(), RunStatus.CREATED);
        assertThrows(StoreException.class, () -> fixture.provisioner.createPlanWithInitialRun(
                rejectedPlan, collidingRun, grant(collidingRun.id(), 'c')));

        assertFalse(fixture.plans.find(rejectedPlan.id()).isPresent());
        assertEquals(existingRun, fixture.runs.find(existingRun.id()).orElseThrow());
        assertFalse(fixture.grants.find(existingRun.id()).isPresent());
    }

    @Test
    void serializesConcurrentProvisioningForTheSameTarget() throws Exception {
        var fixture = fixture();
        var firstPlan = plan("plan_first", "https://target.example/idp");
        var secondPlan = plan("plan_second", firstPlan.target().entityId());
        var ready = new CountDownLatch(2);
        var start = new CountDownLatch(1);
        try (var executor = Executors.newFixedThreadPool(2)) {
            var first = executor.submit(() -> provisionAfterStart(fixture, firstPlan, "run_first", 'a', ready, start));
            var second = executor.submit(() -> provisionAfterStart(fixture, secondPlan, "run_second", 'b', ready, start));
            assertTrue(ready.await(2, TimeUnit.SECONDS));
            start.countDown();

            assertEquals(1, (first.get() ? 1 : 0) + (second.get() ? 1 : 0));
        }
        assertEquals(1, fixture.plans.list().size());
    }

    private boolean provisionAfterStart(
            Fixture fixture, TestPlan plan, String runId, char digest,
            CountDownLatch ready, CountDownLatch start) throws InterruptedException {
        ready.countDown();
        assertTrue(start.await(2, TimeUnit.SECONDS));
        var run = run(runId, plan.id(), RunStatus.CREATED);
        return fixture.provisioner.createPlanWithInitialRun(plan, run, grant(run.id(), digest));
    }

    private Fixture fixture() {
        var database = new SqliteDatabase(directory);
        var json = new JsonCodec();
        return new Fixture(
                new SqliteHostedRunProvisioner(database, json),
                new SqlitePlanRepository(database, json),
                new SqliteRunRepository(database, json),
                new SqliteRunAccessGrantRepository(database));
    }

    private TestPlan plan(String id, String entityId) {
        return new TestPlan(id, id, PlanProfile.IDP_CORE,
                new TestPlan.Target(TargetKind.IDP, entityId,
                        new TestPlan.MetadataSource(MetadataSourceKind.URL, entityId + "/metadata")),
                MetadataDeliveryKind.MANUAL, Map.of(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), Instant.EPOCH, Instant.EPOCH);
    }

    private TestRun run(String id, String planId, RunStatus status) {
        return new TestRun(id, planId, status, Reachability.UNKNOWN, Map.of(), Instant.EPOCH, Instant.EPOCH);
    }

    private RunAccessGrant grant(String runId, char value) {
        return new RunAccessGrant(runId, "sha256:" + String.valueOf(value).repeat(64),
                null, null, Instant.EPOCH, false);
    }

    private record Fixture(
            SqliteHostedRunProvisioner provisioner,
            SqlitePlanRepository plans,
            SqliteRunRepository runs,
            SqliteRunAccessGrantRepository grants) {}
}
