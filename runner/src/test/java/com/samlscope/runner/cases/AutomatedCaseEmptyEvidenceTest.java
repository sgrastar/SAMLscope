package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.xml.namespace.QName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.caseexec.CaseExecutionStatus;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.MetadataDeliveryKind;
import com.samlscope.core.plan.MetadataSourceKind;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.plan.TargetKind;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.run.RunStatus;
import com.samlscope.core.run.TestRun;
import com.samlscope.runner.AutomatedCaseRunner;
import com.samlscope.runner.CaseExecutionService;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.runner.FunctionalCaseFixtures;
import com.samlscope.saml.crypto.FilePlanKeyStore;
import com.samlscope.store.FileTranscriptRecorder;
import com.samlscope.store.JsonCodec;
import com.samlscope.store.SqliteCaseExecutionRepository;
import com.samlscope.store.SqliteDatabase;
import com.samlscope.store.SqlitePlanRepository;
import com.samlscope.store.SqliteRunRepository;

/** Cross-case safety invariant: absence of target evidence is never target non-conformance. */
class AutomatedCaseEmptyEvidenceTest {
    private static final String RUN_ID = "run_0123456789ABCDEFGHJKMNPQRS";
    private static final String PLAN_ID = "plan_0123456789ABCDEFGHJKMNPQRS";
    private static final Instant NOW = Instant.parse("2026-08-29T00:00:00Z");
    @TempDir java.nio.file.Path directory;

    @Test
    void everyPassiveIdpCaseFailsSafeWithoutTranscriptEvidence() {
        var database = new SqliteDatabase(directory);
        var json = new JsonCodec();
        var plan = plan();
        new SqlitePlanRepository(database, json).save(plan);
        new SqliteRunRepository(database, json).save(new TestRun(
                RUN_ID, PLAN_ID, RunStatus.RUNNING, Reachability.CONFIRMED, Map.of(), NOW, NOW));
        var transcript = new FileTranscriptRecorder(database, json, directory);
        var executions = new SqliteCaseExecutionRepository(database, json);
        var credentials = new FilePlanKeyStore(directory, Clock.fixed(NOW, ZoneOffset.UTC)).getOrCreate(PLAN_ID);
        var selector = SamlOptionalFieldObservationCase.Selector.element(new QName(
                "urn:oasis:names:tc:SAML:2.0:protocol", "Extensions"));
        var dependencies = new AutomatedCaseDependencies(
                transcript,
                attributeFixtures(),
                Map.of("IIP-SSO07-a-idp-01", selector, "IIP-SSO07-a-sp-01", selector),
                List.of(credentials.certificate()),
                "https://suite.example/p/" + PLAN_ID,
                ignored -> Optional.of(credentials.privateKey()),
                (runId, identifier) -> PrincipalIdentityResolver.Resolution.unknown(),
                executions,
                new IdpErrorProbeConfiguration(
                        URI.create("https://idp.example/sso"), "https://suite.example/p/" + PLAN_ID,
                        URI.create("https://suite.example/p/" + PLAN_ID + "/sp/acs/0"),
                        Duration.ofMinutes(2), true, true, true));
        var registry = AutomatedCaseRegistry.create(dependencies);
        var runner = new AutomatedCaseRunner(registry, new CaseExecutionService(executions));
        var context = new DefaultCaseContext(
                RUN_ID, TargetRole.IDP, Clock.fixed(NOW, ZoneOffset.UTC), plan.parameters(),
                plan.interaction(),
                Reachability.CONFIRMED, transcript, true);

        var selected = registry.forRole(TargetRole.IDP).stream().map(value -> value.id()).toArray(String[]::new);
        var snapshot = runner.startReady(
                RUN_ID, FunctionalCaseFixtures.automated(plan.profile(), selected), context);

        assertEquals(registry.forRole(TargetRole.IDP).size(), snapshot.size());
        var finished = snapshot.stream().filter(value -> value.status() == CaseExecutionStatus.FINISHED).toList();
        assertEquals(snapshot.size() - 1, finished.size(), "Only the active error probe should still be waiting");
        assertFalse(finished.stream().anyMatch(value -> value.outcome().outcome() == Outcome.VIOLATED),
                () -> "No-evidence violations: " + finished.stream()
                        .filter(value -> value.outcome().outcome() == Outcome.VIOLATED)
                        .map(value -> value.caseId()).toList());
        assertEquals(1, executions.listOutbox(RUN_ID).size());
    }

    @Test
    void everyPassiveSpCaseFailsSafeWithoutTranscriptEvidence() {
        var database = new SqliteDatabase(directory);
        var json = new JsonCodec();
        var plan = new TestPlan(
                PLAN_ID, "Empty SP evidence", FunctionalProfile.BROWSER_SSO_SP,
                new TestPlan.Target(TargetKind.SP, "https://sp.example/entity",
                        new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://sp.example/metadata")),
                MetadataDeliveryKind.MANUAL, Map.of(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), NOW, NOW);
        new SqlitePlanRepository(database, json).save(plan);
        new SqliteRunRepository(database, json).save(new TestRun(
                RUN_ID, PLAN_ID, RunStatus.RUNNING, Reachability.CONFIRMED, Map.of(), NOW, NOW));
        var transcript = new FileTranscriptRecorder(database, json, directory);
        var executions = new SqliteCaseExecutionRepository(database, json);
        var credentials = new FilePlanKeyStore(directory, Clock.fixed(NOW, ZoneOffset.UTC)).getOrCreate(PLAN_ID);
        var selector = SamlOptionalFieldObservationCase.Selector.element(new QName(
                "urn:oasis:names:tc:SAML:2.0:protocol", "Extensions"));
        var registry = AutomatedCaseRegistry.create(new AutomatedCaseDependencies(
                transcript, attributeFixtures(),
                Map.of("IIP-SSO07-a-idp-01", selector, "IIP-SSO07-a-sp-01", selector),
                List.of(credentials.certificate()), "https://suite.example/p/" + PLAN_ID,
                ignored -> Optional.of(credentials.privateKey()),
                (runId, identifier) -> PrincipalIdentityResolver.Resolution.unknown(), executions,
                new IdpErrorProbeConfiguration(
                        URI.create("https://idp.example/sso"), "https://suite.example/p/" + PLAN_ID,
                        URI.create("https://suite.example/p/" + PLAN_ID + "/sp/acs/0"),
                        Duration.ofMinutes(2), false, false, false)));
        var runner = new AutomatedCaseRunner(registry, new CaseExecutionService(executions));
        var context = new DefaultCaseContext(
                RUN_ID, TargetRole.SP, Clock.fixed(NOW, ZoneOffset.UTC), plan.parameters(),
                plan.interaction(),
                Reachability.CONFIRMED, transcript, true);

        var selected = registry.forRole(TargetRole.SP).stream().map(value -> value.id()).toArray(String[]::new);
        var snapshot = runner.startReady(
                RUN_ID, FunctionalCaseFixtures.automated(plan.profile(), selected), context);

        assertEquals(registry.forRole(TargetRole.SP).size(), snapshot.size());
        assertEquals(snapshot.size(), snapshot.stream()
                .filter(value -> value.status() == CaseExecutionStatus.FINISHED).count());
        assertFalse(snapshot.stream().anyMatch(value -> value.outcome().outcome() == Outcome.VIOLATED),
                () -> "No-evidence violations: " + snapshot.stream()
                        .filter(value -> value.outcome().outcome() == Outcome.VIOLATED)
                        .map(value -> value.caseId()).toList());
        assertEquals(0, executions.listOutbox(RUN_ID).size());
    }

    private Map<String, SamlAttributeReleaseFixture> attributeFixtures() {
        return Map.of(
                "IIP-SSO01-dj-idp-01", new SamlAttributeReleaseFixture("no-values", null, List.of()),
                "IIP-SSO01-dk-idp-01", new SamlAttributeReleaseFixture(
                        "empty", null, List.of(SamlAttributeReleaseFixture.EmptyValue.INSTANCE)),
                "IIP-SSO01-dl-idp-01", new SamlAttributeReleaseFixture(
                        "null", null, List.of(SamlAttributeReleaseFixture.NullValue.INSTANCE)),
                "IIP-SSO01-du-idp-01", new SamlAttributeReleaseFixture(
                        "discrete", null, List.of(
                                new SamlAttributeReleaseFixture.TextValue("one"),
                                new SamlAttributeReleaseFixture.TextValue("two"))));
    }

    private TestPlan plan() {
        return new TestPlan(
                PLAN_ID, "Empty evidence", FunctionalProfile.BROWSER_SSO_IDP,
                new TestPlan.Target(TargetKind.IDP, "https://idp.example/entity",
                        new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://idp.example/metadata")),
                MetadataDeliveryKind.MANUAL, Map.of(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), NOW, NOW);
    }
}
