package com.samlscope.runner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.xml.namespace.QName;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.caseexec.CaseExecutionStatus;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.MetadataDeliveryKind;
import com.samlscope.core.plan.MetadataSourceKind;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.plan.TargetKind;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.run.RunStatus;
import com.samlscope.core.run.TestRun;
import com.samlscope.saml.crypto.FilePlanKeyStore;
import com.samlscope.store.FileTranscriptRecorder;
import com.samlscope.store.JsonCodec;
import com.samlscope.store.SqliteCaseExecutionRepository;
import com.samlscope.store.SqliteDatabase;
import com.samlscope.store.SqlitePlanRepository;
import com.samlscope.store.SqliteRunRepository;
import com.samlscope.runner.cases.AutomatedCaseDependencies;
import com.samlscope.runner.cases.AutomatedCaseRegistry;
import com.samlscope.runner.cases.IdpErrorProbeConfiguration;
import com.samlscope.runner.cases.PrincipalIdentityResolver;
import com.samlscope.runner.cases.SamlAttributeReleaseFixture;
import com.samlscope.runner.cases.SamlOptionalFieldObservationCase;

class QuickCheckServiceTest {
    private static final String RUN_ID = "run_0123456789ABCDEFGHJKMNPQRS";
    private static final String PLAN_ID = "plan_0123456789ABCDEFGHJKMNPQRS";
    private static final Instant NOW = Instant.parse("2026-08-29T00:00:00Z");
    @TempDir java.nio.file.Path directory;
    private SqliteRunRepository runs;
    private QuickCheckService service;

    @BeforeEach
    void setUp() {
        var database = new SqliteDatabase(directory);
        var json = new JsonCodec();
        var plans = new SqlitePlanRepository(database, json);
        var plan = new TestPlan(
                PLAN_ID, "Quick check", FunctionalProfile.BROWSER_SSO_IDP,
                new TestPlan.Target(TargetKind.IDP, "https://idp.example/entity",
                        new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://idp.example/metadata")),
                MetadataDeliveryKind.MANUAL, Map.of(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), NOW, NOW);
        plans.save(plan);
        runs = new SqliteRunRepository(database, json);
        var transcript = new FileTranscriptRecorder(database, json, directory);
        var caseExecutions = new SqliteCaseExecutionRepository(database, json);
        var keys = new FilePlanKeyStore(directory, Clock.fixed(NOW, ZoneOffset.UTC));
        var credentials = keys.getOrCreate(PLAN_ID);
        var selector = SamlOptionalFieldObservationCase.Selector.element(new QName(
                "urn:oasis:names:tc:SAML:2.0:protocol", "Extensions"));
        var dependencies = new AutomatedCaseDependencies(
                transcript,
                Map.of(
                        "IIP-SSO01-dj-idp-01", new SamlAttributeReleaseFixture("no-values", null, List.of()),
                        "IIP-SSO01-dk-idp-01", new SamlAttributeReleaseFixture(
                                "empty", null, List.of(SamlAttributeReleaseFixture.EmptyValue.INSTANCE)),
                        "IIP-SSO01-dl-idp-01", new SamlAttributeReleaseFixture(
                                "null", null, List.of(SamlAttributeReleaseFixture.NullValue.INSTANCE)),
                        "IIP-SSO01-du-idp-01", new SamlAttributeReleaseFixture(
                                "discrete", null, List.of(new SamlAttributeReleaseFixture.TextValue("one")))),
                Map.of("IIP-SSO07-a-idp-01", selector, "IIP-SSO07-a-sp-01", selector),
                List.of(), "https://suite.example/p/" + PLAN_ID,
                ignored -> Optional.of(credentials.privateKey()),
                (runId, identifier) -> PrincipalIdentityResolver.Resolution.unknown(),
                caseExecutions,
                new IdpErrorProbeConfiguration(
                        URI.create("https://idp.example/sso"), "https://suite.example/p/" + PLAN_ID,
                        URI.create("https://suite.example/p/" + PLAN_ID + "/sp/acs/0"),
                        Duration.ofMinutes(2), false, false, false));
        var selected = AutomatedCaseRegistry.create(dependencies).forRole(plan.profile().role()).stream()
                .map(value -> value.id()).toArray(String[]::new);
        service = new QuickCheckService(
                plans, runs, transcript, transcript,
                caseExecutions, keys,
                (ignored, runId) -> java.util.List.of(),
                URI.create("https://suite.example"), Clock.fixed(NOW, ZoneOffset.UTC),
                null, null, ignored -> FunctionalCaseFixtures.automated(plan.profile(), selected));
    }

    @Test
    void runsTheApprovedAutomatedSubsetButNeverCallsItConformance() {
        runs.save(run(RunStatus.COMPLETED));

        var result = service.execute(RUN_ID);

        assertEquals(QuickCheckService.DISCLAIMER, result.disclaimer());
        assertFalse(result.cases().isEmpty());
        assertFalse(result.cases().stream().anyMatch(value ->
                value.status() == CaseExecutionStatus.FINISHED
                        && value.outcome().outcome() == Outcome.VIOLATED));
        assertEquals(CaseExecutionStatus.FINISHED, result.cases().stream()
                .filter(value -> value.caseId().equals("IIP-IDP05-a-idp-01"))
                .findFirst().orElseThrow().status());
        assertEquals(Outcome.NOT_VERIFIED, result.cases().stream()
                .filter(value -> value.caseId().equals("IIP-IDP05-a-idp-01"))
                .findFirst().orElseThrow().outcome().outcome());
    }

    @Test
    void refusesToTreatAnIncompleteProtocolRunAsACompleteTranscript() {
        runs.save(run(RunStatus.RUNNING));

        assertThrows(IllegalArgumentException.class, () -> service.execute(RUN_ID));
    }

    @Test
    void repeatedExecutionReusesThePersistedCaseExecutions() {
        runs.save(run(RunStatus.COMPLETED));

        var first = service.execute(RUN_ID);
        var second = service.execute(RUN_ID);

        assertEquals(first.cases(), second.cases());
    }

    private TestRun run(RunStatus status) {
        return new TestRun(RUN_ID, PLAN_ID, status, Reachability.CONFIRMED, Map.of(), NOW, NOW);
    }
}
