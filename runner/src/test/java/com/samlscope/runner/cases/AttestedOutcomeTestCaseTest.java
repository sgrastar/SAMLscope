package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.caseexec.CaseEvent;
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
import com.samlscope.runner.CaseExecutionService;
import com.samlscope.runner.AttestationService;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.runner.TestCaseRegistry;
import com.samlscope.store.FileTranscriptRecorder;
import com.samlscope.store.JsonCodec;
import com.samlscope.store.SqliteCaseExecutionRepository;
import com.samlscope.store.SqliteDatabase;
import com.samlscope.store.SqlitePlanRepository;
import com.samlscope.store.SqliteRunRepository;

class AttestedOutcomeTestCaseTest {
    private static final String RUN_ID = "run_0123456789ABCDEFGHJKMNPQRS";
    private static final Instant NOW = Instant.parse("2026-08-29T02:00:00Z");

    @TempDir java.nio.file.Path directory;
    private SqliteCaseExecutionRepository repository;
    private CaseExecutionService executions;
    private TestPlan plan;
    private FileTranscriptRecorder transcript;

    @BeforeEach
    void setUp() {
        var database = new SqliteDatabase(directory);
        var json = new JsonCodec();
        plan = plan(true);
        new SqlitePlanRepository(database, json).save(plan);
        new SqliteRunRepository(database, json).save(new TestRun(
                RUN_ID, plan.id(), RunStatus.RUNNING, Reachability.UNKNOWN, Map.of(), NOW, NOW));
        repository = new SqliteCaseExecutionRepository(database, json);
        executions = new CaseExecutionService(repository);
        transcript = new FileTranscriptRecorder(database, json, directory);
    }

    @Test
    void persistsThePromptAndMapsOnlyAServerDefinedOptionToOutcome() {
        var testCase = testCase();
        var waiting = executions.start(RUN_ID, testCase, context(plan));
        var attestations = new AttestationService(
                new TestCaseRegistry(List.of(testCase)), executions, ignored -> context(plan));

        assertEquals(CaseExecutionStatus.WAITING_ATTESTATION, waiting.status());
        assertEquals("attestation.iip-g02-c", waiting.waitCondition().promptKey());
        assertEquals(NOW.plus(Duration.ofHours(1)), waiting.waitCondition().expiresAt());

        assertThrows(IllegalArgumentException.class, () -> attestations.attest(
                RUN_ID, testCase.id(), "FAIL", "client supplied verdict"));
        assertEquals(CaseExecutionStatus.WAITING_ATTESTATION,
                repository.find(RUN_ID, testCase.id()).orElseThrow().status());

        var result = attestations.attest(
                RUN_ID, testCase.id(), "truncated", "Observed in the admin UI");
        var finished = repository.find(RUN_ID, testCase.id()).orElseThrow();

        assertEquals(CaseExecutionStatus.FINISHED, result.status());
        assertEquals(Outcome.VIOLATED, result.outcome().outcome());
        assertEquals(CaseExecutionStatus.FINISHED, finished.status());
        assertEquals(Outcome.VIOLATED, finished.outcome().outcome());
        assertEquals("attestation.truncated", finished.outcome().reasonCode());
        assertEquals(true, finished.outcome().details().get("attested"));
        assertEquals("truncated", finished.outcome().details().get("attestation_option"));
        assertEquals("Observed in the admin UI", finished.outcome().details().get("attestation_note"));
        assertEquals("attestation", finished.outcome().evidence().getFirst().kind());
        assertFalse(finished.outcome().evidence().getFirst().reference().contains("Observed in the admin UI"));

        var repeated = attestations.attest(RUN_ID, testCase.id(), "preserved", "different retry");
        assertEquals(finished.outcome(), repeated.outcome());
    }

    @Test
    void interactionPolicyFailsClosedWithoutOpeningAnAttestationWait() {
        var disabled = plan(false);
        var finished = executions.start(RUN_ID, testCase(), context(disabled));

        assertEquals(CaseExecutionStatus.FINISHED, finished.status());
        assertEquals(Outcome.NOT_VERIFIED, finished.outcome().outcome());
        assertEquals("interaction_disallowed", finished.outcome().notVerifiedReason());
        assertEquals(null, finished.waitCondition());
    }

    @Test
    void timeoutAndExplicitUncertaintyRemainNonViolations() {
        var timedCase = testCase("IIP-G02-c-idp-timeout");
        executions.start(RUN_ID, timedCase, context(plan));
        var timedOut = executions.resume(
                RUN_ID, timedCase, context(plan), new CaseEvent.TimedOut(Duration.ofHours(1)));
        assertEquals(Outcome.NOT_VERIFIED, timedOut.outcome().outcome());
        assertEquals("timeout", timedOut.outcome().notVerifiedReason());

        var unclearCase = testCase("IIP-G02-c-idp-unclear");
        executions.start(RUN_ID, unclearCase, context(plan));
        var unclear = executions.resume(
                RUN_ID, unclearCase, context(plan), new CaseEvent.Attested("unclear", "No readback available"));
        assertEquals(Outcome.NOT_VERIFIED, unclear.outcome().outcome());
        assertEquals("user_skipped", unclear.outcome().notVerifiedReason());
    }

    @Test
    void rejectsUnsafeOrAmbiguousDefinitionsAndOversizedNotes() {
        assertThrows(IllegalArgumentException.class, () -> AttestationOption.of(
                "conflict", Outcome.INCONSISTENT, "attestation.conflict"));
        assertThrows(IllegalArgumentException.class, () -> new AttestedOutcomeTestCase(
                "IIP-G02-c-idp-duplicate", TargetRole.IDP, "question", Duration.ofMinutes(1),
                List.of(
                        AttestationOption.of("same", Outcome.SATISFIED, "one"),
                        AttestationOption.of("same", Outcome.VIOLATED, "two"))));

        var testCase = testCase("IIP-G02-c-idp-long-note");
        executions.start(RUN_ID, testCase, context(plan));
        assertThrows(IllegalArgumentException.class, () -> executions.resume(
                RUN_ID, testCase, context(plan), new CaseEvent.Attested("preserved", "x".repeat(4_001))));
    }

    private AttestedOutcomeTestCase testCase() {
        return testCase("IIP-G02-c-idp-01");
    }

    private AttestedOutcomeTestCase testCase(String id) {
        return new AttestedOutcomeTestCase(
                id, TargetRole.IDP, "attestation.iip-g02-c", Duration.ofHours(1),
                List.of(
                        AttestationOption.of("preserved", Outcome.SATISFIED, "attestation.preserved"),
                        AttestationOption.of("truncated", Outcome.VIOLATED, "attestation.truncated"),
                        AttestationOption.notVerified(
                                "unclear", "attestation.unclear", "user_skipped")));
    }

    private DefaultCaseContext context(TestPlan source) {
        return new DefaultCaseContext(
                RUN_ID, TargetRole.IDP, Clock.fixed(NOW, ZoneOffset.UTC), source.parameters(), source.interaction(),
                Reachability.UNKNOWN, transcript, false);
    }

    private TestPlan plan(boolean allowAttestation) {
        return new TestPlan(
                "plan_0123456789ABCDEFGHJKMNPQRS", "Attestation test", FunctionalProfile.BROWSER_SSO_IDP,
                new TestPlan.Target(
                        TargetKind.IDP, "https://idp.example/entity",
                        new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://idp.example/metadata")),
                MetadataDeliveryKind.MANUAL, Map.of(), TestPlan.Parameters.defaults(),
                new TestPlan.Interaction(true, allowAttestation), NOW, NOW);
    }
}
