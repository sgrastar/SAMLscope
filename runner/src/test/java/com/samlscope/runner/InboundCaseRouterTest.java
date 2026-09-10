package com.samlscope.runner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseExecutionStatus;
import com.samlscope.core.caseexec.CaseState;
import com.samlscope.core.caseexec.CaseStep;
import com.samlscope.core.caseexec.InboundMatcher;
import com.samlscope.core.caseexec.TestCase;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.evaluation.EvidenceRef;
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
import com.samlscope.store.FileTranscriptRecorder;
import com.samlscope.store.JsonCodec;
import com.samlscope.store.SqliteCaseExecutionRepository;
import com.samlscope.store.SqliteDatabase;
import com.samlscope.store.SqlitePlanRepository;
import com.samlscope.store.SqliteRunRepository;

class InboundCaseRouterTest {
    private static final String RUN_ID = "run_0123456789ABCDEFGHJKMNPQRS";
    private static final Instant NOW = Instant.parse("2026-08-29T00:00:00Z");
    @TempDir java.nio.file.Path directory;
    private SqliteCaseExecutionRepository repository;
    private CaseExecutionService executions;
    private DefaultCaseContext context;

    @BeforeEach
    void setUp() {
        var database = new SqliteDatabase(directory);
        var json = new JsonCodec();
        var plan = plan();
        new SqlitePlanRepository(database, json).save(plan);
        new SqliteRunRepository(database, json).save(new TestRun(
                RUN_ID, plan.id(), RunStatus.RUNNING, Reachability.CONFIRMED, Map.of(), NOW, NOW));
        repository = new SqliteCaseExecutionRepository(database, json);
        executions = new CaseExecutionService(repository);
        context = new DefaultCaseContext(
                RUN_ID, TargetRole.IDP, Clock.fixed(NOW, ZoneOffset.UTC), plan.parameters(),
                plan.interaction(),
                Reachability.CONFIRMED, new FileTranscriptRecorder(database, json, directory), false);
    }

    @Test
    void resumesTheSingleCaseWhosePersistedCriteriaMatch() {
        var first = inboundCase("IIP-G03-a-idp-01", "_request-one");
        var second = inboundCase("IIP-SSO01-aa-idp-01", "_request-two");
        executions.start(RUN_ID, first, context);
        executions.start(RUN_ID, second, context);
        var router = new InboundCaseRouter(
                repository, new TestCaseRegistry(List.of(first, second)), executions);

        var routed = router.route(
                RUN_ID, "saml-response", Map.of("InResponseTo", "_request-two"),
                "<Response/>".getBytes(java.nio.charset.StandardCharsets.UTF_8),
                new EvidenceRef("transcript", "tx_two"), context).orElseThrow();

        assertEquals("IIP-SSO01-aa-idp-01", routed.caseId());
        assertEquals(CaseExecutionStatus.FINISHED, routed.status());
        assertEquals(Outcome.SATISFIED, routed.outcome().outcome());
        assertEquals(CaseExecutionStatus.WAITING_INBOUND,
                repository.find(RUN_ID, first.id()).orElseThrow().status());
    }

    @Test
    void returnsEmptyForAnUnsolicitedMessageAndFailsClosedOnAmbiguity() {
        var first = inboundCase("IIP-G03-a-idp-01", "_same");
        var second = inboundCase("IIP-SSO01-aa-idp-01", "_same");
        executions.start(RUN_ID, first, context);
        executions.start(RUN_ID, second, context);
        var router = new InboundCaseRouter(
                repository, new TestCaseRegistry(List.of(first, second)), executions);

        assertTrue(router.route(
                RUN_ID, "saml-response", Map.of("InResponseTo", "_other"), new byte[] {1},
                new EvidenceRef("transcript", "tx_other"), context).isEmpty());
        assertThrows(IllegalStateException.class, () -> router.route(
                RUN_ID, "saml-response", Map.of("InResponseTo", "_same"), new byte[] {1},
                new EvidenceRef("transcript", "tx_same"), context));
    }

    @Test
    void requiresEveryPersistedCriterionInsteadOfMatchingOnlyOne() {
        var testCase = new AwaitingCase(
                "IIP-G03-a-idp-01", Map.of("InResponseTo", "_one", "Destination", "https://suite.example/acs"));
        executions.start(RUN_ID, testCase, context);
        var router = new InboundCaseRouter(repository, new TestCaseRegistry(List.of(testCase)), executions);

        assertTrue(router.route(
                RUN_ID, "saml-response", Map.of("InResponseTo", "_one"), new byte[] {1},
                new EvidenceRef("transcript", "tx_partial"), context).isEmpty());
    }

    private TestCase inboundCase(String id, String requestId) {
        return new AwaitingCase(id, Map.of("InResponseTo", requestId));
    }

    private final class AwaitingCase implements TestCase {
        private final String id;
        private final Map<String, String> criteria;
        private AwaitingCase(String id, Map<String, String> criteria) { this.id = id; this.criteria = criteria; }
        @Override public String id() { return id; }
        @Override public TargetRole role() { return TargetRole.IDP; }
        @Override public CaseStep start(CaseContext ignored) {
            return new CaseStep.AwaitInbound(
                    new CaseState("waiting", Map.of()), List.of(),
                    new InboundMatcher("saml-response", criteria), Duration.ofMinutes(2));
        }
        @Override public CaseStep resume(CaseContext ignored, CaseState state, CaseEvent event) {
            if (!(event instanceof CaseEvent.InboundMessage inbound)) throw new IllegalArgumentException();
            return new CaseStep.Finish(CaseOutcome.of(
                    Outcome.SATISFIED, "matched", List.of(inbound.evidence())));
        }
    }

    private TestPlan plan() {
        return new TestPlan(
                "plan_0123456789ABCDEFGHJKMNPQRS", "Inbound routing", FunctionalProfile.BROWSER_SSO_IDP,
                new TestPlan.Target(TargetKind.IDP, "https://idp.example/entity",
                        new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://idp.example/metadata")),
                MetadataDeliveryKind.MANUAL, Map.of(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), NOW, NOW);
    }
}
