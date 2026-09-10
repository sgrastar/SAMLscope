package com.samlscope.runner.result;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import com.samlscope.core.evaluation.ApplicabilityEvaluation;
import com.samlscope.core.evaluation.ApplicabilityInput;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.evaluation.CaseRun;
import com.samlscope.core.evaluation.CoverageCatalog;
import com.samlscope.core.evaluation.CoverageCatalog.Obligation;
import com.samlscope.core.evaluation.CoverageCatalog.ProfileScope;
import com.samlscope.core.evaluation.CoverageCatalog.Testability;
import com.samlscope.core.evaluation.Evaluator;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.evaluation.PredicateKind;
import com.samlscope.core.evaluation.Rfc2119Level;
import com.samlscope.core.evaluation.RunResult.Conformance;
import com.samlscope.core.plan.MetadataDeliveryKind;
import com.samlscope.core.plan.MetadataSourceKind;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.plan.TargetKind;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.run.RunStatus;
import com.samlscope.core.run.TestRun;
import com.samlscope.runner.FunctionalCaseFixtures;

class ResultDocumentAssemblerTest {
    private static final Instant NOW = Instant.parse("2026-08-29T14:00:00Z");

    @org.junit.jupiter.api.Test
    void redactsOnlyInternalHttpEntityIdentifiers() {
        org.junit.jupiter.api.Assertions.assertEquals("redacted:internal-target",
                ResultDocumentAssembler.publicEntityId("https://idp.internal/entity"));
        org.junit.jupiter.api.Assertions.assertEquals("redacted:internal-target",
                ResultDocumentAssembler.publicEntityId("https://192.168.1.5/entity"));
        org.junit.jupiter.api.Assertions.assertEquals("https://idp.example/entity",
                ResultDocumentAssembler.publicEntityId("https://idp.example/entity"));
        org.junit.jupiter.api.Assertions.assertEquals("urn:example:idp",
                ResultDocumentAssembler.publicEntityId("urn:example:idp"));
    }

    @Test
    void assemblesEveryAuthoritativeSectionWithoutPublishingUserHints() throws Exception {
        var fixture = fixture();

        var document = ResultDocumentAssembler.assemble(
                fixture.catalog(), fixture.plan(), fixture.run(), fixture.evaluation(), fixture.cases(), context());
        var json = new ResultJsonWriter().write(document);
        var tree = new ResultJsonWriter().mapper().readTree(json);
        // Generated only from the Evaluator fixture; never hand-edit the golden document.
        if ("true".equals(System.getenv("SAMLSCOPE_UPDATE_RESULT_GOLDEN"))) {
            java.nio.file.Files.writeString(java.nio.file.Path.of("src/test/resources/golden/result-v1.json"), json);
            return;
        }
        try (var golden = ResultDocumentAssemblerTest.class.getResourceAsStream("/golden/result-v1.json")) {
            assertEquals(new String(golden.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8), json);
        }

        assertEquals("1", document.schemaVersion());
        assertEquals(Conformance.CONFORMANT_WITH_DECLARED_EXCLUSIONS, document.run().conformance());
        assertEquals(4, document.coverage().obligationsTotal());
        assertEquals(3, document.coverage().obligationsApplicable());
        assertEquals(1, document.coverage().excludedByDeclaration());
        assertEquals(2, document.requirements().size());
        assertEquals(2, document.summary().cases().total());
        assertEquals(1, document.evidenceSummary().externallyVerified());
        assertEquals(1, document.evidenceSummary().selfAttested());
        assertEquals(0, document.evidenceSummary().notVerified());
        assertEquals("SELF_ATTESTED", document.requirements().get(0).cases().get(1).evidenceClass());
        assertEquals(1, document.notObservable().size());
        assertTrue(document.conformanceStatement().contains("REQ.c"));
        assertTrue(document.conformanceStatement().contains("not a certification"));
        assertFalse(json.contains("secret-user@example.test"));
        assertFalse(json.contains("test_user_hint"));
        assertEquals("idp", tree.at("/target/role").asText().toLowerCase());
        assertEquals("2026-08-29T14:00:00Z", tree.at("/run/started_at").asText());
        assertEquals("2019-12-18", tree.at("/profile/spec/date").asText());
        assertEquals("1", tree.at("/evaluation_bundle/components/outcome_mapping_version").asText());
        assertEquals(context().evaluationComponents().compositeDigest(),
                tree.at("/evaluation_bundle/digest").asText());
        assertEquals(json, new ResultJsonWriter().write(document));
    }

    @Test
    void failsClosedWhenCaseRunsOrPublicationMetadataDoNotMatchEvaluation() {
        var fixture = fixture();
        assertThrows(IllegalArgumentException.class, () -> ResultDocumentAssembler.assemble(
                fixture.catalog(), fixture.plan(), fixture.run(), fixture.evaluation(), List.of(), context()));

        var missingUrls = new ResultDocumentContext(
                context().suite(), context().evaluationComponents(), context().profileSpec(), context().target(),
                Map.of(), context().caseDefinitionUrls(), List.of());
        assertThrows(IllegalArgumentException.class, () -> ResultDocumentAssembler.assemble(
                fixture.catalog(), fixture.plan(), fixture.run(), fixture.evaluation(), fixture.cases(), missingUrls));
    }

    @Test
    void compositeDigestChangesForEveryEvaluationComponent() {
        var source = context().evaluationComponents();
        var changed = new ResultDocumentContext.EvaluationComponents(
                digest('d'), source.testDefinitions(), source.specsYaml(),
                source.outcomeMappingVersion(), source.aggregationPolicyVersion());
        assertFalse(source.compositeDigest().equals(changed.compositeDigest()));
        assertThrows(IllegalArgumentException.class, () -> new ResultDocumentContext.EvaluationComponents(
                "not-a-digest", source.testDefinitions(), source.specsYaml(), "1", "1"));
    }

    private Fixture fixture() {
        var catalog = new CoverageCatalog(List.of(
                obligation("REQ.a", "REQ", Rfc2119Level.MUST, Testability.AUTOMATED, null),
                obligation("REQ.b", "REQ", Rfc2119Level.SHOULD, Testability.ATTESTED, null),
                obligation("REQ.c", "REQ", Rfc2119Level.MUST, Testability.NOT_OBSERVABLE, null),
                obligation("OTHER.a", "OTHER", Rfc2119Level.MUST, Testability.AUTOMATED, "classification")));
        var plan = plan();
        var run = new TestRun(
                "run_0123456789ABCDEFGHJKMNPQRS", plan.id(), RunStatus.COMPLETED,
                Reachability.CONFIRMED, Map.of(), NOW, NOW.plusSeconds(30));
        var cases = List.of(
                CaseRun.completed("REQ-a-idp-01", "REQ.a", CaseOutcome.of(Outcome.SATISFIED, "ok", List.of())),
                CaseRun.completed("REQ-b-idp-01", "REQ.b", CaseOutcome.of(Outcome.VIOLATED, "recommendation", List.of())));
        var exclusion = new ApplicabilityEvaluation(
                "OTHER.a", "classification", PredicateKind.CLASSIFICATION_BASED, false, null,
                ApplicabilityEvaluation.EffectiveResult.FALSE, false,
                ApplicabilityEvaluation.Basis.DECLARATION_ONLY_EXCLUSION, List.of(),
                new ApplicabilityInput.ExclusionDeclaration(
                        "Target is outside this classification", "operator", NOW));
        var definition = FunctionalCaseFixtures.forCases(
                FunctionalProfile.BROWSER_SSO_IDP, catalog,
                Map.of("REQ-a-idp-01", "REQ.a", "REQ-b-idp-01", "REQ.b",
                        "OTHER-a-idp-01", "OTHER.a"), java.util.Set.of("REQ.c"));
        var evaluation = Evaluator.evaluateFunctionalCases(
                definition, catalog, List.of(exclusion), cases, List.of());
        return new Fixture(catalog, plan, run, cases, evaluation);
    }

    private TestPlan plan() {
        return new TestPlan(
                "plan_0123456789ABCDEFGHJKMNPQRS", "Result fixture", FunctionalProfile.BROWSER_SSO_IDP,
                new TestPlan.Target(
                        TargetKind.IDP, "https://idp.example/entity",
                        new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://idp.example/metadata")),
                MetadataDeliveryKind.HTTP_URL, Map.of("single_logout", true),
                new TestPlan.Parameters(180, 300, "secret-user@example.test"),
                TestPlan.Interaction.defaults(), NOW, NOW);
    }

    private Obligation obligation(
            String key, String requirement, Rfc2119Level level, Testability testability, String condition) {
        return new Obligation(
                key, requirement, level, List.of(TargetRole.IDP), condition, testability, ProfileScope.CORE);
    }

    private ResultDocumentContext context() {
        return new ResultDocumentContext(
                new ResultDocumentContext.Suite("SAMLscope", "0.1.0", digest('a'), "self-hosted"),
                new ResultDocumentContext.EvaluationComponents(
                        digest('b'), digest('c'), digest('d'), "1", "1"),
                new ResultDocumentContext.ProfileSpec(
                        "SAML V2.0 Implementation Profile for Federation Interoperability",
                        "1.1", LocalDate.parse("2019-12-18"),
                        "Core and Full are SAMLscope test scopes, not IIP conformance classes."),
                new ResultDocumentContext.TargetDeclaration("Example IdP", "operator", digest('e')),
                Map.of("REQ", "https://example.test/spec#REQ", "OTHER", "https://example.test/spec#OTHER"),
                Map.of(
                        "REQ-a-idp-01", "https://example.test/cases/REQ-a-idp-01",
                        "REQ-b-idp-01", "https://example.test/cases/REQ-b-idp-01"),
                List.of(new ResultDocument.AdvisoryView(
                        "clock_skew.very_permissive", "REQ.a", "info", "Observed only.", false)));
    }

    private String digest(char value) {
        return "sha256:" + String.valueOf(value).repeat(64);
    }

    private record Fixture(
            CoverageCatalog catalog,
            TestPlan plan,
            TestRun run,
            List<CaseRun> cases,
            com.samlscope.core.evaluation.RunResult evaluation) {}
}
