package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import com.samlscope.core.casedef.CaseDefinitionCatalog;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.io.TempDir;

class MetadataValidityConfigurationTestCaseTest {
    private static final String RUN = "run_0123456789ABCDEFGHJKMNPQRS";
    @TempDir Path rootDirectory;
    Path directory;

    @BeforeEach void isolatedAdapterDirectories() throws Exception {
        directory = Files.createDirectories(rootDirectory.resolve("metadata-validity-evidence"));
    }

    @Test void absentNativeOriginalsKeepConfigurationPreparation() {
        var test = implementation(ConfigurationFailureSemantics.TEST_PRECONDITION);
        assertInstanceOf(CaseStep.AwaitConfig.class, test.start(context(true)));
        assertFalse(test.evidenceStatus(context(true)).ready());
        assertTrue(test.reevaluateRecordedEvidence(context(true), pending()).isEmpty());
    }

    @Test void malformedNativeOriginalsCannotBeReplacedByADeclaration() throws Exception {
        var test = implementation(ConfigurationFailureSemantics.TEST_PRECONDITION);
        var waiting = (CaseStep.AwaitConfig) test.start(context(true));
        malformedReceipt();
        assertUnproven(test.start(context(true)));
        for (var event : List.<CaseEvent>of(new CaseEvent.ConfigConfirmed(),
                new CaseEvent.TranscriptReady(), new CaseEvent.Attested("evidence_satisfies", "the document expired"))) {
            assertUnproven(test.resume(context(true), waiting.next(), event));
        }
        assertFalse(test.evidenceStatus(context(true)).ready());
        assertTrue(test.reevaluateRecordedEvidence(context(true), pending()).isEmpty());
    }

    @Test void configurationFailureKeepsItsApprovedCapabilityMeaning() throws Exception {
        for (var semantics : ConfigurationFailureSemantics.values()) {
            var test = implementation(semantics);
            var waiting = (CaseStep.AwaitConfig) test.start(context(true));
            malformedReceipt();
            var finish = assertInstanceOf(CaseStep.Finish.class, test.resume(context(true), waiting.next(),
                    new CaseEvent.ConfigUnavailable(CaseEvent.ConfigurationIssue.CAPABILITY_ABSENT,
                            "native test configuration is unavailable")));
            assertEquals(semantics == ConfigurationFailureSemantics.NORMATIVE_CAPABILITY
                    ? Outcome.VIOLATED : Outcome.NOT_VERIFIED, finish.outcome().outcome());
            Files.delete(directory.resolve(RUN).resolve("manifest.json"));
            Files.delete(directory.resolve(RUN));
        }
    }

    @Test void incompleteHistoryAndExistingConclusionsAreNeverUpgraded() throws Exception {
        var test = implementation(ConfigurationFailureSemantics.TEST_PRECONDITION);
        malformedReceipt();
        assertUnproven(test.start(context(false)));
        assertTrue(test.reevaluateRecordedEvidence(context(false), pending()).isEmpty());
        var previous = new CaseOutcome(Outcome.SATISFIED, null, "previous", "previous", List.of(), Map.of());
        assertFalse(test.supportsRecordedEvidenceReevaluation(previous));
        assertTrue(test.reevaluateRecordedEvidence(context(true), previous).isEmpty());
    }

    @Test void malformedSimpleSamlPhpOwnerCannotFallBackToAnAttestation() throws Exception {
        var test = implementation(ConfigurationFailureSemantics.TEST_PRECONDITION);
        var waiting = (CaseStep.AwaitConfig) test.start(context(true));
        var folder = Files.createDirectories(rootDirectory.resolve("simplesamlphp-metadata-validity-evidence").resolve(RUN));
        Files.writeString(folder.resolve("manifest.json"), "{}");
        var start = assertInstanceOf(CaseStep.Finish.class, test.start(context(true)));
        assertEquals(Outcome.NOT_VERIFIED, start.outcome().outcome());
        assertEquals("metadata.validity.native-evidence-incomplete", start.outcome().reasonCode());
        var resume = assertInstanceOf(CaseStep.Finish.class, test.resume(context(true), waiting.next(),
                new CaseEvent.Attested("evidence_satisfies", "the document expired")));
        assertEquals(start.outcome(), resume.outcome());
        assertTrue(test.reevaluateRecordedEvidence(context(true), pending()).isEmpty());
    }

    @Test void competingNativeOwnersAreNotMergedIntoAConclusion() throws Exception {
        var test = implementation(ConfigurationFailureSemantics.TEST_PRECONDITION);
        malformedReceipt();
        Files.createDirectories(rootDirectory.resolve("simplesamlphp-metadata-validity-evidence").resolve(RUN));
        assertUnproven(test.start(context(true)));
        assertFalse(test.evidenceStatus(context(true)).ready());
        assertTrue(test.reevaluateRecordedEvidence(context(true), pending()).isEmpty());
    }

    @Test void productionRegistryUsesTheNativeWrapperForTheApprovedValidityCase() {
        var definition = new CaseDefinitionCatalog.CaseDefinition(
                MetadataValidityConfigurationTestCase.ID, "IIP-MD05.ar", TargetRole.IDP,
                CaseDefinitionCatalog.ExecutionMode.CONFIG, CaseDefinitionCatalog.Milestone.M2,
                List.of(), Map.of(), List.of(), List.of(), List.of(),
                "Expiry is determined from the native effective validity.", List.of(),
                new CaseDefinitionCatalog.Requirements(List.of(), "none"), false,
                ConfigurationFailureSemantics.TEST_PRECONDITION, "sha256:" + "a".repeat(64));
        var registry = ApprovedConfigCaseRegistry.create(new CaseDefinitionCatalog(List.of(definition)),
                CaseDefinitionCatalog.Milestone.M2, r -> new byte[0], e -> new byte[0], r -> Optional.empty());
        assertInstanceOf(MetadataValidityConfigurationTestCase.class, registry.find(definition.id()).orElseThrow());
    }

    private void malformedReceipt() throws Exception {
        Files.createDirectories(directory.resolve(RUN));
        Files.writeString(directory.resolve(RUN).resolve("manifest.json"), "{}");
    }

    private static void assertUnproven(CaseStep step) {
        var finish = assertInstanceOf(CaseStep.Finish.class, step);
        assertEquals(Outcome.NOT_VERIFIED, finish.outcome().outcome());
        assertEquals("metadata.validity.native-unproven", finish.outcome().reasonCode());
    }

    private static CaseOutcome pending() {
        return CaseOutcome.notVerified("case_pending_interaction", "case.pending-interaction");
    }

    private MetadataValidityConfigurationTestCase implementation(ConfigurationFailureSemantics semantics) {
        var delegate = new AttestedOutcomeTestCase(MetadataValidityConfigurationTestCase.ID,
                TargetRole.IDP, "validity.evidence", Duration.ofMinutes(1),
                List.of(AttestationOption.of("evidence_satisfies", Outcome.SATISFIED, "declaration.satisfies")));
        var fallback = new ConfigurationGateTestCase(delegate, "validity.config", Duration.ofMinutes(1), semantics);
        return new MetadataValidityConfigurationTestCase(fallback, directory, e -> new byte[0],
                r -> new byte[0], (r, v) -> Optional.empty());
    }

    private CaseContext context(boolean complete) {
        TranscriptRecorder recorder = new TranscriptRecorder() {
            public List<TranscriptEntry> list(String run) { return List.of(); }
            public TranscriptEntry record(TranscriptInput input) { throw new UnsupportedOperationException(); }
            public TranscriptEntry updateSamlAnalysis(String id, String correlation, Map<String, Object> summary) {
                throw new UnsupportedOperationException();
            }
        };
        return new DefaultCaseContext(RUN, TargetRole.IDP, Clock.systemUTC(),
                new TestPlan.Parameters(180, 300, "reference-principal"), TestPlan.Interaction.defaults(),
                Reachability.CONFIRMED, recorder, complete);
    }
}
