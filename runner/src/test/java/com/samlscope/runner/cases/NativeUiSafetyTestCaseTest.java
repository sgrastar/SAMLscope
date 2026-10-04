package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.BrowserFrontChannelScenario;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.runner.TestCaseRegistry;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class NativeUiSafetyTestCaseTest {
    private static final String RUN = "run_00000000000000000000000000";
    @TempDir Path directory;
    private DefaultCaseContext context(boolean complete) {
        return new DefaultCaseContext(RUN, TargetRole.IDP, Clock.systemUTC(),
                TestPlan.Parameters.defaults(), TestPlan.Interaction.defaults(), Reachability.CONFIRMED,
                new TranscriptRecorder() {
                    public List<TranscriptEntry> list(String run) { return List.of(); }
                    public TranscriptEntry record(TranscriptInput input) { throw new AssertionError("Read only"); }
                    public TranscriptEntry updateSamlAnalysis(String id, String correlation, Map<String,Object> summary) {
                        throw new AssertionError("Read only");
                    }
                }, complete);
    }
    private TestCase hooked() {
        var original = new IdpExecutableBrowserFixtureScenarioTestCase(NativeUiSafetyTestCase.CASE,
                run -> { throw new AssertionError("Native evidence must not dispatch a scenario"); });
        var registry = ApprovedBrowserCaseRegistry.withNativeUiUrls(new TestCaseRegistry(List.of(original)),
                e -> { throw new AssertionError("No fabricated originals"); }, run -> new byte[0], directory.resolve("ui-url-evidence"));
        return registry.require(NativeUiSafetyTestCase.CASE);
    }
    @Test void incompleteNativeProofNeverDispatchesOrCompletesAnActiveScenario() throws Exception {
        var nativeDirectory = directory.resolve("ui-url-evidence").resolve(RUN);
        Files.createDirectories(nativeDirectory);
        Files.writeString(nativeDirectory.resolve("manifest.json"), "{}");
        var test = hooked();
        assertInstanceOf(BrowserFrontChannelScenario.class, test);
        assertInstanceOf(BrowserPrompt.class, test);
        var finish = assertInstanceOf(CaseStep.Finish.class, test.start(context(true)));
        assertEquals(Outcome.NOT_VERIFIED, finish.outcome().outcome());
        var queued = assertInstanceOf(QueuedProtocolEvidenceCase.class, test);
        assertEquals(Outcome.NOT_VERIFIED, queued.queuedEvidenceOutcome(context(true)).outcome());
        assertFalse(queued.evidenceStatus(context(true)).ready());
        var recorded = assertInstanceOf(com.samlscope.runner.RecordedEvidenceReevaluation.class, test);
        assertTrue(recorded.reevaluateRecordedEvidence(context(true),
                CaseOutcome.notVerified("partial", "browser_fixture_partial")).isEmpty());
        assertTrue(recorded.reevaluateRecordedEvidence(context(false),
                CaseOutcome.notVerified("partial", "browser_fixture_partial")).isEmpty());
    }
    @Test void missingNativeProofKeepsApprovedBrowserPresentation() {
        var test = hooked();
        var scenario = assertInstanceOf(BrowserFrontChannelScenario.class, test);
        assertEquals("active-probe-chain", scenario.evidenceCampaignId());
        assertEquals(List.of("active-probe-login-1"), scenario.evidenceActionKeys());
        assertTrue(assertInstanceOf(BrowserPrompt.class, test).browserInstructionsEn().contains("correlated SAML fixtures"));
        assertFalse(assertInstanceOf(QueuedProtocolEvidenceCase.class, test).evidenceStatus(context(true)).ready());
    }
    @Test void ownedSimpleSamlPhpProofCannotFallBackToAnActiveBrowserOperation() throws Exception {
        var nativeDirectory = directory.resolve("ui-safety-evidence").resolve(RUN);
        Files.createDirectories(nativeDirectory);
        Files.writeString(nativeDirectory.resolve("manifest.json"), "{}");
        var finish = assertInstanceOf(CaseStep.Finish.class, hooked().start(context(true)));
        assertEquals(Outcome.NOT_VERIFIED, finish.outcome().outcome());
        assertFalse(assertInstanceOf(QueuedProtocolEvidenceCase.class, hooked()).evidenceStatus(context(true)).ready());
    }
    @Test void twoProductReceiptsForOneRunAreAmbiguous() throws Exception {
        var shibbolethDirectory = directory.resolve("ui-url-evidence").resolve(RUN);
        Files.createDirectories(shibbolethDirectory);
        Files.writeString(shibbolethDirectory.resolve("manifest.json"), "{}");
        var nativeDirectory = directory.resolve("ui-safety-evidence").resolve(RUN);
        Files.createDirectories(nativeDirectory);
        Files.writeString(nativeDirectory.resolve("manifest.json"), "{}");
        var finish = assertInstanceOf(CaseStep.Finish.class, hooked().start(context(true)));
        assertEquals(Outcome.NOT_VERIFIED, finish.outcome().outcome());
        assertEquals("browser.ui-safety.evidence-incomplete", finish.outcome().reasonCode());
    }

    @Test void ownedKeycloakProofCannotDispatchAReplacementBrowserOperation() throws Exception {
        var nativeDirectory = directory.resolve("ui-native-feature-absence");
        Files.createDirectories(nativeDirectory);
        Files.writeString(nativeDirectory.resolve(RUN + ".keycloak-ui-safety.json"), "{}");
        var test = hooked();
        var finish = assertInstanceOf(CaseStep.Finish.class, test.start(context(true)));
        assertEquals(Outcome.NOT_VERIFIED, finish.outcome().outcome());
        var queued = assertInstanceOf(QueuedProtocolEvidenceCase.class, test);
        assertFalse(queued.evidenceStatus(context(true)).ready());
        assertTrue(assertInstanceOf(com.samlscope.runner.RecordedEvidenceReevaluation.class, test)
                .reevaluateRecordedEvidence(context(true), CaseOutcome.notVerified("partial", "browser_fixture_partial"))
                .isEmpty());
    }

    @Test void keycloakProofCannotBeCombinedWithAnotherProductReceipt() throws Exception {
        var keycloakDirectory = directory.resolve("ui-native-feature-absence");
        Files.createDirectories(keycloakDirectory);
        Files.writeString(keycloakDirectory.resolve(RUN + ".keycloak-ui-safety.json"), "{}");
        var shibbolethDirectory = directory.resolve("ui-url-evidence").resolve(RUN);
        Files.createDirectories(shibbolethDirectory);
        Files.writeString(shibbolethDirectory.resolve("manifest.json"), "{}");
        var finish = assertInstanceOf(CaseStep.Finish.class, hooked().start(context(true)));
        assertEquals(Outcome.NOT_VERIFIED, finish.outcome().outcome());
        assertEquals("browser.ui-safety.evidence-incomplete", finish.outcome().reasonCode());
    }
}
