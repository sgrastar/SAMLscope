package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;

import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.runner.ExternallyObservedCase;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Product ownership cannot be bypassed through a second generic receipt or a completion event. */
class KeycloakNativeUiConsumerWiringTest {
    private static final String RUN = "run_00000000000000000000000000";
    @TempDir Path root;

    private Path generic() throws Exception { return Files.createDirectories(root.resolve("ui-browser")); }
    private Path keycloak() throws Exception {
        return Files.createDirectories(root.resolve("ui-native-feature-absence"))
                .resolve(RUN + ".keycloak-ui-consumer.json");
    }
    private DefaultCaseContext context(boolean complete) {
        return new DefaultCaseContext(RUN, TargetRole.IDP, Clock.systemUTC(),
                TestPlan.Parameters.defaults(), TestPlan.Interaction.defaults(), Reachability.CONFIRMED,
                new TranscriptRecorder() {
                    public List<TranscriptEntry> list(String run) { assertEquals(RUN, run); return List.of(); }
                    public TranscriptEntry record(TranscriptInput input) { throw new AssertionError("Read only observer"); }
                    public TranscriptEntry updateSamlAnalysis(String id, String correlation, Map<String,Object> summary) {
                        throw new AssertionError("Observer changed recorded history");
                    }
                }, complete);
    }
    private UiLogoBrowserEvidenceTestCase logo(Path directory) {
        return new UiLogoBrowserEvidenceTestCase(e -> { throw new AssertionError("No decoded originals exist"); },
                run -> new byte[] {1}, directory);
    }
    private UiUrlBrowserEvidenceTestCase urls(Path directory) {
        return new UiUrlBrowserEvidenceTestCase(e -> { throw new AssertionError("No decoded originals exist"); },
                run -> new byte[] {1}, directory);
    }
    private void ownedInvalidCannotFallBack() throws Exception {
        var directory = generic();
        // This deliberately invalid proposed conclusion would be read by a generic fallback.
        Files.writeString(directory.resolve(RUN + ".json"), "{\"outcome\":\"SATISFIED\"}");
        for (var value : List.of(logo(directory).queuedEvidenceOutcome(context(true)),
                urls(directory).queuedEvidenceOutcome(context(true)))) {
            assertEquals(Outcome.NOT_VERIFIED, value.outcome());
            assertEquals("browser.ui-native-consumer.evidence-incomplete", value.reasonCode());
            assertEquals(Map.of("evidence_issue", "receipt"), value.details());
            assertTrue(value.evidence().isEmpty());
        }
    }
    @Test void noOwnedReceiptRetainsEachGenericContract() throws Exception {
        var directory = generic();
        assertEquals(UiLogoComparison.evaluate(List.of(), List.of()), logo(directory).queuedEvidenceOutcome(context(true)));
        assertEquals(UiUrlComparison.evaluate(List.of(), List.of("native_receipt_unavailable")),
                urls(directory).queuedEvidenceOutcome(context(true)));
    }
    @Test void malformedOwnedReceiptCannotFallBack() throws Exception {
        Files.writeString(keycloak(), "{}"); ownedInvalidCannotFallBack();
    }
    @Test void directoryOwnedReceiptCannotFallBack() throws Exception {
        Files.createDirectory(keycloak()); ownedInvalidCannotFallBack();
    }
    @Test void symlinkOwnedReceiptCannotFallBack() throws Exception {
        var external = root.resolve("external.json"); Files.writeString(external, "{}");
        Files.createSymbolicLink(keycloak(), external); ownedInvalidCannotFallBack();
    }
    @Test void keycloakAndSimpleSamlPhpOwnershipCannotSelectOneLogoProduct() throws Exception {
        Files.writeString(keycloak(), "{}"); var directory = generic(); Files.createDirectory(directory.resolve(RUN));
        var value = logo(directory).queuedEvidenceOutcome(context(true));
        assertEquals(UiLogoComparison.evaluate(List.of(), List.of("native_browser_evidence_unproven")), value);
        assertFalse(logo(directory).evidenceStatus(context(true)).ready());
    }
    @Test void keycloakAndShibbolethOwnershipCannotSelectOneUrlProduct() throws Exception {
        Files.writeString(keycloak(), "{}"); var directory = generic(); Files.createDirectory(directory.resolve(RUN));
        var value = urls(directory).queuedEvidenceOutcome(context(true));
        assertEquals(UiUrlComparison.evaluate(List.of(), List.of("native_ui_url_evidence_unproven")), value);
        assertFalse(urls(directory).evidenceStatus(context(true)).ready());
    }
    @Test void queuedStartResumeAndRecordedPathsRemainReadOnlyAndDoNotCreateAttestations() throws Exception {
        Files.writeString(keycloak(), "{}"); var directory = generic();
        var logo = logo(directory); var urls = urls(directory);
        assertInstanceOf(ExternallyObservedCase.class, logo); assertInstanceOf(ExternallyObservedCase.class, urls);
        assertEquals(TargetRole.IDP, logo.role()); assertEquals(TargetRole.IDP, urls.role());
        assertEquals(2, logo.evidenceActionKeys().size()); assertEquals(15, new HashSet<>(urls.evidenceActionKeys()).size());
        var logoValue = logo.queuedEvidenceOutcome(context(true)); var urlValue = urls.queuedEvidenceOutcome(context(true));
        assertEquals(logoValue, ((CaseStep.Finish) logo.start(context(true))).outcome());
        assertEquals(urlValue, ((CaseStep.Finish) urls.start(context(true))).outcome());
        var event = new CaseEvent.TranscriptReady();
        assertEquals(logoValue, ((CaseStep.Finish) logo.resume(context(true), null, event)).outcome());
        assertEquals(urlValue, ((CaseStep.Finish) urls.resume(context(true), null, event)).outcome());
        assertFalse(logo.evidenceStatus(context(true)).ready()); assertFalse(urls.evidenceStatus(context(true)).ready());
        var previous = CaseOutcome.notVerified("not_measured", "browser.oracle-unavailable");
        assertTrue(logo.supportsRecordedEvidenceReevaluation(previous)); assertTrue(urls.supportsRecordedEvidenceReevaluation(previous));
        assertTrue(logo.reevaluateRecordedEvidence(context(true), previous).isEmpty());
        assertTrue(urls.reevaluateRecordedEvidence(context(true), previous).isEmpty());
        assertTrue(logo.reevaluateRecordedEvidence(context(false), previous).isEmpty());
        assertTrue(urls.reevaluateRecordedEvidence(context(false), previous).isEmpty());
        var satisfied = CaseOutcome.of(Outcome.SATISFIED, "already_measured", List.of());
        assertTrue(logo.reevaluateRecordedEvidence(context(true), satisfied).isEmpty());
        assertTrue(urls.reevaluateRecordedEvidence(context(true), satisfied).isEmpty());
    }
}
