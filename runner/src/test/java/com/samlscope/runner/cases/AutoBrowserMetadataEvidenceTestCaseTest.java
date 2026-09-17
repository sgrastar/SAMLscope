package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.Test;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.CaseStep;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.TargetRole;

class AutoBrowserMetadataEvidenceTestCaseTest {
    @Test
    void registryConnectsPublishedNotesAndPreservesBrowserFallback() {
        for (var suffix : List.of("f7", "f8", "fa")) {
            var id = "IIP-MD05-" + suffix + "-idp-01";
            var unavailableRegistry = new com.samlscope.runner.TestCaseRegistry(List.of(new UnavailableBrowserOracleTestCase(id, TargetRole.IDP)));
            ApprovedBrowserCaseRegistry.withPublishedMetadata(unavailableRegistry, ignored -> null, ignored -> java.util.Optional.empty());
            var evidence = new AttestedOutcomeTestCase(id, TargetRole.IDP, "test", "Review evidence.", Duration.ofDays(7),
                    List.of(AttestationOption.of("satisfied", Outcome.SATISFIED, "attestation.satisfied")));
            var fallback = new BrowserEvidenceTestCase(evidence, java.net.URI.create("https://suite.example"), "Inspect UI.", Duration.ofDays(7));
            var registry = new com.samlscope.runner.TestCaseRegistry(List.of(fallback));
            byte[] metadata = ("<EntityDescriptor xmlns='urn:oasis:names:tc:SAML:2.0:metadata' entityID='https://idp.example'>"
                    + "<IDPSSODescriptor protocolSupportEnumeration='urn:oasis:names:tc:SAML:2.0:protocol'/></EntityDescriptor>").getBytes(StandardCharsets.UTF_8);
            var connected = ApprovedBrowserCaseRegistry.withPublishedMetadata(registry, ignored -> metadata, ignored -> java.util.Optional.of("https://idp.example")).all().iterator().next();
            var finish = assertInstanceOf(CaseStep.Finish.class, connected.start(context()));
            assertEquals(Outcome.SATISFIED_WITH_NOTE, finish.outcome().outcome());
            var wrongTarget = ApprovedBrowserCaseRegistry.withPublishedMetadata(registry, ignored -> metadata, ignored -> java.util.Optional.of("https://other.example")).all().iterator().next();
            assertInstanceOf(CaseStep.AwaitBrowser.class, wrongTarget.start(context()));
            var unavailable = ApprovedBrowserCaseRegistry.withPublishedMetadata(registry, ignored -> null, ignored -> java.util.Optional.of("https://idp.example")).all().iterator().next();
            assertInstanceOf(CaseStep.AwaitBrowser.class, unavailable.start(context()));
        }
    }

    private CaseContext context() {
        return new CaseContext() {
            @Override public String runId() { return "run"; }
            @Override public TargetRole targetRole() { return TargetRole.IDP; }
            @Override public Clock clock() {
                return Clock.fixed(Instant.parse("2026-08-31T00:00:00Z"), ZoneOffset.UTC);
            }
            @Override public com.samlscope.core.plan.TestPlan.Parameters parameters() {
                return com.samlscope.core.plan.TestPlan.Parameters.defaults();
            }
            @Override public com.samlscope.core.plan.TestPlan.Interaction interaction() {
                return new com.samlscope.core.plan.TestPlan.Interaction(
                        true, true,
                        com.samlscope.core.plan.TestPlan.ExecutionPreset.assisted_with_attestation);
            }
            @Override public com.samlscope.core.run.Reachability reachability() {
                return com.samlscope.core.run.Reachability.CONFIRMED;
            }
            @Override public com.samlscope.core.transcript.TranscriptRecorder transcript() { return null; }
            @Override public boolean transcriptComplete() { return true; }
        };
    }
}
