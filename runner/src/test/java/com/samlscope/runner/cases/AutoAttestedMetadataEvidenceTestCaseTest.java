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

class AutoAttestedMetadataEvidenceTestCaseTest {
    private static final String CASE_ID = "IIP-MD09-a-idp-01";

    @Test
    void finishesFromPublishedAlgorithmCapabilitiesWithoutOpeningQuestionnaire() {
        var testCase = new AutoAttestedMetadataEvidenceTestCase(
                fallback(), ignored -> metadata(true));

        var finish = assertInstanceOf(CaseStep.Finish.class, testCase.start(context()));
        assertEquals(Outcome.SATISFIED, finish.outcome().outcome());
        assertEquals("target-metadata", finish.outcome().evidence().getFirst().kind());
    }

    @Test
    void retainsApprovedAttestationWhenMetadataDoesNotProveBothCapabilities() {
        var testCase = new AutoAttestedMetadataEvidenceTestCase(
                fallback(), ignored -> metadata(false));

        assertInstanceOf(CaseStep.AwaitAttestation.class, testCase.start(context()));
    }

    private AttestedOutcomeTestCase fallback() {
        return new AttestedOutcomeTestCase(
                CASE_ID, TargetRole.IDP, "case.md09.attestation", "Review capability evidence.",
                Duration.ofDays(7),
                List.of(AttestationOption.of("satisfied", Outcome.SATISFIED, "attestation.satisfied")));
    }

    private byte[] metadata(boolean includeEncryption) {
        return ("""
                <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                  xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport"
                  entityID="https://idp.example/entity">
                  <md:Extensions>
                    <alg:SigningMethod Algorithm="urn:example:signature"/>
                    %s
                  </md:Extensions>
                </md:EntityDescriptor>
                """).formatted(includeEncryption
                        ? "<alg:EncryptionMethod Algorithm=\"urn:example:encryption\"/>" : "")
                .getBytes(StandardCharsets.UTF_8);
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
