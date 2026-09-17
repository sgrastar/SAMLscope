package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;

class MetadataSnapshotResumeTest {
    @Test void upgradedOracleReusesSnapshotButDoesNotOverrideUnavailableAnswer() {
        var recorder = new TranscriptRecorder() {
            public TranscriptEntry record(TranscriptInput input) { throw new UnsupportedOperationException(); }
            public TranscriptEntry updateSamlAnalysis(String id, String c, Map<String,Object> s) { throw new UnsupportedOperationException(); }
            public List<TranscriptEntry> list(String run) { return List.of(); }
        };
        var context = new DefaultCaseContext("run_0123456789ABCDEFGHJKMNPQRS", TargetRole.IDP, Clock.systemUTC(),
                TestPlan.Parameters.defaults(), TestPlan.Interaction.defaults(), Reachability.CONFIRMED, recorder, true);
        var fallback = new ConfigurationGateTestCase(new AttestedOutcomeTestCase("IIP-MD05-e5-idp-01", TargetRole.IDP,
                "evidence", "Review", Duration.ofHours(1), List.of(AttestationOption.notVerified("unknown", "unknown", "unknown"))),
                "config", "Prepare", Duration.ofHours(1), ConfigurationFailureSemantics.TEST_PRECONDITION);
        var state = assertInstanceOf(CaseStep.AwaitConfig.class, fallback.start(context)).next();
        var bytes = """
                <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="urn:test">
                  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/>
                </md:EntityDescriptor>
                """.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        var test = new AutoConfigurationEvidenceTestCase(fallback, ignored -> bytes);
        var outcome = assertInstanceOf(CaseStep.Finish.class, test.resume(context, state, new CaseEvent.ConfigConfirmed())).outcome();
        assertEquals(Outcome.SATISFIED, outcome.outcome());
        assertEquals("target-metadata", outcome.evidence().getFirst().kind());
        var unavailable = assertInstanceOf(CaseStep.Finish.class, test.resume(context, state,
                new CaseEvent.ConfigUnavailable(CaseEvent.ConfigurationIssue.TARGET_CONFIG_UNAVAILABLE, ""))).outcome();
        assertEquals(Outcome.NOT_VERIFIED, unavailable.outcome());
        var missing = new AutoConfigurationEvidenceTestCase(fallback, ignored -> null);
        assertFalse(missing.resume(context, state, new CaseEvent.ConfigConfirmed()) instanceof CaseStep.Finish finish
                && finish.outcome().outcome() == Outcome.SATISFIED);
    }
}
