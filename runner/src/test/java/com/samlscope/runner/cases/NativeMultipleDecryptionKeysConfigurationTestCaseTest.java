package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.runner.*;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class NativeMultipleDecryptionKeysConfigurationTestCaseTest {
    @TempDir Path directory;
    private final CaseContext context = SelfContainedMetadataTrustEvidenceTestCaseTest.context(true);

    private static final class LegacyProof implements TestCase, ConfigurationPrompt, AttestationPrompt,
            ProtocolEvidenceCase, FallbackEvidenceCase, RecordedEvidenceReevaluation {
        final CaseOutcome legacy = new CaseOutcome(Outcome.SATISFIED, null, "legacy-proof", "legacy-proof", List.of(), Map.of());
        public String id() { return SimpleSamlPhpMultipleDecryptionKeysEvidence.CASE; }
        public TargetRole role() { return TargetRole.IDP; }
        public String instructionEn() { return "Configure the approved capability"; }
        public String promptEn() { return "Check the approved capability"; }
        public List<AttestationOption> options() { return List.of(AttestationOption.of("satisfied", Outcome.SATISFIED, "manual-proof")); }
        public CaseStep start(CaseContext c) { return new CaseStep.Finish(legacy); }
        public CaseStep resume(CaseContext c, CaseState s, CaseEvent e) { return start(c); }
        public EvidenceStatus evidenceStatus(CaseContext c) { return new EvidenceStatus(true, List.of("legacy"), List.of("legacy"), Map.of()); }
        public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous) { return previous.outcome() == Outcome.NOT_VERIFIED; }
        public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext c, CaseOutcome previous) { return Optional.of(legacy); }
        public boolean resolvedFromExternalEvidence(CaseExecution e) { return e != null && legacy.equals(e.outcome()); }
    }
    private NativeConfigurationSourceRunTestCase test(LegacyProof fallback) {
        return (NativeConfigurationSourceRunTestCase) ApprovedConfigCaseRegistry.withNativeMultipleDecryptionKeys(
                fallback, directory, entry -> { throw new AssertionError("Missing originals must not be read"); }, run -> new byte[0]);
    }
    private CaseExecution saved(CaseOutcome outcome) {
        return new CaseExecution(context.runId(), SimpleSamlPhpMultipleDecryptionKeysEvidence.CASE, 1,
                CaseExecutionStatus.FINISHED, new CaseState("finished", Map.of()), null, outcome, Instant.EPOCH);
    }
    @Test void absentOwnProofPreservesExistingIndependentProtocolProofAndPrompts() {
        var fallback = new LegacyProof(); var t = test(fallback);
        assertEquals(fallback.start(context), t.start(context));
        assertEquals(fallback.options(), t.options()); assertEquals(fallback.instructionEn(), t.instructionEn());
        assertEquals(fallback.evidenceStatus(context), t.evidenceStatus(context));
        assertEquals(fallback.legacy, t.reevaluateRecordedEvidence(context, CaseOutcome.notVerified("before", "before")).orElseThrow());
        assertTrue(t.resolvedFromExternalEvidence(saved(fallback.legacy)));
        assertEquals(RunCampaignQuery.EvidenceClass.PROTOCOL_OBSERVED, t.evidenceClass(saved(fallback.legacy)));
        assertEquals(RunCampaignQuery.ActionKind.NONE, t.evidenceActionKind(saved(fallback.legacy)));
        assertFalse(BrowserFrontChannelScenario.class.isInstance(t));
    }
    @Test void existingNativeWrapperGetsOneSourceWrapperAndRepeatedDecorationPreservesIdentity() {
        var fallback=new LegacyProof();
        var sameRun=new NativeMultipleDecryptionKeysConfigurationTestCase(fallback,
                new SimpleSamlPhpMultipleDecryptionKeysEvidence(directory.resolve("multiple-decryption-keys-evidence"),
                        entry->{throw new AssertionError();},run->new byte[0],
                        new DefaultAlgorithmSourceRunStore(directory,SimpleSamlPhpMultipleDecryptionKeysEvidence.CASE,SimpleSamlPhpMultipleDecryptionKeysEvidence.DIGEST)));
        var first=ApprovedConfigCaseRegistry.withNativeMultipleDecryptionKeys(sameRun,directory,null,null);
        assertInstanceOf(NativeConfigurationSourceRunTestCase.class,first);
        assertSame(first,ApprovedConfigCaseRegistry.withNativeMultipleDecryptionKeys(first,directory,null,null));
        var decorated=ApprovedConfigCaseRegistry.withMultipleDecryptionKeys(new TestCaseRegistry(List.of(sameRun)),
                run->{throw new AssertionError("Missing native proof must not construct supplemental keys");},(run,id)->Optional.empty());
        var outer=assertInstanceOf(NativeConfigurationSourceRunTestCase.class,decorated.require(fallback.id()));
        assertEquals(fallback.start(context),outer.start(context));
        assertEquals(sameRun.evidenceCampaignId(),outer.evidenceCampaignId());
        assertSame(outer,ApprovedConfigCaseRegistry.withMultipleDecryptionKeys(decorated,
                run->{throw new AssertionError("Repeated decoration must not construct keys");},(run,id)->Optional.empty()).require(fallback.id()));
    }
    @Test void malformedOwnedProofCannotBorrowSuccessOrOfferAnotherHumanAction() throws Exception {
        var fallback = new LegacyProof(); var t = test(fallback);
        var receipt = directory.resolve("multiple-decryption-keys-evidence")
                .resolve(context.runId() + SimpleSamlPhpMultipleDecryptionKeysEvidence.SUFFIX);
        Files.createDirectories(receipt); Files.writeString(receipt.resolve("manifest.json"), "{\"schema\":\"wrong\",\"success\":true}");
        var finished = assertInstanceOf(CaseStep.Finish.class, t.start(context));
        assertEquals(Outcome.NOT_VERIFIED, finished.outcome().outcome());
        assertFalse(t.evidenceStatus(context).ready());
        assertTrue(t.reevaluateRecordedEvidence(context, CaseOutcome.notVerified("before", "before")).isEmpty());
        assertFalse(t.resolvedFromExternalEvidence(saved(fallback.legacy)));
        assertEquals(RunCampaignQuery.ActionKind.NONE, t.evidenceActionKind(saved(finished.outcome())));
        assertEquals(RunCampaignQuery.EvidenceClass.OPERATOR_ASSISTED, t.evidenceClass(saved(finished.outcome())));
    }
    @Test void nativeProvenanceRequiresExactRunAdapterDigestAndReference() {
        var t = test(new LegacyProof());
        var fields = new LinkedHashMap<String, Object>();
        fields.put("evidence_adapter", SimpleSamlPhpMultipleDecryptionKeysEvidence.SCHEMA);
        fields.put("run_id", context.runId()); fields.put("case_digest", SimpleSamlPhpMultipleDecryptionKeysEvidence.DIGEST);
        var ref = new EvidenceRef("native-multiple-decryption-keys", context.runId() + SimpleSamlPhpMultipleDecryptionKeysEvidence.SUFFIX + "/manifest.json");
        var outcome = new CaseOutcome(Outcome.SATISFIED, null, SimpleSamlPhpMultipleDecryptionKeysEvidence.REASON,
                SimpleSamlPhpMultipleDecryptionKeysEvidence.REASON, List.of(ref), fields);
        assertTrue(t.resolvedFromExternalEvidence(saved(outcome)));
        assertEquals(RunCampaignQuery.EvidenceClass.OPERATOR_ASSISTED, t.evidenceClass(saved(outcome)));
        for (String field : fields.keySet()) {
            var altered = new LinkedHashMap<>(fields); altered.put(field, "unrelated");
            var wrong = new CaseOutcome(Outcome.SATISFIED, null, outcome.reasonCode(), outcome.reasonMessageKey(), List.of(ref), altered);
            assertFalse(t.resolvedFromExternalEvidence(saved(wrong)));
        }
        var wrongRef = new CaseOutcome(Outcome.SATISFIED, null, outcome.reasonCode(), outcome.reasonMessageKey(),
                List.of(new EvidenceRef(ref.kind(), "unrelated/manifest.json")), fields);
        assertFalse(t.resolvedFromExternalEvidence(saved(wrongRef)));
    }
}
