package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;

import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.runner.EvidenceCampaignCase;
import com.samlscope.runner.RecordedEvidenceReevaluation;
import com.samlscope.runner.RunCampaignQuery;
import java.nio.file.*;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class NativeMetadataTrustRegistryTest {
    private static final String RUN = SelfContainedMetadataTrustEvidenceTestCaseTest.RUN;
    @TempDir Path directory;

    private TestCase hooked() {
        return ApprovedAttestedCaseRegistry.withNativeMetadataTrust(
                SelfContainedMetadataTrustEvidenceTestCaseTest.fallback(), directory,
                entry -> { throw new AssertionError("Ambiguous or missing originals must not be consumed"); },
                run -> new byte[0]);
    }

    private void receipt(String product) throws Exception {
        var folder = directory.resolve(product.equals("keycloak")
                ? "metadata-rejection-evidence" : "metadata-trust-evidence");
        Files.createDirectories(folder);
        var suffix = switch (product) {
            case "keycloak" -> ".native-trust.json";
            case "simplesamlphp" -> ".simplesamlphp-trust.json";
            case "shibboleth" -> ".shibboleth-trust.json";
            default -> throw new IllegalArgumentException(product);
        };
        Files.writeString(folder.resolve(RUN + suffix), "{}");
    }

    @Test void noNativeOriginalsRetainsApprovedAttestationWithoutNewActions() {
        var test = hooked();
        var context = SelfContainedMetadataTrustEvidenceTestCaseTest.context(true);
        var fallback = SelfContainedMetadataTrustEvidenceTestCaseTest.fallback();
        assertEquals(fallback.start(context), test.start(context));
        assertEquals(fallback.options(), assertInstanceOf(AttestationPrompt.class, test).options());
        var campaign = assertInstanceOf(EvidenceCampaignCase.class, test);
        assertEquals(RunCampaignQuery.ActionKind.NONE, campaign.evidenceActionKind());
        assertTrue(campaign.evidenceActionKeys().isEmpty());
    }

    @Test void invalidOwnedShibbolethOriginalsCannotBecomeAnAttestation() throws Exception {
        receipt("shibboleth");
        var test = hooked();
        var context = SelfContainedMetadataTrustEvidenceTestCaseTest.context(true);
        assertEquals(Outcome.NOT_VERIFIED, assertInstanceOf(CaseStep.Finish.class, test.start(context))
                .outcome().outcome());
        assertEquals(Outcome.NOT_VERIFIED, assertInstanceOf(CaseStep.Finish.class,
                test.resume(context, null, new CaseEvent.Attested("satisfied", ""))).outcome().outcome());
        assertFalse(assertInstanceOf(ProtocolEvidenceCase.class, test).evidenceStatus(context).ready());
        assertTrue(assertInstanceOf(RecordedEvidenceReevaluation.class, test)
                .reevaluateRecordedEvidence(context, CaseOutcome.notVerified("before", "before")).isEmpty());
    }

    @Test void everyPairOfNativeProductReceiptsIsRejectedAsAmbiguous() throws Exception {
        for (var pair : List.of(List.of("keycloak", "simplesamlphp"),
                List.of("keycloak", "shibboleth"), List.of("simplesamlphp", "shibboleth"))) {
            try (var files = Files.walk(directory)) {
                for (var path : files.filter(Files::isRegularFile).toList()) Files.delete(path);
            }
            for (var product : pair) receipt(product);
            var test = hooked();
            var context = SelfContainedMetadataTrustEvidenceTestCaseTest.context(true);
            var result = assertInstanceOf(CaseStep.Finish.class, test.start(context)).outcome();
            assertEquals(Outcome.NOT_VERIFIED, result.outcome(), pair.toString());
            assertEquals("native_metadata_trust_ambiguous", result.notVerifiedReason(), pair.toString());
            assertFalse(assertInstanceOf(ProtocolEvidenceCase.class, test).evidenceStatus(context).ready());
        }
    }
}
