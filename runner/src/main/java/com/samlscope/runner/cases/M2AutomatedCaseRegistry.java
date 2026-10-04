package com.samlscope.runner.cases;

import java.util.function.Function;
import java.util.ArrayList;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.runner.TestCaseRegistry;

/** Implemented passive subset of approved M2 AUTOMATED cases. */
public final class M2AutomatedCaseRegistry {
    private M2AutomatedCaseRegistry() {}

    public static TestCaseRegistry create(Function<String, byte[]> metadata) {
        return create(metadata, null, null, null);
    }

    public static TestCaseRegistry create(Function<String, byte[]> metadata,
            com.samlscope.core.transcript.TranscriptContentReader content,
            Function<String, byte[]> runMetadata, java.nio.file.Path rejectionDirectory) {
        var cases = new ArrayList<com.samlscope.core.caseexec.TestCase>();
        var rsaSha1Directory = rejectionDirectory == null ? null
                : rejectionDirectory.toAbsolutePath().normalize().resolveSibling("metadata-rsa-sha1-evidence");
        MetadataSignatureTestCase.approvedIds().stream()
                .map(id -> new MetadataSignatureTestCase(id, metadata, rsaSha1Directory)).forEach(cases::add);
        bind(cases, "am", MetadataConsumerObservationTestCase.Rule.PERMITTED_IDENTITY_TRANSFORM,
                content, runMetadata, rejectionDirectory);
        bind(cases, "an", MetadataConsumerObservationTestCase.Rule.EXCLUDED_CONTENT,
                content, runMetadata, rejectionDirectory);
        // The KeyInfo rule is only decidable once the target verifies the document signature, so it
        // needs the same Run-scoped evidence directory as the transform rules.
        bind(cases, "ao", MetadataConsumerObservationTestCase.Rule.OMITTED_KEY_INFO,
                content, runMetadata, rejectionDirectory);
        return new TestCaseRegistry(cases);
    }

    private static void bind(
            ArrayList<com.samlscope.core.caseexec.TestCase> cases,
            String suffix,
            MetadataConsumerObservationTestCase.Rule rule,
            com.samlscope.core.transcript.TranscriptContentReader content,
            Function<String, byte[]> runMetadata, java.nio.file.Path rejectionDirectory) {
        cases.add(new MetadataConsumerObservationTestCase(
                "IIP-MD05-" + suffix + "-idp-01", TargetRole.IDP, rule, content, runMetadata, rejectionDirectory));
        cases.add(new MetadataConsumerObservationTestCase(
                "IIP-MD05-" + suffix + "-sp-01", TargetRole.SP, rule, content, runMetadata, rejectionDirectory));
    }
}
