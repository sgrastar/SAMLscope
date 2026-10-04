package com.samlscope.runner.cases;

import java.util.Map;
import java.util.LinkedHashMap;
import java.util.Objects;
import java.nio.file.Path;
import java.util.function.Function;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseState;
import com.samlscope.core.caseexec.CaseStep;
import com.samlscope.core.caseexec.TestCase;
import com.samlscope.core.plan.TargetRole;

/** Executable wrapper for one approved role-specific metadata-signature rule. */
public final class MetadataSignatureTestCase implements TestCase {
    private static final Map<String, MetadataSignatureProfileCase.Rule> RULES = rules();
    private final String id;
    private final Function<String, byte[]> metadata;
    private final MetadataRsaSha1CapabilityEvidenceFile rsaSha1Evidence;

    public MetadataSignatureTestCase(String id, Function<String, byte[]> metadata) {
        this(id, metadata, (Path) null);
    }

    public MetadataSignatureTestCase(String id, Function<String, byte[]> metadata, Path rsaSha1EvidenceDirectory) {
        this(id, metadata, new MetadataRsaSha1CapabilityEvidenceFile(rsaSha1EvidenceDirectory));
    }

    MetadataSignatureTestCase(String id, Function<String, byte[]> metadata,
            MetadataRsaSha1CapabilityEvidenceFile rsaSha1Evidence) {
        if (!RULES.containsKey(id)) throw new IllegalArgumentException("Unapproved metadata signature case: " + id);
        this.id = id;
        this.metadata = Objects.requireNonNull(metadata, "metadata");
        this.rsaSha1Evidence = Objects.requireNonNull(rsaSha1Evidence, "rsaSha1Evidence");
    }

    @Override public String id() { return id; }
    @Override public TargetRole role() { return id.contains("-idp-") ? TargetRole.IDP : TargetRole.SP; }
    @Override public CaseStep start(CaseContext context) {
        var targetMetadata = metadata.apply(context.runId());
        var passive = new MetadataSignatureProfileCase(RULES.get(id)).evaluate(targetMetadata);
        if (!MetadataRsaSha1CapabilityEvidenceFile.CASE_ID.equals(id)
                || passive.outcome() != com.samlscope.core.evaluation.Outcome.SATISFIED) {
            return new CaseStep.Finish(passive);
        }
        var proof = rsaSha1Evidence.read(context, targetMetadata);
        if (proof.isEmpty()) {
            return new CaseStep.Finish(com.samlscope.core.evaluation.CaseOutcome.notVerified(
                    "rsa_sha1_verification_unproven", "metadata.rsa-sha1.verification-unproven"));
        }
        var details = new LinkedHashMap<String, Object>(passive.details());
        details.put("native_receipt_sha256", proof.get().receiptSha256());
        details.put("signing_certificate_sha256", proof.get().signingCertificateSha256());
        details.put("product_version", proof.get().productVersion());
        details.put("producer_variant_proven", true);
        details.put("verifier_variant_proven", true);
        return new CaseStep.Finish(new com.samlscope.core.evaluation.CaseOutcome(
                com.samlscope.core.evaluation.Outcome.SATISFIED, null,
                "metadata.rsa-sha1.observed", "metadata.rsa-sha1.observed",
                passive.evidence(), details));
    }
    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        throw new IllegalStateException("Metadata signature cases finish during start");
    }

    public static java.util.Set<String> approvedIds() { return RULES.keySet(); }

    private static Map<String, MetadataSignatureProfileCase.Rule> rules() {
        var result = new java.util.LinkedHashMap<String, MetadataSignatureProfileCase.Rule>();
        bind(result, "ag", MetadataSignatureProfileCase.Rule.ENVELOPED);
        bind(result, "ah", MetadataSignatureProfileCase.Rule.RSA_SHA1);
        bind(result, "ai", MetadataSignatureProfileCase.Rule.SIGNED_ELEMENT_ID);
        bind(result, "aj", MetadataSignatureProfileCase.Rule.SINGLE_ROOT_REFERENCE);
        bind(result, "ak", MetadataSignatureProfileCase.Rule.EXCLUSIVE_C14N);
        bind(result, "al", MetadataSignatureProfileCase.Rule.ALLOWED_TRANSFORMS);
        return Map.copyOf(result);
    }

    private static void bind(
            Map<String, MetadataSignatureProfileCase.Rule> result,
            String suffix,
            MetadataSignatureProfileCase.Rule rule) {
        result.put("IIP-MD05-" + suffix + "-idp-01", rule);
        result.put("IIP-MD05-" + suffix + "-sp-01", rule);
    }
}
