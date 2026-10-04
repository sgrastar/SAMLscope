package com.samlscope.runner.cases;

import java.util.*;
import com.samlscope.core.evaluation.*;

/** Internal input only: the native adapter must validate originals, configuration and event correlation. */
final class NativeCertificateComparison {
    static final String VALIDITY = "IIP-MD12-b-idp-01";
    static final String CONTAINER = "IIP-MD12-d-idp-01";
    static final String RUNTIME = "IIP-MD06-a9-idp-01";
    static final Set<String> CASES = Set.of(VALIDITY, CONTAINER, RUNTIME);
    static final Set<String> ALL = Set.of("control", "certificate-expired", "certificate-not-yet-valid",
            "certificate-critical-extension", "certificate-noncritical-extension", "certificate-no-digital-signature",
            "certificate-unrelated-eku", "certificate-empty-subject", "certificate-unknown-ca");
    enum Decision { SIGNED_SUCCESS, NATIVE_SIGNATURE_REJECTION, UNOBSERVED }
    record Sample(String variant, String runId, String entityId, boolean conditionVerified,
                  boolean positiveSignatureVerified, boolean invalidControlVerified,
                  Decision positiveDecision, Decision negativeDecision, List<EvidenceRef> evidence) {
        Sample { Objects.requireNonNull(positiveDecision); Objects.requireNonNull(negativeDecision); evidence=List.copyOf(evidence); }
    }
    static CaseOutcome evaluate(String caseId, List<Sample> samples, List<String> collectionIssues) {
        if (!CASES.contains(caseId)) throw new IllegalArgumentException("Unsupported certificate case");
        var required = new HashSet<>(ALL);
        if (VALIDITY.equals(caseId)) required.retainAll(Set.of("control", "certificate-expired", "certificate-not-yet-valid"));
        // MD12.d omits expiration; MDIOP runtime interpretation explicitly includes it.
        else if (CONTAINER.equals(caseId)) required.remove("certificate-expired");
        var issues = new LinkedHashSet<>(collectionIssues);
        var variants = new HashMap<String, Sample>();
        var identities = new HashSet<List<String>>();
        var evidence = new LinkedHashSet<EvidenceRef>();
        for (var sample : samples) {
            if (!ALL.contains(sample.variant()) || variants.put(sample.variant(), sample) != null) issues.add("unexpected_or_duplicate_condition");
            if (sample.runId() == null || sample.runId().isBlank() || sample.entityId() == null || sample.entityId().isBlank()) issues.add("identity_unavailable");
            else identities.add(List.of(sample.runId(), sample.entityId()));
            if (!sample.conditionVerified()) issues.add("certificate_condition_unproven");
            if (!sample.positiveSignatureVerified() || !sample.invalidControlVerified()) issues.add("suite_signature_control_unproven");
            if (sample.negativeDecision() != Decision.NATIVE_SIGNATURE_REJECTION) issues.add("native_negative_control_unproven");
            if (sample.positiveDecision() == Decision.UNOBSERVED) issues.add("positive_decision_unobserved");
            if (sample.evidence().isEmpty()) issues.add("provenance_unavailable");
            for (var ref : sample.evidence()) if (!evidence.add(ref)) issues.add("reused_evidence");
        }
        if (identities.size() != 1) issues.add("mixed_experiment");
        if (!variants.keySet().containsAll(required)) issues.add("missing_condition");
        if (!variants.containsKey("control") || variants.get("control").positiveDecision() != Decision.SIGNED_SUCCESS) issues.add("positive_control_unproven");
        var rejected = required.stream().filter(v -> !v.equals("control") && variants.containsKey(v)
                && variants.get(v).positiveDecision() == Decision.NATIVE_SIGNATURE_REJECTION).sorted().toList();
        var outcome = !issues.isEmpty() ? Outcome.NOT_VERIFIED : rejected.isEmpty() ? Outcome.SATISFIED : Outcome.VIOLATED;
        var code = "metadata.certificate.native-" + (!issues.isEmpty() ? "evidence-incomplete" : rejected.isEmpty() ? "key-use-observed" : "valid-request-rejected");
        return new CaseOutcome(outcome, outcome == Outcome.NOT_VERIFIED ? "native_certificate_evidence_unproven" : null,
                code, code, List.copyOf(evidence), Map.of("evidence_issues", List.copyOf(issues),
                "required_variants", required.stream().sorted().toList(), "rejected_variants", rejected,
                "native_configuration_scope", "observed-client-import-and-signature-policy"));
    }
}
