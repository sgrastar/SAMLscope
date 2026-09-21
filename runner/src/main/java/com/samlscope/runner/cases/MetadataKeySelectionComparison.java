package com.samlscope.runner.cases;

import java.util.*;
import com.samlscope.core.evaluation.*;

/** Trusted adapter input, never caller assertions: originals and native decisions must be verified first. */
final class MetadataKeySelectionComparison {
    static final String CASE_ID = "IIP-MD07-b-idp-01";
    static final String FIRST = "multiple-signing-keys-first";
    static final String SECOND = "multiple-signing-keys";
    static final String UNADVERTISED = "multiple-signing-keys-unadvertised";
    static final Set<String> REQUIRED = Set.of(FIRST, SECOND, UNADVERTISED);
    static final String ANY_PURPOSE = "IIP-MD05-ad-idp-01";
    static final String KEY_COUNT = "IIP-MD07-a-idp-01";
    static final String REPRESENTATION = "IIP-MD06-a7-idp-01";
    static final String PUBLIC_KEY = "IIP-MD06-a8-idp-01";
    static final String SAME_KEY = "certificate-runtime-same-key", OTHER_KEY = "certificate-runtime-other-key";
    static final Set<String> CASES = Set.of(CASE_ID, ANY_PURPOSE, KEY_COUNT, REPRESENTATION, PUBLIC_KEY);
    record Condition(String family, int count, int signerIndex, boolean omittedUse) {}
    static final Map<String, Condition> CONDITIONS = Map.ofEntries(
            Map.entry("entity-root",new Condition("single",1,0,false)),
            Map.entry("keyvalue-only",new Condition("single",1,0,true)),
            Map.entry(SAME_KEY,new Condition("single",1,0,false)),
            Map.entry(OTHER_KEY,new Condition("single",1,-1,false)),
            Map.entry(FIRST,new Condition("pair",2,0,false)),
            Map.entry(SECOND,new Condition("pair",2,1,false)),
            Map.entry(UNADVERTISED,new Condition("pair",2,-1,false)),
            Map.entry("multiple-omitted-keys-first",new Condition("omitted",2,0,true)),
            Map.entry("multiple-omitted-keys-second",new Condition("omitted",2,1,true)),
            Map.entry("three-signing-keys-first",new Condition("triple",3,0,false)),
            Map.entry("three-signing-keys-second",new Condition("triple",3,1,false)),
            Map.entry("three-signing-keys",new Condition("triple",3,2,false)));
    static Set<String> required(String caseId) {
        return switch (caseId) {
            case CASE_ID -> REQUIRED;
            case ANY_PURPOSE -> Set.of("entity-root",FIRST,SECOND,"multiple-omitted-keys-first","multiple-omitted-keys-second");
            case PUBLIC_KEY -> Set.of("entity-root",SAME_KEY,OTHER_KEY);
            case REPRESENTATION -> Set.of("entity-root","keyvalue-only");
            case KEY_COUNT -> Set.of("entity-root",FIRST,SECOND,"three-signing-keys-first","three-signing-keys-second","three-signing-keys");
            default -> throw new IllegalArgumentException("Unsupported key selection case");
        };
    }
    enum Decision { SIGNED_SUCCESS, NATIVE_SIGNATURE_REJECTION, UNOBSERVED }
    record Sample(String variant, String runId, String entityId, List<String> advertisedKeyHashes,
                  String signerKeyHash, boolean nativeImportVerified, boolean validRequestSignature,
                  boolean malformedSignatureRejected, Decision decision, List<EvidenceRef> evidence) {
        Sample {
            advertisedKeyHashes = List.copyOf(advertisedKeyHashes);
            evidence = List.copyOf(evidence);
            Objects.requireNonNull(decision);
        }
    }

    static CaseOutcome evaluate(List<Sample> samples, List<String> collectionIssues) {
        return evaluate(CASE_ID,samples,collectionIssues);
    }
    static CaseOutcome evaluate(String caseId, List<Sample> samples, List<String> collectionIssues) {
        var required = required(caseId);
        var issues = new LinkedHashSet<>(collectionIssues);
        var variants = new HashMap<String, Sample>();
        var identities = new HashSet<List<String>>();
        var keySets = new HashMap<String,List<String>>();
        var evidence = new LinkedHashSet<EvidenceRef>();
        for (var sample : samples) {
            var condition=CONDITIONS.get(sample.variant());
            if (condition == null || variants.put(sample.variant(), sample) != null) {
                issues.add("unexpected_or_duplicate_condition"); continue;
            }
            if (sample.runId() == null || sample.runId().isBlank() || sample.entityId() == null || sample.entityId().isBlank())
                issues.add("identity_unavailable");
            else identities.add(List.of(sample.runId(), sample.entityId()));
            var keys = sample.advertisedKeyHashes();
            var earlier=keySets.putIfAbsent(condition.family(),keys);
            if (earlier != null && !earlier.equals(keys)) issues.add("advertised_keys_changed");
            if (keys.size() != condition.count() || new HashSet<>(keys).size() != condition.count()
                    || keys.stream().anyMatch(k -> !sha256(k))) issues.add("advertised_pair_unproven");
            if (!sha256(sample.signerKeyHash())) issues.add("signer_key_unproven");
            else if (keys.size() == condition.count()) {
                boolean correct=condition.signerIndex()<0 ? !keys.contains(sample.signerKeyHash())
                        : sample.signerKeyHash().equals(keys.get(condition.signerIndex()));
                if (!correct) issues.add("signing_condition_unproven");
            }
            if (!sample.nativeImportVerified()) issues.add("native_import_unproven");
            if (!sample.validRequestSignature()) issues.add("request_signature_unproven");
            if (!sample.malformedSignatureRejected()) issues.add("signature_policy_control_unproven");
            if (sample.decision() == Decision.UNOBSERVED) issues.add("native_decision_unobserved");
            if (sample.evidence().isEmpty()) issues.add("provenance_unavailable");
            for (var ref : sample.evidence()) if (!evidence.add(ref)) issues.add("reused_evidence");
        }
        if (identities.size() != 1) issues.add("mixed_experiment");
        if (!variants.keySet().containsAll(required)) issues.add("missing_condition");
        var baseline=CASE_ID.equals(caseId)?FIRST:"entity-root";
        boolean baselineObserved=REPRESENTATION.equals(caseId)
                ? required.stream().anyMatch(v -> variants.containsKey(v) && variants.get(v).decision()==Decision.SIGNED_SUCCESS)
                : variants.containsKey(baseline) && variants.get(baseline).decision()==Decision.SIGNED_SUCCESS;
        if (!baselineObserved) issues.add("positive_control_unproven");
        var violations = new ArrayList<String>();
        for(var variant:required.stream().sorted().toList()) {
            if(!variants.containsKey(variant)||(!REPRESENTATION.equals(caseId)&&variant.equals(baseline)))continue;
            var decision=variants.get(variant).decision();
            if(OTHER_KEY.equals(variant)) {
                // Approved as a control, not an independently evaluative variant.
                if(decision!=Decision.NATIVE_SIGNATURE_REJECTION)issues.add("public_key_control_unproven");
                continue;
            }
            if(UNADVERTISED.equals(variant) && decision==Decision.SIGNED_SUCCESS)
                violations.add("unadvertised_key_accepted");
            else if(!UNADVERTISED.equals(variant) && decision==Decision.NATIVE_SIGNATURE_REJECTION)
                violations.add(variant+":advertised_key_rejected");
        }
        var outcome = !issues.isEmpty() ? Outcome.NOT_VERIFIED : violations.isEmpty() ? Outcome.SATISFIED : Outcome.VIOLATED;
        var code = "metadata.keys." + (!issues.isEmpty() ? "evidence-incomplete" : violations.isEmpty() ? "selection-observed" : "selection-violated");
        return new CaseOutcome(outcome, outcome == Outcome.NOT_VERIFIED ? "native_key_selection_unproven" : null,
                code, code, List.copyOf(evidence), Map.of("evidence_issues", List.copyOf(issues),
                "violations", List.copyOf(violations),
                "native_decisions", variants.entrySet().stream().sorted(Map.Entry.comparingByKey())
                    .collect(java.util.stream.Collectors.toMap(Map.Entry::getKey,e -> e.getValue().decision().name(),
                            (a,b)->a,LinkedHashMap::new)),
                "required_variants", required.stream().sorted().toList(),
                "missing_variants", required.stream().filter(v -> !variants.containsKey(v)).sorted().toList()));
    }
    private static boolean sha256(String value) { return value != null && value.matches("[0-9a-f]{64}"); }
}
