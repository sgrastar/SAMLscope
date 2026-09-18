package com.samlscope.runner.cases;

import java.time.Instant;
import java.util.*;
import com.samlscope.core.evaluation.*;

/** Internal comparison after native preparation and original signed responses have been bound. */
final class NameIdOmissionComparison {
    static final String CASE_ID = "IIP-IDP11-a-idp-01";
    enum Condition { BASELINE, NAME_ID_DISABLED }
    record Sample(String experiment, Condition condition, String entityId, String loginInputFingerprint,
                  String stableInputFingerprint, Instant issued, Instant received,
                  NameIdOmissionResponseEvidence.Presence presence, List<EvidenceRef> evidence) {
        Sample {
            Objects.requireNonNull(condition);Objects.requireNonNull(issued);Objects.requireNonNull(received);
            Objects.requireNonNull(presence);evidence=List.copyOf(evidence);
        }
    }

    static CaseOutcome evaluate(List<Sample> samples, List<String> collectionIssues) {
        var issues=new ArrayList<>(collectionIssues);
        var byCondition=new EnumMap<Condition,Sample>(Condition.class);
        var evidence=new LinkedHashSet<EvidenceRef>();
        for(var sample:samples) {
            if(byCondition.put(sample.condition(),sample)!=null) issues.add("duplicate_condition");
            if(sample.experiment()==null || sample.experiment().isBlank()
                    || sample.entityId()==null || sample.entityId().isBlank()) issues.add("experiment_binding_unavailable");
            if(!fingerprint(sample.loginInputFingerprint()) || !fingerprint(sample.stableInputFingerprint())) {
                issues.add("fixed_input_unproven");
            }
            if(sample.received().isBefore(sample.issued())) issues.add("response_precedes_request");
            if(sample.evidence().size()!=2) issues.add("incomplete_exchange_references");
            for(var ref:sample.evidence()) {
                if(!"transcript".equals(ref.kind()) || ref.reference()==null || ref.reference().isBlank()
                        || !evidence.add(ref)) issues.add("ambiguous_exchange_references");
            }
        }
        var baseline=byCondition.get(Condition.BASELINE);
        var disabled=byCondition.get(Condition.NAME_ID_DISABLED);
        if(baseline==null || disabled==null) issues.add("missing_condition");
        else {
            if(!Objects.equals(baseline.experiment(),disabled.experiment())
                    || !Objects.equals(baseline.entityId(),disabled.entityId())) issues.add("mixed_experiments");
            if(!Objects.equals(baseline.loginInputFingerprint(),disabled.loginInputFingerprint())
                    || !Objects.equals(baseline.stableInputFingerprint(),disabled.stableInputFingerprint())) {
                issues.add("uncontrolled_input_changed");
            }
            if(!baseline.received().isBefore(disabled.issued())) issues.add("overlapping_or_reordered_conditions");
            if(baseline.presence()!=NameIdOmissionResponseEvidence.Presence.NAME_ID) issues.add("baseline_name_id_unobserved");
            // This path proves complete omission. It makes no adverse judgment about BaseID configurations.
            if(disabled.presence()!=NameIdOmissionResponseEvidence.Presence.OMITTED) issues.add("omission_unobserved");
        }
        boolean satisfied=issues.isEmpty();
        String code=satisfied?"configuration.nameid-omission.observed":"configuration.nameid-omission.evidence-incomplete";
        return new CaseOutcome(satisfied?Outcome.SATISFIED:Outcome.NOT_VERIFIED,
            satisfied?null:"nameid_omission_unproven",code,code,List.copyOf(evidence),
            Map.of("evidence_issues",issues.stream().distinct().toList()));
    }
    private static boolean fingerprint(String value) { return value!=null && value.matches("[0-9a-f]{64}"); }
}
