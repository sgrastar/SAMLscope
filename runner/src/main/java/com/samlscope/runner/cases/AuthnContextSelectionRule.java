package com.samlscope.runner.cases;

import java.util.*;
import com.samlscope.saml.normal.SamlRequestedAuthnContextRequestFactory.Comparison;

/** Internal rule for verified successful responses. No target-independent authentication ranking. */
final class AuthnContextSelectionRule {
    enum Status { MATCH, MISMATCH, UNPROVEN }
    record Check(Status status, String reason) {}
    /** Native preparation must establish the ordering and exhaustive availability for the fixed input. */
    record PreparedOrdering(Map<String,Integer> ranks, Set<String> available, boolean availabilityComplete) {
        PreparedOrdering { ranks=Map.copyOf(ranks);available=Set.copyOf(available); }
    }

    static Check strength(Comparison comparison, List<String> requested, String returned, PreparedOrdering preparation) {
        if(comparison==null || requested==null || requested.size()!=1 || requested.getFirst()==null
                || requested.getFirst().isBlank() || returned==null || returned.isBlank() || preparation==null) {
            return unproven("comparison_input_unavailable");
        }
        if(comparison==Comparison.EXACT) return unproven("strength_rule_not_applicable_to_exact_fixture");
        var threshold=preparation.ranks().get(requested.getFirst());var actual=preparation.ranks().get(returned);
        if(threshold==null || actual==null) return unproven("target_strength_order_unavailable");
        boolean matches;
        if(comparison==Comparison.MINIMUM) matches=actual>=threshold;
        else if(comparison==Comparison.BETTER) matches=actual>threshold;
        else {
            if(!preparation.availabilityComplete() || preparation.available().isEmpty()
                    || !preparation.ranks().keySet().containsAll(preparation.available())
                    || !preparation.available().contains(returned)) return unproven("target_availability_unproven");
            var permitted=preparation.available().stream().map(preparation.ranks()::get).filter(rank->rank<=threshold).toList();
            if(permitted.isEmpty()) return unproven("no_prepared_satisfiable_context");
            matches=actual.equals(Collections.max(permitted));
        }
        return new Check(matches?Status.MATCH:Status.MISMATCH,
                matches?"target_strength_selection_matches":"target_strength_selection_differs");
    }

    /** Only for fixtures where every candidate was independently prepared as satisfiable. */
    static Check preference(List<String> requested, String returned, Set<String> preparedSatisfiable) {
        if(requested==null || requested.size()<2 || requested.stream().anyMatch(value->value==null || value.isBlank())
                || new HashSet<>(requested).size()!=requested.size() || returned==null || returned.isBlank()
                || preparedSatisfiable==null || !preparedSatisfiable.containsAll(requested)) {
            return unproven("candidate_satisfiability_unproven");
        }
        boolean matches=requested.getFirst().equals(returned);
        return new Check(matches?Status.MATCH:Status.MISMATCH,
                matches?"request_preference_matches":"request_preference_differs");
    }
    private static Check unproven(String reason) { return new Check(Status.UNPROVEN,reason); }
}
