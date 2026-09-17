package com.samlscope.runner.cases;

import java.util.*;
import com.samlscope.core.evaluation.*;

/** Approved algorithm order and role-precedence decisions, after input preparation is confirmed. */
final class MetadataAlgorithmSelection {
    static final String ORDER="IIP-MD05-ea-idp-01", ROLE="IIP-MD05-eb-idp-01";
    static final String D256="http://www.w3.org/2001/04/xmlenc#sha256", D384="http://www.w3.org/2001/04/xmldsig-more#sha384";
    static final String S256="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", S384="http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
    record Methods(List<String> digests,List<String> signatures) {
        Methods { digests=List.copyOf(digests);signatures=List.copyOf(signatures); }
    }
    record Input(Methods entity,Methods role) {}
    record Sample(String campaign,String variant,Input advertised,List<Methods> selected,List<EvidenceRef> evidence) {
        Sample { selected=List.copyOf(selected);evidence=List.copyOf(evidence); }
    }
    private static Methods methods(List<String> d,List<String>s) { return new Methods(d,s); }
    private static final Methods EMPTY=methods(List.of(),List.of()), A=methods(List.of(D256),List.of(S256)), B=methods(List.of(D384),List.of(S384));
    static final Map<String,Input> INPUTS=Map.ofEntries(
        Map.entry("control",new Input(EMPTY,EMPTY)),
        Map.entry("algorithm-entity-sha256",new Input(A,EMPTY)),
        Map.entry("algorithm-entity-sha384",new Input(B,EMPTY)),
        Map.entry("algorithm-entity-order-256-384",new Input(methods(List.of(D256,D384),List.of(S256,S384)),EMPTY)),
        Map.entry("algorithm-entity-order-384-256",new Input(methods(List.of(D384,D256),List.of(S384,S256)),EMPTY)),
        Map.entry("algorithm-role-order-256-384",new Input(EMPTY,methods(List.of(D256,D384),List.of(S256,S384)))),
        Map.entry("algorithm-role-order-384-256",new Input(EMPTY,methods(List.of(D384,D256),List.of(S384,S256)))),
        Map.entry("algorithm-role-signing-384",new Input(A,methods(List.of(),List.of(S384)))),
        Map.entry("algorithm-role-digest-384",new Input(A,methods(List.of(D384),List.of()))),
        Map.entry("algorithm-role-both-384",new Input(A,B)),Map.entry("algorithm-role-both-256",new Input(B,A)));
    static List<String> required(String id) {
        return ORDER.equals(id) ? List.of("control","algorithm-entity-sha256","algorithm-entity-sha384",
            "algorithm-entity-order-256-384","algorithm-entity-order-384-256","algorithm-role-order-256-384","algorithm-role-order-384-256")
            : List.of("control","algorithm-entity-sha256","algorithm-entity-sha384","algorithm-role-signing-384",
                "algorithm-role-digest-384","algorithm-role-both-384","algorithm-role-both-256");
    }
    static CaseOutcome evaluate(String id,List<Sample> samples,List<String> issues) {
        if(!ORDER.equals(id) && !ROLE.equals(id))throw new IllegalArgumentException("Unsupported algorithm obligation");
        var campaigns=samples.stream().map(Sample::campaign).distinct().toList();
        if(campaigns.size()>1) {
            var outcomes=campaigns.stream().map(c->evaluate(id,samples.stream().filter(s->c.equals(s.campaign())).toList(),issues)).toList();
            return outcomes.stream().filter(o->o.outcome()==Outcome.VIOLATED).findFirst()
                .orElseGet(()->outcomes.stream().filter(o->o.outcome()==Outcome.SATISFIED).findFirst().orElse(outcomes.getLast()));
        }
        var required=required(id);var found=new HashMap<String,List<Sample>>();
        for(var s:samples)if(required.contains(s.variant()))found.computeIfAbsent(s.variant(),v->new ArrayList<>()).add(s);
        var missing=required.stream().filter(v->!found.containsKey(v)).toList();
        var allIssues=new ArrayList<>(issues);
        for(var sample:samples)if(required.contains(sample.variant()) && (!INPUTS.get(sample.variant()).equals(sample.advertised()) || sample.selected().isEmpty() || sample.selected().stream().anyMatch(m->m.digests().isEmpty() || m.signatures().isEmpty())))allIssues.add("input_or_signature_unproven:"+sample.variant());
        var evidence=samples.stream().flatMap(s->s.evidence().stream()).distinct().toList();
        var details=new LinkedHashMap<String,Object>();details.put("required_variants",required);details.put("observed_variants",required.stream().filter(found::containsKey).toList());
        details.put("missing_variants",missing);details.put("evidence_issues",List.copyOf(allIssues));details.put("campaigns",campaigns);
        if(!missing.isEmpty() || !allIssues.isEmpty())return result(Outcome.NOT_VERIFIED,"metadata.algorithms.evidence-incomplete",evidence,details);
        var mismatches=new ArrayList<String>();
        for(var variant:required) {
            if(variant.equals("control"))continue;
            for(var sample:found.get(variant)) {
                var input=sample.advertised();var d=input.role().digests().isEmpty()?input.entity().digests():input.role().digests();
                var s=input.role().signatures().isEmpty()?input.entity().signatures():input.role().signatures();
                for(var selected:sample.selected()) {
                    if(selected.digests().stream().anyMatch(v->!d.contains(v)) || selected.signatures().stream().anyMatch(v->!s.contains(v)))mismatches.add(variant+":outside-effective-list");
                    else if(ORDER.equals(id) && (selected.digests().stream().anyMatch(v->!v.equals(d.getFirst())) || selected.signatures().stream().anyMatch(v->!v.equals(s.getFirst()))))mismatches.add(variant+":not-first-advertised");
                }
            }
        }
        details.put("selection_mismatches",mismatches.stream().distinct().toList());
        if(ORDER.equals(id) && !mismatches.isEmpty()) {
            details.put("local_policy_verified",false);
            return result(Outcome.NOT_VERIFIED,"metadata.algorithms.local-policy-unverified",evidence,details);
        }
        // Standalone controls support diagnosis, but only role conflict fixtures establish this obligation's violation.
        boolean conflict=mismatches.stream().anyMatch(v->v.startsWith("algorithm-role-"));
        if(ROLE.equals(id) && conflict)return result(Outcome.VIOLATED,"metadata.algorithms.role-precedence-violated",evidence,details);
        if(!mismatches.isEmpty())return result(Outcome.NOT_VERIFIED,"metadata.algorithms.control-incomplete",evidence,details);
        return result(Outcome.SATISFIED,ORDER.equals(id)?"metadata.algorithms.first-supported-observed":"metadata.algorithms.role-precedence-observed",evidence,details);
    }
    private static CaseOutcome result(Outcome outcome,String code,List<EvidenceRef> evidence,Map<String,Object>details) {
        return new CaseOutcome(outcome,outcome==Outcome.NOT_VERIFIED?"metadata_algorithm_evidence_unavailable":null,code,code,evidence,details);
    }
}
