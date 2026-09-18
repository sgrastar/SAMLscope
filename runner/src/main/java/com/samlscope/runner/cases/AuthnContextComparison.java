package com.samlscope.runner.cases;

import java.time.Instant;
import java.util.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.saml.normal.SamlRequestedAuthnContextRequestFactory.*;

/** Internal aggregation after original-response verification and native preparation binding. */
final class AuthnContextComparison {
    enum Controls { VERIFIED, UNVERIFIED }
    record NativeContext(AuthnContextComparisonInputs.References references,
                         AuthnContextSelectionRule.PreparedOrdering ordering, Set<String> satisfiable, Set<String> provenUnachievable) {
        NativeContext { Objects.requireNonNull(references);Objects.requireNonNull(ordering);satisfiable=Set.copyOf(satisfiable);provenUnachievable=Set.copyOf(provenUnachievable); }
    }
    record Preparation(String experiment,String entityId,String loginFingerprint,String configurationFingerprint,
                       Map<ReferenceKind,NativeContext> contexts,Controls controls) {
        Preparation { contexts=Map.copyOf(contexts);Objects.requireNonNull(controls); }
    }
    record Sample(String condition,String experiment,String entityId,String loginFingerprint,String configurationFingerprint,
                  ContextRequest request,Instant issued,Instant received,AuthnContextResponseEvidence.Observation response,
                  List<EvidenceRef> evidence) {
        Sample { Objects.requireNonNull(request);Objects.requireNonNull(issued);Objects.requireNonNull(received);
            Objects.requireNonNull(response);evidence=List.copyOf(evidence); }
    }

    static CaseOutcome evaluate(String caseId,Preparation prepared,List<Sample> samples,List<String> collectionIssues) {
        var issues=new ArrayList<>(collectionIssues);var mismatches=new ArrayList<String>();
        var evidence=new LinkedHashSet<EvidenceRef>();var expected=new LinkedHashMap<String,ContextRequest>();
        if(prepared==null) return result(List.of("verified_preparation_unavailable"),mismatches,evidence);
        if(prepared.controls()!=Controls.VERIFIED) issues.add("controls_unverified");
        if(prepared.experiment()==null || prepared.experiment().isBlank() || prepared.entityId()==null || prepared.entityId().isBlank()
                || !fingerprint(prepared.loginFingerprint()) || !fingerprint(prepared.configurationFingerprint())) issues.add("preparation_binding_unavailable");
        for(var kind:ReferenceKind.values()) {
            var nativeContext=prepared.contexts().get(kind);
            if(nativeContext==null) {issues.add("native_reference_kind_unavailable");continue;}
            if(!validNative(caseId,nativeContext)) issues.add("native_fixture_prerequisites_unproven");
            for(var input:AuthnContextComparisonInputs.forCase(caseId,kind,nativeContext.references())) expected.put(input.condition(),input.request());
        }
        var seen=new HashSet<String>();var successfulKinds=EnumSet.noneOf(ReferenceKind.class);
        var ordered=new ArrayList<>(samples);ordered.sort(Comparator.comparing(Sample::issued));
        Instant previous=null;
        for(var sample:ordered) {
            if(!seen.add(sample.condition()) || !sample.request().equals(expected.get(sample.condition()))) issues.add("condition_missing_duplicate_or_changed");
            if(!Objects.equals(prepared.experiment(),sample.experiment()) || !Objects.equals(prepared.entityId(),sample.entityId())
                    || !Objects.equals(prepared.loginFingerprint(),sample.loginFingerprint())
                    || !Objects.equals(prepared.configurationFingerprint(),sample.configurationFingerprint())) issues.add("experiment_inputs_changed");
            if(sample.received().isBefore(sample.issued()) || (previous!=null && !previous.isBefore(sample.issued()))) issues.add("overlapping_exchange");
            previous=sample.received();
            if(sample.evidence().size()!=2) issues.add("exchange_provenance_incomplete");
            for(var ref:sample.evidence()) if(!"transcript".equals(ref.kind()) || ref.reference()==null || ref.reference().isBlank()
                    || !evidence.add(ref)) issues.add("exchange_provenance_reused");
            boolean preference="IIP-SSO01-gj-idp-01".equals(caseId);
            if(sample.response().kind()==AuthnContextResponseEvidence.ResponseKind.ERROR) {
                if(preference) issues.add("preference_not_observed_on_error");
                continue; // Signed correlated errors are not strength-selection violations.
            }
            var kind=sample.request().kind();var nativeContext=prepared.contexts().get(kind);
            if(nativeContext==null) continue;
            var returned=kind==ReferenceKind.CLASS?sample.response().classReference():sample.response().declarationReference();
            if(returned.isEmpty()) {issues.add("requested_reference_kind_unobserved");continue;}
            var check=preference?AuthnContextSelectionRule.preference(sample.request().references(),returned.orElseThrow(),nativeContext.satisfiable())
                :AuthnContextSelectionRule.strength(sample.request().comparison(),sample.request().references(),returned.orElseThrow(),nativeContext.ordering());
            if(check.status()==AuthnContextSelectionRule.Status.UNPROVEN) issues.add(check.reason());
            else {
                successfulKinds.add(kind);
                if(check.status()==AuthnContextSelectionRule.Status.MISMATCH) mismatches.add(sample.condition());
            }
        }
        if(!seen.equals(expected.keySet())) issues.add("required_conditions_incomplete");
        // An error-only experiment is not a product violation, nor proof of successful selection controls.
        if(successfulKinds.size()!=ReferenceKind.values().length) issues.add("successful_selection_control_unobserved");
        return result(issues,mismatches,evidence);
    }
    private static boolean validNative(String caseId,NativeContext context) {
        var refs=context.references();var ranks=context.ordering().ranks();
        var low=ranks.get(refs.low());var high=ranks.get(refs.high());
        if(low==null || high==null || low>=high) return false;
        if("IIP-SSO01-gj-idp-01".equals(caseId)) return context.satisfiable().containsAll(List.of(refs.low(),refs.high()));
        if(!context.provenUnachievable().contains(refs.unavailable())) return false;
        if("IIP-SSO01-gc-idp-01".equals(caseId)) {
            var medium=ranks.get(refs.medium());
            return medium!=null && low<medium && medium<high && context.ordering().availabilityComplete()
                && context.ordering().available().containsAll(List.of(refs.low(),refs.medium()))
                && !context.ordering().available().contains(refs.high());
        }
        return context.satisfiable().containsAll(List.of(refs.low(),refs.high()));
    }
    private static CaseOutcome result(List<String> issues,List<String> mismatches,Set<EvidenceRef> evidence) {
        Outcome outcome=!issues.isEmpty()?Outcome.NOT_VERIFIED:mismatches.isEmpty()?Outcome.SATISFIED:Outcome.VIOLATED;
        String code=switch(outcome) {
            case SATISFIED -> "configuration.authn-context.comparison-observed";
            case VIOLATED -> "configuration.authn-context.selection-mismatch";
            default -> "configuration.authn-context.evidence-incomplete";
        };
        return new CaseOutcome(outcome,outcome==Outcome.NOT_VERIFIED?"authn_context_comparison_unproven":null,code,code,
            List.copyOf(evidence),Map.of("evidence_issues",issues.stream().distinct().toList(),"mismatched_conditions",List.copyOf(mismatches)));
    }
    private static boolean fingerprint(String value) { return value!=null && value.matches("[0-9a-f]{64}"); }
}
