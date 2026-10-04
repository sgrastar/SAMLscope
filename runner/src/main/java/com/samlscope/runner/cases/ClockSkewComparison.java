package com.samlscope.runner.cases;

import com.samlscope.core.evaluation.*;
import java.time.Instant;
import java.util.*;

/** Evaluate verified consumer observations, never receipt labels or Suite tolerance defaults. */
final class ClockSkewComparison {
    static final List<String> REQUIRED = List.of("issue-control", "issue-invalid-signature",
            "issue-within-past", "issue-within-future", "issue-outside-past", "issue-outside-future",
            "conditions-control", "conditions-not-before", "conditions-not-on-or-after",
            "metadata-control", "metadata-valid-until");
    record Sample(String fixtureId, Instant shiftedValue, ClockSkewNativeAdapter.NativeUse nativeUse,
            List<EvidenceRef> evidence) {
        Sample { evidence = List.copyOf(evidence); }
    }
    static CaseOutcome evaluate(String runId, String adapter, List<Sample> samples, List<EvidenceRef> originals) {
        var byId = new HashMap<String,Sample>(); var refs = new LinkedHashSet<EvidenceRef>(originals);
        for (var sample : samples) {
            if (!REQUIRED.contains(sample.fixtureId()) || byId.put(sample.fixtureId(),sample) != null)
                return missing("ambiguous_observations", List.of());
            if (sample.nativeUse() == null) return missing("consumer_unproven", List.of());
            refs.addAll(sample.evidence()); refs.addAll(sample.nativeUse().evidence());
        }
        // Positive and negative controls must actually exercise the same native consumer and
        // policy, not a different library/context that happens to accept the same timestamp.
        var issue = byId.get("issue-control"); var signature = byId.get("issue-invalid-signature");
        if (!accepted(issue) || signature == null || !sameScope(issue,signature)
                || signature.nativeUse().decision()!=ClockSkewNativeAdapter.Decision.INVALID_SIGNATURE_REJECTION)
            return missing("issue_controls_unproven", List.copyOf(refs));
        var completed = new ArrayList<String>(); var counterexamples = new ArrayList<String>();
        var advisory = new ArrayList<String>();
        var nonIssueInstantRefusals = new ArrayList<String>();
        for (var id : REQUIRED) {
            var sample = byId.get(id); if (sample == null) continue;
            var base = byId.get(id.startsWith("issue-") ? "issue-control"
                    : id.startsWith("conditions-") ? "conditions-control" : "metadata-control");
            if (!accepted(base) || !sameScope(base,sample)) continue;
            if (id.endsWith("control")) { completed.add(id); continue; }
            if (id.equals("issue-invalid-signature")) { completed.add(id); continue; }
            if (sample.shiftedValue()==null) continue;
            var direction = id.endsWith("future") || id.equals("conditions-not-before")
                    ? ClockSkewTiming.Direction.FUTURE : ClockSkewTiming.Direction.PAST;
            ClockSkewTiming.Position position;
            try {
                position=ClockSkewTiming.classify(sample.shiftedValue(),
                        new ClockSkewTiming.ClockInterval(sample.nativeUse().nativeStartedAt(),sample.nativeUse().nativeCompletedAt()),
                        sample.nativeUse().targetAttestedTolerance(),direction);
            } catch(RuntimeException unavailable) { continue; }
            if (id.startsWith("issue-outside-")) {
                if (position==ClockSkewTiming.Position.STRICTLY_OUTSIDE
                        && Set.of(ClockSkewNativeAdapter.Decision.ACCEPTED,ClockSkewNativeAdapter.Decision.CAUSAL_TIME_REJECTION)
                        .contains(sample.nativeUse().decision())) {
                    completed.add(id);
                    if(accepted(sample)) advisory.add(id);
                }
                continue; // Acceptance outside T is never a normative counterexample.
            }
            if(position!=ClockSkewTiming.Position.STRICTLY_WITHIN) continue;
            if(accepted(sample)) completed.add(id);
            else if(sample.nativeUse().decision()==ClockSkewNativeAdapter.Decision.CAUSAL_TIME_REJECTION) {
                if(id.startsWith("issue-within-")) {
                    completed.add(id);counterexamples.add(id);
                } else {
                    // The approved instructions make only IssueInstant verdict-affecting,
                    // while the approved ALL variant plan still treats these paths as
                    // evaluative. Preserve their actual observations without resolving
                    // that interpretation conflict as either failure or satisfaction.
                    nonIssueInstantRefusals.add(id);
                }
            }
        }
        var details = new LinkedHashMap<String,Object>();
        details.put("evidence_adapter",adapter);details.put("run_id",runId);
        details.put("completed_observations",List.copyOf(completed));details.put("required_observations",REQUIRED);
        details.put("outside_t_acceptance_advisory",List.copyOf(advisory));details.put("advisory_affects_verdict",false);
        details.put("non_issue_instant_refusal_advisory",List.copyOf(nonIssueInstantRefusals));
        details.put("non_issue_instant_refusal_affects_verdict",false);
        details.put("target_tolerance_source","native-originals");details.put("suite_tolerance_used",false);
        details.put("counterexamples",List.copyOf(counterexamples));
        if(!counterexamples.isEmpty()) return new CaseOutcome(Outcome.VIOLATED,null,
                "clock-skew.within-attested-t-rejected","clock-skew.within-attested-t-rejected",List.copyOf(refs),details);
        if(!new HashSet<>(completed).equals(new HashSet<>(REQUIRED))) {
            details.put("required_action","administrator_evidence");
            details.put("instructions_en","Provide target clock-tolerance and actual consumer evidence for every approved temporal path. Repeating ordinary logins cannot establish missing clock policies or assertion-consumer paths.");
            return new CaseOutcome(Outcome.NOT_VERIFIED,nonIssueInstantRefusals.isEmpty()
                    ? "clock_consumer_paths_incomplete" : "approved_variant_semantics_ambiguous",
                    "clock-skew.native-evidence-incomplete","clock-skew.native-evidence-incomplete",List.copyOf(refs),details);
        }
        return new CaseOutcome(Outcome.SATISFIED,null,"clock-skew.attested-t-observed",
                "clock-skew.attested-t-observed",List.copyOf(refs),details);
    }
    private static boolean accepted(Sample sample) {
        return sample!=null&&sample.nativeUse()!=null&&sample.nativeUse().decision()==ClockSkewNativeAdapter.Decision.ACCEPTED;
    }
    private static boolean sameScope(Sample first,Sample second) {
        if(first==null||second==null||first.nativeUse()==null||second.nativeUse()==null)return false;
        var a=first.nativeUse();var b=second.nativeUse();
        return a.policyId()!=null&&!a.policyId().isBlank()&&a.policyId().equals(b.policyId())
                &&a.consumerId()!=null&&!a.consumerId().isBlank()&&a.consumerId().equals(b.consumerId())
                &&a.targetAttestedTolerance()!=null&&a.targetAttestedTolerance().equals(b.targetAttestedTolerance());
    }
    static CaseOutcome missing(String reason,List<EvidenceRef> refs) {
        return new CaseOutcome(Outcome.NOT_VERIFIED,reason,"clock-skew.native-evidence-incomplete",
                "clock-skew.native-evidence-incomplete",refs,Map.of("required_action","administrator_evidence",
                "instructions_en","Provide original-backed target clock tolerance and consumer evidence before running clock probes. Additional ordinary logins cannot verify this case.","suite_tolerance_used",false));
    }
    private ClockSkewComparison() { }
}
