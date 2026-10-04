package com.samlscope.runner.cases;

import java.nio.file.Path;
import java.util.*;
import java.util.function.Function;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.runner.RecordedEvidenceReevaluation;

/** Adds native original-backed resolution without replacing the generic semantic oracle. */
final class NativeSubjectPrincipalTestCase implements TestCase,ProtocolEvidenceCase,RecordedEvidenceReevaluation {
    private final TestCase fallback;private final SimpleSamlPhpSubjectPrincipalEvidence evidence;
    NativeSubjectPrincipalTestCase(TestCase fallback,Path directory,TranscriptContentReader content,Function<String,byte[]> metadata) {
        if(!SimpleSamlPhpSubjectPrincipalEvidence.CASE.equals(fallback.id()))throw new IllegalArgumentException("Unsupported principal case");
        this.fallback=fallback;this.evidence=new SimpleSamlPhpSubjectPrincipalEvidence(directory,content,metadata);
    }
    @Override public String id(){return fallback.id();}
    @Override public TargetRole role(){return fallback.role();}
    @Override public CaseStep start(CaseContext context){var result=evidence.evaluate(context);return result.outcome()==Outcome.SATISFIED?new CaseStep.Finish(result):fallback.start(context);}
    @Override public CaseStep resume(CaseContext context,CaseState state,CaseEvent event){return fallback.resume(context,state,event);}
    @Override public EvidenceStatus evidenceStatus(CaseContext context){var result=evidence.evaluate(context);boolean ready=result.outcome()==Outcome.SATISFIED;return new EvidenceStatus(ready,List.of("native-principal-resolution"),ready?List.of("native-principal-resolution"):List.of(),result.details());}
    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous){return previous!=null&&previous.outcome()==Outcome.NOT_VERIFIED&&Set.of("saml.subject-principal.undetermined","saml.subject-principal.native-unproven").contains(previous.reasonCode());}
    @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context,CaseOutcome previous){return supportsRecordedEvidenceReevaluation(previous)?RecordedEvidenceReevaluation.conclusiveUpdate(previous,evidence.evaluate(context)):Optional.empty();}
}
