package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;
import com.samlscope.core.evaluation.*;
import com.samlscope.saml.normal.SamlRequestedAuthnContextRequestFactory.*;

class AuthnContextComparisonTest {
    private AuthnContextComparison.Preparation preparation(AuthnContextComparison.Controls controls) {
        var contexts=new EnumMap<ReferenceKind,AuthnContextComparison.NativeContext>(ReferenceKind.class);
        for(var kind:ReferenceKind.values()) {
            String p=kind.name();var refs=new AuthnContextComparisonInputs.References(p+"a",p+"b",p+"c",p+"u");
            contexts.put(kind,new AuthnContextComparison.NativeContext(refs,new AuthnContextSelectionRule.PreparedOrdering(
                Map.of(refs.low(),1,refs.medium(),2,refs.high(),3),Set.of(refs.low(),refs.medium()),true),
                Set.of(refs.low(),refs.high()),Set.of(refs.unavailable())));
        }
        return new AuthnContextComparison.Preparation("experiment","entity","a".repeat(64),"b".repeat(64),contexts,controls);
    }
    private List<AuthnContextComparison.Sample> samples(String id,AuthnContextComparison.Preparation p,boolean bad,boolean allErrors) {
        var result=new ArrayList<AuthnContextComparison.Sample>();int index=0;
        for(var kind:ReferenceKind.values()) for(var input:AuthnContextComparisonInputs.forCase(id,kind,p.contexts().get(kind).references())) {
            boolean error=allErrors || input.condition().endsWith("unachievable");
            var refs=p.contexts().get(kind).references();String returned;
            if(id.contains("-gj-")) returned=bad?refs.low():input.request().references().getFirst();
            else returned=bad?refs.low():refs.medium();
            var response=new AuthnContextResponseEvidence.Observation(error?AuthnContextResponseEvidence.ResponseKind.ERROR:AuthnContextResponseEvidence.ResponseKind.SUCCESS,
                !error && kind==ReferenceKind.CLASS?Optional.of(returned):Optional.empty(),
                !error && kind==ReferenceKind.DECLARATION?Optional.of(returned):Optional.empty(),false);
            result.add(new AuthnContextComparison.Sample(input.condition(),p.experiment(),p.entityId(),p.loginFingerprint(),p.configurationFingerprint(),
                input.request(),Instant.ofEpochSecond(index*2),Instant.ofEpochSecond(index*2+1),response,
                List.of(new EvidenceRef("transcript","request-"+index),new EvidenceRef("transcript","response-"+index))));index++;
        }
        return result;
    }
    @Test void maximumDetectsWeakSelectionOnlyWithCompleteNativeAndControlEvidence() {
        String id="IIP-SSO01-gc-idp-01";var p=preparation(AuthnContextComparison.Controls.VERIFIED);
        assertEquals(Outcome.SATISFIED,AuthnContextComparison.evaluate(id,p,samples(id,p,false,false),List.of()).outcome());
        assertEquals(Outcome.VIOLATED,AuthnContextComparison.evaluate(id,p,samples(id,p,true,false),List.of()).outcome());
        var unverified=preparation(AuthnContextComparison.Controls.UNVERIFIED);
        assertEquals(Outcome.NOT_VERIFIED,AuthnContextComparison.evaluate(id,unverified,samples(id,unverified,true,false),List.of()).outcome());
    }
    @Test void errorOnlyAndIncompleteExperimentsAreNotProductViolations() {
        var p=preparation(AuthnContextComparison.Controls.VERIFIED);
        for(String suffix:List.of("ga","gb","gc","gj")) {
            String id="IIP-SSO01-"+suffix+"-idp-01";
            assertEquals(Outcome.NOT_VERIFIED,AuthnContextComparison.evaluate(id,p,samples(id,p,false,true),List.of()).outcome());
            var partial=new ArrayList<>(samples(id,p,false,false));partial.removeLast();
            assertEquals(Outcome.NOT_VERIFIED,AuthnContextComparison.evaluate(id,p,partial,List.of()).outcome());
            var duplicate=new ArrayList<>(samples(id,p,false,false));duplicate.add(duplicate.getFirst());
            assertEquals(Outcome.NOT_VERIFIED,AuthnContextComparison.evaluate(id,p,duplicate,List.of()).outcome());
        }
    }
    @Test void orderIgnoringMutantFailsTheReversedCandidateCondition() {
        String id="IIP-SSO01-gj-idp-01";var p=preparation(AuthnContextComparison.Controls.VERIFIED);
        assertEquals(Outcome.SATISFIED,AuthnContextComparison.evaluate(id,p,samples(id,p,false,false),List.of()).outcome());
        assertEquals(Outcome.VIOLATED,AuthnContextComparison.evaluate(id,p,samples(id,p,true,false),List.of()).outcome());
    }
}
