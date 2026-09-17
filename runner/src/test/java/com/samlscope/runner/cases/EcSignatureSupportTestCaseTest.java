package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;

class EcSignatureSupportTestCaseTest {
    private static final String RUN = "run_0123456789ABCDEFGHJKMNPQRS";
    private static final String VALID = "ecdsa-sha256";
    private static final String INVALID = "ecdsa-sha256-invalid-signature";
    private static final Instant NOW = Instant.parse("2026-09-14T00:00:00Z");
    @Test void separateSignatureControlCannotSupplyTheNormalEcSuccess() {
        var entries = new ArrayList<TranscriptEntry>();
        append(entries,"control",1);append(entries,VALID,1);append(entries,INVALID,2);
        var old=entries.get(3);var summary=new HashMap<String,Object>(old.samlSummary());
        summary.put("metadataSignatureControl","invalid");
        entries.set(3,entry(old.id(),RUN,old.url(),10,summary));
        assertFalse(new EcSignatureSupportTestCase().evidenceStatus(context(entries,true)).ready());
    }
    @Test void allResponseCombinationsRequireSuccessfulControlsAndExplicitRejection() {
        // 4^3 combinations, repeated with incomplete history. Missing/unknown statuses are not errors.
        for (int control=0; control<4; control++) for (int valid=0; valid<4; valid++) for (int invalid=0; invalid<4; invalid++) {
            var entries = new ArrayList<TranscriptEntry>();
            append(entries, "control", control); append(entries, VALID, valid); append(entries, INVALID, invalid);
            for (boolean complete : List.of(true,false)) {
                var ctx = context(entries, complete); var test = new EcSignatureSupportTestCase();
                var start = (CaseStep.AwaitConfig) test.start(ctx);
                var outcome = ((CaseStep.Finish)test.resume(ctx,start.next(),new CaseEvent.ConfigConfirmed())).outcome();
                boolean proven = complete && control==1 && valid==1 && invalid==2;
                assertEquals(proven ? Outcome.SATISFIED : Outcome.NOT_VERIFIED, outcome.outcome(),
                        control+"/"+valid+"/"+invalid+" complete="+complete);
                assertEquals(proven, test.evidenceStatus(ctx).ready());
            }
        }
    }
    @Test void staleUncorrelatedAndContradictoryEvidenceCannotProveSupport() {
        var good = new ArrayList<TranscriptEntry>();
        append(good,"control",1);append(good,VALID,1);append(good,INVALID,2);
        var test = new EcSignatureSupportTestCase();
        assertTrue(test.evidenceStatus(context(good,true)).ready());
        var swapped = new ArrayList<>(good); Collections.swap(swapped,2,3);
        assertFalse(test.evidenceStatus(context(swapped,true)).ready());
        var contradictory = new ArrayList<>(good);append(contradictory,INVALID,1);
        assertFalse(test.evidenceStatus(context(contradictory,true)).ready());
        for (String query : List.of("mdv="+VALID+"-suffix&run="+RUN,
                "mdv="+VALID+"&run="+RUN+"-suffix", "mdv="+VALID+"&mdv="+VALID+"&run="+RUN)) {
            var changed = new ArrayList<>(good);var old=changed.get(3);
            changed.set(3,entry(old.id(),RUN,"https://suite.example/acs?"+query,10,old.samlSummary()));
            assertFalse(test.evidenceStatus(context(changed,true)).ready());
        }
        var crossRun = new ArrayList<>(good);var old=crossRun.get(3);
        crossRun.set(3,entry(old.id(),"other-run",old.url(),10,old.samlSummary()));
        assertFalse(test.evidenceStatus(context(crossRun,true)).ready());
    }
    @Test void freshEvidenceMayCompleteAnIncompleteResultButCannotReviveAnAbort() {
        var entries = new ArrayList<TranscriptEntry>();append(entries,"control",1);
        var test = new EcSignatureSupportTestCase();var ctx=context(entries,true);
        var state=((CaseStep.AwaitConfig)test.start(ctx)).next();
        var previous=((CaseStep.Finish)test.resume(ctx,state,new CaseEvent.ConfigConfirmed())).outcome();
        append(entries,VALID,1);append(entries,INVALID,2);
        assertEquals(Outcome.SATISFIED,test.reevaluateRecordedEvidence(ctx,previous).orElseThrow().outcome());
        assertTrue(test.reevaluateRecordedEvidence(ctx,CaseOutcome.notVerified("abort","ec-signature.aborted")).isEmpty());
        assertTrue(test.reevaluateRecordedEvidence(context(entries,false),previous).isEmpty());
    }
    private static void append(List<TranscriptEntry> entries,String variant,int response) {
        entries.add(entry("tx-"+entries.size(),RUN,"https://suite.example/metadata/live",0,
                Map.of("type","MetadataFetch","variant",variant)));
        if(response==0)return;
        entries.add(entry("tx-"+entries.size(),RUN,"https://suite.example/acs?run="+RUN+"&mdv="+variant,10,
                Map.of("type","SAMLResponse","metadataProbeAccepted",true,"statusCode",
                        "urn:oasis:names:tc:SAML:2.0:status:"+(response==1?"Success":response==2?"Responder":"Unknown"))));
    }
    private static TranscriptEntry entry(String id,String run,String url,int bytes,Map<String,Object> summary) {
        return new TranscriptEntry(id,run,Direction.INBOUND,NOW,"corr","POST",url,200,Map.of(),null,0,
                bytes>0?"decoded":null,bytes,null,null,summary);
    }
    private static CaseContext context(List<TranscriptEntry> entries,boolean complete) {
        return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.fixed(NOW,ZoneOffset.UTC),TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(),Reachability.CONFIRMED,new TranscriptRecorder(){
            public TranscriptEntry record(TranscriptInput input){throw new AssertionError("must be read-only");}
            public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary){throw new AssertionError("must be read-only");}
            public List<TranscriptEntry> list(String run){return entries;}
        },complete);
    }
}
