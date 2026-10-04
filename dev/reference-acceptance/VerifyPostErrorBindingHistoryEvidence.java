package com.samlscope.runner.cases;

import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.store.JsonCodec;
import java.net.URI;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.*;
import java.util.*;

/** Verify the real Auto wrapper rejects mixed/duplicate history before reading originals. */
public final class VerifyPostErrorBindingHistoryEvidence {
    private static final JsonCodec JSON=new JsonCodec();
    private static final String CASE="IIP-SSO03-b-idp-01";
    private static void require(boolean ok,String why){if(!ok)throw new IllegalArgumentException(why);}
    private static String sha(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
    private static DefaultCaseContext context(String run,List<TranscriptEntry> entries){
        var recorder=new TranscriptRecorder(){public List<TranscriptEntry> list(String id){require(id.equals(run),"Wrong context Run");return entries;}public TranscriptEntry record(TranscriptInput input){throw new AssertionError("Replay cannot write");}public TranscriptEntry updateSamlAnalysis(String id,String c,Map<String,Object>s){throw new AssertionError("Replay cannot write");}};
        return new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,true);
    }
    private static BrowserEvidenceTestCase fallback(){return new BrowserEvidenceTestCase(new AttestedOutcomeTestCase(CASE,TargetRole.IDP,"unused",Duration.ofMinutes(1),List.of(AttestationOption.notVerified("unknown","unknown","unused"))),URI.create("http://localhost:18080"),"Recorded evidence replay",Duration.ofMinutes(1));}
    public static void main(String[] args)throws Exception {
        var folder=Path.of(args[0]).toAbsolutePath();var output=Path.of(args[2]);require(!Files.exists(output),"Immutable output exists");
        var run=JSON.mapper().readTree(folder.resolve("created.json").toFile()).at("/run/id").asText();
        var entries=List.of(JSON.mapper().readValue(folder.resolve("transcript.json").toFile(),TranscriptEntry[].class));
        var byId=new HashMap<String,TranscriptEntry>();for(var e:entries)require(e.runId().equals(run)&&byId.put(e.id(),e)==null,"Captured history ambiguous");
        var bodies=new HashMap<String,byte[]>();
        for(var row:JSON.mapper().readTree(folder.resolve("decoded-manifest.json").toFile())){
            var path=folder.resolve(row.path("file").asText()).normalize();require(path.getParent().equals(folder.resolve("decoded")),"Original path escaped");var raw=Files.readAllBytes(path);var e=byId.get(row.path("id").asText());
            require(e!=null&&e.decodedSamlBytes()==raw.length&&sha(raw).equals(row.path("sha256").asText()),"Original hash/length differs");bodies.put(e.id(),raw);
        }
        var test=new AutoBrowserEvidenceTestCase(fallback(),e->bodies.get(e.id()));
        var step=test.start(context(run,entries));require(step instanceof CaseStep.Finish,"Native complete history was not conclusive");var nativeOutcome=((CaseStep.Finish)step).outcome();
        require(nativeOutcome.outcome()==Outcome.SATISFIED,"Native history changed conclusion");
        var previous=CaseOutcome.notVerified("timeout","browser.timeout");
        require(test.reevaluateRecordedEvidence(context(run,entries),previous).orElseThrow().equals(nativeOutcome),"Reevaluation differs from start");
        var before=JSON.mapper().readTree(folder.resolve("baseline-reader-replay.json").toFile());
        require(before.path("outcome").asText().equals(nativeOutcome.outcome().name())&&before.path("reasonCode").asText().equals(nativeOutcome.reasonCode())
                &&before.path("details").equals(JSON.mapper().valueToTree(nativeOutcome.details()))&&before.path("evidence").equals(JSON.mapper().valueToTree(nativeOutcome.evidence())),"Strict wrapper differs from adopted original outcome/details/evidence");
        var checks=new TreeMap<String,String>();checks.put("native-original-full-outcome-unchanged",nativeOutcome.outcome().name());
        var guarded=new AutoBrowserEvidenceTestCase(fallback(),e->{throw new AssertionError("Invalid history read content");});
        for(var name:List.of("foreign-run-history","duplicate-recorder-id")){
            var changed=new ArrayList<>(entries);var first=entries.getFirst();
            if(name.equals("duplicate-recorder-id"))changed.add(first);
            else changed.set(0,new TranscriptEntry(first.id(),"run_00000000000000000000000000",first.direction(),first.timestamp(),first.correlationId(),first.method(),first.url(),first.status(),first.headers(),first.bodyRef(),first.bodyBytes(),first.decodedSamlRef(),first.decodedSamlBytes(),first.contentType(),first.rawQuery(),first.samlSummary()));
            require(guarded.start(context(run,changed)) instanceof CaseStep.AwaitBrowser,"Invalid history concluded at start");
            require(guarded.reevaluateRecordedEvidence(context(run,changed),previous).isEmpty(),"Invalid history concluded at reevaluation");checks.put(name,"NOT_VERIFIED");
        }
        var result=new TreeMap<String,Object>();result.put("runId",run);result.put("caseId",CASE);result.put("nativeOutcome",nativeOutcome);result.put("checks",checks);result.put("configurationWrites",0);result.put("privateKeyExported",false);
        JSON.mapper().writerWithDefaultPrettyPrinter().writeValue(output.toFile(),result);
    }
}
