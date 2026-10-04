package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.time.*;
import java.util.*;

/** Actual production-reader replay of captured internal observations and semantic corruptions. */
public final class VerifySimpleSamlPhpForceAuthnMechanism {
    private static final JsonCodec JSON=new JsonCodec();
    public static void main(String[] args)throws Exception {
        Path source=Path.of(args[0]),receipt=Path.of(args[1]);var json=JSON.mapper();
        String run=json.readTree(Files.readAllBytes(source.resolve("browser/created.json"))).path("run").path("id").asText();
        Path folder=receipt.resolve(run+".simplesamlphp-forceauthn-mechanism"),marker=folder.resolve("manifest.json");
        var entries=json.readValue(Files.readAllBytes(source.resolve("browser/transcript.json")),json.getTypeFactory().constructCollectionType(List.class,TranscriptEntry.class));
        @SuppressWarnings("unchecked") List<TranscriptEntry> history=(List<TranscriptEntry>)entries;
        TranscriptRecorder recorder=new TranscriptRecorder(){public List<TranscriptEntry> list(String id){if(!run.equals(id))throw new AssertionError("Foreign Run");return history;}
            public TranscriptEntry record(TranscriptInput i){throw new AssertionError("Read only");}
            public TranscriptEntry updateSamlAnalysis(String id,String c,Map<String,Object>s){throw new AssertionError("Read only");}};
        var context=new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,true);
        TranscriptContentReader content=e->{try{return Files.readAllBytes(source.resolve("browser/decoded").resolve(e.id()+".xml"));}catch(Exception missing){throw new IllegalArgumentException(missing);}};
        byte[] target=Files.readAllBytes(source.resolve("browser/target-metadata.xml"));
        var reader=new SimpleSamlPhpForceAuthnMechanismEvidence(receipt,content,r->target,r->"browser_sso_idp");
        var outcome=reader.read(context).orElseThrow();if(outcome.outcome()!=Outcome.SATISFIED)throw new IllegalStateException("Original proof failed: "+outcome);
        byte[] manifestOriginal=Files.readAllBytes(marker),statesOriginal=Files.readAllBytes(folder.resolve("native-mechanism-observations.json"));
        var controls=new LinkedHashMap<String,String>();
        try {
            for(String mutation:List.of("lost-true","always-true","missing-flag","wrong-request","wrong-mechanism","wrong-stage","wrong-source","state-after-response","credentials-persisted","state-handle-persisted","duplicate-state","restore-mismatch","wrong-run","wrong-target","wrong-command")){
                var manifest=(ObjectNode)json.readTree(manifestOriginal);var states=(ObjectNode)json.readTree(statesOriginal);
                var baseline=(ObjectNode)states.withArray("observations").get(1);var forced=(ObjectNode)states.withArray("observations").get(2);
                var state=(ObjectNode)forced.path("state");String changedFile="native-mechanism-observations.json";byte[] original=statesOriginal;
                switch(mutation){case "lost-true"->state.put("forceAuthn",false);case "always-true"->((ObjectNode)baseline.path("state")).put("forceAuthn",true);
                    case "missing-flag"->state.remove("forceAuthn");case "wrong-request"->state.put("requestId","_wrong");case "wrong-mechanism"->state.put("mechanismId","other");
                    case "wrong-stage"->state.put("stateStage","other");case "wrong-source"->state.put("mechanismSourceSha256","0".repeat(64));
                    case "state-after-response"->forced.put("recordedAt","2099-01-01T00:00:00Z");case "credentials-persisted"->state.put("credentialsPersisted",true);
                    case "state-handle-persisted"->forced.put("stateHandlePersisted",true);case "duplicate-state"->states.withArray("observations").set(1,forced.deepCopy());
                    case "wrong-run"->manifest.put("runId","run_00000000000000000000000000");case "wrong-target"->manifest.put("targetEntityId","urn:other");
                    case "restore-mismatch"->{changedFile="final-sp-config.php";original=Files.readAllBytes(folder.resolve(changedFile));}
                    case "wrong-command"->{changedFile="native-state-command.php";original=Files.readAllBytes(folder.resolve(changedFile));}}
                byte[] changed=(mutation.equals("restore-mismatch")||mutation.equals("wrong-command"))?"changed".getBytes(java.nio.charset.StandardCharsets.UTF_8):json.writeValueAsBytes(states);
                Files.write(folder.resolve(changedFile),changed);((ObjectNode)manifest.path("files")).put(changedFile,SimpleSamlPhpForceAuthnMechanismEvidence.hash(changed));
                Files.write(marker,json.writeValueAsBytes(manifest));
                try {var rejected=reader.read(context).orElseThrow();if(rejected.outcome()!=Outcome.NOT_VERIFIED)throw new IllegalStateException("Mutation accepted: "+mutation);controls.put(mutation,rejected.outcome().name());}
                finally {Files.write(folder.resolve(changedFile),original);Files.write(marker,manifestOriginal);}
            }
        }finally{Files.write(marker,manifestOriginal);Files.write(folder.resolve("native-mechanism-observations.json"),statesOriginal);}
        var wrapper=new ForceAuthnMechanismEvidenceTestCase(new IdpForceAuthnScenarioTestCase(IdpForceAuthnScenarioTestCase.MECHANISM_ACCESS_CASE,
            r->{throw new AssertionError("Internal evidence must not trigger further logins");}),reader);
        if(((CaseStep.Finish)wrapper.start(context)).outcome().outcome()!=Outcome.SATISFIED||!wrapper.evidenceStatus(context).ready()
            ||wrapper.queuedEvidenceOutcome(context).outcome()!=Outcome.SATISFIED
            ||wrapper.reevaluateRecordedEvidence(context,CaseOutcome.notVerified("pending","case.pending-interaction")).orElseThrow().outcome()!=Outcome.SATISFIED)
            throw new IllegalStateException("Production wrapper path unavailable");
        var report=new LinkedHashMap<String,Object>();report.put("runId",run);report.put("outcome",outcome);report.put("manifestSha256",SimpleSamlPhpForceAuthnMechanismEvidence.hash(manifestOriginal));
        report.put("negativeControls",controls);report.put("productOperations",0);report.put("operatorAttestationSupplied",false);report.put("privateCredentialsPersisted",false);
        Files.write(Path.of(args[2]),json.writerWithDefaultPrettyPrinter().writeValueAsBytes(report));System.out.println("Native internal-state candidate verified; "+controls.size()+" semantic controls rejected");
    }
}
