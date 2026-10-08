package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.profile.*;
import com.samlscope.core.run.*;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.sql.DriverManager;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class NativeConfigurationSourceRunEvidenceTest {
    @TempDir Path data;
    NativeConfigurationSourceRunEvidence reader() {
        return new NativeConfigurationSourceRunEvidence(data,data.resolve("bindings"),data.resolve("sources"),
                e->{throw new AssertionError("An invalid binding read an original");},
                r->{throw new AssertionError("An invalid binding accessed metadata");});
    }
    @Test void absentBindingAndOwnedMalformedBindingHaveDifferentFailClosedPaths()throws Exception {
        var t=reader();var c=ClockSkewEvidenceTestCaseTest.context(true);assertTrue(t.read(c).isEmpty());
        Files.createDirectories(data.resolve("bindings"));Files.writeString(data.resolve("bindings").resolve(c.runId()),"invalid");
        assertTrue(t.exists(c.runId()));assertEquals(Outcome.NOT_VERIFIED,t.read(c).orElseThrow().outcome());
    }
    @Test void incompleteRecipientAndForeignCaseCannotAccessSourceMetadata()throws Exception {
        var t=reader();var c=ClockSkewEvidenceTestCaseTest.context(true);var folder=Files.createDirectories(data.resolve("bindings").resolve(c.runId()));
        Files.writeString(folder.resolve("manifest.json"),"{}");assertEquals(Outcome.NOT_VERIFIED,t.read(ClockSkewEvidenceTestCaseTest.context(false)).orElseThrow().outcome());
        Files.writeString(folder.resolve("manifest.json"),"{\"schema\":\""+NativeConfigurationSourceRunEvidence.SCHEMA+"\",\"caseId\":\"IIP-IDP19-a-idp-01\"}");
        assertEquals(Outcome.NOT_VERIFIED,t.read(c).orElseThrow().outcome());
    }
    @Test void sourceHasNoOrdinaryCompletionShortcutOrManualSuccessFlag()throws Exception {
        var c=ClockSkewEvidenceTestCaseTest.context(false);
        var store=new DefaultAlgorithmSourceRunStore(data,SimpleSamlPhpMultipleDecryptionKeysEvidence.CASE,SimpleSamlPhpMultipleDecryptionKeysEvidence.DIGEST);
        var source=new SimpleSamlPhpMultipleDecryptionKeysEvidence(data,e->{throw new AssertionError();},r->{throw new AssertionError();},store);
        var folder=Files.createDirectories(data.resolve(c.runId()+SimpleSamlPhpMultipleDecryptionKeysEvidence.SUFFIX));
        Files.writeString(folder.resolve("manifest.json"),"{\"success\":true,\"sourceTranscriptComplete\":true}");
        assertEquals(Outcome.NOT_VERIFIED,source.readIndependentConfigurationSource(c,"a".repeat(64)).orElseThrow().outcome());
        assertEquals(Outcome.NOT_VERIFIED,source.read(c).orElseThrow().outcome());
        assertFalse(Files.exists(data.resolve("samlscope.db")));assertFalse(Files.exists(data.resolve("keys")));
    }
    @Test void runtimeMountOrderIsIrrelevantButEveryMountFieldAndDestinationRemainsBound()throws Exception {
        var json=new JsonCodec().mapper();
        var first=json.readTree("{\"imageId\":\"same\",\"mounts\":[{\"Destination\":\"/one\",\"Source\":\"/a\",\"RW\":true},{\"Destination\":\"/two\",\"Source\":\"/b\",\"RW\":false}]}");
        var reordered=json.readTree("{\"imageId\":\"same\",\"mounts\":[{\"Destination\":\"/two\",\"Source\":\"/b\",\"RW\":false},{\"Destination\":\"/one\",\"Source\":\"/a\",\"RW\":true}]}");
        assertEquals(NativeConfigurationSourceRunEvidence.normalizedRuntime(first),NativeConfigurationSourceRunEvidence.normalizedRuntime(reordered));
        ((ObjectNode)reordered.path("mounts").get(0)).put("RW",true);
        assertNotEquals(NativeConfigurationSourceRunEvidence.normalizedRuntime(first),NativeConfigurationSourceRunEvidence.normalizedRuntime(reordered));
        ((ObjectNode)reordered.path("mounts").get(0)).put("Destination","/one");
        assertThrows(IllegalArgumentException.class,()->NativeConfigurationSourceRunEvidence.normalizedRuntime(reordered));
        assertEquals("/one",first.path("mounts").get(0).path("Destination").textValue());
    }
    @Test void wholeOtherCaseExecutionFenceDetectsChangesAndNeverWritesTheDatabase()throws Exception {
        String source="run_11111111111111111111111111",recipient="run_00000000000000000000000000";
        var codec=new JsonCodec();
        try(var c=DriverManager.getConnection("jdbc:sqlite:"+data.resolve("samlscope.db"));var s=c.createStatement()) {
            s.execute("CREATE TABLE case_executions(run_id TEXT,case_id TEXT,revision INTEGER,status TEXT,document_json TEXT)");
            var execution=new CaseExecution(recipient,"IIP-IDP19-c-idp-01",0,CaseExecutionStatus.FINISHED,CaseState.initial(),null,CaseOutcome.notVerified("pending","pending"),Instant.EPOCH);
            try(var q=c.prepareStatement("INSERT INTO case_executions VALUES(?,?,?,?,?)")){q.setString(1,recipient);q.setString(2,execution.caseId());q.setInt(3,0);q.setString(4,"FINISHED");q.setString(5,codec.write(execution));q.executeUpdate();}
        }
        var metadata=new java.util.concurrent.atomic.AtomicReference<>("saved metadata".getBytes());
        var t=new NativeConfigurationSourceRunEvidence(data,data.resolve("bindings"),data.resolve("sources"),e->{throw new AssertionError();},r->metadata.get());
        var sourceBinding=binding(source,RunStatus.RUNNING,codec.mapper().createObjectNode().put("source","unchanged"));
        var recipientBinding=binding(recipient,RunStatus.COMPLETED,codec.mapper().createObjectNode().put("caseExecutionSha256","expected-own-case-change"));
        byte[] before=Files.readAllBytes(data.resolve("samlscope.db"));var fence=t.fence(sourceBinding,recipientBinding,List.of(),List.of());
        assertArrayEquals(before,Files.readAllBytes(data.resolve("samlscope.db")));assertFalse(fence.path("recipientStore").has("caseExecutionSha256"));
        metadata.set("changed metadata".getBytes());assertNotEquals(fence,t.fence(sourceBinding,recipientBinding,List.of(),List.of()));metadata.set("saved metadata".getBytes());
        try(var c=DriverManager.getConnection("jdbc:sqlite:"+data.resolve("samlscope.db"));var q=c.prepareStatement("UPDATE case_executions SET document_json=? WHERE run_id=?")) {
            var changed=new CaseExecution(recipient,"IIP-IDP19-c-idp-01",0,CaseExecutionStatus.FINISHED,CaseState.initial(),null,new CaseOutcome(Outcome.VIOLATED,null,"changed","changed",List.of(),Map.of()),Instant.EPOCH);
            q.setString(1,codec.write(changed));q.setString(2,recipient);q.executeUpdate();
        }
        assertNotEquals(fence,t.fence(sourceBinding,recipientBinding,List.of(),List.of()));
    }
    private DefaultAlgorithmSourceRunStore.Binding binding(String run,RunStatus status,ObjectNode snapshot) {
        String planId="plan_"+run.substring(4);var plan=new TestPlan(planId,"fixture",FunctionalProfile.SINGLE_LOGOUT_IDP,
                new FunctionalDefinitionIdentity(FunctionalProfile.SINGLE_LOGOUT_IDP,"functional-case-v1","sha256:"+"a".repeat(64)),
                new TestPlan.Target(TargetKind.IDP,"http://localhost:18380/idp",new TestPlan.MetadataSource(MetadataSourceKind.URL,"http://localhost:18380/metadata")),
                MetadataDeliveryKind.HTTP_URL,Map.of(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Instant.EPOCH,Instant.EPOCH);
        return new DefaultAlgorithmSourceRunStore.Binding(new TestRun(run,planId,status,Reachability.CONFIRMED,Map.of(),Instant.EPOCH,Instant.EPOCH),plan,List.of(),snapshot);
    }
}
