package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.profile.*;
import com.samlscope.core.run.*;
import com.samlscope.core.transcript.*;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.sql.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class DefaultAlgorithmSourceRunStoreTest {
    static final String RUN="run_00000000000000000000000000",PLAN="plan_00000000000000000000000000",CASE=DefaultAlgorithmComparison.CASE,DIGEST="sha256:"+"a".repeat(64);
    static final Instant NOW=Instant.parse("2026-10-04T08:00:00Z");
    @TempDir Path data;
    final JsonCodec json=new JsonCodec();final Map<String,byte[]> resources=new HashMap<>();
    TestPlan plan;
    void prepare(boolean caseSelected,boolean executed)throws Exception {
        data=data.toRealPath();
        var sources=new TreeMap<String,String>();
        for(String path:List.of("tests/coverage.yaml","tests/cases.yaml","tests/predicates.yaml")) {
            byte[] raw=("approved "+path).getBytes();resources.put("/catalog/"+path,raw);sources.put(path,"sha256:"+DefaultAlgorithmPreventionEvidence.hash(raw));
        }
        byte[] profile=json.mapper().writeValueAsBytes(Map.of("schema_version",1,"version","functional-case-v1","profile","ecp_idp","source_digests",sources,
                "cases",List.of(Map.of("id",caseSelected?CASE:"other-approved-case","digest",DIGEST)),"non_executable_obligations",List.of()));
        String pin="sha256:"+DefaultAlgorithmPreventionEvidence.hash(profile);resources.put("/profiles/ecp_idp.json",profile);
        resources.put("/profiles/release-pins.properties",("ecp_idp="+pin+"\n").getBytes());
        plan=new TestPlan(PLAN,"scope",FunctionalProfile.ECP_IDP,new FunctionalDefinitionIdentity(FunctionalProfile.ECP_IDP,"functional-case-v1",pin),
                new TestPlan.Target(TargetKind.IDP,"https://target.example/idp",new TestPlan.MetadataSource(MetadataSourceKind.URL,"https://target.example/metadata")),
                MetadataDeliveryKind.HTTP_URL,Map.of(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),NOW,NOW);
        var run=new TestRun(RUN,PLAN,RunStatus.CREATED,Reachability.CONFIRMED,Map.of("preflight",true),NOW,NOW);
        try(var c=DriverManager.getConnection("jdbc:sqlite:"+data.resolve("samlscope.db"));var s=c.createStatement()) {
            s.execute("CREATE TABLE runs(id TEXT,plan_id TEXT,document_json TEXT)");s.execute("CREATE TABLE plans(id TEXT,document_json TEXT)");
            s.execute("CREATE TABLE case_executions(run_id TEXT,case_id TEXT,revision INTEGER,status TEXT,document_json TEXT)");
            s.execute("CREATE TABLE outbox_actions(run_id TEXT,action_id TEXT,case_id TEXT,kind TEXT,status TEXT,action_json TEXT,send_result_json TEXT,transcript_entry_id TEXT,created_at TEXT,updated_at TEXT)");
            try(var q=c.prepareStatement("INSERT INTO runs VALUES(?,?,?)")){q.setString(1,RUN);q.setString(2,PLAN);q.setString(3,json.write(run));q.executeUpdate();}
            try(var q=c.prepareStatement("INSERT INTO plans VALUES(?,?)")){q.setString(1,PLAN);q.setString(2,json.write(plan));q.executeUpdate();}
            if(executed) {var execution=new CaseExecution(RUN,CASE,0,CaseExecutionStatus.FINISHED,CaseState.initial(),null,CaseOutcome.notVerified("missing","pending"),NOW);
                try(var q=c.prepareStatement("INSERT INTO case_executions VALUES(?,?,?,?,?)")){q.setString(1,RUN);q.setString(2,CASE);q.setLong(3,0);q.setString(4,"FINISHED");q.setString(5,json.write(execution));q.executeUpdate();}}
        }
    }
    DefaultAlgorithmSourceRunStore store(){return new DefaultAlgorithmSourceRunStore(data,DIGEST,resources::get);}
    @Test void plannedMembershipIsIndependentOfSavedOutcomeAndReadOnly()throws Exception {
        prepare(true,true);byte[] before=Files.readAllBytes(data.resolve("samlscope.db"));
        var binding=store().execution(RUN);assertEquals(plan,binding.plan());assertEquals(DIGEST,binding.snapshot().path("caseDigest").asText());
        assertArrayEquals(before,Files.readAllBytes(data.resolve("samlscope.db")));assertFalse(Files.exists(data.resolve("keys")));
    }
    @Test void savedCaseLabelCannotInsertCaseMissingFromPinnedPlan()throws Exception {prepare(false,true);assertThrows(IllegalArgumentException.class,()->store().execution(RUN));}
    @Test void preflightDoesNotStartCaseAndExecutionNeedsActualSlot()throws Exception {prepare(true,false);assertEquals(plan,store().planned(RUN).plan());assertThrows(IllegalArgumentException.class,()->store().execution(RUN));}
    @Test void alteredReleaseSourceApprovalDigestOrForeignRunIsRejected()throws Exception {
        prepare(true,true);var store=store();assertThrows(IllegalArgumentException.class,()->store.execution("run_11111111111111111111111111"));
        resources.put("/catalog/tests/cases.yaml","changed catalog".getBytes());assertThrows(IllegalArgumentException.class,()->store.execution(RUN));
        resources.put("/catalog/tests/cases.yaml","approved tests/cases.yaml".getBytes());
        assertThrows(IllegalArgumentException.class,()->new DefaultAlgorithmSourceRunStore(data,"sha256:"+"b".repeat(64),resources::get).execution(RUN));
        resources.put("/profiles/release-pins.properties",("ecp_idp=sha256:"+"0".repeat(64)+"\n").getBytes());assertThrows(IllegalArgumentException.class,()->store.execution(RUN));
    }
    @Test void aDifferentNativeCaseCannotUseAnAlgorithmSlotEvenWithTheSameDigest()throws Exception {
        prepare(true,true);
        var nativeCase=new DefaultAlgorithmSourceRunStore(data,"IIP-IDP06-b-idp-01",DIGEST,resources::get);
        assertEquals("IIP-IDP06-b-idp-01",nativeCase.approvedCaseId());
        assertThrows(IllegalArgumentException.class,()->nativeCase.planned(RUN));
        assertThrows(IllegalArgumentException.class,()->nativeCase.execution(RUN));
        assertEquals(CASE,store().approvedCaseId());assertEquals(plan,store().execution(RUN).plan());
    }
    @Test void wholeSourceContextUsesRealPlanAndReadOnlyCompleteHistory()throws Exception {
        prepare(true,true);var binding=store().execution(RUN);var context=binding.context(Clock.fixed(NOW,ZoneOffset.UTC),List.of());
        assertEquals(plan.parameters(),context.parameters());assertEquals(plan.interaction(),context.interaction());assertEquals(Reachability.CONFIRMED,context.reachability());
        assertTrue(context.transcriptComplete());assertThrows(IllegalArgumentException.class,()->context.transcript().list("run_11111111111111111111111111"));
        assertThrows(UnsupportedOperationException.class,()->context.transcript().record(null));
    }
    @Test void everyOriginalBodyAndEntryIsBoundAndDuplicatesCannotBeHidden()throws Exception {
        prepare(true,true);String tx="tx_00000000000000000000000000";byte[] body="public native scope".getBytes();
        var path=data.resolve("transcripts/"+RUN+"/"+tx+".body");Files.createDirectories(path.getParent());Files.write(path,body);
        var e=new TranscriptEntry(tx,RUN,Direction.INBOUND,NOW,null,"POST","https://suite.example",200,Map.of(),"transcripts/"+RUN+"/"+tx+".body",body.length,null,0,"application/json",null,Map.of());
        var original=store().history(RUN,List.of(e),entry->{throw new AssertionError();});
        Files.write(path,"public native scOpe".getBytes());assertNotEquals(original,store().history(RUN,List.of(e),entry->{throw new AssertionError();}));
        assertThrows(IllegalArgumentException.class,()->store().history(RUN,List.of(e,e),entry->{throw new AssertionError();}));
        Files.delete(path);Files.createSymbolicLink(path,data.resolve("samlscope.db"));assertThrows(IllegalArgumentException.class,()->store().history(RUN,List.of(e),entry->{throw new AssertionError();}));
    }
}
